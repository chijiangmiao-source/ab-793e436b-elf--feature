"""多成员联合审计的单元/集成/HTTP 测试（unittest，无第三方依赖）。

覆盖：跨成员成功解析（local/member/external 三类来源）、按成员标识排序的
对齐连续布局、提交次序无关的冻结摘要、重复导出/未解析/非代码节/全局直引/
自引用拒绝、PC32 溢出与补丁重叠整组拒绝无部分结论、成员数量与标识校验、
HTTP 联合接口及单文件接口回归。
"""

from __future__ import annotations

import base64
import json
import struct
import sys
import threading
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import joinaudit
from app.server import build_server, run_audit, run_joint_audit
from elfbuild import STB_LOCAL, build_elf

BASE = 0x400000


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------------------
# 构造两个互相引用的成员：
#   alpha: 导出全局 alpha_fn(.text+0x10)；本地 alpha_local(.text+0x08) 被
#          本成员 PC32 引用；偏移 0x10 有 R64 引用外部 ext_helper
#   beta : SHN_UNDEF 引用 alpha_fn，偏移 0 的 PC32 完成跨成员解析
# ---------------------------------------------------------------------------


def alpha_elf(text_size: int = 32) -> bytes:
    return build_elf(
        text=bytes(range(text_size)),
        symbols=[
            ("alpha_fn", "text", 0x10),
            ("alpha_local", "text", 0x08, STB_LOCAL),
            ("ext_helper", 0, 0),
        ],
        relocs=[
            {"offset": 0x00, "sym": 2, "type": 2, "addend": 0},   # -> 本地 +0x08
            {"offset": 0x10, "sym": 3, "type": 1, "addend": 0x20},  # -> 外部
        ],
        text_addralign=16,
    )


def beta_elf(text_size: int = 32) -> bytes:
    return build_elf(
        text=b"\x00" * text_size,
        symbols=[("alpha_fn", 0, 0)],
        relocs=[{"offset": 0x00, "sym": 1, "type": 2, "addend": -4}],
        text_addralign=16,
    )


def joint_payload(
    members: list[tuple[str, bytes]],
    audit_id: str = "joint-1",
    *,
    base: int = BASE,
    symbols: dict[str, int] | None = None,
) -> dict:
    return {
        "audit_id": audit_id,
        "load_base": base,
        "symbols": {"ext_helper": 0x600000} if symbols is None else symbols,
        "members": [
            {"member_id": mid, "file_base64": b64(data)} for mid, data in members
        ],
    }


def two_members() -> list[tuple[str, bytes]]:
    return [("alpha", alpha_elf()), ("beta", beta_elf())]


class JointRequestValidationTests(unittest.TestCase):
    def test_bad_member_count(self):
        # 核心层：返回结构化违约
        r = joinaudit.joint_audit(BASE, two_members()[:1], {"ext_helper": 0x600000})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.stage, "request")
        self.assertEqual(r.violation.code, "bad_member_count")

        good = alpha_elf()
        r = joinaudit.joint_audit(BASE, [(f"m{i}", good) for i in range(9)], {})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "bad_member_count")

        # HTTP 入口层：非法数量直接 ValueError（400）
        with self.assertRaises(ValueError):
            run_joint_audit(joint_payload(two_members()[:1]))

    def test_eight_members_boundary_ok(self):
        # 8 个仅导出同一全局符号、不含重定位的成员：重复导出未被引用即允许
        elf = build_elf(
            text=b"\x90" * 8,
            symbols=[("shared", "text", 0)],
            relocs=[],
        )
        payload = joint_payload([(f"m{i}", elf) for i in range(8)], symbols={})
        r = run_joint_audit(payload)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["member_count"], 8)

    def test_duplicate_member_id(self):
        members = [("same", alpha_elf()), ("same", beta_elf())]
        with self.assertRaises(ValueError):
            run_joint_audit(joint_payload(members))
        # 核心层同样拒绝（stage=request）
        r = joinaudit.joint_audit(BASE, members, {"ext_helper": 0x600000})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "duplicate_member_id")

    def test_bad_member_id(self):
        members = [("alpha", alpha_elf()), ("bad/id!", beta_elf())]
        with self.assertRaises(ValueError):
            run_joint_audit(joint_payload(members))
        r = joinaudit.joint_audit(BASE, members, {"ext_helper": 0x600000})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "bad_member_id")

    def test_bad_base(self):
        r = joinaudit.joint_audit(-1, two_members(), {"ext_helper": 0x600000})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "bad_base")

    def test_member_structural_failure_located(self):
        r = joinaudit.joint_audit(
            BASE, [("alpha", b"not an elf" * 8), ("beta", beta_elf())], {}
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.stage, "member")
        self.assertEqual(r.violation.member, "alpha")
        self.assertEqual(r.violation.code, "bad_magic")
        self.assertEqual(r.members, [])

    def test_extra_unreferenced_external_symbol_rejected(self):
        r = joinaudit.joint_audit(
            BASE, two_members(), {"ext_helper": 0x600000, "ghost": 1}
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "unexpected_symbol")


class JointLayoutTests(unittest.TestCase):
    def test_sorted_aligned_contiguous_layout(self):
        # alpha 3 字节、对齐 16；beta 若干字节、对齐 8；基址故意非对齐
        a = build_elf(
            text=b"\x90" * 3,
            symbols=[("alpha_fn", "text", 0)],
            relocs=[],
            text_addralign=16,
        )
        b = build_elf(
            text=b"\x90" * 5,
            symbols=[("alpha_fn", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
            text_addralign=8,
        )
        # 故意把 beta 放在提交列表前面：布局必须仍按标识排序
        r = joinaudit.joint_audit(0x400001, [("beta", b), ("alpha", a)], {})
        self.assertTrue(r.ok, r.violation)
        layout = {m.member: m for m in r.members}
        self.assertEqual([m.member for m in r.members], ["alpha", "beta"])
        self.assertEqual(layout["alpha"].start, 0x400010)  # 上取整到 16
        self.assertEqual(layout["alpha"].end, 0x400013)
        self.assertEqual(layout["beta"].start, 0x400018)  # 上取整到 8
        self.assertEqual(layout["beta"].end, 0x40001D)
        # beta 的 PC32：S=alpha 基址+0=0x400010，P=0x400018 => -8
        it = r.items[0]
        self.assertEqual(it.symbol, "alpha_fn")
        self.assertEqual(it.source, "member")
        self.assertEqual(it.source_member, "alpha")
        self.assertEqual(it.value, -8)
        self.assertEqual(it.after, struct.pack("<i", -8))

    def test_member_bases_ranges_and_items_in_success(self):
        r = joinaudit.joint_audit(BASE, two_members(), {"ext_helper": 0x600000})
        self.assertTrue(r.ok, r.violation)
        pub = r.to_public_dict()
        self.assertEqual([m["member"] for m in pub["members"]], ["alpha", "beta"])
        ma, mb = pub["members"]
        self.assertEqual(ma["base"], "0x0000000000400000")
        self.assertEqual(ma["range"], ["0x0000000000400000", "0x0000000000400020"])
        self.assertEqual(mb["base"], "0x0000000000400020")
        self.assertEqual(mb["text_addralign"], 16)

        # 稳定顺序：先按成员（排序后），再按节内偏移
        keys = [(it.member, it.offset) for it in r.ordered_items()]
        self.assertEqual(keys, [("alpha", 0), ("alpha", 0x10), ("beta", 0)])
        # 全局连续编号
        self.assertEqual([it.index for it in r.ordered_items()], [0, 1, 2])

        local, external, cross = r.ordered_items()
        self.assertEqual(local.source, "local")
        self.assertEqual(local.s, BASE + 0x08)
        self.assertEqual(local.p, BASE + 0)
        self.assertEqual(local.value, 8)
        self.assertEqual(local.before, bytes(range(4)))
        self.assertEqual(local.after, struct.pack("<i", 8))

        self.assertEqual(external.source, "external")
        self.assertIsNone(external.source_member)
        self.assertEqual(external.s, 0x600000)
        self.assertEqual(external.a, 0x20)
        self.assertEqual(external.value, 0x600020)
        self.assertEqual(external.after, struct.pack("<Q", 0x600020))

        self.assertEqual(cross.source, "member")
        self.assertEqual(cross.source_member, "alpha")
        self.assertEqual(cross.member, "beta")
        self.assertEqual(cross.s, BASE + 0x10)
        self.assertEqual(cross.p, BASE + 0x20)
        self.assertEqual(cross.value, BASE + 0x10 - 4 - (BASE + 0x20))
        self.assertEqual(cross.after, struct.pack("<i", cross.value))

        # 补丁后节体摘要与逐项 after 一致
        patched_a = bytearray(range(32))
        patched_a[0:4] = struct.pack("<i", 8)
        patched_a[0x10:0x18] = struct.pack("<Q", 0x600020)
        self.assertEqual(ma["patched_text_hex"], bytes(patched_a).hex())
        self.assertEqual(ma["patched_sha256"], __import__("hashlib").sha256(bytes(patched_a)).hexdigest())

    def test_order_invariance_same_layout_and_freeze(self):
        syms = {"ext_helper": 0x600000}
        r1 = joinaudit.joint_audit(BASE, [("alpha", alpha_elf()), ("beta", beta_elf())], syms)
        r2 = joinaudit.joint_audit(BASE, [("beta", beta_elf()), ("alpha", alpha_elf())], syms)
        self.assertTrue(r1.ok and r2.ok)
        c1 = joinaudit.freeze_joint_conclusion("jid", r1, syms)
        c2 = joinaudit.freeze_joint_conclusion("jid", r2, syms)
        self.assertEqual(c1, c2)
        self.assertEqual(len(c1), 64)
        b1 = {m.member: (m.start, m.end) for m in r1.members}
        b2 = {m.member: (m.start, m.end) for m in r2.members}
        self.assertEqual(b1, b2)
        # 换基址 / 换标识 -> 结论改变
        r3 = joinaudit.joint_audit(BASE + 0x1000, [("alpha", alpha_elf()), ("beta", beta_elf())], syms)
        self.assertNotEqual(c1, joinaudit.freeze_joint_conclusion("jid", r3, syms))
        self.assertNotEqual(c1, joinaudit.freeze_joint_conclusion("other", r1, syms))

    def test_patched_bytes_member_isolation(self):
        # beta 的补丁不得改动 alpha 的节体（成员字节分别保存）
        r = joinaudit.joint_audit(BASE, two_members(), {"ext_helper": 0x600000})
        self.assertTrue(r.ok)
        for m in r.members:
            self.assertEqual(len(m.patched), m.text_size)


class JointResolutionRejectionTests(unittest.TestCase):
    def _reject(self, members, symbols=None, code=None):
        r = joinaudit.joint_audit(BASE, members, {} if symbols is None else symbols)
        self.assertFalse(r.ok)
        self.assertEqual(r.members, [])
        self.assertEqual(r.items, [])
        if code is not None:
            self.assertEqual(r.violation.code, code)
        return r.violation

    def test_unresolved_cross_member_reference(self):
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("ghost", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        a = build_elf(text=b"\x90" * 8, symbols=[("other", "text", 0)], relocs=[])
        v = self._reject([("a", a), ("b", b)], code="unresolved_symbol")
        self.assertEqual(v.member, "b")
        self.assertEqual(v.symbol, "ghost")
        self.assertEqual(v.entry_index, 0)

    def test_duplicate_export_two_members(self):
        a = build_elf(text=b"\x90" * 8, symbols=[("dup", "text", 0)], relocs=[])
        g = build_elf(text=b"\x90" * 8, symbols=[("dup", "text", 4)], relocs=[])
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("dup", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        v = self._reject([("alpha", a), ("beta", b), ("gamma", g)], code="duplicate_export")
        # 首个相关重定位在 beta（排序 alpha,beta,gamma），全局序号 0
        self.assertEqual(v.member, "beta")
        self.assertEqual(v.entry_index, 0)
        definers = v.detail["definers"]
        self.assertEqual(len(definers), 2)
        self.assertEqual({d["member"] for d in definers}, {"alpha", "gamma"})

    def test_duplicate_export_twice_in_same_member(self):
        # 同一成员文件内两个同名 .text 全局定义，被另一成员引用 => 歧义
        a = build_elf(
            text=b"\x90" * 16,
            symbols=[("dup", "text", 0), ("dup", "text", 8)],
            relocs=[],
        )
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("dup", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        self._reject([("a", a), ("b", b)], code="duplicate_export")

    def test_external_and_member_export_ambiguous(self):
        a = build_elf(text=b"\x90" * 8, symbols=[("shared", "text", 0)], relocs=[])
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("shared", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        v = self._reject([("a", a), ("b", b)], {"shared": 0x700000}, code="duplicate_export")
        sources = {d["source"] for d in v.detail["definers"]}
        self.assertEqual(sources, {"member", "external"})

    def test_non_code_section_definition_rejected(self):
        a = build_elf(
            text=b"\x90" * 8,
            rodata=b"\x01\x02\x03\x00",
            symbols=[("data_sym", "rodata", 0)],
            relocs=[],
        )
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("data_sym", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        v = self._reject([("a", a), ("b", b)], code="non_code_definition")
        self.assertEqual(v.member, "b")
        self.assertEqual(v.symbol, "data_sym")
        self.assertEqual(v.entry_index, 0)

    def test_direct_global_reference_in_own_member_rejected(self):
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("g", "text", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        a = build_elf(text=b"\x90" * 8, symbols=[("x", "text", 0)], relocs=[])
        self._reject([("a", a), ("b", b)], code="global_direct_reference")

    def test_self_undefined_reference_rejected(self):
        # 同一成员既导出 selfish 又以 SHN_UNDEF 引用它
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("selfish", "text", 0), ("selfish", 0, 0)],
            relocs=[{"offset": 0, "sym": 2, "type": 2, "addend": 0}],
        )
        b = build_elf(text=b"\x90" * 8, symbols=[("x", "text", 0)], relocs=[])
        self._reject([("a", a), ("b", b)], code="self_global_reference")

    def test_local_reference_succeeds(self):
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("loc", "text", 8, STB_LOCAL)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
            text_addralign=16,
        )
        b = build_elf(text=b"\x90" * 16, symbols=[], relocs=[], text_addralign=16)
        r = joinaudit.joint_audit(BASE, [("a", a), ("b", b)], {})
        self.assertTrue(r.ok, r.violation)
        self.assertEqual(r.items[0].source, "local")
        self.assertEqual(r.items[0].value, 8)


class JointWholeGroupRejectTests(unittest.TestCase):
    def test_pc32_overflow_rejects_entire_group_no_partial(self):
        # beta 的外部 PC32 目标远超 i32：整组拒绝
        a = build_elf(text=b"\x90" * 8, symbols=[("alpha_fn", "text", 0)], relocs=[])
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("far", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        r = joinaudit.joint_audit(BASE, [("a", a), ("b", b)], {"far": 0x7F0000000000})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "pc32_overflow")
        self.assertEqual(r.violation.member, "b")
        # 不得留下部分联合结论
        self.assertEqual(r.members, [])
        self.assertEqual(r.items, [])

    def test_patch_overlap_rejects_entire_group(self):
        a = build_elf(text=b"\x90" * 8, symbols=[("alpha_fn", "text", 0)], relocs=[])
        b = build_elf(
            text=b"\x00" * 32,
            symbols=[("x", 0, 0), ("y", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 4, "sym": 2, "type": 2, "addend": 0},
            ],
        )
        r = joinaudit.joint_audit(BASE, [("a", a), ("b", b)], {"x": 0x1000, "y": 0x1000})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "patch_overlap")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.entry_index, 1)

    def test_write_out_of_range_rejected(self):
        a = build_elf(text=b"\x90" * 8, symbols=[("alpha_fn", "text", 0)], relocs=[])
        b = build_elf(
            text=b"\x00" * 8,
            symbols=[("alpha_fn", 0, 0)],
            relocs=[{"offset": 6, "sym": 1, "type": 1, "addend": 0}],  # 8B 写出界
        )
        r = joinaudit.joint_audit(BASE, [("a", a), ("b", b)], {})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "write_out_of_range")
        self.assertEqual(r.violation.member, "b")

    def test_unsupported_reloc_type_locates_first(self):
        a = build_elf(text=b"\x90" * 8, symbols=[("alpha_fn", "text", 0)], relocs=[])
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("x", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 9, "addend": 0}],
        )
        r = joinaudit.joint_audit(BASE, [("a", a), ("b", b)], {"x": 0x1000})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "unsupported_reloc_type")
        self.assertEqual(r.violation.rela_section, ".rela.text")


class JointApiTests(unittest.TestCase):
    def setUp(self):
        from app import server

        server._store.clear()
        server._joint_store.clear()

    def test_joint_api_success_shape(self):
        rec = run_joint_audit(joint_payload(two_members(), "j-ok"))
        self.assertTrue(rec["ok"], rec.get("violation"))
        self.assertTrue(rec["joint"])
        self.assertEqual(len(rec["conclusion"]), 64)
        self.assertEqual(rec["member_count"], 2)
        self.assertEqual(rec["item_count"], 3)
        # 成员基址与范围
        self.assertEqual(rec["members"][0]["base"], "0x0000000000400000")
        self.assertEqual(rec["members"][1]["range"],
                         ["0x0000000000400020", "0x0000000000400040"])
        # 按成员、节内偏移稳定排序
        keys = [(it["member"], it["offset"]) for it in rec["items"]]
        self.assertEqual(keys, [("alpha", 0), ("alpha", 0x10), ("beta", 0)])
        for it in rec["items"]:
            for key in ("S", "A", "P", "value", "before_hex", "after_hex", "source"):
                self.assertIn(key, it)

    def test_joint_failure_clears_previous_success(self):
        ok = run_joint_audit(joint_payload(two_members(), "stable-joint"))
        self.assertTrue(ok["ok"])
        bad = build_elf(
            text=b"\x00" * 32,
            symbols=[("far", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        payload = joint_payload(
            [("alpha", alpha_elf()), ("beta", bad)],
            "stable-joint",
            symbols={"far": 0x7F0000000000, "ext_helper": 0x600000},
        )
        fail = run_joint_audit(payload)
        self.assertFalse(fail["ok"])
        self.assertEqual(fail["violation"]["code"], "pc32_overflow")
        self.assertNotIn("conclusion", fail)
        from app import server

        stored = server._joint_store["stable-joint"]
        self.assertEqual(stored["kind"], "joint_fail")
        self.assertNotIn("result", stored)

    def test_single_file_api_unchanged(self):
        # 联合接口与单文件接口互不干扰；同一标识在两个命名空间各自独立
        from tests.elfbuild import build_elf as _be  # noqa: F401
        from tests.test_audit import SYMS, two_type_elf

        single = run_audit({
            "audit_id": "same-id",
            "file_base64": b64(two_type_elf()),
            "load_base": BASE,
            "symbols": dict(SYMS),
        })
        joint = run_joint_audit(joint_payload(two_members(), "same-id"))
        self.assertTrue(single["ok"] and joint["ok"])
        self.assertNotIn("joint", single)
        self.assertTrue(joint["joint"])
        self.assertNotEqual(single["conclusion"], joint["conclusion"])

    def test_bad_payload_shapes(self):
        good_b64 = b64(alpha_elf())
        for payload in [
            {"audit_id": "x", "load_base": 0, "symbols": {}, "members": []},
            {"audit_id": "x", "load_base": 0, "symbols": {},
             "members": [{"member_id": "only", "file_base64": good_b64}]},
            {"audit_id": "x", "load_base": 0, "symbols": {},
             "members": [{"member_id": "a", "file_base64": good_b64},
                         {"member_id": "a", "file_base64": good_b64}]},
            {"audit_id": "x", "load_base": 0, "symbols": {},
             "members": [{"member_id": "bad/name", "file_base64": good_b64},
                         {"member_id": "b", "file_base64": good_b64}]},
            {"audit_id": "x", "load_base": 0, "symbols": {},
             "members": [{"member_id": "a", "file_base64": "@@@"},
                         {"member_id": "b", "file_base64": good_b64}]},
            "not-a-dict",
        ]:
            with self.assertRaises(ValueError):
                run_joint_audit(payload)


class JointHttpSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = build_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _post(self, path, payload):
        req = urllib.request.Request(
            self._url(path),
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())

    def _get(self, path):
        with urllib.request.urlopen(self._url(path), timeout=5) as resp:
            return resp.status, json.loads(resp.read())

    def test_joint_http_flow_and_single_file_regression(self):
        status, ok = self._post("/api/joint/audit", joint_payload(two_members(), "http-joint"))
        self.assertEqual(status, 200)
        self.assertTrue(ok["ok"], ok)
        status, fetched = self._get("/api/joint/result/http-joint")
        self.assertEqual(status, 200)
        self.assertTrue(fetched["ok"])
        self.assertEqual(fetched["conclusion"], ok["conclusion"])

        # 健康检查包含联合计数
        _, health = self._get("/healthz")
        self.assertGreaterEqual(health["joint_passed"], 1)

        # 重复导出整组拒绝
        a = build_elf(text=b"\x90" * 8, symbols=[("dup", "text", 0)], relocs=[])
        g = build_elf(text=b"\x90" * 8, symbols=[("dup", "text", 4)], relocs=[])
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("dup", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        status, bad = self._post(
            "/api/joint/audit", joint_payload([("a", a), ("b", b), ("g", g)], "http-joint", symbols={})
        )
        self.assertEqual(status, 200)
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["violation"]["code"], "duplicate_export")
        status, again = self._get("/api/joint/result/http-joint")
        self.assertFalse(again["ok"])
        self.assertNotIn("conclusion", again)

        # 未知联合标识 404
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/api/joint/result/nope")
        self.assertEqual(cm.exception.code, 404)

    def test_single_file_endpoints_still_work(self):
        from tests.test_audit import SYMS, two_type_elf

        payload = {
            "audit_id": "single-regression",
            "file_base64": b64(two_type_elf()),
            "load_base": BASE,
            "symbols": dict(SYMS),
        }
        status, body = self._post("/api/audit", payload)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertNotIn("joint", body)
        status, fetched = self._get("/api/result/single-regression")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["conclusion"], body["conclusion"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
