"""联合审计（2..8 个供应商拆分成员）的单元 / 集成测试。

覆盖：

* 按成员标识排序 + 各自 ``.text`` 对齐的连续布局（与提交次序无关）；
* 跨成员全局定义解析、同成员局部定义不外泄、外部地址解析；
* 重复导出 / 未解析引用 / 非代码节定义均定位到首个相关重定位；
* PC32 溢出、补丁重叠整组拒绝且无部分联合结论；
* 成员次序调换得到同一布局与冻结摘要；
* 联合审计存储与单文件审计互不影响；
* 单文件审计接口与读取结果保持不变（回归在 test_audit.py，本文件额外复核）。
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

from app import elfaudit, server  # noqa: E402
from app.server import build_server, run_audit, run_group_audit  # noqa: E402
from elfbuild import build_elf  # noqa: E402

BASE = 0x400000


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def member(mid: str, data: bytes) -> dict:
    return {"member_id": mid, "data": data}


# ---------------------------------------------------------------------------
# 夹具
# ---------------------------------------------------------------------------


def member_a_producer(text: bytes = b"\x11" * 32) -> bytes:
    """成员 a：导出 produce@.text+0x10；R64@0 引用外部 ext_base。"""
    return build_elf(
        text=text,
        symbols=[("ext_base", 0, 0), ("produce", "text", 0x10)],
        relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0x8}],
    )


def member_b_consumer(text: bytes = b"\x22" * 32) -> bytes:
    """成员 b：PC32@0 引用他成员 produce；R64@24 引用外部 ext_base。"""
    return build_elf(
        text=text,
        symbols=[("produce", 0, 0), ("ext_base", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 2, "addend": -4},
            {"offset": 24, "sym": 2, "type": 1, "addend": 0},
        ],
    )


def member_c_aligned(text: bytes = b"\x33" * 16, align: int = 64) -> bytes:
    return build_elf(
        text=text,
        text_align=align,
        symbols=[("ext_base", 0, 0)],
        relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
    )


def group_two(a: bytes = None, b: bytes = None, symbols=None):
    a = member_a_producer() if a is None else a
    b = member_b_consumer() if b is None else b
    return elfaudit.audit_group(
        "grp",
        [member("vendor-a", a), member("vendor-b", b)],
        BASE,
        {"ext_base": 0x500000} if symbols is None else symbols,
    )


# ---------------------------------------------------------------------------
# 成功路径与布局
# ---------------------------------------------------------------------------


class GroupSuccessLayoutTests(unittest.TestCase):
    def test_cross_member_resolve_and_ranges(self):
        r = group_two()
        self.assertTrue(r.ok, r.violation)
        self.assertEqual([m.member_id for m in r.members], ["vendor-a", "vendor-b"])
        ma, mb = r.members
        self.assertEqual(ma.base, BASE)
        self.assertEqual(ma.end, BASE + 32)
        self.assertEqual(mb.base, BASE + 32)
        self.assertEqual(mb.end, BASE + 64)
        self.assertEqual(r.region_end, BASE + 64)

        # b 的 PC32 引用 a.produce：S = 0x400010, P = b.base+0 = 0x400020, A=-4
        pc = next(it for m in r.members if m.member_id == "vendor-b" for it in m.items
                  if it.reloc_type == 2)
        self.assertEqual(pc.s, BASE + 0x10)
        self.assertEqual(pc.a, -4)
        self.assertEqual(pc.p, BASE + 32)
        self.assertEqual(pc.value, BASE + 0x10 - 4 - (BASE + 32))
        self.assertEqual(pc.after, struct.pack("<i", pc.value))

        # a 的 R64 写外部 ext_base+8
        r64 = next(it for m in r.members if m.member_id == "vendor-a" for it in m.items)
        self.assertEqual(r64.s, 0x500000)
        self.assertEqual(r64.value, 0x500008)

        # 每个成员给出基址与范围
        pub = r.to_public_dict()
        self.assertEqual(pub["region_range"], [elfaudit.hex64(BASE), elfaudit.hex64(BASE + 64)])
        for mp in pub["members"]:
            self.assertEqual(mp["range"][0], mp["base"])
            self.assertEqual(int(mp["range"][1], 16) - int(mp["range"][0], 16), mp["text_size"])
            # 节内偏移稳定升序
            offs = [it["offset"] for it in mp["items"]]
            self.assertEqual(offs, sorted(offs))

    def test_order_swap_same_layout_and_freeze(self):
        a = member_a_producer()
        b = member_b_consumer()
        syms = {"ext_base": 0x500000}
        r1 = elfaudit.audit_group(
            "frozen", [member("vendor-a", a), member("vendor-b", b)], BASE, syms
        )
        # 提交次序整体调换
        r2 = elfaudit.audit_group(
            "frozen", [member("vendor-b", b), member("vendor-a", a)], BASE, syms
        )
        self.assertTrue(r1.ok and r2.ok)
        lay1 = [(m.member_id, m.base, m.end) for m in r1.members]
        lay2 = [(m.member_id, m.base, m.end) for m in r2.members]
        self.assertEqual(lay1, lay2)
        self.assertEqual(r1.conclusion, r2.conclusion)
        self.assertEqual(len(r1.conclusion), 64)

    def test_alignment_padding_between_members(self):
        # a:20B align64 从 0x400000 起；b:16B align16 需对齐到 0x400020
        a = member_c_aligned(b"\x33" * 20, align=64)
        b = build_elf(
            text=b"\x44" * 16,
            text_align=16,
            symbols=[("ext_base", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        r = elfaudit.audit_group(
            "al", [member("aaa", a), member("bbb", b)], BASE, {"ext_base": 0x500000}
        )
        self.assertTrue(r.ok, r.violation)
        ma, mb = r.members
        self.assertEqual(ma.text_offset, 0)
        self.assertEqual(ma.text_align, 64)
        # 0x400014 之后按 16 对齐 -> 下一个边界 0x400020（相对偏移 0x20）
        self.assertEqual(mb.base, 0x400020)
        self.assertEqual(mb.text_offset, 0x20)
        self.assertEqual(r.region_end, 0x400030)

    def test_first_member_requires_aligned_base(self):
        a = member_c_aligned(b"\x33" * 16, align=64)
        b = member_c_aligned(b"\x44" * 16, align=16)
        r = elfaudit.audit_group(
            "al", [member("aaa", a), member("bbb", b)], 0x400004, {"ext_base": 0x500000}
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.scope, "request")
        self.assertEqual(r.violation.code, "bad_base_alignment")

    def test_member_local_symbol_not_visible_other_member(self):
        # a 定义 LOCAL secret 与 GLOBAL pub；b 引用 pub 成功、引用 secret 必须未解析
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("secret", "text", 4, 0), ("pub", "text", 0)],
            relocs=[{"offset": 0, "sym": 2, "type": 2, "addend": 0}],
        )
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("pub", 0, 0), ("secret", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 2, "addend": 0},
                {"offset": 8, "sym": 2, "type": 2, "addend": 0},
            ],
        )
        r = elfaudit.audit_group("loc", [member("a", a), member("b", b)], BASE, {})
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "unresolved_symbol")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.symbol, "secret")
        self.assertEqual(r.violation.rela_index, 1)
        self.assertEqual(r.violation.offset, 8)

    def test_same_member_definition_resolves_within_member(self):
        # b 以 LOCAL 定义 produce 时，b 内对 produce 的引用必须解析到自己，
        # 而不是 a 导出的全局 produce；a 仍唯一全局导出 produce。
        a = member_a_producer()
        b = build_elf(
            text=b"\x22" * 16,
            symbols=[("produce", "text", 6, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        # a 还引用 ext_base，必须提供
        r = elfaudit.audit_group(
            "self", [member("a", a), member("b", b)], BASE, {"ext_base": 0x500000}
        )
        self.assertTrue(r.ok, r.violation)
        item = r.members[1].items[0]
        self.assertEqual(item.s, BASE + 32 + 6)  # b.base + 6，而非 a 的 0x400010

    def test_freeze_changes_with_inputs(self):
        a = member_a_producer()
        b = member_b_consumer()
        syms = {"ext_base": 0x500000}
        base = elfaudit.audit_group("fz", [member("a", a), member("b", b)], BASE, syms)
        # 稳定
        again = elfaudit.audit_group("fz", [member("a", a), member("b", b)], BASE, syms)
        self.assertEqual(base.conclusion, again.conclusion)
        # 改 audit_id
        self.assertNotEqual(
            base.conclusion,
            elfaudit.audit_group("fz2", [member("a", a), member("b", b)], BASE, syms).conclusion,
        )
        # 改基址
        self.assertNotEqual(
            base.conclusion,
            elfaudit.audit_group("fz", [member("a", a), member("b", b)], BASE + 0x10, syms).conclusion,
        )
        # 改外部地址
        self.assertNotEqual(
            base.conclusion,
            elfaudit.audit_group("fz", [member("a", a), member("b", b)], BASE,
                                 {"ext_base": 0x500001}).conclusion,
        )
        # 改某成员字节
        a2 = member_a_producer(text=b"\x00" * 32)
        self.assertNotEqual(
            base.conclusion,
            elfaudit.audit_group("fz", [member("a", a2), member("b", b)], BASE, syms).conclusion,
        )


# ---------------------------------------------------------------------------
# 请求级拒绝
# ---------------------------------------------------------------------------


class GroupRequestValidationTests(unittest.TestCase):
    def _expect_request(self, audit_id="grp", members=None, base=BASE, symbols=None):
        if members is None:
            members = [member("a", member_a_producer()), member("b", member_b_consumer())]
        if symbols is None:
            symbols = {"ext_base": 0x500000}
        r = elfaudit.audit_group(audit_id, members, base, symbols)
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.scope, "request")
        return r.violation

    def test_member_count_bounds(self):
        one = [member("only", member_c_aligned())]
        v = self._expect_request(members=one, symbols={"ext_base": 0x500000})
        self.assertEqual(v.code, "bad_member_count")
        many = [member(f"m{i:02d}", member_a_producer()) for i in range(9)]
        # 每个成员都引用 ext_base
        v = self._expect_request(members=many, symbols={"ext_base": 0x500000})
        self.assertEqual(v.code, "bad_member_count")

    def test_bad_or_duplicate_member_id(self):
        a = member_a_producer()
        self.assertEqual(
            self._expect_request(members=[member("bad id", a), member("b", a)]).code,
            "bad_member_id",
        )
        self.assertEqual(
            self._expect_request(members=[member("same", a), member("same", a)]).code,
            "duplicate_member_id",
        )

    def test_bad_audit_id_base_symbols(self):
        a, b = member_a_producer(), member_b_consumer()
        self.assertEqual(
            elfaudit.audit_group("", [member("a", a), member("b", b)], BASE,
                                 {"ext_base": 1}).violation.code,
            "bad_audit_id",
        )
        self.assertEqual(
            elfaudit.audit_group("g", [member("a", a), member("b", b)], -1,
                                 {"ext_base": 1}).violation.code,
            "bad_base",
        )
        self.assertEqual(
            elfaudit.audit_group("g", [member("a", a), member("b", b)], BASE,
                                 {"ext_base": 1 << 70}).violation.code,
            "bad_symbol_addr",
        )

    def test_unexpected_external_symbol(self):
        a = member_a_producer()
        b = member_b_consumer()
        v = self._expect_request(
            members=[member("a", a), member("b", b)],
            symbols={"ext_base": 0x500000, "ghost": 0x600000},
        )
        self.assertEqual(v.code, "unexpected_symbol")
        self.assertEqual(v.detail["unexpected"], ["ghost"])


# ---------------------------------------------------------------------------
# 成员结构级与解析级拒绝
# ---------------------------------------------------------------------------


class GroupRejectionTests(unittest.TestCase):
    def test_structural_failure_attached_to_member(self):
        good = member_a_producer()
        r = elfaudit.audit_group(
            "g", [member("a", good), member("b", b"not an elf, but long enough!!" * 4)],
            BASE, {"ext_base": 0x500000},
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.scope, "member")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.code, "bad_magic")
        self.assertEqual(r.violation.detail["file_stage"], "file")
        # 结构失败不带任何补丁结论
        self.assertEqual(r.members, [])

    def test_truncated_member_attached_to_member(self):
        good = member_a_producer()
        r = elfaudit.audit_group(
            "g", [member("a", good), member("b", b"\x7fELF" + b"\x00" * 8)],
            BASE, {"ext_base": 0x500000},
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.code, "truncated")

    def test_duplicate_export_located_at_first_related_reloc(self):
        # a 与 c 都导出 dup；b 先在 rela#0 用 z，再在 rela#1(off=8) 引用 dup
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0), ("dup", "text", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        c = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0), ("dup", "text", 4)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0), ("dup", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 8, "sym": 2, "type": 2, "addend": 0},
            ],
        )
        r = elfaudit.audit_group(
            "g", [member("a", a), member("b", b), member("c", c)],
            BASE, {"z": 0x600000},
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "duplicate_export")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.rela_index, 1)
        self.assertEqual(r.violation.offset, 8)
        self.assertEqual(sorted(r.violation.detail["exporters"]), ["a", "c"])

    def test_duplicate_export_unreferenced_located_via_symbol_table(self):
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0), ("dup", "text", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        c = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0), ("dup", "text", 4)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        r = elfaudit.audit_group(
            "g", [member("a", a), member("c", c)], BASE, {"z": 0x600000}
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "duplicate_export")
        self.assertEqual(r.violation.member, "c")
        self.assertEqual(r.violation.detail["located_via"], "symbol_table")

    def test_unresolved_located_at_reloc(self):
        a = member_a_producer()
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("missing", 0, 0)],
            relocs=[{"offset": 4, "sym": 1, "type": 1, "addend": 0}],
        )
        r = elfaudit.audit_group(
            "g", [member("a", a), member("b", b)], BASE, {"ext_base": 0x500000}
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "unresolved_symbol")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.symbol, "missing")
        self.assertEqual(r.violation.offset, 4)

    def test_non_code_definition_cross_member(self):
        a = build_elf(
            text=b"\x00" * 16,
            rodata=b"abc",
            symbols=[("z", 0, 0), ("ro_sym", "rodata", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("ro_sym", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        r = elfaudit.audit_group(
            "g", [member("a", a), member("b", b)], BASE, {"z": 0x600000}
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "non_code_definition")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.symbol, "ro_sym")

    def test_non_code_definition_same_member(self):
        a = build_elf(
            text=b"\x00" * 16,
            rodata=b"abc",
            symbols=[("ro_sym", "rodata", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        b = member_c_aligned()
        r = elfaudit.audit_group(
            "g", [member("a", a), member("b", b)], BASE, {"ext_base": 0x500000}
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "non_code_definition")
        self.assertEqual(r.violation.member, "a")

    def test_external_address_shadows_export_rejected(self):
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0), ("fn", "text", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("fn", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        r = elfaudit.audit_group(
            "g", [member("a", a), member("b", b)], BASE,
            {"z": 0x600000, "fn": 0x999999},
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "external_shadows_export")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.rela_index, 0)

    def test_pc32_overflow_rejects_whole_group_without_partial(self):
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("huge", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
        )
        r = elfaudit.audit_group(
            "g", [member("a", a), member("b", b)], BASE,
            {"z": 0x600000, "huge": 0x7F0000000000},
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "pc32_overflow")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.rela_index, 0)
        self.assertEqual(r.violation.offset, 0)
        self.assertIn("S", r.violation.detail)
        # 无部分联合结论
        self.assertEqual(r.members, [])
        self.assertEqual(r.conclusion, "")

    def test_patch_overlap_rejects_whole_group(self):
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("p", 0, 0), ("q", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 4, "sym": 2, "type": 2, "addend": 0},
            ],
        )
        r = elfaudit.audit_group(
            "g", [member("a", a), member("b", b)], BASE,
            {"z": 0x600000, "p": 0x600010, "q": 0x600020},
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "patch_overlap")
        self.assertEqual(r.violation.member, "b")
        self.assertEqual(r.violation.rela_index, 1)
        self.assertEqual(r.members, [])

    def test_write_out_of_range(self):
        a = member_a_producer()
        b = build_elf(
            text=b"\x00" * 8,
            symbols=[("produce", 0, 0)],
            relocs=[{"offset": 6, "sym": 1, "type": 1, "addend": 0}],  # 8B 写越界
        )
        r = elfaudit.audit_group(
            "g", [member("a", a), member("b", b)], BASE, {"ext_base": 0x500000}
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.violation.code, "write_out_of_range")
        self.assertEqual(r.violation.member, "b")


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------


def group_payload(members, audit_id="g-http", base=BASE, symbols=None):
    return {
        "audit_id": audit_id,
        "members": [{"member_id": m, "file_base64": b64(d)} for m, d in members],
        "load_base": base,
        "symbols": {"ext_base": 0x500000} if symbols is None else symbols,
    }


class GroupApiTests(unittest.TestCase):
    def setUp(self):
        server._store.clear()
        server._group_store.clear()

    def test_group_success_payload_shape(self):
        rec = run_group_audit(
            group_payload([("vendor-a", member_a_producer()),
                           ("vendor-b", member_b_consumer())], "g-ok")
        )
        self.assertTrue(rec["ok"])
        self.assertEqual(len(rec["conclusion"]), 64)
        self.assertEqual(rec["member_count"], 2)
        for mp in rec["members"]:
            for it in mp["items"]:
                for key in ("S", "A", "P", "value", "before_hex", "after_hex"):
                    self.assertIn(key, it)
            offs = [p["offset"] for p in mp["patches"]]
            self.assertEqual(offs, sorted(offs))

    def test_group_failure_clears_previous_success(self):
        payload_ok = group_payload(
            [("vendor-a", member_a_producer()), ("vendor-b", member_b_consumer())],
            "stable-g",
        )
        ok = run_group_audit(payload_ok)
        self.assertTrue(ok["ok"])

        # 同一标识提交含重复导出的坏组
        a = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0), ("dup", "text", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        c = build_elf(
            text=b"\x00" * 16,
            symbols=[("z", 0, 0), ("dup", "text", 4)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        bad = group_payload([("a", a), ("c", c)], "stable-g",
                            symbols={"z": 0x600000})
        fail = run_group_audit(bad)
        self.assertFalse(fail["ok"])
        self.assertEqual(fail["violation"]["code"], "duplicate_export")
        self.assertNotIn("conclusion", fail)
        stored = server._group_store["stable-g"]
        self.assertEqual(stored["kind"], "fail")
        self.assertNotIn("result", stored)

    def test_group_store_isolated_from_single_store(self):
        # 同名标识分别用于单文件与联合，互不覆盖
        run_audit({
            "audit_id": "same-id",
            "file_base64": b64(member_a_producer()),
            "load_base": BASE,
            "symbols": {"ext_base": 0x500000},
        })
        run_group_audit(group_payload(
            [("vendor-a", member_a_producer()), ("vendor-b", member_b_consumer())],
            "same-id",
        ))
        single = server._store["same-id"]
        grp = server._group_store["same-id"]
        self.assertEqual(single["kind"], "pass")
        self.assertEqual(grp["kind"], "pass")
        self.assertNotEqual(single["conclusion"], grp["result"]["conclusion"])

    def test_bad_group_payloads(self):
        good_pair = [("a", member_a_producer()), ("b", member_b_consumer())]
        for payload in [
            {"audit_id": "x", "members": [], "load_base": 0, "symbols": {}},
            {"audit_id": "x",
             "members": [{"member_id": "a", "file_base64": b64(member_a_producer())}],
             "load_base": 0, "symbols": {"ext_base": 0}},
            {"audit_id": "x",
             "members": [{"member_id": "a", "file_base64": "@@bad@@"},
                          {"member_id": "b", "file_base64": b64(member_b_consumer())}],
             "load_base": 0, "symbols": {}},
            {"audit_id": "x", "members": "not-list", "load_base": 0},
            "not-a-dict",
        ]:
            with self.assertRaises(ValueError):
                run_group_audit(payload)
        # 正常载荷不受影响
        self.assertTrue(run_group_audit(group_payload(good_pair, "x"))["ok"])


class GroupHttpSmokeTest(unittest.TestCase):
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

    def test_group_http_flow(self):
        payload = group_payload(
            [("vendor-b", member_b_consumer()), ("vendor-a", member_a_producer())],
            "g-http-id",
        )
        status, ok = self._post("/api/group_audit", payload)
        self.assertEqual(status, 200)
        self.assertTrue(ok["ok"])
        # 提交次序调换，成员仍按标识排序
        self.assertEqual([m["member"] for m in ok["members"]], ["vendor-a", "vendor-b"])

        status, fetched = self._get("/api/group/result/g-http-id")
        self.assertEqual(status, 200)
        self.assertTrue(fetched["ok"])
        self.assertEqual(fetched["conclusion"], ok["conclusion"])

        # 单文件读取接口看不到联合记录，反之亦然
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/api/result/g-http-id")
        self.assertEqual(cm.exception.code, 404)

        # healthz 含联合计数
        _, health = self._get("/healthz")
        self.assertIn("group_records", health)
        self.assertGreaterEqual(health["group_passed"], 1)

    def test_group_http_failure_no_conclusion(self):
        # 未解析符号：a 引用 ext_base（提供），b 引用 missing（不提供）
        b = build_elf(
            text=b"\x00" * 16,
            symbols=[("missing", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        payload = group_payload(
            [("a", member_a_producer()), ("b", b)], "g-bad",
            symbols={"ext_base": 0x500000},
        )
        status, body = self._post("/api/group_audit", payload)
        self.assertEqual(status, 200)
        self.assertFalse(body["ok"])
        self.assertEqual(body["violation"]["code"], "unresolved_symbol")
        self.assertNotIn("conclusion", body)
        status, stored = self._get("/api/group/result/g-bad")
        self.assertEqual(status, 200)
        self.assertFalse(stored["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
