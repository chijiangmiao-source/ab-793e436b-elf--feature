"""Compose verify 验收组件的一键检查脚本。

在一次运行中依次核对：

1. 单元测试（``python -m unittest`` 全量）；
2. 构建检查（全部源码字节编译 + 关键模块导入）；
3. 旧单文件 HTTP 回归（健康检查 + 三个必测场景）：
   a. 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   b. 重叠写入被拒绝（patch_overlap）；
   c. PC32 有符号 32 位溢出被拒绝（pc32_overflow），且无部分结果。
4. 联合审计 HTTP 新能力：
   a. 跨成员成功解析（他成员全局定义 PC32 + 外部地址 R64），给出每个成员
      基址/范围、逐项 S/A/P 与冻结摘要；提交次序调换得到同一布局与摘要；
   b. 重复导出被拒绝（duplicate_export），定位到首个相关重定位，并清除同
      标识下旧的联合成功结论。

任何一步失败立即以非零退出码结束；全部成功退出码为 0。
"""

from __future__ import annotations

import base64
import json
import os
import py_compile
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from elfbuild import build_elf  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")
TIMEOUT = 5


def step(name: str) -> None:
    print(f"\n=== verify: {name} ===", flush=True)


def fail(msg: str) -> None:
    print(f"verify: FAIL — {msg}", flush=True)
    sys.exit(1)


def check_unit_tests() -> None:
    step("1/4 单元测试")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail(f"单元测试失败（退出码 {proc.returncode}）")
    print("verify: 单元测试全部通过")


def check_build() -> None:
    step("2/4 构建检查（字节编译 + 模块导入）")
    for py in list((ROOT / "app").rglob("*.py")) + [Path(__file__)]:
        try:
            py_compile.compile(str(py), doraise=True)
        except py_compile.PyCompileError as exc:
            fail(f"字节编译失败 {py}: {exc}")
    proc = subprocess.run(
        [sys.executable, "-c", "import app.server, app.elfaudit; print('import ok')"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail("关键模块导入失败")
    # 静态资源（页面）必须存在
    page = ROOT / "app" / "static" / "index.html"
    if not page.is_file() or page.stat().st_size == 0:
        fail("审计页面 app/static/index.html 缺失或为空")
    print("verify: 构建检查通过")


def http_get(path: str) -> tuple[int, dict | None]:
    req = urllib.request.Request(BASE_URL + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            body = json.loads(raw) if "application/json" in ctype else None
            return resp.status, body
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        ctype = exc.headers.get("Content-Type", "")
        body = json.loads(raw) if "application/json" in ctype else None
        return exc.code, body


def http_post(path: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_health(attempts: int = 30) -> None:
    for i in range(attempts):
        try:
            status, body = http_get("/healthz")
            if status == 200 and body and body.get("status") == "ok":
                print(f"verify: 健康检查通过 {BASE_URL}/healthz -> {body}")
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
    fail(f"服务在 {attempts}s 内未通过健康检查：{BASE_URL}/healthz")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def double_type_elf() -> bytes:
    return build_elf(
        text=bytes(range(48)),
        symbols=[
            ("ext_foo", 0, 0),
            ("memcpy", 0, 0),
            ("local_fn", "text", 0x10),
        ],
        relocs=[
            {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
            {"offset": 0x08, "sym": 2, "type": 2, "addend": -4},
            {"offset": 0x10, "sym": 3, "type": 2, "addend": 0},
        ],
    )


def overlap_elf() -> bytes:
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},  # [0,8)
            {"offset": 4, "sym": 2, "type": 2, "addend": 0},  # [4,8) 重叠
        ],
    )


def pc32_overflow_elf() -> bytes:
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("ext_foo", 0, 0), ("far_away", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},
            {"offset": 8, "sym": 2, "type": 2, "addend": 0},
        ],
    )


# --- 联合审计夹具 ---------------------------------------------------------

def group_producer_elf() -> bytes:
    """供应商 A：导出 produce@.text+0x10；R64@0 引用外部 ext_base（A=+0x8）。"""
    return build_elf(
        text=b"\xaa" * 32,
        symbols=[("ext_base", 0, 0), ("produce", "text", 0x10)],
        relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0x8}],
    )


def group_consumer_elf() -> bytes:
    """供应商 B：PC32@0 引用他成员 produce；R64@24 引用外部 ext_base。"""
    return build_elf(
        text=b"\xbb" * 32,
        symbols=[("produce", 0, 0), ("ext_base", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 2, "addend": -4},
            {"offset": 24, "sym": 2, "type": 1, "addend": 0},
        ],
    )


def group_duplicate_export_elfs():
    """返回 (a, b, c)：a 与 c 均全局导出 dup；b 在 rela#1(offset=8) 引用 dup。"""
    a = build_elf(
        text=b"\x00" * 16,
        symbols=[("ext_foo", 0, 0), ("dup", "text", 0)],
        relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
    )
    c = build_elf(
        text=b"\x00" * 16,
        symbols=[("ext_foo", 0, 0), ("dup", "text", 4)],
        relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
    )
    b = build_elf(
        text=b"\x00" * 16,
        symbols=[("ext_foo", 0, 0), ("dup", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},
            {"offset": 8, "sym": 2, "type": 2, "addend": 0},
        ],
    )
    return a, b, c


def check_group_http() -> None:
    step("4/4 联合审计 HTTP")
    wait_for_health()
    group_syms = {"ext_base": 0x500000}

    # 场景 a：跨成员成功解析。故意按 b,a 次序提交，成员必须按标识排序。
    payload = {
        "audit_id": "verify-group-ok",
        "members": [
            {"member_id": "vendor-b", "file_base64": b64(group_consumer_elf())},
            {"member_id": "vendor-a", "file_base64": b64(group_producer_elf())},
        ],
        "load_base": 0x400000,
        "symbols": group_syms,
    }
    status, body = http_post("/api/group_audit", payload)
    if status != 200 or not body.get("ok"):
        fail(f"联合审计跨成员解析应成功：HTTP {status} {body}")
    if [m["member"] for m in body["members"]] != ["vendor-a", "vendor-b"]:
        fail(f"成员未按标识排序：{[m['member'] for m in body['members']]}")
    ma, mb = body["members"]
    if ma["base"] != "0x0000000000400000" or mb["base"] != "0x0000000000400020":
        fail(f"连续布局基址错误：{ma['base']} {mb['base']}")
    if body["region_range"] != ["0x0000000000400000", "0x0000000000400040"]:
        fail(f"装载区范围错误：{body['region_range']}")
    # b 的 PC32 必须解析到 a.produce=0x400010
    pc = next(it for it in mb["items"] if it["type_name"] == "R_X86_64_PC32")
    if pc["S"] != "0x0000000000400010":
        fail(f"跨成员符号地址 S 错误：{pc['S']}")
    if pc["P"] != "0x0000000000400020" or pc["A"] != "-4":
        fail(f"跨成员 P/A 错误：P={pc['P']} A={pc['A']}")
    # 每个成员补丁按节内偏移升序，且包含写入前后字节
    for mp in body["members"]:
        offs = [p["offset"] for p in mp["patches"]]
        if offs != sorted(offs):
            fail(f"成员 {mp['member']} 补丁未按偏移排序")
        for p in mp["patches"]:
            if not p["before_hex"] or not p["after_hex"]:
                fail("补丁缺少写入前/后字节")
    conclusion_a = body["conclusion"]
    if len(conclusion_a) != 64:
        fail("联合冻结摘要缺失")
    print(f"verify: 联合审计跨成员解析成功，结论 {conclusion_a}")

    # 冻结结论可凭标识读回
    status, fetched = http_get("/api/group/result/verify-group-ok")
    if status != 200 or not fetched.get("ok") or fetched.get("conclusion") != conclusion_a:
        fail("联合冻结结论无法按标识读回或内容不一致")
    print("verify: 联合冻结结论读回一致")

    # 顺序调换（a,b）但标识与内容相同 -> 同一布局与冻结摘要
    payload_swapped = {
        "audit_id": "verify-group-ok",
        "members": [
            {"member_id": "vendor-a", "file_base64": b64(group_producer_elf())},
            {"member_id": "vendor-b", "file_base64": b64(group_consumer_elf())},
        ],
        "load_base": 0x400000,
        "symbols": group_syms,
    }
    status, body2 = http_post("/api/group_audit", payload_swapped)
    if status != 200 or not body2.get("ok"):
        fail(f"顺序调换后的联合审计应成功：HTTP {status} {body2}")
    if body2["conclusion"] != conclusion_a:
        fail("成员次序调换后冻结摘要发生变化，违反顺序无关性")
    lay = [(m["member"], m["base"]) for m in body2["members"]]
    if lay != [("vendor-a", "0x0000000000400000"), ("vendor-b", "0x0000000000400020")]:
        fail(f"成员次序调换后布局发生变化：{lay}")
    print("verify: 成员次序调换 -> 同一布局与冻结摘要")

    # 场景 b：重复导出拒绝，定位首个相关重定位，并清除旧联合成功结论
    a, b, c = group_duplicate_export_elfs()
    payload_bad = {
        "audit_id": "verify-group-ok",  # 故意复用：旧 PASS 必须被清除
        "members": [
            {"member_id": "vendor-a", "file_base64": b64(a)},
            {"member_id": "vendor-b", "file_base64": b64(b)},
            {"member_id": "vendor-c", "file_base64": b64(c)},
        ],
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000},
    }
    status, body_bad = http_post("/api/group_audit", payload_bad)
    if status != 200 or body_bad.get("ok"):
        fail(f"重复导出应被整组拒绝：HTTP {status} {body_bad}")
    v = body_bad["violation"]
    if v["code"] != "duplicate_export":
        fail(f"违约代码应为 duplicate_export：{v}")
    if v.get("member") != "vendor-b" or v.get("rela_index") != 1:
        fail(f"未定位到首个相关重定位（vendor-b 的 rela#1）：{v}")
    if "conclusion" in body_bad:
        fail("拒绝响应中不得携带旧联合冻结结论")
    status, again = http_get("/api/group/result/verify-group-ok")
    if status != 200 or again.get("ok") or "conclusion" in again:
        fail("旧联合成功结论未被清除")
    print("verify: 重复导出已拒绝，定位 vendor-b rela#1，旧联合成功结论已清除")

    # 联合存储与单文件存储隔离：单文件接口读不到联合标识
    status, single_view = http_get("/api/result/verify-group-ok")
    if status != 404:
        fail(f"单文件接口不应暴露联合记录：HTTP {status} {single_view}")
    print("verify: 单文件/联合结论命名空间相互隔离")


def check_http_smoke() -> None:
    step("3/4 旧单文件 HTTP 回归")
    wait_for_health()

    # 页面可访问且包含审计台标记
    try:
        with urllib.request.urlopen(BASE_URL + "/", timeout=TIMEOUT) as resp:
            page = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        page = ""
    if status != 200 or "ELF64" not in page:
        fail(f"审计页面异常：HTTP {status}")
    print("verify: 页面 GET / -> 200")

    # 场景 a：双类型重定位成功
    payload = {
        "audit_id": "verify-double-type",
        "file_base64": b64(double_type_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, body = http_post("/api/audit", payload)
    if status != 200 or not body.get("ok"):
        fail(f"双类型重定位应成功：HTTP {status} {body}")
    if len(body.get("items", [])) != 3:
        fail(f"应返回 3 个重定位项，实际 {len(body.get('items', []))}")
    types = sorted(it["type_name"] for it in body["items"])
    if types != ["R_X86_64_64", "R_X86_64_PC32", "R_X86_64_PC32"]:
        fail(f"重定位类型集合异常：{types}")
    r64 = next(it for it in body["items"] if it["type_name"] == "R_X86_64_64")
    for key in ("S", "A", "P", "value", "before_hex", "after_hex"):
        if key not in r64:
            fail(f"成功结果缺少字段 {key}")
    if r64["after_hex"] != struct.pack("<Q", 0x500010).hex():
        fail(f"R_X86_64_64 写入值错误：{r64['after_hex']}")
    offsets = [p["offset"] for p in body["patches"]]
    if offsets != sorted(offsets):
        fail("补丁未按偏移排序")
    if len(body.get("conclusion", "")) != 64:
        fail("冻结结论 SHA-256 缺失")
    print(f"verify: 双类型重定位成功，结论 {body['conclusion']}")

    # 冻结结论可凭标识读回
    status, fetched = http_get("/api/result/verify-double-type")
    if status != 200 or not fetched.get("ok") or fetched.get("conclusion") != body["conclusion"]:
        fail("冻结结论无法按标识读回或内容不一致")
    print("verify: 冻结结论读回一致")

    # 场景 b：重叠写入拒绝，且清除旧成功结论（使用同一标识）
    payload_b = {
        "audit_id": "verify-double-type",  # 故意复用：旧 PASS 必须被清除
        "file_base64": b64(overlap_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, body_b = http_post("/api/audit", payload_b)
    if status != 200 or body_b.get("ok"):
        fail(f"重叠写入应被拒绝：HTTP {status} {body_b}")
    if body_b["violation"]["code"] != "patch_overlap":
        fail(f"违约代码应为 patch_overlap：{body_b['violation']}")
    if body_b["violation"].get("entry_index") != 1:
        fail("未定位到首个违约项（entry_index 应为 1）")
    if "conclusion" in body_b:
        fail("拒绝响应中不得携带旧冻结结论")
    status, again = http_get("/api/result/verify-double-type")
    if status != 200 or again.get("ok") or "conclusion" in again:
        fail("旧成功结论未被清除")
    print("verify: 重叠写入已拒绝，首个违约项 entry_index=1，旧成功结论已清除")

    # 场景 c：PC32 溢出拒绝，无部分结果
    payload_c = {
        "audit_id": "verify-pc32-overflow",
        "file_base64": b64(pc32_overflow_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "far_away": 0x7F0000000000},
    }
    status, body_c = http_post("/api/audit", payload_c)
    if status != 200 or body_c.get("ok"):
        fail(f"PC32 溢出应被拒绝：HTTP {status} {body_c}")
    if body_c["violation"]["code"] != "pc32_overflow":
        fail(f"违约代码应为 pc32_overflow：{body_c['violation']}")
    if body_c["violation"].get("entry_index") != 1:
        fail("PC32 溢出未定位到首个违约项（entry_index 应为 1）")
    status, stored = http_get("/api/result/verify-pc32-overflow")
    if status != 200 or stored.get("ok"):
        fail("溢出记录不应包含成功结论/部分补丁")
    print("verify: PC32 有符号 32 位溢出已拒绝，未生成部分结果")


def main() -> None:
    print(f"verify: 目标服务 {BASE_URL}")
    check_unit_tests()
    check_build()
    check_http_smoke()
    check_group_http()
    print("\n=== verify: ALL CHECKS PASSED ===", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
