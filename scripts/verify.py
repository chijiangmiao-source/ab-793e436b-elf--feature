"""Compose verify 验收组件的一键检查脚本。

在一次运行中依次核对：

1. 单元测试（``python -m unittest`` 全量）；
2. 构建检查（全部源码字节编译 + 关键模块导入）；
3. HTTP 冒烟（健康检查 + 单文件三场景 + 联合审计三场景）：
   a. 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   b. 重叠写入被拒绝（patch_overlap）；
   c. PC32 有符号 32 位溢出被拒绝（pc32_overflow），且无部分结果；
   d. 联合审计跨成员成功解析（local/member/external 三类来源），成员按
      标识排序对齐布局，冻结结论可凭标识读回；
   e. 联合审计重复导出被整组拒绝（duplicate_export），旧联合成功结论清除；
   f. 成员次序调换但标识与内容相同，布局与冻结摘要保持一致。

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

from elfbuild import STB_LOCAL, build_elf  # noqa: E402

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


# --- 联合审计成员 -----------------------------------------------------------


def joint_alpha_elf() -> bytes:
    # alpha 导出 alpha_fn@.text+0x10；本地 alpha_local@.text+0x08 被本成员
    # PC32 引用；偏移 0x10 的 R64 引用外部 ext_helper。
    return build_elf(
        text=bytes(range(32)),
        symbols=[
            ("alpha_fn", "text", 0x10),
            ("alpha_local", "text", 0x08, STB_LOCAL),
            ("ext_helper", 0, 0),
        ],
        relocs=[
            {"offset": 0x00, "sym": 2, "type": 2, "addend": 0},
            {"offset": 0x10, "sym": 3, "type": 1, "addend": 0x20},
        ],
        text_addralign=16,
    )


def joint_beta_elf() -> bytes:
    # beta 以 SHN_UNDEF 引用 alpha 的全局 alpha_fn（PC32）
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("alpha_fn", 0, 0)],
        relocs=[{"offset": 0x00, "sym": 1, "type": 2, "addend": -4}],
        text_addralign=16,
    )


def joint_payload(members, audit_id="verify-joint", symbols=None):
    return {
        "audit_id": audit_id,
        "load_base": 0x400000,
        "symbols": {"ext_helper": 0x600000} if symbols is None else symbols,
        "members": [
            {"member_id": mid, "file_base64": b64(blob)} for mid, blob in members
        ],
    }


def check_joint_smoke() -> None:
    step("4/4 联合（多成员）审计 HTTP 冒烟")
    # 场景 d：跨成员成功解析；故意把 beta 放在提交列表前面，验证稳定排序
    payload = joint_payload(
        [("beta", joint_beta_elf()), ("alpha", joint_alpha_elf())],
        "verify-joint-ok",
    )
    status, body = http_post("/api/joint/audit", payload)
    if status != 200 or not body.get("ok"):
        fail(f"联合审计跨成员解析应成功：HTTP {status} {body}")
    if body.get("member_count") != 2 or body.get("item_count") != 3:
        fail(f"联合结果成员/重定位项数量异常：{body.get('member_count')}/{body.get('item_count')}")
    members = body["members"]
    if [m["member"] for m in members] != ["alpha", "beta"]:
        fail(f"成员未按标识排序：{[m['member'] for m in members]}")
    if members[0]["base"] != "0x0000000000400000" or members[1]["base"] != "0x0000000000400020":
        fail(f"成员连续布局基址错误：{[(m['member'], m['base']) for m in members]}")
    if members[0]["range"] != ["0x0000000000400000", "0x0000000000400020"]:
        fail(f"成员代码范围错误：{members[0]['range']}")
    items = body["items"]
    keys = [(it["member"], it["offset"]) for it in items]
    if keys != [("alpha", 0), ("alpha", 0x10), ("beta", 0)]:
        fail(f"重定位项未按成员/节内偏移稳定排序：{keys}")
    sources = {(it["member"], it["symbol"]): it["source"] for it in items}
    if sources != {
        ("alpha", "alpha_local"): "local",
        ("alpha", "ext_helper"): "external",
        ("beta", "alpha_fn"): "member",
    }:
        fail(f"重定位来源分类异常：{sources}")
    cross = next(it for it in items if it["member"] == "beta")
    if cross["source_member"] != "alpha" or cross["S"] != "0x0000000000400010":
        fail(f"跨成员符号地址解析错误：{cross}")
    if cross["after_hex"] != struct.pack("<i", 0x400010 - 4 - 0x400020).hex():
        fail(f"跨成员 PC32 写入值错误：{cross['after_hex']}")
    for it in items:
        for key in ("S", "A", "P", "value", "before_hex", "after_hex"):
            if key not in it:
                fail(f"联合结果缺少字段 {key}")
    if len(body.get("conclusion", "")) != 64:
        fail("联合冻结结论 SHA-256 缺失")
    print(f"verify: 联合审计跨成员解析成功，结论 {body['conclusion']}")

    status, fetched = http_get("/api/joint/result/verify-joint-ok")
    if status != 200 or not fetched.get("ok") or fetched.get("conclusion") != body["conclusion"]:
        fail("联合冻结结论无法按标识读回或内容不一致")
    print("verify: 联合冻结结论读回一致")

    # 场景 f：成员次序调换（标识与内容相同）-> 同一布局与冻结摘要
    swapped = joint_payload(
        [("alpha", joint_alpha_elf()), ("beta", joint_beta_elf())],
        "verify-joint-ok",
    )
    status, body2 = http_post("/api/joint/audit", swapped)
    if status != 200 or not body2.get("ok"):
        fail(f"调换次序后的联合审计应成功：HTTP {status} {body2}")
    if body2["conclusion"] != body["conclusion"]:
        fail("成员次序调换但标识与内容相同，冻结摘要应一致")
    if [(m["member"], m["base"], m["range"]) for m in body2["members"]] != [
        (m["member"], m["base"], m["range"]) for m in body["members"]
    ]:
        fail("成员次序调换后布局不一致")
    print("verify: 成员次序无关性成立（布局与冻结摘要一致）")

    # 场景 e：重复导出整组拒绝，且清除该标识下旧联合成功结论
    dup_a = build_elf(text=b"\x90" * 8, symbols=[("dup", "text", 0)], relocs=[])
    dup_g = build_elf(text=b"\x90" * 8, symbols=[("dup", "text", 4)], relocs=[])
    dup_b = build_elf(
        text=b"\x00" * 16,
        symbols=[("dup", 0, 0)],
        relocs=[{"offset": 0, "sym": 1, "type": 2, "addend": 0}],
    )
    payload_dup = joint_payload(
        [("alpha", dup_a), ("beta", dup_b), ("gamma", dup_g)],
        "verify-joint-ok",  # 故意复用：旧 PASS 必须被清除
        symbols={},
    )
    status, body_dup = http_post("/api/joint/audit", payload_dup)
    if status != 200 or body_dup.get("ok"):
        fail(f"重复导出应被整组拒绝：HTTP {status} {body_dup}")
    if body_dup["violation"]["code"] != "duplicate_export":
        fail(f"违约代码应为 duplicate_export：{body_dup['violation']}")
    if body_dup["violation"].get("member") != "beta":
        fail(f"重复导出未定位到首个相关重定位所在成员：{body_dup['violation']}")
    if "conclusion" in body_dup:
        fail("拒绝响应中不得携带旧联合冻结结论")
    status, again = http_get("/api/joint/result/verify-joint-ok")
    if status != 200 or again.get("ok") or "conclusion" in again:
        fail("旧联合成功结论未被清除")
    print("verify: 重复导出已整组拒绝，首个相关重定位已定位，旧成功结论已清除")

    # 单文件接口不受联合审计影响（旧单文件回归）
    status, single = http_post(
        "/api/audit",
        {
            "audit_id": "verify-single-regression",
            "file_base64": b64(double_type_elf()),
            "load_base": 0x400000,
            "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
        },
    )
    if status != 200 or not single.get("ok") or single.get("joint"):
        fail(f"单文件接口回归失败：HTTP {status} {single}")
    status, single_get = http_get("/api/result/verify-single-regression")
    if status != 200 or single_get.get("conclusion") != single["conclusion"]:
        fail("单文件结果读回回归失败")
    print("verify: 旧单文件审计接口与读取结果保持不变")


def check_http_smoke() -> None:
    step("3/4 单文件 HTTP 冒烟")
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
    check_joint_smoke()
    print("\n=== verify: ALL CHECKS PASSED ===", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
