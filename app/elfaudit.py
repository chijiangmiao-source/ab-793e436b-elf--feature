"""ELF64 小端 ET_REL 外部符号重定位审计核心（仅依赖标准库）。

审计对象为 x86-64 可重定位目标文件，且满足：

* ELF64 / 小端 / ``ET_REL`` / ``EM_X86_64``；
* 节表中存在唯一名为 ``.text`` 的节；
* 所有 ``SHT_RELA`` 节都必须指向该 ``.text``，不接受 ``SHT_REL``；
* 仅处理 ``R_X86_64_64``（8 字节绝对写）与 ``R_X86_64_PC32``
  （4 字节有符号 PC 相对写）。

对每条重定位按 AMD64 psABI 计算 S（符号地址）、A（加数）、P（写入位置
虚拟地址 = 装载基址 + 节内偏移）：

* ``R_X86_64_64``:  写入 ``(S + A) mod 2**64``；
* ``R_X86_64_PC32``: 写入 ``S + A - P``，结果必须落在有符号 32 位范围内，
  一旦越界则整体拒绝，不产生任何部分补丁。

审计采用两阶段：先逐条做全部结构性/范围性校验并定位首个违约位置，全部通过
后才计算并落补丁，因此失败时不会返回部分结果。
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# ELF / x86-64 常量
# ---------------------------------------------------------------------------

ELFMAG = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1

ET_REL = 1
EM_X86_64 = 62

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9

SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00

R_X86_64_64 = 1
R_X86_64_PC32 = 2
_RELOC_WIDTH = {R_X86_64_64: 8, R_X86_64_PC32: 4}
_RELOC_NAME = {R_X86_64_64: "R_X86_64_64", R_X86_64_PC32: "R_X86_64_PC32"}

UINT64_MAX = (1 << 64) - 1
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1

_EHDR_FMT = "<16sHHIQQQIHHHHHH"
_SHDR_FMT = "<IIQQQQIIQQ"
_SYM_FMT = "<IBBHQQ"
_RELA_FMT = "<QQq"
EHDR_SIZE = 64
SHDR_SIZE = 64
SYM_SIZE = 24
RELA_SIZE = 24


class AuditViolation(Exception):
    """审计违约。``stage`` 取值 ``file`` / ``section`` / ``entry`` / ``request``。"""

    def __init__(
        self,
        stage: str,
        code: str,
        message: str,
        *,
        entry_index: int | None = None,
        rela_section: str | None = None,
        rela_index: int | None = None,
        offset: int | None = None,
        reloc_type: int | None = None,
        symbol: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.code = code
        self.message = message
        self.entry_index = entry_index
        self.rela_section = rela_section
        self.rela_index = rela_index
        self.offset = offset
        self.reloc_type = reloc_type
        self.symbol = symbol
        self.detail = detail or {}

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "stage": self.stage,
            "code": self.code,
            "message": self.message,
        }
        if self.entry_index is not None:
            out["entry_index"] = self.entry_index
        if self.rela_section is not None:
            out["rela_section"] = self.rela_section
        if self.rela_index is not None:
            out["rela_index"] = self.rela_index
        if self.offset is not None:
            out["offset"] = offset_hex(self.offset)
        if self.reloc_type is not None:
            out["type"] = self.reloc_type
            out["type_name"] = _RELOC_NAME.get(self.reloc_type, f"UNKNOWN({self.reloc_type})")
        if self.symbol is not None:
            out["symbol"] = self.symbol
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class RelocItem:
    index: int
    rela_section: str
    rela_index: int
    reloc_type: int
    symbol_index: int
    symbol: str
    offset: int  # .text 节内偏移
    width: int
    s: int
    a: int
    p: int
    value: int
    before: bytes
    after: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "rela_section": self.rela_section,
            "rela_index": self.rela_index,
            "type": self.reloc_type,
            "type_name": _RELOC_NAME[self.reloc_type],
            "symbol_index": self.symbol_index,
            "symbol": self.symbol,
            "offset": self.offset,
            "offset_hex": offset_hex(self.offset),
            "width": self.width,
            "S": hex64(self.s),
            "A": str(self.a),
            "A_hex": signed_hex(self.a, 64),
            "P": hex64(self.p),
            "value": signed_hex(self.value, self.width * 8)
            if self.reloc_type == R_X86_64_PC32
            else hex64(self.value),
            "before_hex": self.before.hex(),
            "after_hex": self.after.hex(),
        }


@dataclass
class AuditResult:
    ok: bool
    violation: AuditViolation | None = None
    items: list[RelocItem] = field(default_factory=list)
    file_sha256: str = ""
    text_size: int = 0
    text_sha256_before: str = ""
    patched_sha256: str = ""
    load_base: int = 0
    patched: bytes = b""

    def to_public_dict(self) -> dict[str, Any]:
        """返回可序列化的审计结论（不含整个补丁后节体）。"""
        if not self.ok:
            return {"ok": False, "violation": self.violation.to_dict()}  # type: ignore[union-attr]
        ordered = sorted(self.items, key=lambda it: (it.offset, it.index))
        return {
            "ok": True,
            "file_sha256": self.file_sha256,
            "load_base": hex64(self.load_base),
            "text_size": self.text_size,
            "text_sha256_before": self.text_sha256_before,
            "patched_sha256": self.patched_sha256,
            "item_count": len(self.items),
            "items": [it.to_dict() for it in ordered],
            "patches": [
                {
                    "offset": it.offset,
                    "offset_hex": offset_hex(it.offset),
                    "width": it.width,
                    "type": it.reloc_type,
                    "type_name": _RELOC_NAME[it.reloc_type],
                    "symbol": it.symbol,
                    "before_hex": it.before.hex(),
                    "after_hex": it.after.hex(),
                }
                for it in ordered
            ],
        }


def hex64(value: int) -> str:
    return f"0x{value & UINT64_MAX:016x}"


def signed_hex(value: int, bits: int) -> str:
    mask = (1 << bits) - 1
    return f"0x{value & mask:0{bits // 4}x}"


def offset_hex(value: int) -> str:
    return f"0x{value:x}"


# ---------------------------------------------------------------------------
# 结构化解析辅助
# ---------------------------------------------------------------------------


def _unpack(fmt: str, data: bytes, off: int, what: str) -> tuple[Any, ...]:
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        raise AuditViolation("file", "truncated", f"{what}被截断：需要 {size} 字节，偏移 {off} 越界")
    return struct.unpack(fmt, data[off : off + size])


def _read_cstr(blob: bytes, start: int) -> str | None:
    """读取 NUL 结尾字符串；越界或无终止符返回 None。"""
    if start < 0 or start >= len(blob):
        return None
    end = blob.find(b"\x00", start)
    if end == -1:
        return None
    return blob[start:end].decode("latin-1")


# ---------------------------------------------------------------------------
# 主审计流程
# ---------------------------------------------------------------------------


def audit(data: bytes, load_base: int, symbols: dict[str, int]) -> AuditResult:
    """对 ELF 字节流执行完整重定位审计。

    ``symbols`` 为被引用外部（``SHN_UNDEF``）符号名到绝对地址的映射。
    任何违约都返回 ``ok=False`` 的结果，且绝不携带部分补丁。
    """
    try:
        return _audit(data, load_base, symbols)
    except AuditViolation as exc:
        return AuditResult(ok=False, violation=exc)


def _audit(data: bytes, load_base: int, symbols: dict[str, int]) -> AuditResult:
    if not isinstance(data, (bytes, bytearray)):
        raise AuditViolation("request", "bad_payload", "文件载荷必须为字节流")
    if not (0 <= load_base <= UINT64_MAX):
        raise AuditViolation("request", "bad_base", "装载基址必须是 0..2^64-1 范围内的整数")
    for name, addr in symbols.items():
        if not isinstance(name, str) or not name or "\x00" in name or len(name) > 255:
            raise AuditViolation("request", "bad_symbol_name", f"非法外部符号名：{name!r}")
        if not isinstance(addr, int) or not (0 <= addr <= UINT64_MAX):
            raise AuditViolation("request", "bad_symbol_addr", f"符号 {name!r} 地址非法")

    file_sha = hashlib.sha256(data).hexdigest()

    # --- ELF 头 -----------------------------------------------------------
    if len(data) < EHDR_SIZE:
        raise AuditViolation("file", "truncated", "文件短于 64 字节 ELF 头")
    e_ident = data[:16]
    if e_ident[:4] != ELFMAG:
        raise AuditViolation("file", "bad_magic", "ELF 魔数不匹配（不是 ELF 文件）")
    if e_ident[4] != ELFCLASS64:
        raise AuditViolation("file", "bad_class", "仅接受 ELF64（EI_CLASS 必须为 2）")
    if e_ident[5] != ELFDATA2LSB:
        raise AuditViolation("file", "bad_data", "仅接受小端 ELF（EI_DATA 必须为 1）")
    if e_ident[6] != EV_CURRENT:
        raise AuditViolation("file", "bad_version", "ELF 版本号不受支持")

    (
        _,
        e_type,
        e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = _unpack(_EHDR_FMT, data, 0, "ELF 头")

    if e_type != ET_REL:
        raise AuditViolation("file", "bad_type", f"仅接受 ET_REL 可重定位文件，e_type={e_type}")
    if e_machine != EM_X86_64:
        raise AuditViolation("file", "bad_machine", f"仅接受 EM_X86_64，e_machine={e_machine}")
    if _e_version != EV_CURRENT:
        raise AuditViolation("file", "bad_e_version", f"ELF 头 e_version 必须为 1，实际 {_e_version}")
    if e_phoff != 0:
        raise AuditViolation("file", "program_header_forbidden", "ET_REL 不得携带程序头表")
    if e_shoff == 0 or e_shnum == 0:
        raise AuditViolation("section", "no_section_table", "缺少节表")
    if e_shentsize != SHDR_SIZE:
        raise AuditViolation("section", "bad_shentsize", f"e_shentsize 必须为 64，实际 {e_shentsize}")
    if e_shstrndx >= e_shnum:
        raise AuditViolation("section", "bad_shstrndx", "e_shstrndx 超出节表范围")
    if e_shoff + e_shnum * SHDR_SIZE > len(data):
        raise AuditViolation("section", "section_table_truncated", "节表超出文件边界")

    # --- 节表 -------------------------------------------------------------
    sections: list[dict[str, Any]] = []
    for i in range(e_shnum):
        off = e_shoff + i * SHDR_SIZE
        (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        ) = _unpack(_SHDR_FMT, data, off, f"节头 #{i}")
        sec = {
            "index": i,
            "name_off": sh_name,
            "type": sh_type,
            "flags": sh_flags,
            "addr": sh_addr,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "info": sh_info,
            "addralign": sh_addralign,
            "entsize": sh_entsize,
            "name": "",
        }
        if i != 0 and sh_type != SHT_NOBITS:
            # SHT_NOBITS（如 .bss）在文件中不占字节，只校验其占位不与文件
            # 末尾之后冲突；其余节的数据区间必须完整落在文件内。
            if sh_offset > len(data) or sh_size > len(data) - sh_offset:
                raise AuditViolation(
                    "section",
                    "section_out_of_bounds",
                    f"节 #{i} 数据区间 [{offset_hex(sh_offset)}, +{sh_size}) 超出文件边界",
                )
        sections.append(sec)

    shstr = sections[e_shstrndx]
    if shstr["type"] != SHT_STRTAB:
        raise AuditViolation("section", "bad_shstrtab", "e_shstrndx 未指向 SHT_STRTAB")
    shstr_blob = data[shstr["offset"] : shstr["offset"] + shstr["size"]]
    for sec in sections:
        name = _read_cstr(shstr_blob, sec["name_off"]) if sec["index"] != 0 else ""
        if name is None:
            raise AuditViolation(
                "section",
                "bad_section_name",
                f"节 #{sec['index']} 的 sh_name 在节名字符串表中越界",
            )
        sec["name"] = name

    text_indexes = [s["index"] for s in sections if s["name"] == ".text"]
    if len(text_indexes) != 1:
        raise AuditViolation(
            "section",
            "text_not_unique",
            f"必须存在唯一的 .text 节，实际找到 {len(text_indexes)} 个",
        )
    text = sections[text_indexes[0]]
    if text["type"] != SHT_PROGBITS:
        raise AuditViolation("section", "bad_text_type", ".text 节类型必须为 SHT_PROGBITS")
    text_bytes = bytes(data[text["offset"] : text["offset"] + text["size"]])
    text_before_sha = hashlib.sha256(text_bytes).hexdigest()

    # --- 符号表 -----------------------------------------------------------
    symtab_indexes = [s["index"] for s in sections if s["type"] == SHT_SYMTAB]
    if len(symtab_indexes) != 1:
        raise AuditViolation(
            "section",
            "symtab_not_unique",
            f"必须存在唯一的 SHT_SYMTAB，实际找到 {len(symtab_indexes)} 个",
        )
    symtab = sections[symtab_indexes[0]]
    if symtab["link"] >= len(sections) or sections[symtab["link"]]["type"] != SHT_STRTAB:
        raise AuditViolation("section", "bad_symtab_link", "符号表的 sh_link 未指向字符串表")
    if symtab["entsize"] not in (0, SYM_SIZE):
        raise AuditViolation("section", "bad_sym_entsize", f"符号表表项尺寸必须为 24，实际 {symtab['entsize']}")
    if symtab["size"] % SYM_SIZE != 0:
        raise AuditViolation("section", "bad_symtab_size", "符号表字节数不是 24 的整数倍")
    sym_count = symtab["size"] // SYM_SIZE
    if not (1 <= symtab["info"] <= sym_count):
        raise AuditViolation(
            "section",
            "bad_symtab_info",
            f"符号表 sh_info（首个非局部符号索引）必须在 1..{sym_count} 范围内，实际 {symtab['info']}",
        )
    strtab = sections[symtab["link"]]
    strtab_blob = data[strtab["offset"] : strtab["offset"] + strtab["size"]]

    def parse_symbol(sym_idx: int, *, owner_entry: int | None = None) -> dict[str, Any]:
        if sym_idx == 0 or sym_idx >= sym_count:
            raise AuditViolation(
                "entry",
                "bad_symbol_index",
                f"r_info 符号索引 {sym_idx} 越界（符号表共 {sym_count} 项，0 为保留项）",
                entry_index=owner_entry,
            )
        soff = symtab["offset"] + sym_idx * SYM_SIZE
        st_name, st_info, _st_other, st_shndx, st_value, _st_size = _unpack(
            _SYM_FMT, data, soff, f"符号 #{sym_idx}"
        )
        name = _read_cstr(strtab_blob, st_name)
        if name is None:
            raise AuditViolation(
                "entry",
                "bad_symbol_name",
                f"符号 #{sym_idx} 的 st_name={st_name} 在字符串表中越界或缺少 NUL",
                entry_index=owner_entry,
            )
        return {
            "index": sym_idx,
            "name": name,
            "shndx": st_shndx,
            "value": st_value,
            "info": st_info,
        }

    # --- RELA 节 ----------------------------------------------------------
    rela_sections = [s for s in sections if s["type"] in (SHT_RELA, SHT_REL)]
    if not rela_sections:
        raise AuditViolation("section", "no_rela", "未找到任何重定位节")
    for sec in rela_sections:
        if sec["type"] == SHT_REL:
            raise AuditViolation(
                "section",
                "rel_unsupported",
                f"节 {sec['name'] or '#' + str(sec['index'])} 为 SHT_REL，仅接受带加数的 SHT_RELA",
            )
        if sec["info"] != text["index"]:
            target = sections[sec["info"]]["name"] if sec["info"] < len(sections) else "?"
            raise AuditViolation(
                "section",
                "rela_not_for_text",
                f"RELA 节 {sec['name'] or '#' + str(sec['index'])} 指向 {target or '#' + str(sec['info'])}，"
                "仅接受指向唯一 .text 的 RELA 节",
            )
        if sec["link"] != symtab["index"]:
            raise AuditViolation(
                "section", "bad_rela_link", f"RELA 节 {sec['name']} 的 sh_link 未指向符号表"
            )
        if sec["entsize"] not in (0, RELA_SIZE):
            raise AuditViolation(
                "section",
                "bad_rela_entsize",
                f"RELA 节 {sec['name']} 表项尺寸必须为 24，实际 {sec['entsize']}",
            )
        if sec["size"] % RELA_SIZE != 0:
            raise AuditViolation(
                "section", "bad_rela_size", f"RELA 节 {sec['name']} 字节数不是 24 的整数倍"
            )

    raw_entries: list[dict[str, Any]] = []
    for sec in rela_sections:
        count = sec["size"] // RELA_SIZE
        base = sec["offset"]
        for j in range(count):
            r_offset, r_info, r_addend = _unpack(
                _RELA_FMT, data, base + j * RELA_SIZE, f"RELA 项 {sec['name']}[{j}]"
            )
            raw_entries.append(
                {
                    "global_index": len(raw_entries),
                    "rela_section": sec["name"] or f"#{sec['index']}",
                    "rela_index": j,
                    "offset": r_offset,
                    "sym_idx": r_info >> 32,
                    "type": r_info & 0xFFFFFFFF,
                    "addend": r_addend,
                }
            )

    if not raw_entries:
        raise AuditViolation("section", "no_rela", "RELA 节存在但不含任何重定位项")

    # --- 第一阶段：逐项独立校验 -------------------------------------------
    prepared: list[dict[str, Any]] = []
    referenced_undefined: set[str] = set()

    for ent in raw_entries:
        idx = ent["global_index"]
        loc = dict(
            entry_index=idx,
            rela_section=ent["rela_section"],
            rela_index=ent["rela_index"],
            offset=ent["offset"],
            reloc_type=ent["type"],
        )

        width = _RELOC_WIDTH.get(ent["type"])
        if width is None:
            raise AuditViolation(
                "entry",
                "unsupported_reloc_type",
                f"不支持的重定位类型 {ent['type']}，仅处理 R_X86_64_64(1) 与 R_X86_64_PC32(2)",
                **loc,
            )

        addend = ent["addend"]
        if not (INT64_MIN <= addend <= INT64_MAX):  # struct 'q' 已保证，显式复核加数
            raise AuditViolation("entry", "bad_addend", "RELA 加数超出有符号 64 位范围", **loc)

        sym = parse_symbol(ent["sym_idx"], owner_entry=idx)
        loc["symbol"] = sym["name"]

        shndx = sym["shndx"]
        if shndx == SHN_UNDEF:
            if sym["name"] not in symbols:
                raise AuditViolation(
                    "entry",
                    "unresolved_symbol",
                    f"第 {idx} 项引用的外部符号 {sym['name']!r} 未提供地址",
                    **loc,
                )
            s_addr = symbols[sym["name"]]
            referenced_undefined.add(sym["name"])
        elif shndx == text["index"]:
            if sym["value"] > text["size"]:
                raise AuditViolation(
                    "entry",
                    "symbol_value_out_of_section",
                    f"已定义符号 {sym['name']!r} 的 st_value=0x{sym['value']:x} 超出 .text 范围",
                    **loc,
                )
            s_addr = (load_base + sym["value"]) & UINT64_MAX
        elif shndx >= SHN_LORESERVE or shndx >= len(sections):
            raise AuditViolation(
                "entry",
                "unsupported_symbol_section",
                f"符号 {sym['name']!r} 的 st_shndx={shndx} 为不受支持的特殊节索引",
                **loc,
            )
        else:
            raise AuditViolation(
                "entry",
                "symbol_not_in_text",
                f"符号 {sym['name']!r} 定义在非 .text 节 "
                f"{sections[shndx]['name'] or '#' + str(shndx)}，无法由单一装载基址推导地址",
                **loc,
            )

        r_off = ent["offset"]
        if r_off > text["size"] or width > text["size"] - r_off:
            raise AuditViolation(
                "entry",
                "write_out_of_range",
                f"写入区间 [.text+0x{r_off:x}, {width}) 超出节边界（.text 大小 {text['size']} 字节）",
                **loc,
            )

        p_addr = (load_base + r_off) & UINT64_MAX
        if ent["type"] == R_X86_64_64:
            value = (s_addr + addend) & UINT64_MAX
        else:
            # 与硬件/链接器一致：S+A-P 在 64 位补码下回绕，再按有符号
            # 64 位解读，最后判定能否无损截成有符号 32 位。
            raw = (s_addr + addend - p_addr) & UINT64_MAX
            value = raw - (1 << 64) if raw >= (1 << 63) else raw
            if not (INT32_MIN <= value <= INT32_MAX):
                raise AuditViolation(
                    "entry",
                    "pc32_overflow",
                    "R_X86_64_PC32 计算值超出有符号 32 位范围，拒绝生成任何补丁",
                    **loc,
                    detail={
                        "S": hex64(s_addr),
                        "A": str(addend),
                        "P": hex64(p_addr),
                        "computed": str(value),
                        "computed_mod2_64": hex64(raw),
                        "int32_min": str(INT32_MIN),
                        "int32_max": str(INT32_MAX),
                    },
                )

        prepared.append(
            {
                **ent,
                "width": width,
                "symbol_name": sym["name"],
                "s": s_addr,
                "p": p_addr,
                "value": value,
            }
        )

    extra = set(symbols) - referenced_undefined
    if extra:
        raise AuditViolation(
            "request",
            "unexpected_symbol",
            f"提供了未被任何重定位项引用的外部符号地址：{sorted(extra)}",
            detail={"unexpected": sorted(extra)},
        )

    # --- 第二阶段：补丁区间不重叠 -----------------------------------------
    by_offset = sorted(prepared, key=lambda e: (e["offset"], e["global_index"]))
    for prev, cur in zip(by_offset, by_offset[1:]):
        prev_end = prev["offset"] + prev["width"]
        if cur["offset"] < prev_end:
            raise AuditViolation(
                "entry",
                "patch_overlap",
                "重定位写入区间互相重叠："
                f"第 {cur['global_index']} 项 (.text+0x{cur['offset']:x}, {cur['width']}B) "
                f"侵入第 {prev['global_index']} 项 (.text+0x{prev['offset']:x}, {prev['width']}B)",
                entry_index=cur["global_index"],
                rela_section=cur["rela_section"],
                rela_index=cur["rela_index"],
                offset=cur["offset"],
                reloc_type=cur["type"],
                symbol=cur["symbol_name"],
                detail={
                    "conflicts_with": prev["global_index"],
                    "previous_range": [offset_hex(prev["offset"]), offset_hex(prev_end)],
                    "current_range": [offset_hex(cur["offset"]), offset_hex(cur["offset"] + cur["width"])],
                },
            )

    # --- 全部通过，原子落补丁 ---------------------------------------------
    patched = bytearray(text_bytes)
    items: list[RelocItem] = []
    for ent in prepared:
        off = ent["offset"]
        width = ent["width"]
        before = bytes(patched[off : off + width])
        if ent["type"] == R_X86_64_64:
            after = struct.pack("<Q", ent["value"])
        else:
            after = struct.pack("<i", ent["value"])
        patched[off : off + width] = after
        items.append(
            RelocItem(
                index=ent["global_index"],
                rela_section=ent["rela_section"],
                rela_index=ent["rela_index"],
                reloc_type=ent["type"],
                symbol_index=ent["sym_idx"],
                symbol=ent["symbol_name"],
                offset=off,
                width=width,
                s=ent["s"],
                a=ent["addend"],
                p=ent["p"],
                value=ent["value"],
                before=before,
                after=after,
            )
        )

    return AuditResult(
        ok=True,
        items=items,
        file_sha256=file_sha,
        text_size=text["size"],
        text_sha256_before=text_before_sha,
        patched_sha256=hashlib.sha256(patched).hexdigest(),
        load_base=load_base,
        patched=bytes(patched),
    )


# ---------------------------------------------------------------------------
# 联合审计（2..8 个供应商拆分交付的成员装入同一连续代码装载区）
# ---------------------------------------------------------------------------

GROUP_MIN_MEMBERS = 2
GROUP_MAX_MEMBERS = 8
_MEMBER_ID_RE_SRC = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
MEMBER_ID_RE = re.compile(rf"^{_MEMBER_ID_RE_SRC}$")

GROUP_SCHEMA_VERSION = "elfaudit-group/v1"


class GroupAuditViolation(Exception):
    """联合审计违约。

    ``scope`` 为 ``request``（整组请求非法）或 ``member``（可定位到具体成员）。
    成员级违约尽量携带 ``member`` / ``rela_index`` / ``offset`` 等定位信息；
    跨成员符号类问题（重复导出、未解析、非代码节定义）定位到**首个相关重定位**。
    """

    def __init__(
        self,
        scope: str,
        code: str,
        message: str,
        *,
        member: str | None = None,
        member_index: int | None = None,
        rela_index: int | None = None,
        rela_section: str | None = None,
        offset: int | None = None,
        reloc_type: int | None = None,
        symbol: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.scope = scope
        self.code = code
        self.message = message
        self.member = member
        self.member_index = member_index
        self.rela_index = rela_index
        self.rela_section = rela_section
        self.offset = offset
        self.reloc_type = reloc_type
        self.symbol = symbol
        self.detail = detail or {}

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "scope": self.scope,
            "code": self.code,
            "message": self.message,
        }
        if self.member is not None:
            out["member"] = self.member
        if self.member_index is not None:
            out["member_index"] = self.member_index
        if self.rela_section is not None:
            out["rela_section"] = self.rela_section
        if self.rela_index is not None:
            out["rela_index"] = self.rela_index
        if self.offset is not None:
            out["offset"] = offset_hex(self.offset)
        if self.reloc_type is not None:
            out["type"] = self.reloc_type
            out["type_name"] = _RELOC_NAME.get(self.reloc_type, f"UNKNOWN({self.reloc_type})")
        if self.symbol is not None:
            out["symbol"] = self.symbol
        if self.detail:
            out["detail"] = self.detail
        return out


def _gfail_request(code: str, message: str, detail: dict[str, Any] | None = None) -> None:
    raise GroupAuditViolation("request", code, message, detail=detail)


def _parse_member(data: bytes, order: int) -> dict[str, Any]:
    """复用单文件审计的全部结构校验，抽取联合审计所需的最小视图。

    任何文件级/节级结构违约都以普通 :class:`AuditViolation` 抛出，由
    :func:`audit_group` 关联到提交次序对应的成员。
    """
    if not isinstance(data, (bytes, bytearray)):
        raise AuditViolation("request", "bad_payload", "文件载荷必须为字节流")

    if len(data) < EHDR_SIZE:
        raise AuditViolation("file", "truncated", "文件短于 64 字节 ELF 头")
    e_ident = bytes(data[:16])
    if e_ident[:4] != ELFMAG:
        raise AuditViolation("file", "bad_magic", "ELF 魔数不匹配（不是 ELF 文件）")
    if e_ident[4] != ELFCLASS64:
        raise AuditViolation("file", "bad_class", "仅接受 ELF64（EI_CLASS 必须为 2）")
    if e_ident[5] != ELFDATA2LSB:
        raise AuditViolation("file", "bad_data", "仅接受小端 ELF（EI_DATA 必须为 1）")
    if e_ident[6] != EV_CURRENT:
        raise AuditViolation("file", "bad_version", "ELF 版本号不受支持")

    (
        _,
        e_type,
        e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = _unpack(_EHDR_FMT, data, 0, "ELF 头")

    if e_type != ET_REL:
        raise AuditViolation("file", "bad_type", f"仅接受 ET_REL 可重定位文件，e_type={e_type}")
    if e_machine != EM_X86_64:
        raise AuditViolation("file", "bad_machine", f"仅接受 EM_X86_64，e_machine={e_machine}")
    if _e_version != EV_CURRENT:
        raise AuditViolation("file", "bad_e_version", f"ELF 头 e_version 必须为 1，实际 {_e_version}")
    if e_phoff != 0:
        raise AuditViolation("file", "program_header_forbidden", "ET_REL 不得携带程序头表")
    if e_shoff == 0 or e_shnum == 0:
        raise AuditViolation("section", "no_section_table", "缺少节表")
    if e_shentsize != SHDR_SIZE:
        raise AuditViolation("section", "bad_shentsize", f"e_shentsize 必须为 64，实际 {e_shentsize}")
    if e_shstrndx >= e_shnum:
        raise AuditViolation("section", "bad_shstrndx", "e_shstrndx 超出节表范围")
    if e_shoff + e_shnum * SHDR_SIZE > len(data):
        raise AuditViolation("section", "section_table_truncated", "节表超出文件边界")

    sections: list[dict[str, Any]] = []
    for i in range(e_shnum):
        off = e_shoff + i * SHDR_SIZE
        (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        ) = _unpack(_SHDR_FMT, data, off, f"节头 #{i}")
        if i != 0 and sh_type != SHT_NOBITS:
            if sh_offset > len(data) or sh_size > len(data) - sh_offset:
                raise AuditViolation(
                    "section",
                    "section_out_of_bounds",
                    f"节 #{i} 数据区间 [{offset_hex(sh_offset)}, +{sh_size}) 超出文件边界",
                )
        # sh_addralign 为 0/1 或 2 的幂；非法值无法用于确定连续布局。
        if sh_addralign not in (0, 1) and (sh_addralign & (sh_addralign - 1)):
            raise AuditViolation(
                "section",
                "bad_addralign",
                f"节 #{i} 的 sh_addralign={sh_addralign} 不是合法的 2 的幂",
            )
        sections.append(
            {
                "index": i,
                "name_off": sh_name,
                "type": sh_type,
                "flags": sh_flags,
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "info": sh_info,
                "addralign": sh_addralign,
                "entsize": sh_entsize,
                "name": "",
            }
        )

    shstr = sections[e_shstrndx]
    if shstr["type"] != SHT_STRTAB:
        raise AuditViolation("section", "bad_shstrtab", "e_shstrndx 未指向 SHT_STRTAB")
    shstr_blob = data[shstr["offset"] : shstr["offset"] + shstr["size"]]
    for sec in sections:
        name = _read_cstr(shstr_blob, sec["name_off"]) if sec["index"] != 0 else ""
        if name is None:
            raise AuditViolation(
                "section",
                "bad_section_name",
                f"节 #{sec['index']} 的 sh_name 在节名字符串表中越界",
            )
        sec["name"] = name

    text_indexes = [s["index"] for s in sections if s["name"] == ".text"]
    if len(text_indexes) != 1:
        raise AuditViolation(
            "section",
            "text_not_unique",
            f"必须存在唯一的 .text 节，实际找到 {len(text_indexes)} 个",
        )
    text = sections[text_indexes[0]]
    if text["type"] != SHT_PROGBITS:
        raise AuditViolation("section", "bad_text_type", ".text 节类型必须为 SHT_PROGBITS")
    text_bytes = bytes(data[text["offset"] : text["offset"] + text["size"]])

    symtab_indexes = [s["index"] for s in sections if s["type"] == SHT_SYMTAB]
    if len(symtab_indexes) != 1:
        raise AuditViolation(
            "section",
            "symtab_not_unique",
            f"必须存在唯一的 SHT_SYMTAB，实际找到 {len(symtab_indexes)} 个",
        )
    symtab = sections[symtab_indexes[0]]
    if symtab["link"] >= len(sections) or sections[symtab["link"]]["type"] != SHT_STRTAB:
        raise AuditViolation("section", "bad_symtab_link", "符号表的 sh_link 未指向字符串表")
    if symtab["entsize"] not in (0, SYM_SIZE):
        raise AuditViolation(
            "section", "bad_sym_entsize", f"符号表表项尺寸必须为 24，实际 {symtab['entsize']}"
        )
    if symtab["size"] % SYM_SIZE != 0:
        raise AuditViolation("section", "bad_symtab_size", "符号表字节数不是 24 的整数倍")
    sym_count = symtab["size"] // SYM_SIZE
    if not (1 <= symtab["info"] <= sym_count):
        raise AuditViolation(
            "section",
            "bad_symtab_info",
            f"符号表 sh_info（首个非局部符号索引）必须在 1..{sym_count} 范围内，实际 {symtab['info']}",
        )
    strtab = sections[symtab["link"]]
    strtab_blob = data[strtab["offset"] : strtab["offset"] + strtab["size"]]

    def read_symbol(sym_idx: int) -> dict[str, Any]:
        if sym_idx == 0 or sym_idx >= sym_count:
            raise AuditViolation(
                "entry",
                "bad_symbol_index",
                f"r_info 符号索引 {sym_idx} 越界（符号表共 {sym_count} 项，0 为保留项）",
            )
        soff = symtab["offset"] + sym_idx * SYM_SIZE
        st_name, st_info, _st_other, st_shndx, st_value, _st_size = _unpack(
            _SYM_FMT, data, soff, f"符号 #{sym_idx}"
        )
        name = _read_cstr(strtab_blob, st_name)
        if name is None:
            raise AuditViolation(
                "entry",
                "bad_symbol_name",
                f"符号 #{sym_idx} 的 st_name={st_name} 在字符串表中越界或缺少 NUL",
            )
        return {
            "index": sym_idx,
            "name": name,
            "shndx": st_shndx,
            "value": st_value,
            "bind": st_info >> 4,
            "type": st_info & 0xF,
        }

    rela_sections = [s for s in sections if s["type"] in (SHT_RELA, SHT_REL)]
    if not rela_sections:
        raise AuditViolation("section", "no_rela", "未找到任何重定位节")
    for sec in rela_sections:
        if sec["type"] == SHT_REL:
            raise AuditViolation(
                "section",
                "rel_unsupported",
                f"节 {sec['name'] or '#' + str(sec['index'])} 为 SHT_REL，仅接受带加数的 SHT_RELA",
            )
        if sec["info"] != text["index"]:
            target = sections[sec["info"]]["name"] if sec["info"] < len(sections) else "?"
            raise AuditViolation(
                "section",
                "rela_not_for_text",
                f"RELA 节 {sec['name'] or '#' + str(sec['index'])} 指向 {target or '#' + str(sec['info'])}，"
                "仅接受指向唯一 .text 的 RELA 节",
            )
        if sec["link"] != symtab["index"]:
            raise AuditViolation(
                "section", "bad_rela_link", f"RELA 节 {sec['name']} 的 sh_link 未指向符号表"
            )
        if sec["entsize"] not in (0, RELA_SIZE):
            raise AuditViolation(
                "section",
                "bad_rela_entsize",
                f"RELA 节 {sec['name']} 表项尺寸必须为 24，实际 {sec['entsize']}",
            )
        if sec["size"] % RELA_SIZE != 0:
            raise AuditViolation(
                "section", "bad_rela_size", f"RELA 节 {sec['name']} 字节数不是 24 的整数倍"
            )

    # 全部符号（含保留空符号 #0）
    symbols = [read_symbol(i) if i else None for i in range(sym_count)]

    relocs: list[dict[str, Any]] = []
    for sec in rela_sections:
        count = sec["size"] // RELA_SIZE
        for j in range(count):
            r_offset, r_info, r_addend = _unpack(
                _RELA_FMT, data, sec["offset"] + j * RELA_SIZE, f"RELA 项 {sec['name']}[{j}]"
            )
            relocs.append(
                {
                    "member_index": len(relocs),  # 成员内跨 RELA 节的全局序号
                    "rela_section": sec["name"] or f"#{sec['index']}",
                    "rela_index": j,
                    "offset": r_offset,
                    "sym_idx": r_info >> 32,
                    "type": r_info & 0xFFFFFFFF,
                    "addend": r_addend,
                }
            )
    if not relocs:
        raise AuditViolation("section", "no_rela", "RELA 节存在但不含任何重定位项")

    # 第一遍成员内独立校验（与单文件审计同口径），保证坏文件在布局前即被拒绝
    view = {
        "order": order,
        "sections": sections,
        "text_index": text["index"],
        "text": text,
        "text_bytes": text_bytes,
        "symbols": symbols,
        "sym_count": sym_count,
        "relocs": relocs,
        "_file_bytes": bytes(data),
    }
    for rel in relocs:
        _check_reloc_standalone(rel, view)
    return view


def _check_reloc_standalone(rel: dict[str, Any], view: dict[str, Any]) -> None:
    """对一条重定位做不依赖布局的成员内校验。

    ``SHN_UNDEF`` 符号在联合审计中由同组其他成员的全局导出或请求提供的
    外部地址解析；定义在非代码节的符号延迟到联合解析阶段，以便结合
    “是否跨成员”给出稳定的首个相关重定位定位。此处只保证类型/加数/符号
    索引/本成员 .text 内定义的 st_value 合法。
    """
    width = _RELOC_WIDTH.get(rel["type"])
    if width is None:
        raise AuditViolation(
            "entry",
            "unsupported_reloc_type",
            f"不支持的重定位类型 {rel['type']}，仅处理 R_X86_64_64(1) 与 R_X86_64_PC32(2)",
            rela_section=rel["rela_section"],
            rela_index=rel["rela_index"],
            offset=rel["offset"],
            reloc_type=rel["type"],
        )
    addend = rel["addend"]
    if not (INT64_MIN <= addend <= INT64_MAX):
        raise AuditViolation(
            "entry", "bad_addend", "RELA 加数超出有符号 64 位范围",
            rela_section=rel["rela_section"], rela_index=rel["rela_index"],
            offset=rel["offset"], reloc_type=rel["type"],
        )

    sym_idx = rel["sym_idx"]
    if sym_idx == 0 or sym_idx >= view["sym_count"]:
        raise AuditViolation(
            "entry",
            "bad_symbol_index",
            f"r_info 符号索引 {sym_idx} 越界（符号表共 {view['sym_count']} 项，0 为保留项）",
            rela_section=rel["rela_section"],
            rela_index=rel["rela_index"],
            offset=rel["offset"],
            reloc_type=rel["type"],
        )
    sym = view["symbols"][sym_idx]
    shndx = sym["shndx"]
    if shndx == SHN_UNDEF:
        return
    if shndx == view["text_index"]:
        text = view["text"]
        if sym["value"] > text["size"]:
            raise AuditViolation(
                "entry",
                "symbol_value_out_of_section",
                f"已定义符号 {sym['name']!r} 的 st_value=0x{sym['value']:x} 超出 .text 范围",
                rela_section=rel["rela_section"], rela_index=rel["rela_index"],
                offset=rel["offset"], reloc_type=rel["type"], symbol=sym["name"],
            )
        return
    # 定义在其他节（普通非代码节或保留节索引）：延迟到联合解析阶段，
    # 因为需要结合“该引用是否跨成员”给出稳定的首个相关重定位定位。
    return


@dataclass
class MemberLayout:
    member_id: str
    order: int  # 提交次序（0 基），用于成员级结构违约定位
    sort_index: int  # 排序后位置（0 基）
    text_size: int
    text_align: int
    text_offset: int  # 相对装载基址的偏移
    base: int  # = load_base + text_offset
    end: int  # = base + text_size
    file_sha256: str
    text_sha256_before: str
    patched_sha256: str = ""
    patched: bytes = b""
    items: list[RelocItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "member": self.member_id,
            "member_index": self.sort_index,
            "base": hex64(self.base),
            "base_offset": offset_hex(self.text_offset),
            "text_size": self.text_size,
            "text_align": self.text_align,
            "end": hex64(self.end),
            "range": [hex64(self.base), hex64(self.end)],
            "file_sha256": self.file_sha256,
            "text_sha256_before": self.text_sha256_before,
            "patched_sha256": self.patched_sha256,
            "item_count": len(self.items),
            "items": [it.to_dict() for it in sorted(self.items, key=lambda x: (x.offset, x.index))],
            "patches": [
                {
                    "member": self.member_id,
                    "offset": it.offset,
                    "offset_hex": offset_hex(it.offset),
                    "width": it.width,
                    "type": it.reloc_type,
                    "type_name": _RELOC_NAME[it.reloc_type],
                    "symbol": it.symbol,
                    "before_hex": it.before.hex(),
                    "after_hex": it.after.hex(),
                }
                for it in sorted(self.items, key=lambda x: (x.offset, x.index))
            ],
            "patched_text_hex": self.patched.hex(),
        }


@dataclass
class GroupAuditResult:
    ok: bool
    violation: GroupAuditViolation | None = None
    audit_id: str = ""
    load_base: int = 0
    region_end: int = 0
    members: list[MemberLayout] = field(default_factory=list)
    conclusion: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        if not self.ok:
            return {"ok": False, "audit_id": self.audit_id, "violation": self.violation.to_dict()}  # type: ignore[union-attr]
        return {
            "ok": True,
            "audit_id": self.audit_id,
            "conclusion": self.conclusion,
            "load_base": hex64(self.load_base),
            "region_range": [hex64(self.load_base), hex64(self.region_end)],
            "region_size": self.region_end - self.load_base,
            "member_count": len(self.members),
            "members": [m.to_dict() for m in self.members],
        }


STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2


def audit_group(
    audit_id: str,
    members: list[dict[str, Any]],
    load_base: int,
    symbols: dict[str, int],
) -> GroupAuditResult:
    """对 2..8 个成员执行联合审计。

    ``members`` 每项形如 ``{"member_id": str, "data": bytes}``，提交次序仅用于
    结构违约定位；布局一律按 ``member_id`` 排序。任何违约都返回 ``ok=False``
    且不携带任何成员补丁（无部分联合结论）。
    """
    try:
        return _audit_group(audit_id, members, load_base, symbols)
    except GroupAuditViolation as exc:
        return GroupAuditResult(ok=False, violation=exc, audit_id=audit_id, load_base=load_base)


def _audit_group(
    audit_id: str,
    members: list[dict[str, Any]],
    load_base: int,
    symbols: dict[str, int],
) -> GroupAuditResult:
    # --- 请求级校验 -------------------------------------------------------
    if not isinstance(audit_id, str) or not MEMBER_ID_RE.match(audit_id):
        _gfail_request("bad_audit_id", "audit_id 必须为 1..128 字符，仅限字母数字及 . _ : -")
    if not isinstance(members, list):
        _gfail_request("bad_members", "members 必须为成员对象列表")
    if not GROUP_MIN_MEMBERS <= len(members) <= GROUP_MAX_MEMBERS:
        _gfail_request(
            "bad_member_count",
            f"联合审计成员数必须在 {GROUP_MIN_MEMBERS}..{GROUP_MAX_MEMBERS} 之间，实际 {len(members)}",
        )
    if not isinstance(load_base, int) or not (0 <= load_base <= UINT64_MAX):
        _gfail_request("bad_base", "装载基址必须是 0..2^64-1 范围内的整数")
    if not isinstance(symbols, dict):
        _gfail_request("bad_symbols", "外部符号地址必须为名称到地址的映射")
    for name, addr in symbols.items():
        if not isinstance(name, str) or not name or "\x00" in name or len(name) > 255:
            _gfail_request("bad_symbol_name", f"非法外部符号名：{name!r}")
        if not isinstance(addr, int) or not (0 <= addr <= UINT64_MAX):
            _gfail_request("bad_symbol_addr", f"符号 {name!r} 地址非法")

    seen_ids: set[str] = set()
    parsed: list[dict[str, Any]] = []
    for order, m in enumerate(members):
        if not isinstance(m, dict) or "member_id" not in m or "data" not in m:
            _gfail_request("bad_member", f"第 {order} 个成员必须包含 member_id 与 data")
        mid = m["member_id"]
        if not isinstance(mid, str) or not MEMBER_ID_RE.match(mid):
            _gfail_request(
                "bad_member_id",
                f"第 {order} 个成员标识非法：必须为 1..128 字符，仅限字母数字及 . _ : -",
                {"submit_index": order},
            )
        if mid in seen_ids:
            _gfail_request("duplicate_member_id", f"成员标识重复：{mid!r}", {"member": mid})
        seen_ids.add(mid)
        # 结构解析失败：关联到提交次序（此时尚无排序布局）
        try:
            view = _parse_member(m["data"], order)
        except AuditViolation as exc:
            raise GroupAuditViolation(
                "member",
                exc.code,
                f"成员 {mid!r} 结构审计未通过：{exc.message}",
                member=mid,
                member_index=order,
                rela_section=exc.rela_section,
                rela_index=exc.rela_index,
                offset=exc.offset,
                reloc_type=exc.reloc_type,
                symbol=exc.symbol,
                detail={"file_stage": exc.stage, **(exc.detail or {})},
            ) from exc
        view["member_id"] = mid
        parsed.append(view)

    # --- 按成员标识排序确定连续布局（与提交次序无关） ---------------------
    ordered = sorted(parsed, key=lambda v: v["member_id"])

    layouts: list[MemberLayout] = []
    cursor = load_base
    for sort_i, view in enumerate(ordered):
        text = view["text"]
        align = max(1, text["addralign"])
        if sort_i == 0:
            # 首个成员必须恰好从给定代码装载基址开始：基址必须满足其对齐要求
            if load_base % align:
                _gfail_request(
                    "bad_base_alignment",
                    f"装载基址 0x{load_base:x} 未按首成员 {view['member_id']!r} 的 "
                    f".text 对齐要求 {align} 对齐",
                    {"required_align": align, "member": view["member_id"]},
                )
            offset = 0
        else:
            offset = cursor - load_base
            delta = (-cursor) % align
            if delta:
                offset += delta
                cursor += delta
        base = load_base + offset
        end = base + text["size"]
        if end > (1 << 64) or offset + text["size"] > UINT64_MAX - load_base:
            _gfail_request(
                "layout_out_of_address_space",
                f"成员 {view['member_id']!r} 的连续布局越过 64 位地址空间",
                {"member": view["member_id"]},
            )
        layouts.append(
            MemberLayout(
                member_id=view["member_id"],
                order=view["order"],
                sort_index=sort_i,
                text_size=text["size"],
                text_align=align,
                text_offset=offset,
                base=base,
                end=end,
                file_sha256=hashlib.sha256(view["_file_bytes"]).hexdigest(),
                text_sha256_before=hashlib.sha256(view["text_bytes"]).hexdigest(),
            )
        )
        cursor = end
    region_end = cursor

    layout_by_id = {lay.member_id: lay for lay in layouts}

    # --- 收集全局/弱导出定义（含非代码节定义，延迟到引用时判定） ----------
    # exports: 名字 -> 定义列表（按成员排序序、符号表下标序），每项
    # {"member", "sort_index", "in_text", "value", "sym_index"}
    exports: dict[str, list[dict[str, Any]]] = {}
    duplicate_names: dict[str, list[dict[str, Any]]] = {}
    for view in ordered:
        sort_i = layout_by_id[view["member_id"]].sort_index
        for sym in view["symbols"][1:]:
            if sym is None or sym["shndx"] == SHN_UNDEF or sym["bind"] not in (
                STB_GLOBAL,
                STB_WEAK,
            ):
                continue
            shndx = sym["shndx"]
            in_text = shndx == view["text_index"]
            defs = exports.setdefault(
                sym["name"],
                [],
            )
            defs.append(
                {
                    "member": view["member_id"],
                    "sort_index": sort_i,
                    "in_text": in_text,
                    "shndx": shndx,
                    "value": sym["value"],
                    "sym_index": sym["index"],
                }
            )
            if len(defs) > 1 and sym["name"] not in duplicate_names:
                duplicate_names[sym["name"]] = defs

    def raise_at_reloc(
        code: str,
        message: str,
        view: dict[str, Any],
        rel: dict[str, Any],
        *,
        detail: dict[str, Any] | None = None,
    ) -> None:
        raise GroupAuditViolation(
            "member",
            code,
            message,
            member=view["member_id"],
            member_index=layout_by_id[view["member_id"]].sort_index,
            rela_section=rel["rela_section"],
            rela_index=rel["rela_index"],
            offset=rel["offset"],
            reloc_type=rel["type"],
            symbol=view["symbols"][rel["sym_idx"]]["name"],
            detail=detail or {},
        )

    # --- 逐条重定位解析 S（成员局部 / 唯一他成员全局 / 外部地址） ----------
    # 解析顺序按 (成员排序序, 成员内 RELA 全局序)，保证首个违约稳定定位。
    prepared: list[tuple[MemberLayout, dict[str, Any], dict[str, Any]]] = []
    referenced_external: set[str] = set()
    duplicate_reported: set[str] = set()

    for view in ordered:
        lay = layout_by_id[view["member_id"]]
        for rel in sorted(view["relocs"], key=lambda r: r["member_index"]):
            sym = view["symbols"][rel["sym_idx"]]
            shndx = sym["shndx"]

            if shndx == SHN_UNDEF:
                name = sym["name"]
                ext_addr = symbols.get(name)
                defs = exports.get(name, [])
                if ext_addr is not None and defs:
                    raise_at_reloc(
                        "external_shadows_export",
                        f"符号 {name!r} 既由成员 {defs[0]['member']!r} 等全局导出，"
                        "又显式提供了外部地址，解析来源不唯一",
                        view,
                        rel,
                        detail={
                            "exporters": sorted({d["member"] for d in defs}),
                            "external_address": hex64(ext_addr),
                        },
                    )
                if ext_addr is not None:
                    s_addr = ext_addr
                    referenced_external.add(name)
                elif len(defs) > 1:
                    duplicate_reported.add(name)
                    raise_at_reloc(
                        "duplicate_export",
                        f"符号 {name!r} 被多个成员全局导出，未定义引用无法确定唯一定义",
                        view,
                        rel,
                        detail={"exporters": sorted({d["member"] for d in defs})},
                    )
                elif len(defs) == 1:
                    dfn = defs[0]
                    if not dfn["in_text"]:
                        raise_at_reloc(
                            "non_code_definition",
                            f"符号 {name!r} 的唯一全局定义位于成员 {dfn['member']!r} 的"
                            "非代码节，联合装载区只放置 .text，无法推导其地址",
                            view,
                            rel,
                            detail={
                                "definer": dfn["member"],
                                "st_shndx": dfn["shndx"],
                            },
                        )
                    if dfn["value"] > layout_by_id[dfn["member"]].text_size:
                        raise_at_reloc(
                            "symbol_value_out_of_section",
                            f"符号 {name!r} 在成员 {dfn['member']!r} 中的 st_value="
                            f"0x{dfn['value']:x} 超出其 .text 范围",
                            view,
                            rel,
                            detail={"definer": dfn["member"]},
                        )
                    s_addr = (layout_by_id[dfn["member"]].base + dfn["value"]) & UINT64_MAX
                else:
                    raise_at_reloc(
                        "unresolved_symbol",
                        f"成员 {view['member_id']!r} 引用的符号 {name!r} "
                        "既无同组唯一全局定义，也未提供外部地址",
                        view,
                        rel,
                    )
            elif shndx == view["text_index"]:
                # 同成员内定义（局部或全局）：只能解析到本成员自己的定义，
                # 不会因为其他成员的同名导出而解析到错误地址。
                if sym["value"] > view["text"]["size"]:
                    raise_at_reloc(
                        "symbol_value_out_of_section",
                        f"已定义符号 {sym['name']!r} 的 st_value=0x{sym['value']:x} "
                        "超出本成员 .text 范围",
                        view,
                        rel,
                    )
                s_addr = (lay.base + sym["value"]) & UINT64_MAX
            else:
                # 定义在非代码节（含保留节索引）：同一装载区无法推导地址
                sec_name = (
                    view["sections"][shndx]["name"]
                    if shndx < len(view["sections"])
                    else f"保留节索引 {shndx}"
                )
                raise_at_reloc(
                    "non_code_definition",
                    f"符号 {sym['name']!r} 定义在非代码节（{sec_name or f'#{shndx}'}），"
                    "联合装载区只解析 .text 定义",
                    view,
                    rel,
                    detail={"st_shndx": shndx},
                )

            width = _RELOC_WIDTH[rel["type"]]
            if rel["offset"] > view["text"]["size"] or width > view["text"]["size"] - rel["offset"]:
                raise_at_reloc(
                    "write_out_of_range",
                    f"写入区间 [.text+0x{rel['offset']:x}, {width}) 超出成员 "
                    f"{view['member_id']!r} 的 .text 边界（{view['text']['size']} 字节）",
                    view,
                    rel,
                )

            p_addr = (lay.base + rel["offset"]) & UINT64_MAX
            if rel["type"] == R_X86_64_64:
                value = (s_addr + rel["addend"]) & UINT64_MAX
            else:
                raw = (s_addr + rel["addend"] - p_addr) & UINT64_MAX
                value = raw - (1 << 64) if raw >= (1 << 63) else raw
                if not (INT32_MIN <= value <= INT32_MAX):
                    raise_at_reloc(
                        "pc32_overflow",
                        f"成员 {view['member_id']!r} 的 R_X86_64_PC32 计算值超出有符号 "
                        "32 位范围，整组拒绝且不生成任何补丁",
                        view,
                        rel,
                        detail={
                            "S": hex64(s_addr),
                            "A": str(rel["addend"]),
                            "P": hex64(p_addr),
                            "computed": str(value),
                            "computed_mod2_64": hex64(raw),
                            "int32_min": str(INT32_MIN),
                            "int32_max": str(INT32_MAX),
                        },
                    )
            prepared.append(
                (
                    lay,
                    rel,
                    {
                        "sym": sym,
                        "width": width,
                        "s": s_addr,
                        "p": p_addr,
                        "value": value,
                    },
                )
            )

    # 重复导出即使无人引用也必须拒绝；此时不存在“相关重定位”，定位到
    # 排序在后的导出成员的符号表定义处。
    for name in sorted(duplicate_names):
        if name in duplicate_reported:
            continue
        defs = duplicate_names[name]
        later = defs[1]
        raise GroupAuditViolation(
            "member",
            "duplicate_export",
            f"全局符号 {name!r} 被多个成员导出，无法确定唯一定义",
            member=later["member"],
            member_index=later["sort_index"],
            symbol=name,
            detail={
                "exporters": sorted({d["member"] for d in defs}),
                "located_via": "symbol_table",
                "symbol_index": later["sym_index"],
            },
        )

    extra = set(symbols) - referenced_external
    if extra:
        # 未被任何成员引用的外部地址：请求级拒绝（无成员重定位可定位）
        _gfail_request(
            "unexpected_symbol",
            f"提供了未被任何成员重定位引用的外部符号地址：{sorted(extra)}",
            {"unexpected": sorted(extra)},
        )

    # --- 补丁区间两两不得重叠（成员内；成员区间在布局上互不重叠） ---------
    for view in ordered:
        lay = layout_by_id[view["member_id"]]
        rels_sorted = sorted(
            (p for p in prepared if p[0] is lay),
            key=lambda p: (p[1]["offset"], p[1]["member_index"]),
        )
        for (_, prev_rel, _), (_, cur_rel, _) in zip(rels_sorted, rels_sorted[1:]):
            prev_end = prev_rel["offset"] + _RELOC_WIDTH[prev_rel["type"]]
            if cur_rel["offset"] < prev_end:
                cur_sym = view["symbols"][cur_rel["sym_idx"]]
                raise GroupAuditViolation(
                    "member",
                    "patch_overlap",
                    f"成员 {lay.member_id!r} 的重定位写入区间互相重叠："
                    f".text+0x{cur_rel['offset']:x} 侵入 .text+0x{prev_rel['offset']:x}",
                    member=lay.member_id,
                    member_index=lay.sort_index,
                    rela_section=cur_rel["rela_section"],
                    rela_index=cur_rel["rela_index"],
                    offset=cur_rel["offset"],
                    reloc_type=cur_rel["type"],
                    symbol=cur_sym["name"],
                    detail={
                        "conflicts_with_rela_index": prev_rel["rela_index"],
                        "previous_range": [
                            offset_hex(prev_rel["offset"]),
                            offset_hex(prev_end),
                        ],
                        "current_range": [
                            offset_hex(cur_rel["offset"]),
                            offset_hex(cur_rel["offset"] + _RELOC_WIDTH[cur_rel["type"]]),
                        ],
                    },
                )

    # --- 全部通过：逐成员原子落补丁（任何失败都不会执行到这里） -----------
    for view in ordered:
        lay = layout_by_id[view["member_id"]]
        patched = bytearray(view["text_bytes"])
        items: list[RelocItem] = []
        for _, rel, calc in (p for p in prepared if p[0] is lay):
            off = rel["offset"]
            width = calc["width"]
            before = bytes(patched[off : off + width])
            after = (
                struct.pack("<Q", calc["value"])
                if rel["type"] == R_X86_64_64
                else struct.pack("<i", calc["value"])
            )
            patched[off : off + width] = after
            items.append(
                RelocItem(
                    # 成员内稳定序号：跨 RELA 节的成员内全局下标
                    index=rel["member_index"],
                    rela_section=rel["rela_section"],
                    rela_index=rel["rela_index"],
                    reloc_type=rel["type"],
                    symbol_index=rel["sym_idx"],
                    symbol=calc["sym"]["name"],
                    offset=off,
                    width=width,
                    s=calc["s"],
                    a=rel["addend"],
                    p=calc["p"],
                    value=calc["value"],
                    before=before,
                    after=after,
                )
            )
        lay.items = items
        lay.patched = bytes(patched)
        lay.patched_sha256 = hashlib.sha256(patched).hexdigest()

    result = GroupAuditResult(
        ok=True,
        audit_id=audit_id,
        load_base=load_base,
        region_end=region_end,
        members=layouts,
    )
    result.conclusion = freeze_group_conclusion(audit_id, result, symbols)
    return result


def freeze_conclusion(
    audit_id: str, result: AuditResult, symbols: dict[str, int]
) -> str:
    """对通过的审计结果计算稳定的冻结结论摘要（SHA-256）。

    规范化文档保持单文件审计的历史格式不变：同一输入的摘要与既有结论
    逐字符一致，旧读取结果不受联合审计能力影响。
    """
    if not result.ok:
        raise ValueError("失败审计不得生成冻结结论")
    canonical = {
        "audit_id": audit_id,
        "verdict": "PASS",
        "file_sha256": result.file_sha256,
        "load_base": str(result.load_base),
        "text_size": result.text_size,
        "text_sha256_before": result.text_sha256_before,
        "patched_sha256": result.patched_sha256,
        "symbols": {name: str(addr) for name, addr in sorted(symbols.items())},
        "items": [
            {
                "index": it.index,
                "type": it.reloc_type,
                "symbol": it.symbol,
                "symbol_index": it.symbol_index,
                "offset": str(it.offset),
                "width": it.width,
                "S": str(it.s),
                "A": str(it.a),
                "P": str(it.p),
                "value": str(it.value),
                "before": it.before.hex(),
                "after": it.after.hex(),
            }
            for it in sorted(result.items, key=lambda x: (x.offset, x.index))
        ],
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return hashlib.sha256(blob).hexdigest()


def freeze_group_conclusion(
    audit_id: str, result: GroupAuditResult, symbols: dict[str, int]
) -> str:
    """联合审计的稳定冻结摘要：只依赖标识、基址、外部地址与排序后的成员内容。

    成员提交次序调换但标识与文件内容相同时，成员集合一致、布局一致，
    因而摘要一致。
    """
    if not result.ok:
        raise ValueError("失败的联合审计不得生成冻结结论")
    canonical = {
        "schema": GROUP_SCHEMA_VERSION,
        "audit_id": audit_id,
        "verdict": "PASS",
        "load_base": str(result.load_base),
        "region_end": str(result.region_end),
        "external_symbols": {
            name: str(addr) for name, addr in sorted(symbols.items())
        },
        "members": [
            {
                "member": lay.member_id,
                "file_sha256": lay.file_sha256,
                "text_align": lay.text_align,
                "base": str(lay.base),
                "base_offset": str(lay.text_offset),
                "text_size": lay.text_size,
                "text_sha256_before": lay.text_sha256_before,
                "patched_sha256": lay.patched_sha256,
                "items": [
                    {
                        "index": it.index,
                        "type": it.reloc_type,
                        "symbol": it.symbol,
                        "symbol_index": it.symbol_index,
                        "offset": str(it.offset),
                        "width": it.width,
                        "S": str(it.s),
                        "A": str(it.a),
                        "P": str(it.p),
                        "value": str(it.value),
                        "before": it.before.hex(),
                        "after": it.after.hex(),
                    }
                    for it in sorted(lay.items, key=lambda x: (x.offset, x.index))
                ],
            }
            for lay in result.members  # 已按 member_id 排序
        ],
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return hashlib.sha256(blob).hexdigest()
