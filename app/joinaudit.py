"""多成员（供应商拆分交付）ELF64 ET_REL **联合重定位审计** 核心。

在单文件审计（见 :mod:`app.elfaudit`）的结构规则之上，联合审计把 2..8 个
成员的唯一 ``.text`` 节摆入**同一连续装载区**，并在整组范围内解析符号：

* 成员按稳定标识（member id）的码位排序，依次按各自 ``.text`` 的
  ``sh_addralign`` 上取整连续布局；
* 重定位只允许引用三类符号：

  1. 同成员 ``.text`` 内的本地定义（``S = 本成员基址 + st_value``）；
  2. 唯一的**其他成员**全局定义（``S = 属主成员基址 + st_value``）；
  3. 审查员明确提供地址的外部符号（``SHN_UNDEF``）；

* 同一名字被多个成员（或外部地址与成员导出同时）定义时，只要有重定位
  引用即按 ``duplicate_export`` 拒绝整组，并定位首个相关重定位；
* 任何成员出现 PC32 溢出、补丁重叠、写入越界、非代码节定义等，均整组
  拒绝，不留下任何部分联合结论。

所有结构性检查与逐项检查全部通过后，才一次性落补丁并生成冻结结论。
成员提交次序不影响布局与冻结摘要（规范化时按成员标识排序）。
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any

from .elfaudit import (
    ELFCLASS64,
    ELFDATA2LSB,
    ELFMAG,
    EM_X86_64,
    ET_REL,
    EV_CURRENT,
    EHDR_SIZE,
    INT32_MAX,
    INT32_MIN,
    INT64_MAX,
    INT64_MIN,
    RELA_SIZE,
    R_X86_64_64,
    R_X86_64_PC32,
    SHDR_SIZE,
    SHN_LORESERVE,
    SHN_UNDEF,
    SHT_NOBITS,
    SHT_PROGBITS,
    SHT_REL,
    SHT_RELA,
    SHT_STRTAB,
    SHT_SYMTAB,
    SYM_SIZE,
    UINT64_MAX,
    _EHDR_FMT,
    _RELA_FMT,
    _RELOC_NAME,
    _RELOC_WIDTH,
    _SHDR_FMT,
    _SYM_FMT,
    _read_cstr,
    _unpack,
    hex64,
    offset_hex,
    signed_hex,
)

MIN_MEMBERS = 2
MAX_MEMBERS = 8
MAX_MEMBER_ID_LEN = 127
_MEMBER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,126}$")

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2


class JoinViolation(Exception):
    """联合审计违约。

    ``stage`` 取值：``request``（请求本身非法）、``member``（成员文件
    结构性违约）、``layout``（布局阶段）、``entry``（重定位逐项校验）。
    """

    def __init__(
        self,
        stage: str,
        code: str,
        message: str,
        *,
        member: str | None = None,
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
        self.member = member
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
        if self.member is not None:
            out["member"] = self.member
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
class JointItem:
    member: str
    index: int  # 联合全局序号（成员按标识排序后连续编号）
    rela_section: str
    rela_index: int
    reloc_type: int
    symbol_index: int
    symbol: str
    source: str  # "local" | "member" | "external"
    source_member: str | None
    offset: int
    width: int
    s: int
    a: int
    p: int
    value: int
    before: bytes
    after: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "member": self.member,
            "index": self.index,
            "rela_section": self.rela_section,
            "rela_index": self.rela_index,
            "type": self.reloc_type,
            "type_name": _RELOC_NAME[self.reloc_type],
            "symbol_index": self.symbol_index,
            "symbol": self.symbol,
            "source": self.source,
            "source_member": self.source_member,
            "offset": self.offset,
            "offset_hex": offset_hex(self.offset),
            "width": self.width,
            "S": hex64(self.s),
            "A": str(self.a),
            "A_hex": signed_hex(self.a, 64),
            "P": hex64(self.p),
            "value": signed_hex(self.value, 32)
            if self.reloc_type == R_X86_64_PC32
            else hex64(self.value),
            "before_hex": self.before.hex(),
            "after_hex": self.after.hex(),
        }


@dataclass
class MemberOutcome:
    member: str
    order: int
    file_sha256: str
    text_size: int
    text_addralign: int
    start: int
    end: int
    text_sha256_before: str
    patched_sha256: str
    patched: bytes
    items: list[JointItem] = field(default_factory=list)


@dataclass
class JointResult:
    ok: bool
    violation: JoinViolation | None = None
    load_base: int = 0
    members: list[MemberOutcome] = field(default_factory=list)
    items: list[JointItem] = field(default_factory=list)

    def ordered_items(self) -> list[JointItem]:
        order = {m.member: m.order for m in self.members}
        return sorted(self.items, key=lambda it: (order[it.member], it.offset, it.index))

    def to_public_dict(self) -> dict[str, Any]:
        if not self.ok:
            return {"ok": False, "joint": True, "violation": self.violation.to_dict()}  # type: ignore[union-attr]
        items = self.ordered_items()
        return {
            "ok": True,
            "joint": True,
            "load_base": hex64(self.load_base),
            "member_count": len(self.members),
            "item_count": len(items),
            "members": [
                {
                    "member": m.member,
                    "order": m.order,
                    "file_sha256": m.file_sha256,
                    "text_size": m.text_size,
                    "text_addralign": m.text_addralign,
                    "base": hex64(m.start),
                    "start": hex64(m.start),
                    "end": hex64(m.end),
                    "range": [hex64(m.start), hex64(m.end)],
                    "text_sha256_before": m.text_sha256_before,
                    "patched_sha256": m.patched_sha256,
                    "patched_text_hex": m.patched.hex(),
                    "item_count": len(m.items),
                }
                for m in sorted(self.members, key=lambda m: m.order)
            ],
            "items": [it.to_dict() for it in items],
            "patches": [
                {
                    "member": it.member,
                    "index": it.index,
                    "offset": it.offset,
                    "offset_hex": offset_hex(it.offset),
                    "width": it.width,
                    "type": it.reloc_type,
                    "type_name": _RELOC_NAME[it.reloc_type],
                    "symbol": it.symbol,
                    "source": it.source,
                    "source_member": it.source_member,
                    "before_hex": it.before.hex(),
                    "after_hex": it.after.hex(),
                }
                for it in items
            ],
        }


# ---------------------------------------------------------------------------
# 成员文件结构化解析
# ---------------------------------------------------------------------------


@dataclass
class _Symbol:
    index: int
    name: str
    bind: int
    shndx: int
    value: int


@dataclass
class _RawEntry:
    rela_section: str
    rela_index: int
    offset: int
    sym_idx: int
    reloc_type: int
    addend: int


@dataclass
class _ParsedMember:
    member: str
    data: bytes
    file_sha256: str
    text_index: int
    section_count: int
    text_size: int
    text_addralign: int
    text_bytes: bytes
    text_sha: str
    symbols: list[_Symbol]
    exports: dict[str, list[tuple[int, int]]]  # .text 全局定义 name -> [(sym_idx, st_value)]
    non_code_exports: dict[str, list[tuple[int, int]]]  # 非 .text 节全局定义 name -> [(sym_idx, shndx)]
    entries: list[_RawEntry]


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def _parse_member(member_id: str, data: bytes) -> _ParsedMember:
    """解析单个成员，结构性规则与单文件审计保持一致（允许不含重定位节）。"""

    def fail(code: str, message: str, **kw: Any) -> JoinViolation:
        return JoinViolation("member", code, message, member=member_id, **kw)

    if not isinstance(data, (bytes, bytearray)):
        raise fail("bad_payload", "成员文件载荷必须为字节流")

    file_sha = hashlib.sha256(data).hexdigest()

    if len(data) < EHDR_SIZE:
        raise fail("truncated", "文件短于 64 字节 ELF 头")
    e_ident = data[:16]
    if e_ident[:4] != ELFMAG:
        raise fail("bad_magic", "ELF 魔数不匹配（不是 ELF 文件）")
    if e_ident[4] != ELFCLASS64:
        raise fail("bad_class", "仅接受 ELF64（EI_CLASS 必须为 2）")
    if e_ident[5] != ELFDATA2LSB:
        raise fail("bad_data", "仅接受小端 ELF（EI_DATA 必须为 1）")
    if e_ident[6] != EV_CURRENT:
        raise fail("bad_version", "ELF 版本号不受支持")

    (
        _,
        e_type,
        e_machine,
        e_version,
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
        raise fail("bad_type", f"仅接受 ET_REL 可重定位文件，e_type={e_type}")
    if e_machine != EM_X86_64:
        raise fail("bad_machine", f"仅接受 EM_X86_64，e_machine={e_machine}")
    if e_version != EV_CURRENT:
        raise fail("bad_e_version", f"ELF 头 e_version 必须为 1，实际 {e_version}")
    if e_phoff != 0:
        raise fail("program_header_forbidden", "ET_REL 不得携带程序头表")
    if e_shoff == 0 or e_shnum == 0:
        raise fail("no_section_table", "缺少节表")
    if e_shentsize != SHDR_SIZE:
        raise fail("bad_shentsize", f"e_shentsize 必须为 64，实际 {e_shentsize}")
    if e_shstrndx >= e_shnum:
        raise fail("bad_shstrndx", "e_shstrndx 超出节表范围")
    if e_shoff + e_shnum * SHDR_SIZE > len(data):
        raise fail("section_table_truncated", "节表超出文件边界")

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
            if sh_offset > len(data) or sh_size > len(data) - sh_offset:
                raise fail(
                    "section_out_of_bounds",
                    f"节 #{i} 数据区间 [{offset_hex(sh_offset)}, +{sh_size}) 超出文件边界",
                )
        sections.append(sec)

    shstr = sections[e_shstrndx]
    if shstr["type"] != SHT_STRTAB:
        raise fail("bad_shstrtab", "e_shstrndx 未指向 SHT_STRTAB")
    shstr_blob = data[shstr["offset"] : shstr["offset"] + shstr["size"]]
    for sec in sections:
        name = _read_cstr(shstr_blob, sec["name_off"]) if sec["index"] != 0 else ""
        if name is None:
            raise fail("bad_section_name", f"节 #{sec['index']} 的 sh_name 在节名字符串表中越界")
        sec["name"] = name

    text_indexes = [s["index"] for s in sections if s["name"] == ".text"]
    if len(text_indexes) != 1:
        raise fail("text_not_unique", f"必须存在唯一的 .text 节，实际找到 {len(text_indexes)} 个")
    text_sec = sections[text_indexes[0]]
    if text_sec["type"] != SHT_PROGBITS:
        raise fail("bad_text_type", ".text 节类型必须为 SHT_PROGBITS")
    align = text_sec["addralign"]
    # sh_addralign 合法值为 0 或 2 的正整数次幂
    if align != 0 and (align & (align - 1)) != 0:
        raise fail("bad_text_addralign", f".text 的 sh_addralign={align} 不是 0 或 2 的幂")
    if align == 0:
        align = 1
    text_bytes = bytes(data[text_sec["offset"] : text_sec["offset"] + text_sec["size"]])
    text_sha = hashlib.sha256(text_bytes).hexdigest()

    symtab_indexes = [s["index"] for s in sections if s["type"] == SHT_SYMTAB]
    if len(symtab_indexes) != 1:
        raise fail("symtab_not_unique", f"必须存在唯一的 SHT_SYMTAB，实际找到 {len(symtab_indexes)} 个")
    symtab = sections[symtab_indexes[0]]
    if symtab["link"] >= len(sections) or sections[symtab["link"]]["type"] != SHT_STRTAB:
        raise fail("bad_symtab_link", "符号表的 sh_link 未指向字符串表")
    if symtab["entsize"] not in (0, SYM_SIZE):
        raise fail("bad_sym_entsize", f"符号表表项尺寸必须为 24，实际 {symtab['entsize']}")
    if symtab["size"] % SYM_SIZE != 0:
        raise fail("bad_symtab_size", "符号表字节数不是 24 的整数倍")
    sym_count = symtab["size"] // SYM_SIZE
    if not (1 <= symtab["info"] <= sym_count):
        raise fail(
            "bad_symtab_info",
            f"符号表 sh_info（首个非局部符号索引）必须在 1..{sym_count} 范围内，实际 {symtab['info']}",
        )
    strtab = sections[symtab["link"]]
    strtab_blob = data[strtab["offset"] : strtab["offset"] + strtab["size"]]

    symbols: list[_Symbol] = []
    for sym_idx in range(1, sym_count):
        soff = symtab["offset"] + sym_idx * SYM_SIZE
        st_name, st_info, _st_other, st_shndx, st_value, _st_size = _unpack(
            _SYM_FMT, data, soff, f"符号 #{sym_idx}"
        )
        name = _read_cstr(strtab_blob, st_name)
        if name is None:
            raise fail(
                "bad_symbol_name",
                f"符号 #{sym_idx} 的 st_name={st_name} 在字符串表中越界或缺少 NUL",
                detail={"symbol_index": sym_idx},
            )
        symbols.append(
            _Symbol(
                index=sym_idx,
                name=name,
                bind=(st_info >> 4) & 0xF,
                shndx=st_shndx,
                value=st_value,
            )
        )

    # 成员导出表：绑定在本成员 .text 的 GLOBAL/WEAK 定义
    exports: dict[str, list[tuple[int, int]]] = {}
    # 同名但定义在非 .text 节的 GLOBAL/WEAK 定义（不能进入联合代码布局）
    non_code_exports: dict[str, list[tuple[int, int]]] = {}
    for sym in symbols:
        if sym.bind not in (STB_GLOBAL, STB_WEAK) or sym.shndx in (SHN_UNDEF,) or sym.shndx >= SHN_LORESERVE:
            continue
        if sym.shndx == text_sec["index"]:
            exports.setdefault(sym.name, []).append((sym.index, sym.value))
        else:
            non_code_exports.setdefault(sym.name, []).append((sym.index, sym.shndx))

    # RELA 节（允许成员不含任何重定位节——它可能只向其他成员提供定义）
    rela_sections = [s for s in sections if s["type"] in (SHT_RELA, SHT_REL)]
    for sec in rela_sections:
        if sec["type"] == SHT_REL:
            raise fail(
                "rel_unsupported",
                f"节 {sec['name'] or '#' + str(sec['index'])} 为 SHT_REL，仅接受带加数的 SHT_RELA",
            )
        if sec["info"] != text_sec["index"]:
            target = sections[sec["info"]]["name"] if sec["info"] < len(sections) else "?"
            raise fail(
                "rela_not_for_text",
                f"RELA 节 {sec['name'] or '#' + str(sec['index'])} 指向 {target or '#' + str(sec['info'])}，"
                "仅接受指向唯一 .text 的 RELA 节",
            )
        if sec["link"] != symtab["index"]:
            raise fail("bad_rela_link", f"RELA 节 {sec['name']} 的 sh_link 未指向符号表")
        if sec["entsize"] not in (0, RELA_SIZE):
            raise fail("bad_rela_entsize", f"RELA 节 {sec['name']} 表项尺寸必须为 24，实际 {sec['entsize']}")
        if sec["size"] % RELA_SIZE != 0:
            raise fail("bad_rela_size", f"RELA 节 {sec['name']} 字节数不是 24 的整数倍")

    entries: list[_RawEntry] = []
    for sec in sorted(rela_sections, key=lambda s: s["index"]):
        count = sec["size"] // RELA_SIZE
        for j in range(count):
            r_offset, r_info, r_addend = _unpack(
                _RELA_FMT,
                data,
                sec["offset"] + j * RELA_SIZE,
                f"RELA 项 {sec['name']}[{j}]",
            )
            entries.append(
                _RawEntry(
                    rela_section=sec["name"] or f"#{sec['index']}",
                    rela_index=j,
                    offset=r_offset,
                    sym_idx=r_info >> 32,
                    reloc_type=r_info & 0xFFFFFFFF,
                    addend=r_addend,
                )
            )

    return _ParsedMember(
        member=member_id,
        data=bytes(data),
        file_sha256=file_sha,
        text_index=text_sec["index"],
        section_count=len(sections),
        text_size=text_sec["size"],
        text_addralign=align,
        text_bytes=text_bytes,
        text_sha=text_sha,
        symbols=symbols,
        exports=exports,
        non_code_exports=non_code_exports,
        entries=entries,
    )


# ---------------------------------------------------------------------------
# 联合审计主流程
# ---------------------------------------------------------------------------


def joint_audit(
    load_base: int,
    members: list[tuple[str, bytes]],
    symbols: dict[str, int],
) -> JointResult:
    """执行多成员联合审计；任何违约都返回 ``ok=False`` 且无部分结论。"""
    try:
        return _joint_audit(load_base, members, symbols)
    except JoinViolation as exc:
        return JointResult(ok=False, violation=exc)


def _joint_audit(
    load_base: int,
    members: list[tuple[str, bytes]],
    symbols: dict[str, int],
) -> JointResult:
    # --- 请求级校验 -------------------------------------------------------
    if not (0 <= load_base <= UINT64_MAX):
        raise JoinViolation("request", "bad_base", "装载基址必须是 0..2^64-1 范围内的整数")
    if not isinstance(members, list) or not (MIN_MEMBERS <= len(members) <= MAX_MEMBERS):
        raise JoinViolation(
            "request",
            "bad_member_count",
            f"联合审计要求 {MIN_MEMBERS}..{MAX_MEMBERS} 个具名成员，实际 "
            f"{0 if not isinstance(members, list) else len(members)} 个",
        )
    seen_ids: set[str] = set()
    for member_id, _data in members:
        if not isinstance(member_id, str) or not _MEMBER_ID_RE.match(member_id or ""):
            raise JoinViolation(
                "request",
                "bad_member_id",
                f"非法成员标识：{member_id!r}（1..{MAX_MEMBER_ID_LEN} 字符，字母数字开头，仅含 . _ : -）",
            )
        if member_id in seen_ids:
            raise JoinViolation("request", "duplicate_member_id", f"成员标识重复：{member_id!r}")
        seen_ids.add(member_id)
    for name, addr in symbols.items():
        if not isinstance(name, str) or not name or "\x00" in name or len(name) > 255:
            raise JoinViolation("request", "bad_symbol_name", f"非法外部符号名：{name!r}")
        if not isinstance(addr, int) or not (0 <= addr <= UINT64_MAX):
            raise JoinViolation("request", "bad_symbol_addr", f"符号 {name!r} 地址非法")

    # --- 解析全部成员（任一结构违约即整组拒绝，且在布局之前）--------------
    parsed: list[_ParsedMember] = [_parse_member(mid, data) for mid, data in members]
    by_id = {p.member: p for p in parsed}

    # --- 稳定排序 + 连续布局 ---------------------------------------------
    ordered_ids = sorted(by_id)
    bases: dict[str, int] = {}
    cursor = load_base
    for pos, mid in enumerate(ordered_ids):
        p = by_id[mid]
        start = _align_up(cursor, p.text_addralign)
        end = start + p.text_size
        if end > 1 << 64 or end < start:
            raise JoinViolation(
                "layout",
                "layout_overflow",
                f"成员 {mid!r} 的 .text 布局区间 [{hex64(start)}, {hex64(end)}) 超出 64 位地址空间",
                member=mid,
            )
        bases[mid] = start
        cursor = end

    # 跨成员导出表：name -> 定义者列表（成员定义按标识、符号序号稳定排序）
    global_defs: dict[str, list[dict[str, Any]]] = {}
    for mid in ordered_ids:
        for name, defs in by_id[mid].exports.items():
            for sym_idx, value in defs:
                global_defs.setdefault(name, []).append(
                    {"member": mid, "symbol_index": sym_idx, "value": value}
                )
    for defs in global_defs.values():
        defs.sort(key=lambda d: (d["member"], d["symbol_index"]))

    # --- 第一阶段：成员内逐项独立校验（全局序号按排序后成员连续编号）------
    @dataclass
    class _Prepared:
        member: str
        index: int
        entry: _RawEntry
        width: int
        symbol_name: str
        symbol_index: int
        source: str
        source_member: str | None
        s: int
        p: int
        value: int

    prepared: list[_Prepared] = []
    referenced_external: set[str] = set()
    global_index = 0

    for mid in ordered_ids:
        p = by_id[mid]
        member_base = bases[mid]
        sym_by_idx = {s.index: s for s in p.symbols}

        for ent in p.entries:
            loc = dict(
                member=mid,
                entry_index=global_index,
                rela_section=ent.rela_section,
                rela_index=ent.rela_index,
                offset=ent.offset,
                reloc_type=ent.reloc_type,
            )

            def reject(code: str, message: str, **kw: Any) -> JoinViolation:
                return JoinViolation("entry", code, message, **loc, **kw)

            width = _RELOC_WIDTH.get(ent.reloc_type)
            if width is None:
                raise reject(
                    "unsupported_reloc_type",
                    f"不支持的重定位类型 {ent.reloc_type}，仅处理 R_X86_64_64(1) 与 R_X86_64_PC32(2)",
                )
            addend = ent.addend
            if not (INT64_MIN <= addend <= INT64_MAX):
                raise reject("bad_addend", "RELA 加数超出有符号 64 位范围")

            sym = sym_by_idx.get(ent.sym_idx)
            if sym is None:
                raise reject(
                    "bad_symbol_index",
                    f"r_info 符号索引 {ent.sym_idx} 越界（成员 {mid!r} 符号表共 {len(p.symbols) + 1} 项）",
                )
            loc["symbol"] = sym.name

            r_off = ent.offset
            if r_off > p.text_size or width > p.text_size - r_off:
                raise reject(
                    "write_out_of_range",
                    f"写入区间 [.text+0x{r_off:x}, {width}) 超出成员 {mid!r} 的 .text 边界"
                    f"（大小 {p.text_size} 字节）",
                )

            source = ""
            source_member: str | None = None
            if sym.shndx == SHN_UNDEF:
                # 只允许解析到：唯一的*其他成员*全局定义，或明确提供的外部地址
                all_text_defs = list(global_defs.get(sym.name, ()))
                other_defs = [d for d in all_text_defs if d["member"] != mid]
                self_defs = [d for d in all_text_defs if d["member"] == mid]
                non_code_defs: list[dict[str, Any]] = []
                for omid in ordered_ids:
                    for sidx, shndx in by_id[omid].non_code_exports.get(sym.name, ()):
                        non_code_defs.append(
                            {"member": omid, "symbol_index": sidx, "st_shndx": shndx}
                        )
                has_external = sym.name in symbols

                if non_code_defs:
                    raise reject(
                        "non_code_definition",
                        f"符号 {sym.name!r} 的定义位于非代码节，联合装载区仅布局各成员 .text，"
                        "无法推导其地址",
                        detail={"definers": non_code_defs},
                    )
                candidate_count = len(other_defs) + (1 if has_external else 0)
                if candidate_count == 0:
                    if self_defs:
                        raise reject(
                            "self_global_reference",
                            f"成员 {mid!r} 以 SHN_UNDEF 引用本成员已导出的全局符号 {sym.name!r}；"
                            "仅允许直接引用同成员 STB_LOCAL 定义、引用唯一其他成员全局定义或外部地址",
                        )
                    raise reject(
                        "unresolved_symbol",
                        f"成员 {mid!r} 第 {global_index} 项引用的符号 {sym.name!r} 未解析："
                        "既无其他成员的唯一全局定义，也未提供外部地址",
                    )
                if candidate_count > 1:
                    definers = [
                        {
                            "source": "member",
                            "member": d["member"],
                            "symbol_index": d["symbol_index"],
                            "st_value": offset_hex(d["value"]),
                        }
                        for d in other_defs
                    ]
                    if has_external:
                        definers.append({"source": "external", "address": hex64(symbols[sym.name])})
                    raise reject(
                        "duplicate_export",
                        f"符号 {sym.name!r} 存在 {candidate_count} 个可选定义，"
                        "同一装载区无法确定唯一解析，整组拒绝",
                        detail={"definers": definers},
                    )
                if has_external:
                    source = "external"
                    s_addr = symbols[sym.name]
                    referenced_external.add(sym.name)
                else:
                    d = other_defs[0]
                    source = "member"
                    source_member = d["member"]
                    owner = by_id[d["member"]]
                    if d["value"] > owner.text_size:
                        raise reject(
                            "symbol_value_out_of_section",
                            f"成员 {d['member']!r} 的全局符号 {sym.name!r} st_value="
                            f"0x{d['value']:x} 超出其 .text 范围",
                            detail={"definer_member": d["member"], "symbol_index": d["symbol_index"]},
                        )
                    s_addr = (bases[d["member"]] + d["value"]) & UINT64_MAX
            elif sym.shndx == p.text_index:
                # 同成员 .text 内的定义：仅允许 STB_LOCAL 直接引用
                if sym.bind != STB_LOCAL:
                    raise reject(
                        "global_direct_reference",
                        f"成员 {mid!r} 第 {global_index} 项直接引用的符号 {sym.name!r} 为全局绑定，"
                        "联合审计仅允许直接引用同成员的 STB_LOCAL 定义；跨成员引用须以 SHN_UNDEF 提交",
                    )
                if sym.value > p.text_size:
                    raise reject(
                        "symbol_value_out_of_section",
                        f"本地符号 {sym.name!r} 的 st_value=0x{sym.value:x} 超出 .text 范围",
                    )
                source = "local"
                s_addr = (member_base + sym.value) & UINT64_MAX
            elif sym.shndx >= SHN_LORESERVE or sym.shndx >= p.section_count:
                raise reject(
                    "unsupported_symbol_section",
                    f"符号 {sym.name!r} 的 st_shndx={sym.shndx} 为不受支持的特殊节索引",
                )
            else:
                raise reject(
                    "symbol_not_in_text",
                    f"符号 {sym.name!r} 定义在非代码节（st_shndx={sym.shndx}），"
                    "联合装载区只为各成员 .text 推导地址",
                )

            p_addr = (member_base + r_off) & UINT64_MAX
            if ent.reloc_type == R_X86_64_64:
                value = (s_addr + addend) & UINT64_MAX
            else:
                raw = (s_addr + addend - p_addr) & UINT64_MAX
                value = raw - (1 << 64) if raw >= (1 << 63) else raw
                if not (INT32_MIN <= value <= INT32_MAX):
                    raise reject(
                        "pc32_overflow",
                        "R_X86_64_PC32 计算值超出有符号 32 位范围，整组拒绝且不生成任何补丁",
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
                _Prepared(
                    member=mid,
                    index=global_index,
                    entry=ent,
                    width=width,
                    symbol_name=sym.name,
                    symbol_index=sym.index,
                    source=source,
                    source_member=source_member,
                    s=s_addr,
                    p=p_addr,
                    value=value,
                )
            )
            global_index += 1

    extra = set(symbols) - referenced_external
    if extra:
        raise JoinViolation(
            "request",
            "unexpected_symbol",
            f"提供了未被任何重定位项引用的外部符号地址：{sorted(extra)}",
            detail={"unexpected": sorted(extra)},
        )

    # --- 第二阶段：成员内补丁区间两两不得重叠（跨成员区间天然分离）-------
    for mid in ordered_ids:
        own = [e for e in prepared if e.member == mid]
        by_offset = sorted(own, key=lambda e: (e.entry.offset, e.index))
        for prev, cur in zip(by_offset, by_offset[1:]):
            prev_end = prev.entry.offset + prev.width
            if cur.entry.offset < prev_end:
                raise JoinViolation(
                    "entry",
                    "patch_overlap",
                    "成员内重定位写入区间互相重叠："
                    f"第 {cur.index} 项 (.text+0x{cur.entry.offset:x}, {cur.width}B) "
                    f"侵入第 {prev.index} 项 (.text+0x{prev.entry.offset:x}, {prev.width}B)",
                    member=mid,
                    entry_index=cur.index,
                    rela_section=cur.entry.rela_section,
                    rela_index=cur.entry.rela_index,
                    offset=cur.entry.offset,
                    reloc_type=cur.entry.reloc_type,
                    symbol=cur.symbol_name,
                    detail={
                        "conflicts_with": prev.index,
                        "previous_range": [
                            offset_hex(prev.entry.offset),
                            offset_hex(prev_end),
                        ],
                        "current_range": [
                            offset_hex(cur.entry.offset),
                            offset_hex(cur.entry.offset + cur.width),
                        ],
                    },
                )

    # --- 全部通过，原子落补丁 --------------------------------------------
    patched_blobs: dict[str, bytearray] = {mid: bytearray(by_id[mid].text_bytes) for mid in ordered_ids}
    items: list[JointItem] = []
    for prep in prepared:
        ent = prep.entry
        off = ent.offset
        width = prep.width
        blob = patched_blobs[prep.member]
        before = bytes(blob[off : off + width])
        if ent.reloc_type == R_X86_64_64:
            after = struct.pack("<Q", prep.value)
        else:
            after = struct.pack("<i", prep.value)
        blob[off : off + width] = after
        items.append(
            JointItem(
                member=prep.member,
                index=prep.index,
                rela_section=ent.rela_section,
                rela_index=ent.rela_index,
                reloc_type=ent.reloc_type,
                symbol_index=prep.symbol_index,
                symbol=prep.symbol_name,
                source=prep.source,
                source_member=prep.source_member,
                offset=off,
                width=width,
                s=prep.s,
                a=ent.addend,
                p=prep.p,
                value=prep.value,
                before=before,
                after=after,
            )
        )

    outcomes: list[MemberOutcome] = []
    for pos, mid in enumerate(ordered_ids):
        p = by_id[mid]
        start = bases[mid]
        patched = bytes(patched_blobs[mid])
        outcomes.append(
            MemberOutcome(
                member=mid,
                order=pos,
                file_sha256=p.file_sha256,
                text_size=p.text_size,
                text_addralign=p.text_addralign,
                start=start,
                end=start + p.text_size,
                text_sha256_before=p.text_sha,
                patched_sha256=hashlib.sha256(patched).hexdigest(),
                patched=patched,
                items=[it for it in items if it.member == mid],
            )
        )

    return JointResult(ok=True, load_base=load_base, members=outcomes, items=items)


def freeze_joint_conclusion(
    audit_id: str, result: JointResult, symbols: dict[str, int]
) -> str:
    """对通过的联合审计计算稳定冻结结论（SHA-256）。

    规范化时成员按标识排序，因此成员提交次序调换、标识与内容不变时，
    布局与冻结摘要完全相同。
    """
    if not result.ok:
        raise ValueError("失败联合审计不得生成冻结结论")
    order = {m.member: m.order for m in result.members}
    canonical = {
        "audit_id": audit_id,
        "verdict": "JOINT_PASS",
        "load_base": str(result.load_base),
        "symbols": {name: str(addr) for name, addr in sorted(symbols.items())},
        "members": [
            {
                "member": m.member,
                "order": m.order,
                "file_sha256": m.file_sha256,
                "text_size": m.text_size,
                "text_addralign": m.text_addralign,
                "base": str(m.start),
                "end": str(m.end),
                "text_sha256_before": m.text_sha256_before,
                "patched_sha256": m.patched_sha256,
            }
            for m in sorted(result.members, key=lambda m: m.order)
        ],
        "items": [
            {
                "member": it.member,
                "index": it.index,
                "type": it.reloc_type,
                "symbol": it.symbol,
                "symbol_index": it.symbol_index,
                "source": it.source,
                "source_member": it.source_member,
                "offset": str(it.offset),
                "width": it.width,
                "S": str(it.s),
                "A": str(it.a),
                "P": str(it.p),
                "value": str(it.value),
                "before": it.before.hex(),
                "after": it.after.hex(),
            }
            for it in sorted(result.items, key=lambda x: (order[x.member], x.offset, x.index))
        ],
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return hashlib.sha256(blob).hexdigest()
