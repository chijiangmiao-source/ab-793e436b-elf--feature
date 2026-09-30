"""测试夹具：在内存中手工构造 ELF64 小端 ET_REL 文件，不依赖外部工具链。"""

from __future__ import annotations

import struct

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_REL = 9

ET_REL = 1
EM_X86_64 = 62

R_X86_64_64 = 1
R_X86_64_PC32 = 2

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_NOTYPE = 0
STT_SECTION = 3


def _align(pos: int, align: int) -> int:
    if align <= 1:
        return pos
    return (pos + align - 1) // align * align


def _strtab(strings: list[bytes]) -> tuple[bytes, dict[int, int]]:
    blob = b"\x00"
    offsets: dict[int, int] = {}
    for i, s in enumerate(strings):
        offsets[i] = len(blob)
        blob += s + b"\x00"
    return blob, offsets


def build_elf(
    *,
    text: bytes = b"\x90" * 32,
    symbols: list[tuple] | None = None,
    relocs: list[dict] | None = None,
    text_duplicate: bool = False,
    rodata: bytes | None = None,
    bss_size: int | None = None,
    rela_info: int | str | None = None,
    rela_type: int = SHT_RELA,
    second_rela: list[dict] | None = None,
    rela_bad_entsize: int | None = None,
    symtab_bad_entsize: int | None = None,
    e_type: int = ET_REL,
    e_machine: int = EM_X86_64,
    ei_class: int = 2,
    ei_data: int = 1,
    e_phoff: int = 0,
    shstrndx_valid: bool = True,
    text_addralign: int = 16,
) -> bytes:
    """构造一个最小化 ET_REL。

    symbols 每项为 ``(名称, 所属节, st_value)`` 或
    ``(名称, 所属节, st_value, bind)``；所属节为 0 表示 SHN_UNDEF，
    ``"text"`` / ``"rodata"`` 表示对应节索引，bind 默认为 STB_GLOBAL。
    relocs 每项为 ``{"offset","sym","type","addend"}``，sym 为 1 基符号序号
    （0 号为保留空符号）。
    """
    symbols = symbols or []
    relocs = relocs or []

    # ---- 节的逻辑布局：0=null, 1=.text[, 2=.text2], [.rodata], .strtab, .symtab, .rela.text, .shstrtab
    logical: list[dict] = []
    logical.append({"name": "", "type": 0})
    text_idx = len(logical)
    logical.append({"name": ".text", "type": SHT_PROGBITS, "data": text, "align": text_addralign})
    if text_duplicate:
        logical.append({"name": ".text", "type": SHT_PROGBITS, "data": b"\xc3", "align": 16})
    rodata_idx: int | None = None
    if rodata is not None:
        rodata_idx = len(logical)
        logical.append({"name": ".rodata", "type": SHT_PROGBITS, "data": rodata, "align": 1})
    if bss_size is not None:
        logical.append({"name": ".bss", "type": 8, "data": b"", "size_override": bss_size, "align": 16})
    strtab_idx = len(logical)
    logical.append({"name": ".strtab", "type": SHT_STRTAB, "data": b"", "align": 1})
    symtab_idx = len(logical)
    logical.append({"name": ".symtab", "type": SHT_SYMTAB, "data": b"", "align": 8})
    rela_idx = len(logical)
    logical.append({"name": ".rela.text", "type": rela_type, "data": b"", "align": 8})
    rela2_idx: int | None = None
    if second_rela is not None:
        rela2_idx = len(logical)
        logical.append({"name": ".rela.text.alt", "type": rela_type, "data": b"", "align": 8})
    shstr_idx = len(logical)
    logical.append({"name": ".shstrtab", "type": SHT_STRTAB, "data": b"", "align": 1})

    def resolve_shndx(desc: str | int) -> int:
        if isinstance(desc, int):
            return desc
        return {"text": text_idx, "rodata": rodata_idx}[desc]  # type: ignore[index]

    # ---- 字符串表 / 符号表
    # ELF 要求 STB_LOCAL 符号排在 sh_info 之前：局部符号按输入顺序前置，
    # 全局/弱符号按输入顺序随后；reloc 里的 sym 序号（基于 symbols 输入
    # 顺序，1 基）通过 sym_index_map 自动重映射，调用方无需感知。
    str_names = [s[0].encode("latin-1") for s in symbols]
    strtab_blob, str_offsets = _strtab(str_names)
    logical[strtab_idx]["data"] = strtab_blob

    parsed_syms: list[tuple[str, int, int, int]] = []
    for i, spec in enumerate(symbols):
        name = spec[0]
        sec_desc = spec[1]
        value = spec[2]
        bind = spec[3] if len(spec) > 3 else STB_GLOBAL
        parsed_syms.append((name, resolve_shndx(sec_desc), value, bind))

    local_specs = [(i, s) for i, s in enumerate(parsed_syms) if s[3] == STB_LOCAL]
    global_specs = [(i, s) for i, s in enumerate(parsed_syms) if s[3] != STB_LOCAL]
    ordered_specs = local_specs + global_specs
    sym_index_map = {orig_i + 1: new_i + 1 for new_i, (orig_i, _s) in enumerate(ordered_specs)}

    sym_blob = b"\x00" * 24
    for _orig_i, (name, shndx, value, bind) in ordered_specs:
        info = (bind << 4) | STT_NOTYPE
        sym_blob += struct.pack("<IBBHQQ", str_offsets[_orig_i], info, 0, shndx, value, 0)
    logical[symtab_idx]["data"] = sym_blob

    # ---- RELA / REL（sym 序号为输入顺序 1 基，按局部前置布局重映射）
    def encode_rela(relocs: list[dict]) -> bytes:
        blob = b""
        for r in relocs:
            mapped = sym_index_map.get(r["sym"], r["sym"])
            r_info = (mapped << 32) | (r["type"] & 0xFFFFFFFF)
            if rela_type == SHT_RELA:
                blob += struct.pack("<QQq", r["offset"], r_info, r.get("addend", 0))
            else:
                blob += struct.pack("<QQ", r["offset"], r_info)
        return blob

    logical[rela_idx]["data"] = encode_rela(relocs)
    if second_rela is not None:
        logical[rela2_idx]["data"] = encode_rela(second_rela)

    # ---- 节名字符串表
    shstr_blob = b"\x00"
    sh_name_offsets: dict[int, int] = {}
    for i, sec in enumerate(logical):
        sh_name_offsets[i] = 0
        if sec["name"]:
            sh_name_offsets[i] = len(shstr_blob)
            shstr_blob += sec["name"].encode() + b"\x00"
    logical[shstr_idx]["data"] = shstr_blob

    # ---- ELF 头 + 数据布局
    pos = 64
    for sec in logical[1:]:
        pos = _align(pos, sec.get("align", 1))
        sec["offset"] = pos
        sec["size"] = sec.get("size_override", len(sec["data"]))
        if sec["type"] != 8:  # SHT_NOBITS 不占文件空间
            pos += sec["size"]
    shoff = _align(pos, 8)

    # ---- 链接字段
    target = text_idx if rela_info is None else (resolve_shndx(rela_info) if isinstance(rela_info, str) else rela_info)
    logical[symtab_idx]["link"] = strtab_idx
    logical[symtab_idx]["info"] = len(local_specs) + 1  # STB_LOCAL 全部前置
    logical[symtab_idx]["entsize"] = symtab_bad_entsize if symtab_bad_entsize is not None else 24
    logical[rela_idx]["link"] = symtab_idx
    logical[rela_idx]["info"] = target
    logical[rela_idx]["entsize"] = (
        rela_bad_entsize if rela_bad_entsize is not None else (24 if rela_type == SHT_RELA else 16)
    )
    if second_rela is not None:
        logical[rela2_idx]["link"] = symtab_idx
        logical[rela2_idx]["info"] = target
        logical[rela2_idx]["entsize"] = 24 if rela_type == SHT_RELA else 16

    out = bytearray(shoff + len(logical) * 64)

    # ELF 头
    ei_ident = bytearray(16)
    ei_ident[0:4] = b"\x7fELF"
    ei_ident[4] = ei_class
    ei_ident[5] = ei_data
    ei_ident[6] = 1
    if ei_data == 2:  # 构造大端样本时使用大端打包
        ehdr = struct.pack(
            ">16sHHIQQQIHHHHHH",
            bytes(ei_ident), e_type, e_machine, 1, 0, e_phoff, shoff, 0, 64, 0, 0, 64, len(logical),
            shstr_idx if shstrndx_valid else 0xFFFF,
        )
    else:
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            bytes(ei_ident), e_type, e_machine, 1, 0, e_phoff, shoff, 0, 64, 0, 0, 64, len(logical),
            shstr_idx if shstrndx_valid else 0xFFFF,
        )
    out[0:64] = ehdr

    for sec in logical[1:]:
        out[sec["offset"] : sec["offset"] + sec["size"]] = sec["data"]

    # 节头（构造大端样本时使用大端打包）
    for i, sec in enumerate(logical):
        if i == 0:
            continue
        shdr = struct.pack(
            (">IIQQQQIIQQ" if ei_data == 2 else "<IIQQQQIIQQ"),
            sh_name_offsets[i],
            sec["type"],
            0,
            0,
            sec["offset"],
            sec["size"],
            sec.get("link", 0),
            sec.get("info", 0),
            sec.get("align", 1) if sec.get("align", 1) else 1,
            sec.get("entsize", 0),
        )
        out[shoff + i * 64 : shoff + (i + 1) * 64] = shdr

    return bytes(out)
