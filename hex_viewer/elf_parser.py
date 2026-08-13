import struct

ET_NAMES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
EM_NAMES = {3: "EM_386", 62: "EM_X86_64"}
PT_NAMES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
    0x6474E553: "PT_GNU_PROPERTY",
}
SHT_NAMES = {
    0: "SHT_NULL",
    1: "SHT_PROGBITS",
    2: "SHT_SYMTAB",
    3: "SHT_STRTAB",
    4: "SHT_RELA",
    5: "SHT_HASH",
    6: "SHT_DYNAMIC",
    7: "SHT_NOTE",
    8: "SHT_NOBITS",
    9: "SHT_REL",
    10: "SHT_SHLIB",
    11: "SHT_DYNSYM",
    14: "SHT_INIT_ARRAY",
    15: "SHT_FINI_ARRAY",
    16: "SHT_PREINIT_ARRAY",
    17: "SHT_GROUP",
    18: "SHT_SYMTAB_SHNDX",
}


def decode_pflags(v):
    return f"{'R' if v & 4 else '-'}{'W' if v & 2 else '-'}{'E' if v & 1 else '-'}"


def decode_shflags(v):
    out = []
    if v & 0x1:
        out.append("WRITE")
    if v & 0x2:
        out.append("ALLOC")
    if v & 0x4:
        out.append("EXECINSTR")
    return "|".join(out) if out else "-"


def ident_display(raw):
    hexed = raw.hex(" ")
    ei_class = "64-bit" if raw[4] == 2 else "32-bit" if raw[4] == 1 else "?"
    ei_data = "little-endian" if raw[5] == 1 else "big-endian" if raw[5] == 2 else "?"
    return f"{hexed} ({ei_class}, {ei_data})"


ELF64_EHDR_FIELDS = [
    ("e_ident", "16s", ident_display),
    ("e_type", "H", ET_NAMES),
    ("e_machine", "H", EM_NAMES),
    ("e_version", "I", None),
    ("e_entry", "Q", None),
    ("e_phoff", "Q", None),
    ("e_shoff", "Q", None),
    ("e_flags", "I", None),
    ("e_ehsize", "H", None),
    ("e_phentsize", "H", None),
    ("e_phnum", "H", None),
    ("e_shentsize", "H", None),
    ("e_shnum", "H", None),
    ("e_shstrndx", "H", None),
]

ELF64_PHDR_FIELDS = [
    ("p_type", "I", PT_NAMES),
    ("p_flags", "I", decode_pflags),
    ("p_offset", "Q", None),
    ("p_vaddr", "Q", None),
    ("p_paddr", "Q", None),
    ("p_filesz", "Q", None),
    ("p_memsz", "Q", None),
    ("p_align", "Q", None),
]

ELF64_SHDR_FIELDS = [
    ("sh_name", "I", None),
    ("sh_type", "I", SHT_NAMES),
    ("sh_flags", "Q", decode_shflags),
    ("sh_addr", "Q", None),
    ("sh_offset", "Q", None),
    ("sh_size", "Q", None),
    ("sh_link", "I", None),
    ("sh_info", "I", None),
    ("sh_addralign", "Q", None),
    ("sh_entsize", "Q", None),
]


def parse_struct(data, base_offset, field_defs):
    fields = []
    values = {}
    offset = base_offset
    for name, fmt, decorator in field_defs:
        size = struct.calcsize("<" + fmt)
        raw = struct.unpack_from("<" + fmt, data, offset)[0]

        if fmt.endswith("s"):
            display = decorator(raw) if callable(decorator) else raw.hex(" ")
        else:
            display = f"0x{raw:x}"
            if callable(decorator):
                display += f" ({decorator(raw)})"
            elif isinstance(decorator, dict) and raw in decorator:
                display += f" ({decorator[raw]})"

        fields.append({"name": name, "offset": offset, "size": size, "value": raw, "display": display})
        values[name] = raw
        offset += size

    return fields, values


def read_cstr(data, offset):
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


def parse_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    if data[4] != 2:
        return None  # only ELF64 supported

    header_fields, header_values = parse_struct(data, 0, ELF64_EHDR_FIELDS)

    phoff = header_values["e_phoff"]
    phentsize = header_values["e_phentsize"]
    phnum = header_values["e_phnum"]
    shoff = header_values["e_shoff"]
    shentsize = header_values["e_shentsize"]
    shnum = header_values["e_shnum"]
    shstrndx = header_values["e_shstrndx"]

    program_headers = []
    for i in range(phnum):
        base = phoff + i * phentsize
        fields, values = parse_struct(data, base, ELF64_PHDR_FIELDS)
        program_headers.append(
            {
                "index": i,
                "type_name": PT_NAMES.get(values["p_type"], f"0x{values['p_type']:x}"),
                "entry_offset": base,
                "entry_size": phentsize,
                "seg_offset": values["p_offset"],
                "seg_filesz": values["p_filesz"],
                "fields": fields,
            }
        )

    shstr_data = b""
    if shnum and shstrndx < shnum:
        shstr_base = shoff + shstrndx * shentsize
        _, shstr_values = parse_struct(data, shstr_base, ELF64_SHDR_FIELDS)
        so, ss = shstr_values["sh_offset"], shstr_values["sh_size"]
        shstr_data = data[so : so + ss]

    section_headers = []
    for i in range(shnum):
        base = shoff + i * shentsize
        fields, values = parse_struct(data, base, ELF64_SHDR_FIELDS)
        name = read_cstr(shstr_data, values["sh_name"]) if shstr_data else ""
        section_headers.append(
            {
                "index": i,
                "name": name or f"<section {i}>",
                "entry_offset": base,
                "entry_size": shentsize,
                "seg_offset": values["sh_offset"],
                "seg_filesz": values["sh_size"],
                "fields": fields,
            }
        )

    return {
        "header": header_fields,
        "header_size": 64,
        "program_headers": program_headers,
        "section_headers": section_headers,
    }
