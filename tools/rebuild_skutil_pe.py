#!/usr/bin/env python3
"""Rebuild a loadable PE image of SilverKnit's SkUtil.exe from ``ida/skutil-dump.txt``.

The dump is ``dumpbin /RAWDATA`` output of the unpacked sections. This script
rebuilds a PE32 file that Ghidra (or any disassembler) can load with normal
section layout and imports, so the STP reader can be decompiled:

    python tools/rebuild_skutil_pe.py ida/skutil-dump.txt SkUtil_rebuilt.exe

Function addresses are listed in docs/REVERSE_ENGINEERING.md.
"""

import re
import struct
import sys

IMAGE_BASE = 0x400000
ENTRY_RVA = 0x2713C     # CRT start-up routine (SEH frame, GetVersion call)

# name, RVA, virtual size, has raw data, characteristics
# (names and sizes from the dumpbin summary; RVAs from the RAW DATA headers)
SECTIONS = [
    (".text",  0x001000, 0x027000, True,  0x60000020),
    (".bss",   0x028000, 0x126000, False, 0xC0000080),
    (".edata", 0x14E000, 0x001000, True,  0x40000040),
    (".data",  0x14F000, 0x005000, True,  0xC0000040),
    (".idata", 0x154000, 0x003000, True,  0xC0000040),
    (".rdata", 0x157000, 0x001000, True,  0x40000040),
    (".rsrc",  0x158000, 0x00B000, True,  0x40000040),
    (".reloc", 0x163000, 0x003000, True,  0x40000040),
]


def read_dump(path):
    mem = {}
    in_raw = False
    line_re = re.compile(r"\s+([0-9A-F]{8}): ((?:[0-9A-F]{2} ){1,16})")
    with open(path, encoding="latin-1") as f:
        for line in f:
            if line.startswith("RAW DATA #"):
                in_raw = True
                continue
            if line.strip() == "Summary":
                in_raw = False
            m = line_re.match(line) if in_raw else None
            if m:
                addr = int(m.group(1), 16)
                for i, b in enumerate(bytes.fromhex(m.group(2).replace(" ", ""))):
                    mem[addr + i] = b
    return mem


def build_pe(mem):
    def read(va, n):
        return bytes(mem.get(va + i, 0) for i in range(n))

    def u32(va):
        return struct.unpack("<I", read(va, 4))[0]

    # size of the import directory: descriptors up to the null entry
    pos = IMAGE_BASE + 0x154000
    count = 0
    while u32(pos + 12):
        pos += 20
        count += 1
    import_size = (count + 1) * 20

    header_size = 0x400
    file_off = header_size
    section_headers = b""
    body = b""
    for name, rva, vsize, has_raw, chars in SECTIONS:
        data = read(IMAGE_BASE + rva, vsize) if has_raw else b""
        raw_size = (len(data) + 0x1FF) & ~0x1FF
        data = data.ljust(raw_size, b"\0")
        section_headers += struct.pack(
            "<8sIIIIIIHHI", name.encode(), vsize, rva, raw_size,
            file_off if raw_size else 0, 0, 0, 0, 0, chars)
        body += data
        file_off += raw_size

    dirs = [(0, 0)] * 16
    dirs[0] = (0x14E000, 0x1000)       # export
    dirs[1] = (0x154000, import_size)  # import
    dirs[2] = (0x158000, 0xB000)       # resource
    dirs[5] = (0x163000, 0x3000)       # base relocation
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 6, 0, 0x27000, 0x10000, 0x126000, ENTRY_RVA, 0x1000, 0x28000,
        IMAGE_BASE, 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0, 0x166000, header_size,
        0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    optional += b"".join(struct.pack("<II", *d) for d in dirs)
    coff = struct.pack("<HHIIIHH", 0x14C, len(SECTIONS), 0, 0, 0,
                       len(optional), 0x010F)
    dos = b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40)
    header = (dos + b"PE\0\0" + coff + optional + section_headers)
    return header.ljust(header_size, b"\0") + body


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    image = build_pe(read_dump(argv[1]))
    with open(argv[2], "wb") as f:
        f.write(image)
    print("wrote {} ({} bytes)".format(argv[2], len(image)))


if __name__ == "__main__":
    main(sys.argv)
