#!/usr/bin/env python3
"""Turn a module image dumped from memory into a loadable PE file.

In memory every section sits at its virtual address, so the section table is
rewritten with ``PointerToRawData = VirtualAddress`` and ``SizeOfRawData =
VirtualSize``. Sections named in ``--drop`` (by default Themida's
``.themida``/``.boot``) are removed to keep the file small. ``--base`` sets
ImageBase to the address the module was loaded at (from modules.json), so
absolute addresses in the code match the dump.

    python tools/mem_to_pe.py dumps/dk9.exe.mem dk9_unpacked.exe --base 0x400000
"""

import argparse
import struct


def align(x, a):
    return (x + a - 1) & ~(a - 1)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("mem")
    ap.add_argument("out")
    ap.add_argument("--base", type=lambda s: int(s, 0))
    ap.add_argument("--entry", type=lambda s: int(s, 0),
                    help="new entry point RVA (default: keep)")
    ap.add_argument("--drop", nargs="*", default=[".themida", ".boot"])
    a = ap.parse_args(argv)

    img = bytearray(open(a.mem, "rb").read())
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    nsec = struct.unpack_from("<H", img, pe + 6)[0]
    optsize = struct.unpack_from("<H", img, pe + 20)[0]
    opt = pe + 24
    sec_table = opt + optsize

    sections = []
    for i in range(nsec):
        name, vsize, va, rsize, rptr, a1, a2, n1, n2, chars = struct.unpack_from(
            "<8sIIIIIIHHI", img, sec_table + 40 * i)
        if name.rstrip(b"\0").decode("latin-1") in a.drop:
            continue
        sections.append([name, vsize, va, chars])

    # sections in order; drop trailing sections after a dropped one is fine
    end = max(va + align(vsize, 0x1000) for _, vsize, va, _ in sections)
    out = bytearray(img[:end].ljust(end, b"\0"))
    struct.pack_into("<H", out, pe + 6, len(sections))
    for i, (name, vsize, va, chars) in enumerate(sections):
        size = align(vsize, 0x1000)
        if name.rstrip(b"\0") in (b"BSS", b".bss") or chars & 0x80:
            chars |= 0x40   # keep zero-filled data as initialized
        struct.pack_into("<8sIIIIIIHHI", out, sec_table + 40 * i,
                         name, size, va, size, va, 0, 0, 0, 0,
                         chars | 0x40000000)
    for i in range(len(sections), nsec):
        struct.pack_into("40s", out, sec_table + 40 * i, b"")
    # file alignment = section alignment, size of image
    struct.pack_into("<I", out, opt + 36, 0x1000)
    struct.pack_into("<I", out, opt + 56, end)
    if a.base is not None:
        struct.pack_into("<I", out, opt + 28, a.base)
    if a.entry is not None:
        struct.pack_into("<I", out, opt + 16, a.entry)
    # drop directories that point into removed sections (imports, relocs,
    # TLS, load config, IAT) - Themida rewrites them anyway
    ndirs = struct.unpack_from("<I", out, opt + 92)[0]
    for d in range(ndirs):
        rva, size = struct.unpack_from("<II", out, opt + 96 + 8 * d)
        if rva and not any(va <= rva < va + align(vs, 0x1000)
                           for _, vs, va, _ in sections):
            struct.pack_into("<II", out, opt + 96 + 8 * d, 0, 0)
        elif d in (1, 5, 9, 10, 12):   # import, reloc, TLS, load cfg, IAT
            struct.pack_into("<II", out, opt + 96 + 8 * d, 0, 0)
    open(a.out, "wb").write(out)
    print("wrote {} ({} bytes, {} sections)".format(a.out, len(out),
                                                   len(sections)))


if __name__ == "__main__":
    main()
