#!/usr/bin/env python3
"""Print record layouts from Borland TD32 debug information.

DesignaKnit's dk9a.dll carries TD32 debug info (signature ``FB09``) once
Themida has unpacked it in memory. Dump the module with
``tools/dump_process_modules.py`` first, then:

    python tools/td32_types.py dumps/dk9a.dll.mem tStitchPatternHeader tCable

Prints each member as ``offset size type name``. Only the subset of TD32
needed for record layouts is implemented: the names table (sstNames, 0x130),
the global types table (sstGlobalTypes, 0x12B), and the leaves for structures,
field lists, members, arrays, Pascal strings, sets, enums and pointers.
"""

import struct
import sys

BASIC = {
    0x03: ("void", 0), 0x10: ("char", 1), 0x11: ("short", 2), 0x12: ("long", 4),
    0x20: ("uchar", 1), 0x21: ("ushort", 2), 0x22: ("ulong", 4),
    0x30: ("bool", 1), 0x31: ("bool16", 2), 0x32: ("bool32", 4),
    0x40: ("single", 4), 0x41: ("double", 8), 0x42: ("extended", 10),
    0x44: ("real48", 6), 0x61: ("AnsiChar", 1),
    0x68: ("int8", 1), 0x69: ("uint8", 1), 0x70: ("char", 1), 0x71: ("wchar", 2),
    0x72: ("int16", 2), 0x73: ("uint16", 2), 0x74: ("int32", 4),
    0x75: ("uint32", 4), 0x76: ("int64", 8), 0x77: ("uint64", 8),
}


class TD32(object):
    def __init__(self, data):
        self.d = data
        base = data.find(b"FB09")
        while base >= 0:
            lfo = struct.unpack_from("<I", data, base + 4)[0]
            if base + lfo + 16 <= len(data):
                cbh, cbe, cdir = struct.unpack_from("<HHI", data, base + lfo)
                if cbh == 16 and cbe == 12 and 0 < cdir < 100000:
                    break
            base = data.find(b"FB09", base + 1)
        if base < 0:
            raise ValueError("no TD32 debug info found")
        self.base = base
        p = base + lfo
        cbh, cbe, cdir = struct.unpack_from("<HHI", data, p)
        self.sub = {}
        for i in range(cdir):
            s, imod, off, cb = struct.unpack_from("<HHII", data, p + cbh + cbe * i)
            self.sub.setdefault(s, []).append((base + off, cb))
        # names
        nm = self.sub[0x130][0][0]
        count = struct.unpack_from("<I", data, nm)[0]
        self.names = [None]
        q = nm + 4
        for _ in range(count):
            n = data[q]
            self.names.append(data[q + 1:q + 1 + n].decode("latin-1"))
            q += n + 2
        # types
        gt = self.sub[0x12B][0][0]
        ctype = struct.unpack_from("<I", data, gt + 4)[0]
        self.gt = gt
        self.offs = struct.unpack_from("<%dI" % ctype, data, gt + 8)

    def name(self, i):
        return self.names[i] if 0 < i < len(self.names) else "?%d" % i

    def rec(self, t):
        o = self.gt + self.offs[t - 0x1000]
        ln, leaf = struct.unpack_from("<HH", self.d, o)
        return leaf, self.d[o + 4:o + 2 + ln]

    @staticmethod
    def numeric(b, p):
        v = struct.unpack_from("<H", b, p)[0]
        if v < 0x8000:
            return v, p + 2
        fmt = {0x8000: "<b", 0x8001: "<h", 0x8002: "<H", 0x8003: "<i",
               0x8004: "<I"}[v]
        return struct.unpack_from(fmt, b, p + 2)[0], p + 2 + struct.calcsize(fmt)

    def find_struct(self, name):
        for k in range(len(self.offs)):
            leaf, r = self.rec(0x1000 + k)
            if leaf in (0x04, 0x05, 0x06):
                nidx = struct.unpack_from("<I", r, 20)[0]
                if self.name(nidx).split("@")[-1].lower() == name.lower():
                    return 0x1000 + k
        return None

    def describe(self, t):
        """Return (text, size) for a type index."""
        if t < 0x1000:
            n, s = BASIC.get(t & 0xFF, ("basic%#x" % t, None))
            if t & 0x0F00:
                return "ptr(" + n + ")", 4
            return n, s
        leaf, r = self.rec(t)
        if leaf in (0x04, 0x05, 0x06):
            size, _ = self.numeric(r, 24)
            return "record " + self.name(struct.unpack_from("<I", r, 20)[0]), size
        if leaf == 0x32:                         # array: elem, index, name, size, count
            elem, idx, nidx = struct.unpack_from("<III", r, 0)
            size, p = self.numeric(r, 12)
            lo, hi = self.subrange(idx)
            en = self.describe(elem)[0]
            if lo is None:
                return "array of %s" % en, size
            return "array[%s..%s] of %s" % (lo, hi, en), size
        if leaf == 0x33:                         # Pascal ShortString
            size, p = self.numeric(r, 12)
            return "string[%d]" % (size - 1), size
        if leaf == 0x31:                         # subrange: base, name, lo, hi, size
            lo, hi = self.subrange(t)
            size = self.subrange_size(t)
            nidx = struct.unpack_from("<I", r, 4)[0]
            label = self.name(nidx) if nidx else ""
            return ("%s %s..%s" % (label, lo, hi)).strip(), size
        if leaf == 0x07:                         # enum
            nidx = struct.unpack_from("<I", r, 8)[0]
            return "enum " + self.name(nidx), 1
        if leaf == 0x02:                         # pointer
            return "pointer", 4
        if leaf == 0x08:
            return "procedure", 4
        return "leaf%#x" % leaf, None

    def subrange(self, t):
        if t < 0x1000:
            return None, None
        leaf, r = self.rec(t)
        if leaf != 0x31:
            return None, None
        lo, p = self.numeric(r, 8)
        hi, p = self.numeric(r, p)
        return lo, hi

    def subrange_size(self, t):
        leaf, r = self.rec(t)
        lo, p = self.numeric(r, 8)
        hi, p = self.numeric(r, p)
        size, p = self.numeric(r, p)
        return size

    def members(self, t):
        leaf, r = self.rec(t)
        flist = struct.unpack_from("<I", r, 2)[0]
        size, _ = self.numeric(r, 24)
        leaf, fl = self.rec(flist)
        out = []
        p = 0
        while p < len(fl):
            sub = struct.unpack_from("<H", fl, p)[0]
            if sub == 0x0406:                     # member
                mtype, attr, nidx = struct.unpack_from("<IHI", fl, p + 2)
                off, q = self.numeric(fl, p + 16)
                out.append((off, mtype, self.name(nidx)))
                p = q
            else:
                raise ValueError("unexpected sub-leaf %#x at %d" % (sub, p))
            while p < len(fl) and fl[p] >= 0xF0:  # padding f1/f2/f3
                p += 1
        return size, out


def anonymous_record(td, t):
    """Return the type index of an anonymous record behind ``t`` (directly
    or as an array element), else None."""
    while t >= 0x1000:
        leaf, r = td.rec(t)
        if leaf in (0x04, 0x05, 0x06):
            return t if struct.unpack_from("<I", r, 20)[0] == 0 else None
        if leaf != 0x32:
            return None
        t = struct.unpack_from("<I", r, 0)[0]
    return None


def print_members(td, t, indent="  "):
    size, mem = td.members(t)
    for off, mt, mname in mem:
        desc, msize = td.describe(mt)
        print("%s%#06x %6s  %-28s %s" % (indent, off,
                                         "" if msize is None else hex(msize),
                                         mname, desc))
        sub = anonymous_record(td, mt)
        if sub is not None:
            print_members(td, sub, indent + "    ")


def main(argv):
    td = TD32(open(argv[1], "rb").read())
    for name in argv[2:]:
        t = td.find_struct(name)
        if t is None:
            print("== %s: not found" % name)
            continue
        size, mem = td.members(t)
        print("== %s (type %#x, size %#x)" % (name, t, size))
        print_members(td, t)


if __name__ == "__main__":
    main(sys.argv)
