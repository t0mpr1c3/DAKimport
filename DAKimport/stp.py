"""Reader for DesignaKnit ``.stp`` stitch pattern files (magic ``D7c``).

The file layout and the decryption algorithm are documented in
``docs/STP_FORMAT.md``. Field names follow DesignaKnit's own record
declarations (recovered from the debug information in dk9a.dll). In short,
an ``.stp`` file is::

    0x000  header: first 0xF8 bytes of the tStitchPattern record
    0x0F8  color pattern: chain of XOR-encrypted, run-length encoded blocks
    ....   stitch pattern: second chain of encrypted RLE blocks
    ....   color palette        71 x tPaltItem (25 bytes)
    ....   stitch palette       48 x 2 bytes
    ....   colour changer table patternrows x 6 bytes
    ....   note lines           u16 count + up to 10 Pascal strings
    ....   cables               StoredPatContainsCables x tCable (590 bytes)
    ....   stitch definitions   StoredPatContainsSymbDefs x tSymbDef (1270)
    ....   publication record   only if HasPubrec == ','
    ....   trace image record   only if HasTraceImage == 'd' (tOpdTrace)

The behaviour follows DesignaKnit 9's loader (dk9.exe 0x7CFBB0 and the
routines it calls). This module only needs the Python standard library;
``Pattern.color_image()`` uses Pillow if it is installed.
"""

import struct

__all__ = [
    "STPError", "Header", "Color", "StitchType", "CableDefinition",
    "StitchDefinition", "PubRec", "TraceImage", "Pattern", "read_stp",
    "parse_stp", "derive_xor_key", "decrypt_block_chain", "decode_rle",
]

MAGIC = b"D7c"
HEADER_SIZE = 0xF8
MAX_WIDTH = 2000         # limits checked by DesignaKnit 9's loader
MAX_HEIGHT = 3000
XOR_KEY_LENGTH = 21000   # 0x5208
COLOR_COUNT = 71         # 0x47
COLOR_ENTRY_SIZE = 25    # 0x19
COLOR_TABLE_SIZE = COLOR_COUNT * COLOR_ENTRY_SIZE   # 0x6EF
STITCH_TYPE_COUNT = 48   # 0x30
STITCH_TABLE_SIZE = STITCH_TYPE_COUNT * 2           # 0x60
ROW_YARN_SLOTS = 6
MAX_NOTE_LINES = 10
CABLE_RECORD_SIZE = 590      # 0x24E, tCable
STITCH_RECORD_SIZE = 1270    # 0x4F6, tSymbDef
PUBREC_HEADER_SIZE = 0x4D2   # tPubRecHeader
NOTATION_HEADER_SIZE = 0xCA  # tPubNotationHeader
MAX_NOTATIONS = 30
MAX_NOTATION_LINES = 8
TRACE_RECORD_SIZE = 0x148    # tOpdTrace
CABLE_FLAG = 0x40            # set in stitch-pattern cells that continue a cable

# CreatedOrSavedByDK89 thresholds used by the loader
VERSION_CABLES = 7           # cable records present from this version on
VERSION_CABLES_USED = 17     # ... but only interpreted from this version on
VERSION_SYMBDEFS = 16        # stitch definitions present from this version on
CURRENT_VERSION = 0x12       # value DesignaKnit 9 sets after loading

# ShortString limits of the first key-string concatenations. DesignaKnit 9
# uses the first set; the older code embedded in SilverKnit's SkUtil uses
# the second. They only differ for unusually long key strings.
KEY_CONCAT_LIMITS_DK9 = (0x06, 0x15, 0x24, 0x29, 0x38, 0x47)
KEY_CONCAT_LIMITS_SKUTIL = (0x6E, 0x7D, 0x8C, 0xAA, 0xB9, 0xC8)

TEXT_ENCODING = "cp1252"

_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1


class STPError(ValueError):
    """Raised when a file is not a valid ``.stp`` file."""


# --------------------------------------------------------------------------
# Little helpers
# --------------------------------------------------------------------------

def _u16(data, pos):
    return struct.unpack_from("<H", data, pos)[0]


def _i16(data, pos):
    return struct.unpack_from("<h", data, pos)[0]


def _u32(data, pos):
    return struct.unpack_from("<I", data, pos)[0]


def _i32(data, pos):
    return struct.unpack_from("<i", data, pos)[0]


def _need(data, pos, size, what):
    if pos < 0 or pos + size > len(data):
        raise STPError("file truncated while reading {} at offset {:#x}"
                       .format(what, pos))


def _pascal_bytes(data, pos, field_size=None):
    """Return the raw bytes of a Delphi ShortString (length byte + chars)."""
    length = data[pos]
    if field_size is not None:
        length = min(length, field_size - 1)
    return bytes(data[pos + 1:pos + 1 + length])


def _pascal(data, pos, field_size=None):
    return _pascal_bytes(data, pos, field_size).decode(TEXT_ENCODING, "replace")


def _cstr(data):
    """A fixed char array, NUL-terminated or space padded."""
    return bytes(data).split(b"\0", 1)[0].decode(TEXT_ENCODING, "replace").rstrip()


def _real48(b):
    """Decode a Turbo Pascal / Delphi Real48 (6 bytes)."""
    exp = b[0]
    if exp == 0:
        return 0.0
    mant = int.from_bytes(bytes(b[1:6]), "little")
    sign = -1.0 if mant & (1 << 39) else 1.0
    mant &= (1 << 39) - 1
    return sign * (1.0 + mant / float(1 << 39)) * 2.0 ** (exp - 129)


def _check_int32(value):
    # DesignaKnit is compiled with overflow checking; a file needing a larger
    # intermediate value could not have been written by it.
    if not _INT32_MIN <= value <= _INT32_MAX:
        raise STPError("integer overflow while deriving the decryption key")
    return value


def _trunc_mod(a, b):
    """``a mod b`` with the sign of ``a`` (x86 IDIV / Delphi semantics)."""
    r = abs(a) % abs(b)
    return -r if a < 0 else r


def _int_to_str(value):
    """Delphi ``Str(value)`` into a String[15]."""
    return str(value).encode("ascii")[:15]


def _append(dst, src, max_len):
    """Delphi ShortString concatenation truncated to ``max_len`` characters."""
    return (dst + src)[:max_len]


# --------------------------------------------------------------------------
# Decryption
# --------------------------------------------------------------------------

def _apply_legacy_salt_fixups(header):
    """Byte fix-ups SilverKnit's reader applies to 0x39/0x3A before deriving
    the key. DesignaKnit 9 does not do this; it is kept as an option for
    files from very early program versions."""
    h = bytearray(header)
    pair = bytes(h[0x39:0x3B])
    if pair == b"Su":
        h[0x3A] = ord("v")
    elif pair == b"Si":
        h[0x3A] = ord("h")
    elif pair == b"Jt":
        h[0x39] = ord("I")
        h[0x3A] = ord("u")
    return bytes(h)


def derive_xor_key(header, length=XOR_KEY_LENGTH,
                   concat_limits=KEY_CONCAT_LIMITS_DK9, legacy_fixups=False):
    """Derive the XOR key stream from the header's designer-protection
    fields (DesignerNum, PatternCollectionNumber, RandomNum,
    DesignerProtectionOptions, DesignersCustomerLicence, DesignerMessage).

    Mirrors DesignaKnit 9's routine at dk9.exe 0x5A1980, including signed
    16-bit reads, ShortString truncation and truncating division. Part of
    that routine is virtualised by Themida; see docs/STP_FORMAT.md.
    """
    if len(header) < 0xB1:
        raise STPError("header too short to derive the key")
    h = _apply_legacy_salt_fixups(header) if legacy_fixups else bytes(header)

    designer_num = _u32(h, 0x35)                 # read unsigned (SHR)
    collection = _i32(h, 0x39)
    random_num = _i16(h, 0x3D)                   # MOVSX: signed
    protection = _u16(h, 0x3F)
    currentver = h[0x20]

    key = _check_int32((designer_num >> 1) + (protection << 2))
    key = _check_int32(key + collection)
    key = _check_int32(key + random_num)
    key = _check_int32(key + currentver)

    salt1 = _u32(h, 0x39) & 0xFFFF
    salt2 = min(1, designer_num & 0xFFF)

    licence = _pascal_bytes(h, 0x41)
    message = _pascal_bytes(h, 0x60)
    l1, l2, l3, l4, l5, l6 = concat_limits
    ks = message
    ks = _append(ks, licence, l1)
    ks = _append(ks, _int_to_str(random_num), l2)
    ks = _append(ks, _int_to_str(currentver), l3)
    ks = _append(ks, licence, l4)
    ks = _append(ks, _int_to_str(currentver), l5)
    ks = _append(ks, _int_to_str(random_num), l6)

    for i in range(1, len(ks) + 1):
        b = ks[i - 1] >> 1
        r = i % 3
        if r == 0:
            key = _check_int32(key + i * b + (salt2 + b) // 7)
        elif r == 1:
            key = _check_int32(key + (b // 5) * protection + i * salt2 + b * 6)
        else:
            key = _check_int32(key + i * salt1 + b * 4)

    ks = _int_to_str(_check_int32(key * 3))
    for mult, max_len in ((1, 0x1E), (4, 0x2D), (2, 0x3C), (5, 0x4B),
                          (6, 0x5A), (8, 0x69), (7, 0x78)):
        ks = _append(ks, _int_to_str(_check_int32(key * mult)), max_len)

    n = len(ks)
    out = bytearray(length)
    for i in range(1, length + 1):
        out[i - 1] = (_trunc_mod(key, i) & 0xFF) ^ ks[i % n]
    return bytes(out)


class Block(object):
    """One encrypted block of a pattern chain."""

    __slots__ = ("end_row", "offset", "data")

    def __init__(self, end_row, offset, data):
        self.end_row = end_row   # last row (1-based) covered by this block
        self.offset = offset     # file offset of the block header
        self.data = data         # decrypted RLE bytes

    def __repr__(self):
        return "Block(end_row={}, offset={:#x}, size={})".format(
            self.end_row, self.offset, len(self.data))


def decrypt_block_chain(data, pos, height, key):
    """Decrypt one chain of blocks starting at ``pos``.

    Each block is ``int16 end_row, int16 size, size bytes``; every block is
    XORed with the key from its first byte. The chain ends with the block
    whose ``end_row`` equals ``height``. Returns ``(blocks, next_pos)``.
    """
    blocks = []
    prev = 0
    while prev != height:
        _need(data, pos, 4, "block header")
        end_row = _i16(data, pos)
        size = _i16(data, pos + 2)
        if end_row > height or end_row <= prev:
            raise STPError("bad block row {} at {:#x}".format(end_row, pos))
        if not 0 <= size <= len(key):
            raise STPError("bad block size {} at {:#x}".format(size, pos))
        _need(data, pos + 4, size, "block data")
        raw = data[pos + 4:pos + 4 + size]
        blocks.append(Block(end_row, pos,
                            bytes(b ^ k for b, k in zip(raw, key))))
        pos += 4 + size
        prev = end_row
    return blocks, pos


def decode_rle(blocks, width, height, warnings=None):
    """Decode a block chain into ``height`` rows of ``width`` byte values.

    As in DesignaKnit, a byte below 0x7F is a single value and any other
    byte is a repeat count (``b & 0x7F``) for the byte that follows. Rows
    never span blocks.
    """
    rows = []
    start = 0
    for bi, block in enumerate(blocks):
        buf = block.data
        pos = 0
        for row in range(start, block.end_row):
            out = bytearray()
            while len(out) < width:
                if pos >= len(buf):
                    raise STPError("row {} is truncated".format(row))
                value = buf[pos]
                pos += 1
                count = 1
                if value >= 0x7F:
                    count = value & 0x7F
                    if pos >= len(buf):
                        raise STPError("row {} is truncated".format(row))
                    value = buf[pos]
                    pos += 1
                out.extend(bytes((value,)) * count)
            if len(out) != width:
                raise STPError("row {} overruns the pattern width".format(row))
            rows.append(bytes(out))
        if pos != len(buf) and warnings is not None:
            warnings.append("block {} has {} unused bytes".format(
                bi, len(buf) - pos))
        start = block.end_row
    if len(rows) != height:
        raise STPError("pattern has {} rows, expected {}".format(len(rows), height))
    return rows


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

class _Record(object):
    _fields = ()

    def as_dict(self):
        return dict((f, getattr(self, f)) for f in self._fields)

    def __repr__(self):
        return "{}({})".format(type(self).__name__, ", ".join(
            "{}={!r}".format(f, getattr(self, f)) for f in self._fields))


# Header fields: (attribute, offset, kind, DesignaKnit name)
# kinds: B=byte, h=int16, H=uint16, i=int32, f=single, s<N>=ShortString in an
# N-byte field, c<N>=char array, a<N>=byte array
_HEADER_FIELDS = (
    ("stitchmem", 0x03, "h", "stitchmem"),
    ("rowmem", 0x05, "h", "rowmem"),
    ("width", 0x07, "h", "patternstitches"),
    ("height", 0x09, "h", "patternrows"),
    ("xrepeats", 0x0B, "h", "xrepeats"),
    ("yrepeats", 0x0D, "h", "yrepeats"),
    ("sel_x1", 0x0F, "h", "SelX1"),
    ("sel_x2", 0x11, "h", "SelX2"),
    ("sel_y1", 0x13, "h", "SelY1"),
    ("sel_y2", 0x15, "h", "SelY2"),
    ("box_y1", 0x17, "h", "BoxY1"),
    ("box_y2", 0x19, "h", "BoxY2"),
    ("cable_count", 0x1B, "h", "StoredPatContainsCables"),
    ("stitch_def_count", 0x1D, "h", "StoredPatContainsSymbDefs"),
    ("main_colour", 0x1F, "B", "PatMainColour"),
    ("currentver", 0x20, "B", "currentver"),
    ("palt_paint_lmb", 0x21, "B", "PaltPaintLMB"),
    ("palt_paint_mmb", 0x22, "B", "PaltPaintMMB"),
    ("palt_paint_rmb", 0x23, "B", "PaltPaintRMB"),
    ("stitch_paint_lmb", 0x24, "B", "StitchPaintLMB"),
    ("stitch_paint_mmb", 0x25, "B", "StitchPaintMMB"),
    ("stitch_paint_rmb", 0x26, "B", "StitchPaintRMB"),
    ("dragged_colway", 0x27, "B", "DraggedColWay"),
    ("modified_since_cway", 0x28, "B", "ModifiedSinceCway"),
    ("juggled_colway", 0x29, "B", "JuggledColway"),
    ("cway_stored_for_over4needles", 0x2A, "B", "cwayStoredForOver4needles"),
    ("cut_and_sew", 0x2B, "B", "CutAndSew"),
    ("cway_method", 0x2C, "B", "cwayMethod"),
    ("cway_stored_for_method", 0x2D, "B", "cwayStoredForMethod"),
    ("stitch_font_number", 0x2E, "B", "StitchFontNumber"),
    ("num_note_lines", 0x2F, "B", "NumNoteLines"),
    ("has_stitch_pattern", 0x30, "B", "HasStitchPattern"),
    ("spalt_priority", 0x31, "B", "SPaltPriority"),
    ("grid_intervals_centred", 0x32, "B", "xxxGridIntervalsCentred"),
    ("spbyte5", 0x33, "B", "spbyte5"),
    ("spbyte6", 0x34, "B", "spbyte6"),
    ("designer_num", 0x35, "i", "DesignerNum"),
    ("pattern_collection_number", 0x39, "i", "PatternCollectionNumber"),
    ("random_num", 0x3D, "h", "RandomNum"),
    ("designer_protection_options", 0x3F, "H", "DesignerProtectionOptions"),
    ("designers_customer_licence", 0x41, "s31", "DesignersCustomerLicence"),
    ("designer_message", 0x60, "s81", "DesignerMessage"),
    ("hacked_licence", 0x9C, "B", "HackedLicenceStp"),
    ("palt_cols_y", 0x9D, "B", "PaltColsY"),
    ("palt_cols_s", 0x9E, "B", "PaltColsS"),
    ("palt_cols_ys", 0x9F, "B", "PaltColsYS"),
    ("palt_rows_y", 0xA0, "B", "PaltRowsY"),
    ("palt_rows_s", 0xA1, "B", "PaltRowsS"),
    ("palt_rows_ys", 0xA2, "B", "PaltRowsYS"),
    ("cway_stored_for_cc_type", 0xA3, "B", "CwayStoredForCcType"),
    ("cway_stored_for_cc_used", 0xA4, "B", "CwayStoredForCcUsed"),
    ("cway_stored_for_preselect", 0xA5, "B", "CwayStoredForPreselect"),
    ("font_name", 0xB1, "c32", "FontNameVer7"),
    ("best_guess_jacq_seq", 0xD1, "a6", "BestGuessJacqSeq"),
    ("srds_dat_file", 0xD7, "B", "SRDS_Dat_File"),
    ("version", 0xD8, "B", "CreatedOrSavedByDK89"),
    ("sd_h_ruler_x", 0xD9, "f", "SDhRulerX"),
    ("sd_h_ruler_y", 0xDD, "f", "SDhRulerY"),
    ("sd_v_ruler_x", 0xE1, "f", "SDvRulerX"),
    ("sd_v_ruler_y", 0xE5, "f", "SDvRulerY"),
    ("start_hknitting_at_left", 0xE9, "B", "StartHKnittingAtLeft"),
    ("circular_not_flat", 0xEA, "B", "CircularNotFlat"),
    ("main_back_symbol_type", 0xEB, "B", "MainBackSymbolType"),
    ("start_hknitting_wrong_side", 0xEC, "B", "StartHKnittingWrongSide"),
    ("has_colour_pattern", 0xED, "B", "HasColourPattern"),
    ("stp_use_changer", 0xEE, "B", "StpUseChanger"),
    ("has_pubrec", 0xEF, "B", "HasPubrec"),
    ("e6000_tech_num", 0xF0, "h", "E6000techNumStp"),
    ("e8000_tech_num", 0xF2, "h", "E8000techNumStp"),
    ("has_trace_image", 0xF4, "B", "HasTraceImage"),
    ("spare_bytes", 0xF5, "a3", "SpareBytes"),
)


class Header(_Record):
    """The 0xF8-byte file header, i.e. the start of DesignaKnit's
    ``tStitchPattern`` record. ``raw`` keeps every byte; ``FIELDS`` maps
    attribute names to offsets and DesignaKnit's own field names."""

    FIELDS = _HEADER_FIELDS
    _fields = tuple(f[0] for f in _HEADER_FIELDS)

    def __init__(self, raw):
        self.raw = r = bytes(raw[:HEADER_SIZE])
        self.magic = r[0:3]
        for name, off, kind, _ in _HEADER_FIELDS:
            if kind == "B":
                v = r[off]
            elif kind in "hHi":
                v = struct.unpack_from("<" + kind, r, off)[0]
            elif kind == "f":
                v = struct.unpack_from("<f", r, off)[0]
            elif kind[0] == "s":
                v = _pascal(r, off, int(kind[1:]))
            elif kind[0] == "c":
                v = _cstr(r[off:off + int(kind[1:])])
            else:
                v = bytes(r[off:off + int(kind[1:])])
            setattr(self, name, v)

    @property
    def background_color_index(self):
        """PatMainColour; SilverKnit treats 0 as ' ' (0x20)."""
        return self.main_colour or 0x20

    @property
    def stores_cables(self):
        return self.version >= VERSION_CABLES

    @property
    def stores_stitch_definitions(self):
        return self.version >= VERSION_SYMBDEFS


class Color(_Record):
    """A ``tPaltItem`` (25 bytes). The entry index is the pattern value."""

    _fields = ("index", "flags", "symbol", "temp_flag", "number", "memo",
               "texture", "rgb", "name")

    def __init__(self, index, raw):
        self.index = index
        self.raw = bytes(raw)
        self.flags = raw[0]        # 0x10: colour in use
        self.symbol = raw[1]       # yarn symbol shown in the yarn box
        self.temp_flag = raw[2]    # TempFlag
        self.number = raw[3]       # PosnInWbox: position in the yarn box
        self.memo = raw[4]
        self.texture = raw[5]
        self.rgb = (raw[6], raw[7], raw[8])
        self.name = _pascal(raw, 9, 16)   # ColourName: string[15]

    @property
    def defined(self):
        return bool(self.flags & 0x10)

    @property
    def key(self):  # backward-compatible name for ``symbol``
        return self.symbol


class StitchType(_Record):
    """An entry of the 48-entry stitch palette (``SPchar``, ``SPflags``).
    Stitch-pattern cell values 1..48 select entry ``value - 1``."""

    _fields = ("index", "symbol", "flags")

    def __init__(self, index, symbol, flags):
        self.index = index
        self.symbol = symbol
        self.flags = flags

    @property
    def defined(self):
        return self.symbol != 0


class CableDefinition(_Record):
    """A ``tCable`` record (590 bytes)."""

    _fields = ("id", "standard_number", "width", "front", "back", "flags",
               "abbrev_suffix", "used", "code", "source", "name",
               "abbreviation", "temp_byte", "alert_sound_type",
               "instruction1", "instruction2")

    def __init__(self, raw):
        self.raw = bytes(raw)
        self.width = raw[0]            # TotalCrossingWd
        self.front = raw[1]            # FrontCable
        self.back = raw[2]             # BackCable (0: purl background)
        self.flags = raw[3]            # bit 0: back/right cross
        self.abbrev_suffix = raw[4]    # AbbrevSuffix
        self.used = raw[5]             # Used_Cabl
        self.code = _pascal(raw, 0x06, 9)          # TextureResource
        self.source = _pascal(raw, 0x0F, 11)       # CableSource, e.g. [DK9]
        self.name = _pascal(raw, 0x1A, 41)         # CableID
        self.standard_number = _i16(raw, 0x44)     # StandardCableNumber
        self.id = _i16(raw, 0x46)                  # cseq: id used in pattern
        self.abbreviation = _pascal(raw, 0x48, 9)  # Abbrevn
        self.temp_byte = raw[0x51]
        self.alert_sound_type = raw[0x52]
        self.instruction1 = _pascal(raw, 0x58, 201)
        self.instruction2 = _pascal(raw, 0x121, 201)

    @property
    def description(self):
        return " ".join(s for s in (self.instruction1, self.instruction2) if s)

    @property
    def crosses_right(self):
        return bool(self.flags & 1)

    @property
    def purl_centre(self):
        """Whether the centre stitches of a crossover are purled."""
        return not 2 <= (self.flags >> 4) <= 3

    def knit_purl(self):
        """Return the cable as ``'K'``/``'P'`` per stitch, the way the
        reference readers render it."""
        w, n1, n2 = self.width, self.front, self.back
        if n2 == 0:
            if self.crosses_right:
                return "K" * n1 + "P" * (w - n1)
            return "P" * (w - n1) + "K" * n1
        if n1 + n2 >= w or not self.purl_centre:
            return "K" * w
        mid = "P" * (w - n1 - n2)
        if self.crosses_right:
            return "K" * n1 + mid + "K" * n2
        return "K" * n2 + mid + "K" * n1


SYMBDEF_SLOTS = ("hand_rs_knit", "hand_ws_purl", "hand_rs_purl",
                 "hand_ws_knit", "machine")


class StitchDefinition(_Record):
    """A ``tSymbDef`` record (1270 bytes): abbreviation and instruction for
    one stitch symbol, in five variants (``SYMBDEF_SLOTS``): hand knitting
    right side / wrong side for knit- and purl-side views, and machine."""

    _fields = ("symbol", "abbreviations", "instructions")

    def __init__(self, raw):
        self.raw = bytes(raw)
        self.symbol = raw[0]                       # smAscii
        self.abbreviations = [_pascal(raw, 0x01 + 21 * i, 21) for i in range(5)]
        self.instructions = [_pascal(raw, 0x6A + 225 * i, 225) for i in range(5)]

    @property
    def descriptions(self):  # backward-compatible name
        return self.instructions

    def abbreviation(self, slot):
        return self.abbreviations[SYMBDEF_SLOTS.index(slot)]

    def instruction(self, slot):
        return self.instructions[SYMBDEF_SLOTS.index(slot)]


class Notation(_Record):
    """One notation of a publication record (``tPubNotationHeader`` plus
    its text lines)."""

    _fields = ("feature", "font_name", "font_size", "lines")

    def __init__(self, raw, lines):
        self.raw = bytes(raw)
        self.feature = raw[0]
        self.font_name = _pascal(raw, 0x01, 81)
        self.font_size = _i16(raw, 0x52)
        self.num_text_lines = _i16(raw, 0x5E)
        self.line_bytes = list(struct.unpack_from("<8h", raw, 0x88))
        self.lines = lines


class PubRec(_Record):
    """Publication record (``tPubRec``): notations drawn on the chart."""

    _fields = ("has_unicode", "shape_fn", "notations")

    def __init__(self, header, notations):
        self.raw_header = bytes(header)
        self.has_unicode = header[0x1C]
        self.num_notations = header[0x1D]
        self.shape_fn = _cstr(header[0x21:0x21 + 1001])
        self.notations = notations


class TraceImage(_Record):
    """``tOpdTrace``: an image traced under the chart."""

    _fields = ("file_name", "mid_x_mm", "mid_y_mm", "width_mm", "height_mm",
               "brightness", "tint", "quality", "image_type")

    def __init__(self, raw):
        self.raw = bytes(raw)
        self.file_name = _pascal(raw, 0, 256)
        self.mid_x_mm = _real48(raw[0x100:0x106])
        self.mid_y_mm = _real48(raw[0x106:0x10C])
        self.width_mm = _real48(raw[0x10C:0x112])
        self.height_mm = _real48(raw[0x112:0x118])
        self.brightness = raw[0x118]
        self.tint = raw[0x119]
        self.quality = raw[0x11A]
        self.image_type = raw[0x11B]


class Cell(object):
    """A resolved stitch-pattern cell (see ``Pattern.stitch_cells``)."""

    __slots__ = ("stitch", "cable", "cable_offset")

    def __init__(self, stitch=None, cable=None, cable_offset=0):
        self.stitch = stitch              # StitchType or None
        self.cable = cable                # CableDefinition or None
        self.cable_offset = cable_offset  # 0 = first stitch of the cable

    def __repr__(self):
        if self.cable is not None:
            return "Cell(cable={}, offset={})".format(self.cable.id,
                                                      self.cable_offset)
        return "Cell(stitch={})".format(
            None if self.stitch is None else self.stitch.index)


# --------------------------------------------------------------------------
# Pattern
# --------------------------------------------------------------------------

class Pattern(object):
    """A parsed ``.stp`` file.

    Rows are stored in file order: row 0 is the first knitted (bottom) row.
    """

    def __init__(self):
        self.header = None
        self.width = 0
        self.height = 0
        self.color_blocks = []
        self.stitch_blocks = []
        self.color_pattern = []    # list of rows (bytes), values = color index
        self.stitch_pattern = []   # list of rows (bytes), raw stitch codes
        self.colors = []           # 71 Color entries
        self.stitch_types = []     # 48 StitchType entries
        self.row_yarns = []        # per row: 6 raw colour changer bytes
        self.notes = []            # note lines (up to 10)
        self.cables = []
        self.stitch_definitions = []
        self.pubrec = None
        self.trace_image = None
        self.warnings = []
        self.offsets = {}

    @property
    def strings(self):  # backward-compatible name for ``notes``
        return self.notes

    # ---- convenience views ----------------------------------------------

    def used_colors(self):
        """Sorted color indices that occur in the color pattern."""
        seen = set()
        for row in self.color_pattern:
            seen.update(row)
        return sorted(seen)

    def color_of(self, value):
        return self.colors[value]

    def cable_by_id(self, cable_id):
        for cable in self.cables:
            if cable.id == cable_id:
                return cable
        return None

    def stitch_definition(self, symbol):
        for d in self.stitch_definitions:
            if d.symbol == symbol:
                return d
        return None

    def row_yarn_slots(self, row):
        """Return ``[(color_index, active), ...]`` for a row's colour changer
        slots. Bit 7 marks a yarn that is loaded but does not knit in that
        row. Empty slots (0) are skipped. Only meaningful when the pattern
        was set up for a colour changer; other files hold stale bytes."""
        out = []
        for b in self.row_yarns[row]:
            if b:
                out.append((b & 0x7F, not b & 0x80))
        return out

    def stitch_cells(self):
        """Resolve the stitch pattern into ``Cell`` objects.

        A cable occupies ``width`` consecutive cells of one row: the first
        cell holds the low 6 bits of the cable id; the following cells have
        bit 6 (0x40) set, and the first of them holds the high bits of the
        id in its low 6 bits. In repeat patterns a cable may wrap from the
        end of a row to its start.
        """
        grid = []
        for r, row in enumerate(self.stitch_pattern):
            w = len(row)
            cells = [None] * w
            for i in range(w):
                v = row[i]
                nxt = row[(i + 1) % w]
                if v & CABLE_FLAG or not nxt & CABLE_FLAG:
                    continue
                cid = v | ((nxt & 0x3F) << 6)
                cable = self.cable_by_id(cid)
                if cable is None:
                    raise STPError("row {} col {}: unknown cable id {}"
                                   .format(r, i, cid))
                for k in range(cable.width):
                    j = (i + k) % w
                    if k and not row[j] & CABLE_FLAG:
                        raise STPError("row {} col {}: cable {} is cut short"
                                       .format(r, j, cid))
                    cells[j] = Cell(cable=cable, cable_offset=k)
            for i in range(w):
                if cells[i] is not None:
                    continue
                v = row[i]
                if v & CABLE_FLAG:
                    raise STPError("row {} col {}: stray cable cell".format(r, i))
                if not 1 <= v <= len(self.stitch_types):
                    raise STPError("row {} col {}: bad stitch value {}"
                                   .format(r, i, v))
                cells[i] = Cell(stitch=self.stitch_types[v - 1])
            grid.append(cells)
        return grid

    def rgb_rows(self, top_down=True):
        """Return the color pattern as rows of ``(r, g, b)`` tuples."""
        rows = self.color_pattern[::-1] if top_down else self.color_pattern
        return [[self.colors[v].rgb for v in row] for row in rows]

    def color_image(self):
        """Return the color pattern as a ``PIL.Image`` (top row first)."""
        from PIL import Image
        img = Image.new("RGB", (self.width, self.height))
        img.putdata([px for row in self.rgb_rows() for px in row])
        return img

    def summary(self):
        h = self.header
        return {
            "width": self.width,
            "height": self.height,
            "repeats": [h.xrepeats, h.yrepeats],
            "cway_method": h.cway_method,
            "version": h.version,
            "colors_used": [
                {"index": i, "symbol": chr(i), "name": self.colors[i].name,
                 "rgb": "#%02x%02x%02x" % self.colors[i].rgb}
                for i in self.used_colors()],
            "stitch_types": [
                {"index": s.index + 1, "symbol": s.symbol, "flags": s.flags}
                for s in self.stitch_types if s.defined],
            "cables": [{"id": c.id, "code": c.code, "name": c.name,
                        "abbreviation": c.abbreviation} for c in self.cables],
            "stitch_definitions": [
                {"symbol": d.symbol,
                 "abbreviations": dict(zip(SYMBDEF_SLOTS, d.abbreviations)),
                 "instructions": dict(zip(SYMBDEF_SLOTS, d.instructions))}
                for d in self.stitch_definitions],
            "notes": self.notes,
            "warnings": self.warnings,
        }


def parse_stp(data, concat_limits=KEY_CONCAT_LIMITS_DK9, legacy_fixups=False):
    """Parse the bytes of an ``.stp`` file and return a ``Pattern``.

    The section order and the conditions under which optional sections are
    present follow DesignaKnit 9's loader.
    """
    data = bytes(data)
    if len(data) < HEADER_SIZE:
        raise STPError("file is too short for an .stp header")
    if data[0:3] != MAGIC:
        raise STPError("not an .stp file (magic {!r})".format(data[0:3]))

    p = Pattern()
    p.header = hdr = Header(data)
    p.width, p.height = hdr.width, hdr.height
    if not 0 < p.width <= MAX_WIDTH or not 0 < p.height <= MAX_HEIGHT:
        raise STPError("unsupported pattern size {}x{}".format(p.width, p.height))
    if (hdr.stitchmem, hdr.rowmem) != (p.width, p.height):
        p.warnings.append("stitchmem/rowmem {}x{} differ from the pattern size"
                          .format(hdr.stitchmem, hdr.rowmem))

    key = derive_xor_key(data, concat_limits=concat_limits,
                         legacy_fixups=legacy_fixups)
    pos = HEADER_SIZE
    p.offsets["color_pattern"] = pos
    p.color_blocks, pos = decrypt_block_chain(data, pos, p.height, key)
    p.offsets["stitch_pattern"] = pos
    p.stitch_blocks, pos = decrypt_block_chain(data, pos, p.height, key)
    p.color_pattern = decode_rle(p.color_blocks, p.width, p.height, p.warnings)
    p.stitch_pattern = decode_rle(p.stitch_blocks, p.width, p.height, p.warnings)

    p.offsets["colors"] = pos
    _need(data, pos, COLOR_TABLE_SIZE, "color table")
    p.colors = [Color(i, data[pos + COLOR_ENTRY_SIZE * i:
                              pos + COLOR_ENTRY_SIZE * (i + 1)])
                for i in range(COLOR_COUNT)]
    pos += COLOR_TABLE_SIZE

    p.offsets["stitch_types"] = pos
    _need(data, pos, STITCH_TABLE_SIZE, "stitch table")
    p.stitch_types = [StitchType(i, data[pos + 2 * i], data[pos + 2 * i + 1])
                      for i in range(STITCH_TYPE_COUNT)]
    pos += STITCH_TABLE_SIZE

    p.offsets["row_yarns"] = pos
    _need(data, pos, ROW_YARN_SLOTS * p.height, "colour changer table")
    p.row_yarns = [data[pos + ROW_YARN_SLOTS * r:pos + ROW_YARN_SLOTS * (r + 1)]
                   for r in range(p.height)]
    pos += ROW_YARN_SLOTS * p.height

    p.offsets["notes"] = pos
    _need(data, pos, 2, "note count")
    count = _u16(data, pos)
    pos += 2
    if count > MAX_NOTE_LINES:
        raise STPError("{} note lines (at most {})".format(count, MAX_NOTE_LINES))
    for _ in range(count):
        _need(data, pos, 1, "note line")
        _need(data, pos, 1 + data[pos], "note line")
        p.notes.append(_pascal(data, pos, 81))
        pos += 1 + data[pos]

    p.offsets["cables"] = pos
    ncables = hdr.cable_count if hdr.stores_cables else 0
    if ncables < 0:
        raise STPError("negative cable count")
    _need(data, pos, CABLE_RECORD_SIZE * ncables, "cable definitions")
    p.cables = [CableDefinition(data[pos + CABLE_RECORD_SIZE * i:
                                     pos + CABLE_RECORD_SIZE * (i + 1)])
                for i in range(ncables)]
    pos += CABLE_RECORD_SIZE * ncables
    if p.cables and hdr.version < VERSION_CABLES_USED:
        p.warnings.append("DesignaKnit ignores cable records of files saved "
                          "before version {}".format(VERSION_CABLES_USED))

    p.offsets["stitch_definitions"] = pos
    ndefs = hdr.stitch_def_count if hdr.stores_stitch_definitions else 0
    if ndefs < 0:
        raise STPError("negative stitch definition count")
    _need(data, pos, STITCH_RECORD_SIZE * ndefs, "stitch definitions")
    p.stitch_definitions = [
        StitchDefinition(data[pos + STITCH_RECORD_SIZE * i:
                              pos + STITCH_RECORD_SIZE * (i + 1)])
        for i in range(ndefs)]
    pos += STITCH_RECORD_SIZE * ndefs

    if hdr.has_pubrec == ord(","):
        p.offsets["pubrec"] = pos
        p.pubrec, pos = _read_pubrec(data, pos)

    if hdr.has_trace_image == ord("d") and pos + TRACE_RECORD_SIZE <= len(data):
        p.offsets["trace_image"] = pos
        p.trace_image = TraceImage(data[pos:pos + TRACE_RECORD_SIZE])
        pos += TRACE_RECORD_SIZE

    p.offsets["end"] = pos
    p.trailing_bytes = data[pos:]
    if p.trailing_bytes:
        p.warnings.append("{} unparsed bytes at the end".format(
            len(p.trailing_bytes)))
    return p


def _read_pubrec(data, pos):
    _need(data, pos, PUBREC_HEADER_SIZE, "publication record")
    header = data[pos:pos + PUBREC_HEADER_SIZE]
    pos += PUBREC_HEADER_SIZE
    count = header[0x1D]
    if count > MAX_NOTATIONS:
        raise STPError("{} notations (at most {})".format(count, MAX_NOTATIONS))
    encoding = "utf-8" if header[0x1C] else TEXT_ENCODING
    notations = []
    for _ in range(count):
        _need(data, pos, NOTATION_HEADER_SIZE, "notation")
        raw = data[pos:pos + NOTATION_HEADER_SIZE]
        pos += NOTATION_HEADER_SIZE
        nlines = _i16(raw, 0x5E) & 0xFF
        if nlines > MAX_NOTATION_LINES:
            raise STPError("notation with {} text lines".format(nlines))
        lengths = struct.unpack_from("<8h", raw, 0x88)
        lines = []
        for k in range(nlines):
            n = lengths[k]
            if not 0 <= n <= 0xFF:
                raise STPError("bad notation line length {}".format(n))
            _need(data, pos, n, "notation text")
            lines.append(data[pos:pos + n].decode(encoding, "replace"))
            pos += n
        notations.append(Notation(raw, lines))
    return PubRec(header, notations), pos


def read_stp(path, **kwargs):
    """Read and parse an ``.stp`` file."""
    with open(path, "rb") as f:
        return parse_stp(f.read(), **kwargs)


def _main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Dump a DesignaKnit .stp file")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--png", help="write the color pattern to this PNG "
                    "(single input file only; needs Pillow)")
    ap.add_argument("--header", action="store_true",
                    help="also print every header field")
    args = ap.parse_args(argv)
    for name in args.files:
        pattern = read_stp(name)
        out = {"file": name, "pattern": pattern.summary()}
        if args.header:
            out["header"] = dict(
                (dk_name, getattr(pattern.header, attr))
                for attr, off, kind, dk_name in _HEADER_FIELDS)
            for k, v in out["header"].items():
                if isinstance(v, bytes):
                    out["header"][k] = v.hex()
        print(json.dumps(out, indent=2, ensure_ascii=False))
        if args.png:
            pattern.color_image().save(args.png)


if __name__ == "__main__":
    _main()
