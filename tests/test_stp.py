"""Tests for DAKimport.stp.

The smoke test reads every ``.stp`` file in the DesignaKnit sample directory.
Set ``DAK_STITCH_PATTERNS`` to point somewhere else; tests that need the
samples are skipped when the directory does not exist.

Run with ``python -m unittest discover -s tests`` or ``pytest``.
"""

import glob
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from DAKimport import stp  # noqa: E402

SAMPLES = os.environ.get(
    "DAK_STITCH_PATTERNS",
    os.path.join(os.path.expanduser("~"), "Documents", "DesignaKnit 9 Demo",
                 "Stitch patterns"))


def sample_files():
    files = glob.glob(os.path.join(SAMPLES, "*.[sS][tT][pP]"))
    return sorted(files, key=lambda f: os.path.basename(f).lower())


def sample_bytes(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        raise unittest.SkipTest("sample {} not found".format(name))
    with open(path, "rb") as f:
        return f.read()


def sample(name):
    return stp.parse_stp(sample_bytes(name))


def reencrypt(data, new_header):
    """Re-encrypt a file's block chains under the key of ``new_header``."""
    old_key = stp.derive_xor_key(data)
    new_key = stp.derive_xor_key(new_header)
    out = bytearray(new_header[:stp.HEADER_SIZE] + data[stp.HEADER_SIZE:])
    height = struct.unpack_from("<H", data, 9)[0]
    pos = stp.HEADER_SIZE
    for _ in range(2):
        blocks, pos = stp.decrypt_block_chain(data, pos, height, old_key)
        for block in blocks:
            start = block.offset + 4
            for i, b in enumerate(block.data):
                out[start + i] = b ^ new_key[i]
    return bytes(out)


@unittest.skipUnless(os.path.isdir(SAMPLES), "sample directory not found")
class SmokeTest(unittest.TestCase):
    """Every sample file must parse completely and consistently."""

    def test_samples_present(self):
        self.assertTrue(sample_files(), "no .stp files in " + SAMPLES)

    def test_all_samples(self):
        for path in sample_files():
            name = os.path.basename(path)
            with self.subTest(file=name):
                with open(path, "rb") as f:
                    data = f.read()
                p = stp.parse_stp(data)
                # every byte of the file is accounted for, nothing left over
                self.assertEqual(p.offsets["end"], len(data))
                self.assertEqual(p.warnings, [])
                self.assertEqual(len(p.color_pattern), p.height)
                self.assertEqual(len(p.stitch_pattern), p.height)
                self.assertTrue(all(len(r) == p.width for r in p.color_pattern))
                self.assertEqual((p.header.stitchmem, p.header.rowmem),
                                 (p.width, p.height))
                # both known key-string limit sets give the same key here
                self.assertEqual(
                    stp.derive_xor_key(data),
                    stp.derive_xor_key(
                        data, concat_limits=stp.KEY_CONCAT_LIMITS_SKUTIL))
                # every color used is a defined palette entry
                for value in p.used_colors():
                    self.assertTrue(p.colors[value].defined,
                                    "color {} undefined".format(value))
                self.assertTrue(
                    p.colors[p.header.background_color_index].defined)
                # every stitch cell resolves to a stitch type or a cable
                for row in p.stitch_cells():
                    for cell in row:
                        self.assertTrue(cell.stitch is not None
                                        or cell.cable is not None)
                        if cell.stitch is not None:
                            self.assertTrue(cell.stitch.defined)
                # stitch definitions describe symbols of the stitch palette
                symbols = set(s.symbol for s in p.stitch_types)
                for d in p.stitch_definitions:
                    self.assertIn(d.symbol, symbols)
                self.assertEqual(len(set(c.id for c in p.cables)),
                                 len(p.cables))
                self.assertEqual(len(p.notes), p.header.num_note_lines)

    def test_legacy_converter_matches(self):
        try:
            from DAKimport.DAKimport import DAKPatternConverter
        except ImportError:
            self.skipTest("numpy / Pillow not installed")
        for path in sample_files():
            with self.subTest(file=os.path.basename(path)):
                legacy = DAKPatternConverter().stp2im(path)
                self.assertEqual(legacy.tobytes(),
                                 stp.read_stp(path).color_image().tobytes())


class KnownContentTest(unittest.TestCase):
    """Spot checks against facts visible in the sample files."""

    def test_acorn(self):
        p = sample("ACORN.STP")
        self.assertEqual((p.width, p.height), (15, 16))
        self.assertEqual(p.used_colors(), [0x20, 0x33, 0x38])
        self.assertEqual([p.colors[i].name for i in p.used_colors()],
                         ["White", "Green", "Khaki"])
        self.assertEqual(p.colors[0x20].rgb, (0xFF, 0xFF, 0xFF))
        self.assertEqual(p.cables, [])
        self.assertEqual(p.stitch_definitions, [])
        self.assertEqual(p.header.version, 0x12)

    def test_header_fields(self):
        h = sample("ARGYLL.STP").header
        # DesignaKnit draws ARGYLL as 4 x 2 repeats of the 39 x 117 motif
        self.assertEqual((h.xrepeats, h.yrepeats), (4, 2))
        self.assertEqual((h.sel_x1, h.sel_x2, h.sel_y1, h.sel_y2),
                         (1, 39, 1, 117))
        self.assertEqual(h.cway_method, 1)
        self.assertEqual(h.designer_num, 10000000)
        self.assertEqual(h.font_name, "Times New Roman")
        self.assertEqual(sample("ACORN.STP").header.font_name, "Arial")
        self.assertEqual(h.currentver, ord("F"))

    def test_cables(self):
        p = sample("Cables 1.stp")
        self.assertEqual([c.id for c in p.cables], [1, 2, 3, 4, 13])
        c = p.cables[0]
        self.assertEqual((c.code, c.abbreviation, c.name, c.source),
                         ("C211KKL", "C2F", "Front/Left Cross K1,k1", "[DK9]"))
        self.assertEqual((c.width, c.front, c.back), (2, 1, 1))
        self.assertTrue(c.instruction1.startswith("Slip next stitch"))
        self.assertTrue(p.cables[1].crosses_right)
        self.assertEqual(len(p.stitch_definitions), 10)
        self.assertEqual(p.stitch_definitions[0].instruction("machine"), "Tuck")
        # the 3-stitch crossover (id 13) starts row 2 at column 0
        cells = p.stitch_cells()
        self.assertEqual([(c.cable.id, c.cable_offset) for c in cells[2][:3]],
                         [(13, 0), (13, 1), (13, 2)])

    def test_cable_knit_purl(self):
        p = sample("Cables 4.stp")
        by_code = dict((c.code, c.knit_purl()) for c in p.cables)
        self.assertEqual(by_code["C320PPL"], "PKK")
        self.assertEqual(by_code["C410PPR"], "KPPP")
        self.assertEqual(by_code["C422KKL"], "KKKK")
        self.assertEqual(by_code["C511KKL"], "KKKKK")   # K1(k3)k1
        self.assertEqual(by_code["C522PPL"], "KKPKK")   # K2(p1)k2

    def test_cable_wraps_around_row(self):
        p = sample("Cables 3.stp")
        row = p.stitch_cells()[6]
        self.assertEqual((row[-2].cable.id, row[-2].cable_offset), (12, 0))
        self.assertEqual((row[-1].cable.id, row[-1].cable_offset), (12, 1))
        self.assertEqual((row[0].cable.id, row[0].cable_offset), (12, 2))

    def test_high_cable_id_and_notes(self):
        p = sample("Cables 4.stp")
        self.assertEqual(p.notes, ["one", "", "threee"])
        self.assertEqual(p.header.num_note_lines, 3)
        ids = set(c.cable.id for row in p.stitch_cells() for c in row
                  if c.cable is not None)
        self.assertIn(169, ids)  # encoded as 0x29, 0x42, 0x40, 0x40

    def test_stitch_definition_slots(self):
        d = sample("HANDLACE.STP").stitch_definitions[0]
        self.assertEqual(d.symbol, 0x84)
        self.assertEqual(dict(zip(stp.SYMBDEF_SLOTS, d.abbreviations)), {
            "hand_rs_knit": "SSK", "hand_ws_purl": "P2tog",
            "hand_rs_purl": "SSPtbl", "hand_ws_knit": "K2tog",
            "machine": "LTtrL"})
        self.assertEqual(d.instruction("machine"), "Lace tool: left transfer")

    def test_row_yarns(self):
        p = sample("ARCHES.STP")
        self.assertEqual(p.row_yarn_slots(0),
                         [(0x31, True), (0x32, True), (0x33, False)])
        self.assertEqual(p.row_yarn_slots(2),
                         [(0x31, True), (0x32, True), (0x33, True)])


class OptionalSectionTest(unittest.TestCase):
    """Sections no sample file contains, built synthetically."""

    def test_pubrec_and_trace_image(self):
        data = bytearray(sample_bytes("ACORN.STP"))
        data[0xEF] = ord(",")       # HasPubrec
        data[0xF4] = ord("d")       # HasTraceImage
        pub = bytearray(stp.PUBREC_HEADER_SIZE)
        pub[0x1D] = 1               # NumNotations
        note = bytearray(stp.NOTATION_HEADER_SIZE)
        note[0x01:0x07] = b"\x05Arial"
        struct.pack_into("<h", note, 0x52, 12)
        struct.pack_into("<h", note, 0x5E, 2)
        struct.pack_into("<8h", note, 0x88, 5, 3, 0, 0, 0, 0, 0, 0)
        trace = bytearray(stp.TRACE_RECORD_SIZE)
        trace[0:8] = b"\x07img.bmp"
        trace[0x100:0x106] = bytes([0x86, 0, 0, 0, 0, 0x20])   # 40.0
        data += pub + note + b"Hello" + b"K2P" + trace
        p = stp.parse_stp(bytes(data))
        self.assertEqual(p.warnings, [])
        self.assertEqual(len(p.pubrec.notations), 1)
        n = p.pubrec.notations[0]
        self.assertEqual((n.font_name, n.font_size, n.lines),
                         ("Arial", 12, ["Hello", "K2P"]))
        self.assertEqual(p.trace_image.file_name, "img.bmp")
        self.assertAlmostEqual(p.trace_image.mid_x_mm, 40.0)

    def test_old_version_has_no_cables(self):
        data = bytearray(sample_bytes("Cables 1.stp"))
        p = stp.parse_stp(bytes(data))
        n = len(p.cables) * stp.CABLE_RECORD_SIZE
        start = p.offsets["cables"]
        data[0xD8] = 6              # CreatedOrSavedByDK89 < 7
        data[0x1D:0x1F] = b"\0\0"   # no stitch definitions either
        del data[start:]
        p = stp.parse_stp(bytes(data))
        self.assertEqual(p.cables, [])
        self.assertTrue(n > 0)


class KeyTest(unittest.TestCase):

    def test_trunc_mod(self):
        self.assertEqual(stp._trunc_mod(-7, 3), -1)
        self.assertEqual(stp._trunc_mod(7, 3), 1)

    def test_shortstring_helpers(self):
        self.assertEqual(stp._append(b"abc", b"def", 4), b"abcd")
        self.assertEqual(stp._int_to_str(-12), b"-12")

    def test_real48(self):
        self.assertEqual(stp._real48(bytes(6)), 0.0)
        self.assertEqual(stp._real48(bytes([0x81, 0, 0, 0, 0, 0])), 1.0)
        self.assertEqual(stp._real48(bytes([0x82, 0, 0, 0, 0, 0x80])), -2.0)

    def test_concat_limits_matter_for_long_strings(self):
        data = bytearray(sample_bytes("ACORN.STP"))
        data[0x41:0x41 + 31] = b"\x1e" + b"L" * 30   # long licence string
        self.assertNotEqual(
            stp.derive_xor_key(bytes(data)),
            stp.derive_xor_key(bytes(data),
                               concat_limits=stp.KEY_CONCAT_LIMITS_SKUTIL))

    def test_signed_header_word_round_trip(self):
        """A negative RandomNum (read with MOVSX) must still decode."""
        data = sample_bytes("ACORN.STP")
        original = stp.parse_stp(data)
        header = bytearray(data[:stp.HEADER_SIZE])
        struct.pack_into("<h", header, 0x3D, -12345)
        struct.pack_into("<I", header, 0x35, 0x00989000)  # & 0xFFF == 0
        modified = stp.parse_stp(reencrypt(data, bytes(header)))
        self.assertNotEqual(stp.derive_xor_key(header),
                            stp.derive_xor_key(data))
        self.assertEqual(modified.color_pattern, original.color_pattern)
        self.assertEqual(modified.stitch_pattern, original.stitch_pattern)

    def test_rle_run_marker(self):
        """DesignaKnit treats 0x7F like 0x80..0xFF: a repeat count."""
        block = stp.Block(1, 0, bytes([0x7F, 5, 0x81, 7]))
        self.assertEqual(stp.decode_rle([block], 127 + 1, 1),
                         [bytes([5]) * 127 + bytes([7])])

    def test_errors(self):
        with self.assertRaises(stp.STPError):
            stp.parse_stp(b"XYZ" + bytes(0x200))
        data = sample_bytes("ACORN.STP")
        with self.assertRaises(stp.STPError):
            stp.parse_stp(data[:0x150])
        with self.assertRaises(stp.STPError):
            stp.parse_stp(data[:-1])


if __name__ == "__main__":
    unittest.main()
