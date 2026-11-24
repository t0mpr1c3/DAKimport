# DesignaKnit `.stp` stitch pattern format

This describes the `D7c` stitch pattern files written by DesignaKnit 7–9.
`DAKimport/stp.py` implements it. How it was recovered is in
[REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md).

Field names are DesignaKnit's own. They come from the debug information in
`dk9a.dll` (full listing: [dk9a_records.txt](dk9a_records.txt)). The loading
rules come from DesignaKnit 9's loader (`dk9.exe` 0x7CFBB0 and the routines
it calls).

How sure each part is:

* **DK9**: read from DesignaKnit 9's code or record declarations.
* **verified**: matches all 145 sample files byte for byte (the 144 shipped
  files plus the `default.stp` DesignaKnit creates).
* **observed**: a meaning inferred from the samples or the DesignaKnit UI.

All integers are little-endian. Strings are Delphi ShortStrings (one length
byte, then that many characters, Windows-1252) in fixed-size fields.

## Overall layout

| Section | Size | Present when | Record |
|---|---|---|---|
| header | `0xF8` | always | first `0xF8` bytes of `tStitchPattern` |
| color pattern | variable | always | encrypted block chain |
| stitch pattern | variable | always | encrypted block chain |
| color palette | 71 × 25 | always | `tPaltItem` |
| stitch palette | 48 × 2 | always | `SPchar`, `SPflags` |
| colour changer table | `patternrows` × 6 | always | |
| note lines | 2 + Σ(1+len) | always | u16 count, up to 10 × String[80] |
| cables | `StoredPatContainsCables` × 590 | `CreatedOrSavedByDK89` ≥ 7 | `tCable` |
| stitch definitions | `StoredPatContainsSymbDefs` × 1270 | `CreatedOrSavedByDK89` ≥ 16 | `tSymbDef` |
| publication record | variable | `HasPubrec` = `','` | `tPubRecHeader` + notations |
| trace image | `0x148` | `HasTraceImage` = `'d'` | `tOpdTrace` |

DesignaKnit reads the tables from the color palette up to the note lines out
of one 21 000-byte buffer. It reads cable records for version ≥ 7 but only
uses them from version 17 on. In all 145 samples the sections add up to
exactly the file size. No sample has a publication record or a trace image.

## Header (`tStitchPattern`, `0x00`–`0xF7`)

The loader reads these `0xF8` bytes straight into the start of its in-memory
`tStitchPattern` record. The record continues past `0xF8` with the notes
(`0xF8`), the trace record (`0x422`) and row pointers, which are filled from
the later file sections.

| Offset | Type | DesignaKnit name | Meaning / loader behaviour |
|---|---|---|---|
| `0x00` | char[3] | `id` | `D7c` |
| `0x03` | int16 | `stitchmem` | allocated width; zeroed by the loader, equals width in the samples |
| `0x05` | int16 | `rowmem` | allocated height; zeroed by the loader |
| `0x07` | int16 | `patternstitches` | **width** (1–2000) |
| `0x09` | int16 | `patternrows` | **height** (1–3000) |
| `0x0B` | int16 | `xrepeats` | horizontal repeat count of the displayed design |
| `0x0D` | int16 | `yrepeats` | vertical repeat count |
| `0x0F`–`0x15` | 4 × int16 | `SelX1`, `SelX2`, `SelY1`, `SelY2` | selection within the repeated design; reset if out of range |
| `0x17`, `0x19` | int16 | `BoxY1`, `BoxY2` | |
| `0x1B` | int16 | `StoredPatContainsCables` | number of cable records |
| `0x1D` | int16 | `StoredPatContainsSymbDefs` | number of stitch definitions |
| `0x1F` | u8 | `PatMainColour` | main (background) colour |
| `0x20` | u8 | `currentver` | `'F'` in all samples; key material |
| `0x21`–`0x23` | u8 | `PaltPaintLMB/MMB/RMB` | colours on the left/middle/right mouse button |
| `0x24`–`0x26` | u8 | `StitchPaintLMB/MMB/RMB` | stitch types on the mouse buttons |
| `0x27` | u8 | `DraggedColWay` | |
| `0x28` | u8 | `ModifiedSinceCway` | if set, `0x27`, `0x29` and `0xD1`–`0xD6` are cleared on load |
| `0x29` | u8 | `JuggledColway` | |
| `0x2A` | u8 | `cwayStoredForOver4needles` | |
| `0x2B` | u8 | `CutAndSew` | |
| `0x2C` | u8 | `cwayMethod` | colour / knitting method; adjusted on load to fit the selected machine. Seen: 0 (machine default), 1 (intarsia: the title shows `-I`), 2–5, `0x0C` (hand knitting; `DefaultH.stp`), `0x0E`, `0x0F` |
| `0x2D` | u8 | `cwayStoredForMethod` | |
| `0x2E` | u8 | `StitchFontNumber` | |
| `0x2F` | u8 | `NumNoteLines` | set from the note-line count on load |
| `0x30` | u8 | `HasStitchPattern` | |
| `0x31` | u8 | `SPaltPriority` | |
| `0x32` | u8 | `xxxGridIntervalsCentred` | |
| `0x33`, `0x34` | u8 | `spbyte5`, `spbyte6` | spare |
| `0x35` | int32 | `DesignerNum` | key material (10 000 000 in all samples) |
| `0x39` | int32 | `PatternCollectionNumber` | key material (123 in newer files, 999 in older) |
| `0x3D` | int16 | `RandomNum` | key material, random per file (**signed**) |
| `0x3F` | uint16 | `DesignerProtectionOptions` | key material (0 or 99) |
| `0x41` | String | `DesignersCustomerLicence` | key material; String[30] in the old record, String[5] + filler in DK9 |
| `0x60` | String | `DesignerMessage` | key material; String[80] in the old record, String[1] + filler in DK9 |
| `0x9C` | u8 | `HackedLicenceStp` | |
| `0x9D`–`0xA2` | u8 | `PaltColsY/S/YS`, `PaltRowsY/S/YS` | palette window layout |
| `0xA3`–`0xA5` | u8 | `CwayStoredForCcType/CcUsed/Preselect` | colour changer settings; filled from preferences if `0xA3` = 0 |
| `0xB1` | char[32] | `FontNameVer7` | font name, NUL-terminated (`Arial`) |
| `0xD1` | u8[6] | `BestGuessJacqSeq` | |
| `0xD7` | u8 | `SRDS_Dat_File` | cleared on load |
| `0xD8` | u8 | `CreatedOrSavedByDK89` | **format version**: 18 (`0x12`) in newer samples, 0 in older ones. Selects the optional sections and upgrade steps (< 14, < 4); set to 18 after loading |
| `0xD9`–`0xE8` | single ×4 | `SDhRulerX/Y`, `SDvRulerX/Y` | ruler positions (9999 = off) |
| `0xE9` | u8 | `StartHKnittingAtLeft` | |
| `0xEA` | u8 | `CircularNotFlat` | |
| `0xEB` | u8 | `MainBackSymbolType` | |
| `0xEC` | u8 | `StartHKnittingWrongSide` | |
| `0xED` | u8 | `HasColourPattern` | |
| `0xEE` | u8 | `StpUseChanger` | colour changer in use |
| `0xEF` | u8 | `HasPubrec` | `','` → a publication record follows |
| `0xF0`, `0xF2` | int16 | `E6000techNumStp`, `E8000techNumStp` | Passap E6000/E8000 technique numbers |
| `0xF4` | u8 | `HasTraceImage` | `'d'` → a trace image record follows |
| `0xF5` | u8[3] | `SpareBytes` | cleared on load |

The DesignaKnit names show what the "encryption" really is: the key comes
from the *designer protection* fields (`DesignerNum`,
`PatternCollectionNumber`, `RandomNum`, `DesignerProtectionOptions`,
`DesignersCustomerLicence`, `DesignerMessage`).

## Decryption

Both pattern chains are XORed with a 21 000-byte key stream. This follows
DesignaKnit 9's routine at `dk9.exe` 0x5A1980:

```
k  = (u32 DesignerNum >> 1) + (u16 DesignerProtectionOptions << 2)
     + i32 PatternCollectionNumber + i16 RandomNum + u8 currentver
salt1 = u32[0x39] & 0xFFFF
salt2 = min(1, DesignerNum & 0xFFF)

s = DesignerMessage + DesignersCustomerLicence    truncated to L1
s = s + str(RandomNum)                            truncated to L2
s = s + str(currentver)                           truncated to L3
s = s + DesignersCustomerLicence                  truncated to L4
s = s + str(currentver)                           truncated to L5
s = s + str(RandomNum)                            truncated to L6

for i = 1 .. len(s):              (1-based)
    b = s[i] >> 1
    case i mod 3:
      0: k += i*b + (salt2 + b) div 7
      1: k += (b div 5) * DesignerProtectionOptions + i*salt2 + 6*b
      2: k += i*salt1 + 4*b

t = str(3k)
t = t + str(k)  truncated to  30;   t = t + str(4k) truncated to  45
t = t + str(2k) truncated to  60;   t = t + str(5k) truncated to  75
t = t + str(6k) truncated to  90;   t = t + str(8k) truncated to 105
t = t + str(7k) truncated to 120

for i = 1 .. 21000:
    key[i-1] = ((k + X) mod i) xor t[(i mod len(t)) + 1]     (1-based t)
```

Notes on the details:

* `str()` gives a signed decimal of at most 15 characters. `mod` and `div`
  truncate toward zero (x86 `IDIV`). All arithmetic is 32-bit signed with
  overflow checking.
* **L1–L6** are 6, 21, 36, 41, 56, 71 in DesignaKnit 9. The older copy of
  this routine inside SilverKnit's SkUtil uses 110, 125, 140, 170, 185, 200.
  The limits only matter for unusually long licence or message strings; both
  sets give identical keys for all samples. `stp.py` uses DesignaKnit 9's set
  and offers the other as `KEY_CONCAT_LIMITS_SKUTIL`.
* **X**: in DesignaKnit 9, a short stretch of the routine between building
  `t` and the final loop is virtualised by Themida. It can set a value that
  the loop adds to `k`, so it cannot be read statically. SkUtil has no such
  term (X = 0). X = 0 decrypts every sample file, and the samples opened in
  DesignaKnit (`Cables 4.stp`, `ARGYLL.STP`) load and display exactly as
  `stp.py` decodes them, so X is 0 at least for these files.
* SkUtil also rewrites bytes `0x39`/`0x3A` when they read `Su`, `Si` or `Jt`.
  DesignaKnit 9 does not do this; `stp.py` offers it as `legacy_fixups=True`.

## Pattern block chains

```
int16 end_row    last row (1-based) covered by this block
int16 size
u8    data[size] XORed with key[0 .. size-1] (the key restarts for each block)
```

Blocks are read until `end_row` equals `patternrows`; an `end_row` above
that is an error. Each block holds rows `previous end_row + 1 .. end_row`.
The color chain comes first, then the stitch chain.

Each row is run-length encoded. A byte **below `0x7F`** is a single cell.
Any other byte is a count (`b & 0x7F`) for the byte that follows. (SkUtil
treats `0x7F` as a single cell; DesignaKnit treats it as a count of 127.) A
row that runs past the width makes the load fail.

* **Color pattern** cells are indices into the color palette. User colors
  are `0x20`–`0x3C`, shown as the characters ` 0123…<`.
* **Stitch pattern** cells are 1-based indices into the stitch palette.
  Cables are the exception:
  * A cable covering *w* stitches takes *w* cells.
  * The first cell holds `cseq & 0x3F`.
  * The next cell holds `0x40 | (cseq >> 6)`, and the remaining cells hold
    `0x40`.
  * In repeat patterns a cable may wrap from the end of a row to its start.

## Color palette: 71 × `tPaltItem` (25 bytes)

The entry index is the value used in the color pattern.

| Offset | Type | DesignaKnit name | Meaning |
|---|---|---|---|
| 0 | u8 | `flags` | `0x10` = colour in use; `0x40` and `0x04` also seen. For files with version 0, DesignaKnit sets `0x04` on entries that have `0x10` and `0x40` |
| 1 | u8 | `symbol` | yarn symbol, e.g. `'1'` |
| 2 | u8 | `TempFlag` | |
| 3 | u8 | `PosnInWbox` | position in the yarn box (1–48; DesignaKnit renumbers the yarns if it is 0 or > 48) |
| 4 | u8 | `memo` | |
| 5 | u8 | `texture` | |
| 6–8 | u8 ×3 | `r`, `g`, `b` | colour |
| 9 | String[15] | `ColourName` | |

## Stitch palette: 48 × 2 bytes

| Offset | Type | DesignaKnit name |
|---|---|---|
| 0 | char | `SPchar`: stitch symbol in DesignaKnit's symbol font (`' '` knit, `'.'` purl, `0x83`–`0x8A` lace, …) |
| 1 | u8 | `SPflags` |

## Colour changer table (`patternrows` × 6 bytes)

There are six slots per row, holding the yarns in the colour changer. Each
nonzero byte is a color index in its low 7 bits; bit 7 marks a yarn that is
loaded but not knitting in that row. DesignaKnit copies this table only in
its normal load mode.

The table is meaningful only for patterns set up for a colour changer:
* in 42 samples every byte is a defined colour, and the bit-7 flag agrees
  with the pattern for 97.9% of the slots;
* in 19 samples it holds stale bytes;
* in 84 samples it is zero.

## Note lines

```
u16    count               at most 10 (more makes DesignaKnit fail)
String lines[count]        each length byte + characters, stored as String[80]
```

DesignaKnit stores the count in `NumNoteLines` (`0x2F`).

## Cables: `tCable` (590 bytes)

| Offset | Type | DesignaKnit name | Meaning |
|---|---|---|---|
| `0x000` | u8 | `TotalCrossingWd` | stitches covered |
| `0x001` | u8 | `FrontCable` | stitches in the front group |
| `0x002` | u8 | `BackCable` | knit stitches in the back group (0: purl) |
| `0x003` | u8 | `Flags` | bit 0 = back/right cross; high nibble 2 or 3 = knit centre stitches |
| `0x004` | u8 | `AbbrevSuffix` | |
| `0x005` | u8 | `Used_Cabl` | |
| `0x006` | String[8] | `TextureResource` | code `C<w><n1><n2><K/P><K/P><L/R>`, e.g. `C211KKL` |
| `0x00F` | String[10] | `CableSource` | e.g. `[DK9]` (set to that on load if empty) |
| `0x01A` | String[40] | `CableID` | name, e.g. `Front/Left Cross K1,k1` |
| `0x044` | int16 | `StandardCableNumber` | index in DesignaKnit's cable library (0 = not from the library) |
| `0x046` | int16 | `cseq` | id used in the stitch pattern |
| `0x048` | String[8] | `Abbrevn` | e.g. `C2F` |
| `0x051` | u8 | `TempByte` | |
| `0x052` | u8 | `AlertSoundType` | |
| `0x053` | u8[5] | `spare1` | |
| `0x058` | String[200] | `instruction1` | e.g. `Slip next stitch onto cable needle, …`; set to `" "` on load if empty |
| `0x121` | String[200] | `instruction2` | |
| `0x1EA` | u8[100] | `spare2` | |

SilverKnit's reader draws a cable from bytes 0–3 as knit and purl
cells, with w = `TotalCrossingWd`, n1 = `FrontCable`, n2 = `BackCable`:

* n2 = 0: left cross gives `P×(w−n1) K×n1`; right cross gives
  `K×n1 P×(w−n1)`.
* n1 + n2 = w, or a knit centre: all knit.
* otherwise: left cross gives `K×n2 P×… K×n1`; right cross gives
  `K×n1 P×… K×n2`.

`CableDefinition.knit_purl()` implements this.

## Stitch definitions: `tSymbDef` (1270 bytes)

| Offset | Type | DesignaKnit name |
|---|---|---|
| `0x000` | u8 | `smAscii`: the stitch symbol |
| `0x001` | String[20] | `smHandRSKa`: hand knitting abbreviation |
| `0x016` | String[20] | `smHandWSPa` |
| `0x02B` | String[20] | `smHandRSPa` |
| `0x040` | String[20] | `smHandWSKa` |
| `0x055` | String[20] | `smMachinea`: machine knitting abbreviation |
| `0x06A` | String[224] | `smHandRSKi`: instructions, same order as above |
| `0x14B` | String[224] | `smHandWSPi` |
| `0x22C` | String[224] | `smHandRSPi` |
| `0x30D` | String[224] | `smHandWSKi` |
| `0x3EE` | String[224] | `smMachinei` |
| `0x4CF` | u8[39] | `spare` |

RS/WS means right side / wrong side row; K/P is the knit or purl side of
the fabric (the meaning is inferred from the names). DesignaKnit files each
record under its symbol in a 256-entry table, unless the check at `dk9.exe`
0x7CAF50 says that symbol already has a definition.

## Publication record (only if `HasPubrec` = `','`)

```
tPubRecHeader                 0x4D2 bytes (margins, gaps, HasUnicode @0x1C,
                              NumNotations @0x1D (≤ 30), ShapeFn char[1001] @0x21)
NumNotations ×
    tPubNotationHeader        0xCA bytes (font name, size, arrow/bracket geometry,
                              NumTextLines @0x5E (≤ 8),
                              StoredTextLineBytes int16[8] @0x88)
    text line k               StoredTextLineBytes[k] raw bytes, for k < NumTextLines
```

These are the notations drawn on a printed chart (arrows, brackets, text).

## Trace image (only if `HasTraceImage` = `'d'`)

`tOpdTrace`, `0x148` bytes:

| Offset | Type | DesignaKnit name |
|---|---|---|
| `0x000` | String[255] | `TraceFn`: image file name |
| `0x100`–`0x117` | Real48 ×4 | `TraceMidXmm`, `TraceMidYmm`, `TraceWdMm`, `TraceHtMm` |
| `0x118`–`0x11F` | u8 ×8 | `TraceBrightness`, `TraceTint`, `TraceQuality`, `TraceImageType`, `TraceImageRetainAspect`, `NeedsDefaultSizeAndPosn`, `OPDisDiag`, `SDBlobSize` |
| `0x120` | u8[39] | `SpareTrace` |

## Still open

* The value X in the key, inside the Themida-virtualised code. It is 0 for
  every known file.
* The full list of `cwayMethod` values and the exact meaning of most flag
  bytes. The names are known, the semantics only partly.
* The upgrade steps DesignaKnit applies to files with version < 4 and < 14
  (`dk9.exe` 0x7CF7A8, 0x7CE8F0).

Nothing is thrown away: `Header`, `Color`, `CableDefinition`,
`StitchDefinition`, `Notation` and `TraceImage` keep the original bytes in
`raw`, and `Pattern.row_yarns` holds the colour changer table unchanged.
