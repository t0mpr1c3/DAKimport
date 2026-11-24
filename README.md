# DAKimport

A small Python 3 package for reading [DesignaKnit](https://softbyte.co.uk/)
knitting pattern files.

* `.stp` stitch pattern files (DesignaKnit 7-9, magic `D7c`) are fully
  decoded by `DAKimport.stp`, which needs only the standard library.
* `.pat` files (`D4C`/`D6C`) can be converted to images with
  `DAKPatternConverter.pat2im()`.

The `.stp` decryption was first published in Java by Guntram Blohm in
answer to a
[Stack Exchange question](https://reverseengineering.stackexchange.com/questions/12235/reading-stp-designaknit-stitch-pattern-files-ii/12239#12239).
The full format is documented in [docs/STP_FORMAT.md](docs/STP_FORMAT.md),
using DesignaKnit's own field names: header, stitch palette, cables, stitch
definitions, colour changer data, notes, publication record and trace image.
The names come from the debug information in DesignaKnit 9's `dk9a.dll`, and
the loading rules from DesignaKnit 9's own loader. How it was recovered is in
[docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md).

## Reading `.stp` files

```python
from DAKimport import read_stp

p = read_stp("Cables 1.stp")
p.width, p.height                 # 13, 18
p.color_pattern[0]                # bottom row, bytes of color indices
p.colors[0x35].name, p.colors[0x35].rgb
p.stitch_types[0].symbol          # stitch table entry 1
p.cables[0].code, p.cables[0].name, p.cables[0].knit_purl()
p.stitch_definitions[0].abbreviation("machine")
p.row_yarn_slots(0)               # colour changer: [(color_index, active), ...]
p.notes                           # note lines
p.header.xrepeats, p.header.cway_method, p.header.version

for cell in p.stitch_cells()[2]:  # stitches and cables of row 2, resolved
    print(cell)

p.color_image().save("cables.png")   # needs Pillow
```

Rows are kept in file order: row 0 is the first knitted (bottom) row.
`color_image()` and `rgb_rows()` put the top row first, the way the chart is
drawn. Invalid files raise `DAKimport.stp.STPError`.

From the command line:

```
python -m DAKimport "Cables 1.stp"              # JSON summary
python -m DAKimport "Cables 1.stp" --header     # plus every header field
python -m DAKimport ACORN.STP --png acorn.png
```

## Image converter

`DAKimport.DAKimport.DAKPatternConverter` (needs numpy and Pillow) has
`pat2im(filename)` and `stp2im(filename)`, each returning a `PIL.Image` of
the color pattern. `stp2im` now uses `DAKimport.stp` internally; it gives
the same images as before for every sample file.

## Analysis tools

The `tools/` folder holds the scripts used to recover the format; see
[docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md):

* `dump_process_modules.py`: dump module images from a running process
  (DesignaKnit is Themida-protected and only readable once running).
* `mem_to_pe.py`: turn a memory dump into a PE file Ghidra can load.
* `td32_types.py`: print record layouts from Borland TD32 debug info.
* `rebuild_skutil_pe.py`: rebuild SilverKnit's SkUtil.exe from `ida/skutil-dump.txt`.

## Tests

```
python -m unittest discover -s tests      # or: pytest
```

The smoke test reads every `.stp` file in
`~/Documents/DesignaKnit 9 Demo/Stitch patterns` (the samples installed with
the DesignaKnit 9 Demo). Set `DAK_STITCH_PATTERNS` to use another directory.
