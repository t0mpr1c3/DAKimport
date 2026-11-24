"""Read DesignaKnit knitting pattern files.

``DAKimport.stp`` reads ``.stp`` stitch pattern files and needs only the
standard library. ``DAKimport.DAKimport.DAKPatternConverter`` (numpy +
Pillow) converts ``.pat`` and ``.stp`` files to images.
"""

from .stp import (  # noqa: F401
    STPError, Pattern, read_stp, parse_stp,
)

__version__ = "0.1.0"
