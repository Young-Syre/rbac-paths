"""Test package.

``src`` is put on the path here so the suite runs from a checkout with nothing
installed, as well as against an installed wheel.  An installed copy wins,
because site-packages is searched before this insertion only when the package
is already imported; for a plain checkout this is the only thing that makes
``python -m unittest discover -s tests -t .`` work.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _path in (os.path.join(_ROOT, "src"), _HERE):
    # The tests directory goes on the path as well, so `import fixtures` works
    # whether discovery treats these modules as a package or as top-level.
    if _path not in sys.path:
        sys.path.insert(0, _path)
