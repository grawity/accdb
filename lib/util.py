import logging
import os
import sys

# logging functions {{{

debug = os.environ.get("DEBUG", "")

logging.basicConfig(format="accdb: %(levelname)s: (%(module)s) %(message)s",
                    level=(logging.DEBUG if debug else logging.INFO))

_debug = logging.debug

# }}}
