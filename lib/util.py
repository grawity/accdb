import logging
import os
import sys

# logging functions {{{

debug = os.environ.get("DEBUG", "")

logging.basicConfig(format="accdb/%(module)s %(levelname)s: %(message)s",
                    level=(logging.DEBUG if debug else logging.INFO))

# }}}
