import logging
import os
import sys

# logging functions {{{

debug = os.environ.get("DEBUG", "")

logger = logging.getLogger("accdb")

logging.basicConfig(format="accdb/%(module)s %(levelname)s: %(message)s",
                    level=(logging.DEBUG if debug else logging.INFO))

def trace(msg):
    return logging.info("%s", msg)

def _debug(msg):
    return logging.debug("%s", msg)

# }}}
