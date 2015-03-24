import os
import sys

# logging functions {{{

# TODO: replace these with the 'logger' module

debug = os.environ.get("DEBUG", "")

def trace(msg):
    print("accdb: %s" % msg, file=sys.stderr)

def _debug(msg):
    if debug:
        return trace(msg)

# }}}
