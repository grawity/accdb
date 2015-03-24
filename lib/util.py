import os
import sys

# logging functions {{{

# TODO: replace these with the 'logger' module

debug = os.environ.get("DEBUG", "")

def trace(msg, *args):
    print("accdb: %s" % msg, *args, file=sys.stderr)

def _debug(msg, *args):
    if debug:
        return trace(msg, *args)

# }}}
