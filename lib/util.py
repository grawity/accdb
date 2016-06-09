import logging
import os
import sys

# logging functions {{{

class FancyFormatter(logging.Formatter):
    _colors = {
        logging.ERROR: "\033[1;31m",
        logging.DEBUG: "\033[36m",
    }

    def format(self, record):
        arg0 = "accdb"

        color = self._colors.get(record.levelno, "")
        reset = "\033[m" if color else ""

        prefix = record.levelname.lower()
        if record.levelno == logging.DEBUG:
            caller = record.module
            if record.funcName != "__init__":
                caller += ":" + record.funcName
            prefix += " (" + caller + ")"
        msg = record.msg % record.args

        output = "%(arg0)s: %(color)s%(prefix)s:%(reset)s %(msg)s%(reset)s" % locals()
        return output

debug = os.environ.get("DEBUG", "")

handler = logging.StreamHandler()
handler.setFormatter(FancyFormatter())
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

_debug = logging.debug

# }}}
