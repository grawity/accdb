import base64
import fnmatch
import re
import shlex

from .util import _debug

def b64_pad(string, max=4):
    n = len(string)
    if n % max:
        return string.ljust(n + max - (n % max), "=")
    else:
        return string

def ellipsize(string, max):
    if len(string) > max:
        return string[:max-1] + "…"
    else:
        return string

def split_ranges(string):
    for i in string.split():
        for j in i.split(","):
            if "-" in j:
                x, y = j.split("-", 1)
                yield int(x), int(y)+1
            else:
                yield int(j), int(j)+1

def str_split_escaped(string, sep, max=0):
    state = 0
    out = []
    cur = ""
    _debug("str_split: <- %r", string)
    for char in string:
        _debug("str_split:  char %r state %r", char, state)
        if state == 0:
            if char == "\\":
                state = 1
            elif char == sep:
                out.append(cur)
                cur = ""
            else:
                cur += char
        elif state == 1:
            cur += char
            state = 0
    if cur:
        out.append(cur)
    _debug("str_split: -> %r", out)
    return out

def str_split_qwords(string):
    _debug("parsing: <%s>" % string)
    lex = shlex.shlex(string, posix=True)
    lex.commenters = ""
    lex.whitespace_split = True
    args = list(lex)
    for _arg in args:
        _debug("output arg: <%s>" % _arg)
    return args

def expand_range(string):
    items = []
    for m, n in split_ranges(string):
        items.extend(range(m, n))
    return items

def re_compile_glob(glob, flags=None):
    if flags is None:
        flags = re.I
    return re.compile(fnmatch.translate(glob), flags | re.U)

def encode_psk(b):
    return base64.b32encode(b).decode("us-ascii").rstrip("=")

def decode_psk(s):
    raw_tag = "{raw} "
    hex_tag = "{hex} "
    b64_tag = "{b64} "

    if s.startswith(raw_tag):
        s = s[len(raw_tag):]
        return s.encode("utf-8")
    elif s.startswith(hex_tag):
        s = s[len(hex_tag):]
        return bytes.fromhex(s)
    elif s.startswith(b64_tag):
        s = s[len(b64_tag):]
        s = s.replace(" ", "")
        s = b64_pad(s, 4)
        return base64.b64decode(s)
    else:
        s = s.upper()
        s = s.replace(" ", "")
        s = b64_pad(s, 8)
        return base64.b32decode(s)
