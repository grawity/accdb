import base64
import datetime
import fnmatch
import re
import shlex
from nullroute.core import Core

def b64_encode(buf):
    if hasattr(buf, "encode"):
        buf = buf.encode()
    buf = base64.b64encode(buf)
    buf = buf.decode()
    return buf

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

def str_join_qwords(args):
    out = []
    quote_rx = re.compile("['\"\\\\ ]")
    escape_rx = re.compile("['\"\\\\]")
    func = lambda ch: "\\%s" % ch.group(0)
    for arg in args:
        if quote_rx.search(arg):
            arg = "\"%s\"" % escape_rx.sub(func, arg)
        out.append(arg)
    return " ".join(out)

def expand_range(string):
    items = []
    for m, n in split_ranges(string):
        items.extend(range(m, n))
    return items

def is_glob(glob):
    return ("*" in glob or "?" in glob or "[" in glob)

def re_compile_glob(glob, flags=None):
    if not is_glob(glob):
        glob = "*%s*" % glob
    return re.compile(fnmatch.translate(glob), flags or re.I)

def match_globs(string, globs):
    if not globs:
        return False
    return any(fnmatch.fnmatch(string, glob) for glob in globs)

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

def date_parse(s):
    if s == "now" or not s:
        return datetime.datetime.now()
    elif s.startswith("now-"):
        days = int(s[len("now-"):])
        return datetime.datetime.now() - datetime.timedelta(days)
    elif s.startswith("now+"):
        days = int(s[len("now+"):])
        return datetime.datetime.now() + datetime.timedelta(days)

    if " " in s:
        s = s.split(" ")[0]
    if "T" in s:
        s = s.split("T")[0]

    formats = [
        "%Y-%m-%d",
        "%m/%Y", # for credit cards
        "%Y-%m",
        "%Y",
    ]
    for f in formats:
        try:
            return datetime.datetime.strptime(s, f)
        except ValueError:
            continue
    Core.err("failed to parse %r as date", s)
    return datetime.datetime.fromordinal(1)

def date_cmp(a, b):
    ax = date_parse(a).date()
    bx = date_parse(b).date()
    if ax < bx:
        return -1
    elif ax > bx:
        return 1
    else:
        return 0

def round_days(d, coarse=0, terse=False):
    if terse:
        fmt_y = "%dy"
        fmt_m = "%dmo"
        fmt_d = "%dd"
        fmt_s = " "
    else:
        fmt_y = "%d years"
        fmt_m = "%d months"
        fmt_d = "%d days"
        fmt_s = ", "

    if d > 365-14:
        y, d = divmod(d, 365)
        if d < 60 or y > 2:
            return fmt_y % y
        elif d > 365-60:
            return fmt_y % (y+1)
        else:
            return fmt_y % y + fmt_s + round_days(d, 1)
    elif d > 90:
        m, d = divmod(d, 30)
        if d < 3 or coarse:
            return fmt_m % m
        elif d > 27:
            return fmt_m % (m+1)
        else:
            return fmt_m % m + fmt_s + fmt_d % d
    else:
        return fmt_d % d

def relative_date(s):
    a = date_parse(s).date()
    b = date_parse("now").date()
    if a < b:
        d = b - a
        return "%s ago" % round_days(d.days)
    elif a > b:
        d = a - b
        return "in %s" % round_days(d.days)
    else:
        return "today"

def colour_repr(string, start, pos):
    GRAY = "\033[38;5;242m%s\033[m"
    BLUE = "\033[38;5;21m%s\033[m"
    RED  = "\033[38;5;160m%s\033[m"
    if start >= 0:
        pref = string[:start]
        lead = string[start:pos]
        mid = string[pos]
        suff = string[pos+1:]
    else:
        pref = string[:pos]
        lead = ""
        mid = string[pos]
        suff = string[pos+1:]
    pref = (GRAY % pref)
    suff = (GRAY % suff)
    if start >= 0:
        lead = (RED % "‹") + lead
        mid = mid + (RED % "›")
    else:
        mid = (BLUE % "‹") + mid + (BLUE % "›")
    return pref + lead + mid + suff
