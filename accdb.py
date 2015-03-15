#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# accdb - account database using human-editable flat files as storage

from __future__ import print_function
import base64
import cmd
import fnmatch
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from collections import OrderedDict
from io import TextIOWrapper
import nullroute as lib
import hotpie as oath

# logging functions {{{

debug = os.environ.get("DEBUG", "")

def trace(msg, *args):
    print("accdb: %s" % msg, *args, file=sys.stderr)

def _debug(msg, *args):
    if debug:
        return trace(msg, *args)

# }}}

# string functions {{{

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

def split_tags(string):
    string = string.strip(" ,\n")
    items = re.split(Entry.RE_TAGS, string)
    return set(items)

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
    _debug("str_split: <- %r" % string)
    for char in string:
        _debug("str_split:  char %r state %r" % (char, state))
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
    _debug("str_split: -> %r" % out)
    return out

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

# }}}

# attribute name functions {{{

attr_names = {
    "@alias":   "@aka",
    "hostname": "host",
    "machine":  "host",
    "url":      "uri",
    "website":  "uri",
    "user":     "login",
    "username": "login",
    "nicname":  "nic-hdl",
    "password": "pass",
    "!pass":    "pass",
    "mail":     "email",
    "tel":      "phone",
}

attr_groups = {
    "object":   ["entity", "host", "uri", "realm"],
    "username": ["login", "login.", "nic-hdl", "principal"],
    "password": ["pass", "!pass"],
    "email":    ["email", "phone"],
}

attr_order = ["object", "username", "password", "email"]

attr_prefix_re = re.compile(r"^\W+")

def attr_is_metadata(name):
    return name.startswith("@")

def attr_is_private(name):
    return name.startswith("!") or name == "pass"

def attr_is_reflink(name):
    return name.startswith("ref.")

def translate_attr(name):
    return attr_names.get(name, name)

def sort_attrs(entry):
    canonicalize = lambda k: attr_prefix_re.sub("", translate_attr(k))
    names = []
    names += sorted([k for k in entry.attributes
                       if attr_is_metadata(k)])
    for group in attr_order:
        for attr in attr_groups[group]:
            names += sorted([k for k in entry.attributes \
                               if (k == attr
                                   or (attr.endswith(".") and k.startswith(attr)))],
                            key=canonicalize)
    names += sorted([k for k in entry.attributes if k not in names],
                    key=canonicalize)
    return names

# }}}

# 'Clipboard' {{{

class Clipboard():
    @classmethod
    def get(self):
        if sys.platform == "win32":
            import win32clipboard as clip
            clip.OpenClipboard()
            # TODO: what type does this return?
            data = clip.GetClipboardData(clip.CF_UNICODETEXT)
            print("clipboard.get =", repr(data))
            clip.CloseClipboard()
            return data
        else:
            raise RuntimeError("Unsupported platform")

    @classmethod
    def put(self, data):
        if sys.platform == "win32":
            import win32clipboard as clip
            clip.OpenClipboard()
            clip.EmptyClipboard()
            clip.SetClipboardText(data, clip.CF_UNICODETEXT)
            clip.CloseClipboard()
        elif sys.platform.startswith("linux"):
            proc = subprocess.Popen(("xsel", "-i", "-b", "-l", "/dev/null"),
                        stdin=subprocess.PIPE)
            proc.stdin.write(data.encode("utf-8"))
            proc.stdin.close()
            proc.wait()
        else:
            raise RuntimeError("Unsupported platform")

# }}}

# 'Changeset' {{{

class Changeset(list):
    def __init__(self, args, key_alias=None):
        self._key_alias = key_alias
        _ops = {
            "+": "add",
            "-": "rem",
            ":": "set",
            "«": "copy",
            "<": "move",
            "|": "merge",
        }
        dwim = set()
        for a in args:
            _debug("arg %r" % a)
            if a.startswith("-"):
                k = a[1:]
                self.append(("del", k, None))
                _debug("  del-key %r" % k)
            elif "=" in a:
                k, v = a.split("=", 1)
                if k[-1] in _ops:
                    op = _ops[k[-1]]
                    k = k[:-1]
                    _debug("  %s: %r = %r" % (op, k, v))
                else:
                    if k in dwim:
                        op = "add"
                        _debug("  set-value %r = %r, DWIM to add-value" % (k, v))
                    else:
                        op = "set"
                        _debug("  set-value %r = %r" % (k, v))
                self.append((op, k, v))
                dwim.add(k)
            else:
                lib.err("syntax error in %r" % a)
        _debug("changes: %r" % self)

    def apply_to(self, target):
        for op, k, v in self:
            if self._key_alias:
                k = self._key_alias.get(k, k)
            _debug("changeset: key %r op %r val %r" % (k, op, v))
            if op == "set":
                target[k] = [v]
            elif op == "add":
                if k not in target:
                    target[k] = [v]
                if v not in target[k]:
                    target[k].append(v)
            elif op == "rem":
                if k not in target:
                    continue
                if v in target[k]:
                    target[k].remove(v)
            elif op == "copy":
                if self._key_alias:
                    v = self._key_alias.get(v, v)
                if v in target:
                    target[k] = target[v][:]
                else:
                    if k in target:
                        del target[k]
            elif op == "move":
                if self._key_alias:
                    v = self._key_alias.get(v, v)
                if v in target:
                    target[k] = target[v]
                    del target[v]
                else:
                    if k in target:
                        del target[k]
            elif op == "merge":
                if self._key_alias:
                    v = self._key_alias.get(v, v)
                if v not in target:
                    continue
                if k in target:
                    target[k] += [val for val in target[v]
                                  if val not in target[k]]
                else:
                    target[k] = target[v][:]
            elif op == "del":
                if k in target:
                    del target[k]
            else:
                lib.die("unknown changeset operation %r" % op)
        return target

# }}}

# 'TextChangeset' {{{

class TextChangeset(list):
    def __init__(self, args):
        for arg in args:
            _debug("arg %r" % arg)
            if arg == "-":
                _debug("  empty");
                self.append(("empty",))
            elif arg.startswith("+"):
                arg = arg[1:]
                _debug("  add-line %r" % arg)
                self.append(("append", arg))
            elif arg.startswith("s/"):
                arg = arg[2:]
                if arg.endswith("/"):
                    arg = arg[:-1]
                arg = str_split_escaped(arg, "/", 1)
                if len(arg) == 2:
                    from_re, to_str = arg
                    _debug("  regex %r to %r" % (from_re, to_str))
                    self.append(("resub", from_re, to_str))
                else:
                    lib.die("not enough parameters: %r" % arg)
            else:
                self.append(("empty",))
                self.append(("append", arg))

    def apply(self, target):
        lines = target.rstrip("\n").split("\n")

        for op, *rest in self:
            _debug("text changeset: op %r rest %r" % (op, rest))
            if op == "empty":
                lines = []
            elif op == "append":
                lines.append(rest[0])
            elif op == "resub":
                rx = re.compile(rest[0])
                lines = [rx.sub(rest[1], _) for _ in lines]
            else:
                lib.die("unknown operation %r" % op)

        _debug("text changeset: lines %r" % lines)
        return "\n".join(lines)

# }}}

# 'SecretStore' {{{

class UnknownAlgorithmError(Exception):
    pass

class SecretStore(object):
    default_algo = "aes-128-cfb"

    def __init__(self, key):
        self.key = key

    def get_key(self, bits) -> "bytes":
        bytes = int(bits >> 3)
        return self.key[:bytes]

    def wrap(self, clear: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")

        if algo == "none":
            pass
        elif algo[0] == "aes" \
         and algo[1] in {"128", "192", "256"} \
         and algo[2] == "cfb":
            from Crypto.Cipher import AES
            bits = int(algo[1])
            key = self.get_key(bits)
            iv = os.urandom(AES.block_size)
            cipher = AES.new(key, AES.MODE_CFB, iv)
            wrapped = cipher.encrypt(clear)
            wrapped = iv + wrapped
        else:
            raise UnknownAlgorithmError()

        return wrapped

    def unwrap(self, wrapped: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")

        if algo == "none":
            pass
        elif algo[0] == "aes" \
         and algo[1] in {"128", "192", "256"} \
         and algo[2] == "cfb":
            from Crypto.Cipher import AES
            key = self.get_key(bits)
            iv = wrapped[:AES.block_size]
            wrapped = wrapped[AES.block_size:]
            cipher = AES.new(key, AES.MODE_CFB, iv)
            clear = cipher.decrypt(wrapped)
        else:
            raise UnknownAlgorithmError()

        return clear

# @clear: (string) plain data
# -> (base64-encoded string) encrypted data

def wrap_secret(clear: "str") -> "base64: str":
    global ss

    algo = ss.default_algo
    clear = clear.encode("utf-8")
    wrapped = ss.wrap(clear, algo)
    wrapped = base64.b64encode(wrapped)
    wrapped = wrapped.decode("utf-8")
    wrapped = "%s;%s" % (algo, wrapped)
    return wrapped

# @wrapped: (base64-encoded string) encrypted data
# -> (string) plain data

def unwrap_secret(wrapped):
    global ss

    algo, wrapped = wrapped.split(";", 1)
    wrapped = wrapped.encode("utf-8")
    wrapped = base64.b64decode(wrapped)
    clear = ss.unwrap(wrapped, algo)
    clear = clear.decode("utf-8")
    return clear

# }}}

# 'OATHParameters' {{{

class OATHParameters(object):
    """
    A collection of OATH parameters for a single site.
    """
    def __init__(self, raw_psk, digits=6, otype="totp", window=30,
                 login=None, issuer=None):
        if otype not in {"totp"}:
            lib.err("OATH %r is not supported yet" % otype)
        self.raw_psk = raw_psk
        self.digits = digits
        self.otype = otype
        self.window = window
        self.login = login
        self.issuer = issuer

    @property
    def text_psk(self):
        return encode_psk(self.raw_psk)

    def make_uri(self):
        # https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
        # TODO: url-encode label & issuer
        if self.issuer and (self.issuer != self.login):
            issuer = self.issuer
            label = "%s:%s" % (issuer, self.login)
        else:
            issuer = None
            label = self.login

        uri = "otpauth://totp/%s?secret=%s" % (label, self.text_psk)
        if issuer:
            uri += "&issuer=%s" % issuer
        if self.digits != 6:
            uri += "&digits=%d" % self.digits

        return uri

    def generate(self):
        _debug("generating OTP from:", base64.b32encode(self.raw_psk).decode("us-ascii"))

        if self.otype == "totp":
            return oath.TOTP(self.raw_psk, digits=self.digits, window=self.window)
        else:
            lib.err("OATH %r is not supported yet" % self.otype)

# }}}

# 'Filter' {{{

class FilterSyntaxError(Exception):
    pass

class Filter(object):
    def __call__(self, entry):
        return bool(self.test(entry))

    @staticmethod
    def parse(text):
        tokens = []
        depth = 0
        start = -1
        for pos, char in enumerate(text):
            if char == "(":
                if depth == 0:
                    if start >= 0:
                        tokens.append(text[start:pos])
                    start = pos+1
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and start >= 0:
                    tokens.append(text[start:pos])
                    start = -1
            elif char in " \t\r\n":
                if depth == 0 and start >= 0:
                    tokens.append(text[start:pos])
                    start = -1
            else:
                if start < 0:
                    start = pos
        if depth == 0:
            if start >= 0:
                tokens.append(text[start:])
            return tokens
        elif depth > 0:
            raise FilterSyntaxError("unclosed '(' (depth %d)" % depth)
        elif depth < 0:
            raise FilterSyntaxError("too many ')'s (depth %d)" % depth)

    @staticmethod
    def compile(pattern):
        tokens = Filter.parse(pattern)
        _debug("parsing filter %r -> %r" % (pattern, tokens))

        op, *args = tokens
        if len(args) > 0:
            # boolean operators
            if op in {"AND", "and"}:
                filters = [Filter.compile(x) for x in args]
                return ConjunctionFilter(*filters)
            elif op in {"OR", "or"}:
                filters = [Filter.compile(x) for x in args]
                return DisjunctionFilter(*filters)
            elif op in {"NOT", "not"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'NOT'")
                filter = Filter.compile(args[0])
                return NegationFilter(filter)
            # search filters
            elif op in {"ITEM", "item"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'ITEM'")
                return ItemNumberFilter(args[0])
            elif op in {"PATTERN", "pattern"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'PATTERN'")
                return PatternFilter(args[0])
            elif op in {"RANGE", "item"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'RANGE'")
                return ItemNumberRangeFilter(args[0])
            elif op in {"UUID", "uuid"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'UUID'")
                return ItemUuidFilter(args[0])
            # etc.
            else:
                raise FilterSyntaxError("unknown operator %r in (%s)" % (op, pattern))
        elif " " in op or "(" in op or ")" in op:
            return Filter.compile(op)
        elif op.startswith("#"):
            return ItemNumberFilter(op[1:])
        elif op.startswith("{"):
            return ItemUuidFilter(op)
        elif op.isdecimal():
            return ItemNumberFilter(op)
        elif re.match(r"^[0-9,-]+$", op):
            return ItemNumberRangeFilter(op)
        else:
            return PatternFilter(op)

    @staticmethod
    def _compile_and_search(text):
        try:
            filter = Filter.compile(text)
        except FilterSyntaxError as e:
            trace("syntax error in filter:", *e.args)
            sys.exit(1)
        if debug:
            trace("compiled filter:", filter)
        return db.find(filter)

    @staticmethod
    def _cli_compile(arg):
        args = shlex.split(arg)
        try:
            if len(args) > 1:
                arg = "AND"
                for x in args:
                    arg += (" (%s)" if " " in x else " %s") % x
                filters = [Filter.compile(x) for x in args]
                filter = ConjunctionFilter(*filters)
            elif len(args) > 0:
                arg = args[0]
                filter = Filter.compile(arg)
            else:
                arg = "*"
                filter = Filter.compile(arg)
        except FilterSyntaxError as e:
            trace("syntax error in filter:", *e.args)
            sys.exit(1)
        if debug:
            trace("compiled filter:", filter)
        return filter

    @staticmethod
    def _cli_compile_and_search(arg):
        return db.find(Filter._cli_compile(arg))

class PatternFilter(Filter):
    def __init__(self, pattern):
        self.pattern = pattern
        self.func = PatternFilter.compile(self.pattern)

    def test(self, entry):
        if self.func:
            return self.func(entry)

    def __str__(self):
        if isinstance(self.func, Filter):
            return str(self.func)
        else:
            return "(PATTERN %s)" % self.pattern

    @staticmethod
    def compile(pattern):
        _debug("compiling pattern %r" % pattern)

        func = None

        if pattern == "*":
            func = lambda entry: True
        elif pattern.startswith("#"):
            func = ItemNumberFilter(pattern[1:])
        elif pattern == "+untagged":
            func = lambda entry: len(entry.tags) == 0
        elif pattern.startswith("+"):
            regex = re_compile_glob(pattern[1:])
            func = lambda entry: any(regex.match(tag) for tag in entry.tags)
        elif pattern.startswith("@"):
            if "=" in pattern:
                attr, glob = pattern[1:].split("=", 1)
                attr = translate_attr(attr)
                regex = re_compile_glob(glob)
                func = lambda entry:\
                    attr in entry.attributes \
                    and any(regex.match(value)
                        for value in entry.attributes[attr])
            elif "~" in pattern:
                attr, regex = pattern[1:].split("~", 1)
                attr = translate_attr(attr)
                try:
                    regex = re.compile(regex, re.I | re.U)
                except re.error as e:
                    lib.die("invalid regex %r (%s)" % (regex, e))
                func = lambda entry:\
                    attr in entry.attributes \
                    and any(regex.search(value)
                        for value in entry.attributes[attr])
            elif "*" in pattern:
                regex = re_compile_glob(pattern[1:])
                func = lambda entry:\
                    any(regex.match(attr) for attr in entry.attributes)
            else:
                attr = translate_attr(pattern[1:])
                func = lambda entry: attr in entry.attributes
        elif pattern.startswith("~"):
            try:
                regex = re.compile(pattern[1:], re.I | re.U)
            except re.error as e:
                lib.die("invalid regex %r (%s)" % (pattern[1:], e))
            func = lambda entry:\
                    regex.search(entry.name) \
                    or any(regex.search(value)
                       for value in entry.attributes.get("@alias", []))
        elif pattern.startswith("{"):
            func = ItemUuidFilter(pattern)
        else:
            if "*" not in pattern:
                pattern = "*" + pattern + "*"
            regex = re_compile_glob(pattern)
            func = lambda entry:\
                    regex.search(entry.name) \
                    or any(regex.search(value)
                       for value in entry.attributes.get("@alias", []))

        return func

# elementary filters {{{

class ItemNumberFilter(Filter):
    def __init__(self, pattern):
        try:
            self.value = int(pattern)
        except ValueError:
            raise FilterSyntaxError("integer value expected for 'ITEM'")

    def test(self, entry):
        return entry.itemno == self.value

    def __str__(self):
        return "(ITEM %d)" % self.value

class ItemNumberRangeFilter(Filter):
    def __init__(self, pattern):
        self.pattern = pattern
        self.items = set(expand_range(pattern))

    def test(self, entry):
        return entry.itemno in self.items

    def __str__(self):
        return "(RANGE %s)" % self.pattern

class ItemUuidFilter(Filter):
    def __init__(self, pattern):
        try:
            self.value = uuid.UUID(pattern)
        except ValueError:
            raise FilterSyntaxError("malformed value for 'UUID'")

    def test(self, entry):
        return entry.uuid == self.value

    def __str__(self):
        return "(UUID %s)" % self.value

class ConjunctionFilter(Filter):
    def __init__(self, *filters):
        self.filters = list(filters)

    def test(self, entry):
        return all(filter.test(entry) for filter in self.filters)

    def __str__(self):
        return "(AND %s)" % " ".join(str(f) for f in self.filters)

class DisjunctionFilter(Filter):
    def __init__(self, *filters):
        self.filters = list(filters)

    def test(self, entry):
        return any(filter.test(entry) for filter in self.filters)

    def __str__(self):
        return "(OR %s)" % " ".join(str(f) for f in self.filters)

class NegationFilter(Filter):
    def __init__(self, filter):
        self.filter = filter

    def test(self, entry):
        return not self.filter.test(entry)

    def __str__(self):
        return "(NOT %s)" % self.filter

# }}}

# }}}

# 'Database' {{{

class Database(object):
    def __init__(self):
        self.count = 0
        self.path = None
        self.entries = dict()
        self.order = list()
        self.modified = False
        self.readonly = False
        self._modeline = "; vim: ft=accdb:"
        self.flags = set()

    # Import

    @classmethod
    def from_file(self, path):
        db = self()
        db.path = path
        with open(path, "r", encoding="utf-8") as fh:
            db.parseinto(fh)
        return db

    @classmethod
    def parse(self, *args, **kwargs):
        return self().parseinto(*args, **kwargs)

    def parseinto(self, fh):
        data = ""
        lineno = 0
        lastno = 1

        for line in fh:
            lineno += 1
            if line.startswith("; vim:"):
                self._modeline = line.strip()
            elif line.startswith("; dbflags:"):
                self.flags = split_tags(line[10:])
            elif line.startswith("="):
                entry = Entry.parse(data, lineno=lastno)
                if entry and not entry.deleted:
                    self.add(entry)
                data = line
                lastno = lineno
            else:
                data += line

        if data:
            entry = Entry.parse(data, lineno=lastno)
            if entry and not entry.deleted:
                self.add(entry)

        return self

    def add(self, entry, lineno=None):
        if entry.uuid is None:
            entry.uuid = uuid.uuid4()
        elif entry.uuid in self:
            raise KeyError("Duplicate UUID %s" % entry.uuid)

        entry.itemno = self.count + 1

        self.count += 1

        if entry.lineno is None:
            entry.lineno = lineno

        self.entries[entry.uuid] = entry
        self.order.append(entry.uuid)

        return entry

    def replace(self, entry):
        if entry.uuid is None:
            raise ValueError("Entry is missing UUID")

        oldentry = self[entry.uuid]

        entry.itemno = oldentry.itemno
        entry.lineno = oldentry.lineno

        oldpass = oldentry.attributes.get("pass", None)
        newpass = entry.attributes.get("pass", None)

        if oldpass and oldpass != newpass:
            if "!pass.old" not in entry.attributes:
                entry.attributes["!pass.old"] = []
            for p in oldpass:
                p = "%s (until %s)" % (p, time.strftime("%Y-%m-%d"))
                entry.attributes["!pass.old"].append(p)

        self.entries[entry.uuid] = entry

        return entry

    # Lookup

    def __contains__(self, key):
        return key in self.entries

    def __getitem__(self, key):
        return self.entries[key]

    def find_by_itemno(self, itemno):
        uuid = self.order[itemno-1]
        entry = self.entries[uuid]
        assert entry.itemno == itemno
        return entry

    def find_by_uuid(self, uuid_str):
        uuid_parsed = uuid.UUID(uuid_str)
        return self[uuid_parsed]

    def find(self, filter):
        for entry in self:
            if filter(entry):
                yield entry

    # Aggregate lookup

    def tags(self):
        tags = set()
        for entry in self:
            tags |= entry.tags
        return tags

    # Maintenance

    def sort(self):
        self.order.sort(key=lambda uuid: self.entries[uuid].normalized_name)

    # Export

    def __iter__(self):
        for uuid in self.order:
            yield self.entries[uuid]

    def dump(self, fh=sys.stdout, storage=True):
        eargs = {"storage": storage,
            "conceal": ("conceal" in self.flags)}
        if storage:
            if self._modeline:
                print(self._modeline, file=fh)
        for entry in self:
            if entry.deleted:
                continue
            print(entry.dump(**eargs), file=fh)
        if storage:
            if self.flags:
                print("; dbflags: %s" % \
                    ", ".join(sorted(self.flags)),
                    file=fh)

    def to_structure(self):
        return [entry.to_structure() for entry in self]

    def dump_yaml(self, fh=sys.stdout):
        import yaml
        print(yaml.dump(self.to_structure()), file=fh)

    def dump_json(self, fh=sys.stdout):
        import json
        print(json.dumps(self.to_structure(), indent=4), file=fh)

    def to_file(self, path):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            self.dump(fh)

    def flush(self):
        if not self.modified:
            return
        if self.readonly:
            print("(Discarding changes, database read-only)", file=sys.stderr)
            return
        if self.path is None:
            return
        self.to_file(self.path)
        self.modified = False

# }}}

# 'Entry' {{{

class Entry(object):
    RE_TAGS = re.compile(r'\s*,\s*|\s+')
    RE_KEYVAL = re.compile(r'=|: ')

    RE_COLL = re.compile(r'\w.*$')

    def __init__(self):
        self.attributes = dict()
        self.comment = ""
        self.deleted = False
        self.itemno = None
        self.lineno = None
        self.name = None
        self.tags = set()
        self.uuid = None
        self._broken = False

    # Import

    @classmethod
    def parse(self, *args, **kwargs):
        return self().parseinto(*args, **kwargs)

    def parseinto(self, data, lineno=1):
        # lineno is passed here for use in syntax error messages
        self.lineno = lineno

        for line in data.splitlines():
            line = line.lstrip()
            if not line:
                pass
            elif line.startswith("="):
                if self.name:
                    # Ensure that Database only passes us single entries
                    print("Line %d: ignoring multiple name headers" \
                        % lineno,
                        file=sys.stderr)
                self.name = line[1:].strip()
            elif line.startswith("+"):
                self.tags |= split_tags(line[1:])
                if "\\deleted" in self.tags:
                    self.deleted = True
            elif line.startswith(";"):
                self.comment += line[1:] + "\n"
            elif line.startswith("(") and line.endswith(")"):
                # annotations in search output
                pass
            elif line.startswith("█") and line.endswith("█"):
                # QR code
                pass
            elif line.startswith("{") and line.endswith("}"):
                if self.uuid:
                    print("Line %d: ignoring multiple UUID headers" \
                        % lineno,
                        file=sys.stderr)

                try:
                    self.uuid = uuid.UUID(line)
                except ValueError:
                    print("Line %d: ignoring badly formed UUID %r" \
                        % (lineno, line),
                        file=sys.stderr)
                    self.comment += line + "\n"
            else:
                try:
                    key, val = re.split(self.RE_KEYVAL, line, 1)
                except ValueError:
                    print("Line %d: could not parse line %r" \
                        % (lineno, line),
                        file=sys.stderr)
                    self.comment += line + "\n"
                    continue

                if val == "<private>":
                    # trying to load a safe dump
                    print("Line %d: lost private data, you're fucked" \
                        % lineno,
                        file=sys.stderr)
                    val = "<private[data lost]>"
                    self._broken = True
                elif val.startswith("<base64> "):
                    nval = val[len("<base64> "):]
                    nval = base64.b64decode(nval)
                    try:
                        val = nval.decode("utf-8")
                    except UnicodeDecodeError:
                        pass
                elif val.startswith("<wrapped> "):
                    nval = val[len("<wrapped> "):]
                    try:
                        nval = unwrap_secret(nval)
                        val = nval
                        #val = nval.decode("utf-8")
                    except UnicodeDecodeError:
                        pass
                elif key.startswith("date.") and val in {"now", "today"}:
                    val = time.strftime("%Y-%m-%d")

                key = translate_attr(key)

                if key in self.attributes:
                    self.attributes[key].append(val)
                else:
                    self.attributes[key] = [val]

            lineno += 1

        if not self.name:
            self.name = "(Unnamed)"

        return self

    # Export

    def dump(self, storage=False, conceal=True, show_contents=True,
             color=False, itemno=None):
        """
        storage:
            output !private data
            output metadata (UUIDs, etc.)
            do not output line numbers
        conceal
            base64-encode private data
        """

        if itemno is None:
            itemno = not storage

        raw = (storage == True) or (conceal == False)

        if color:
            f = lambda arg, fmt: "\033[%sm%s\033[m" % (fmt, arg)
        else:
            f = lambda arg, fmt: arg

        data = ""

        if itemno and self.itemno:
            data += "%s\n" % f("(item %s)" % self.itemno, "38;5;244")

        data += "= %s\n" % f(self.name, "38;5;50")

        if show_contents:
            for line in self.comment.splitlines():
                data += "%s%s\n" % (f(";", "38;5;8"), f(line, "38;5;30"))

            if self.uuid:
                data += "\t%s\n" % f("{%s}" % self.uuid, "38;5;8")

            for key in sort_attrs(self):
                for value in self.attributes[key]:
                    key = translate_attr(key)
                    if attr_is_private(key):
                        if storage and conceal:
                            _v = value
                            #value = value.encode("utf-8")
                            value = wrap_secret(value)
                            #value = base64.b64encode(value)
                            #value = value.decode("utf-8")
                            #value = "<base64> %s" % value
                            value = "<wrapped> %s" % value
                            #print("maybe encoding %r as %r" % (_v, value))
                            #value = _v
                        elif not raw:
                            value = "<private>"
                        data += "\t%s: %s\n" % (f(key, "38;5;216"), f(value, "34"))
                    elif attr_is_reflink(key):
                        sub_entry = None
                        value_color = "32"
                        if not raw:
                            try:
                                sub_entry = db.find_by_uuid(value)
                            except KeyError:
                                value_color = "33"
                        if sub_entry:
                            text = f(sub_entry.name, value_color)
                            text += f(" (item %d)" % sub_entry.itemno, "38;5;8")
                        else:
                            text = value
                        data += "\t%s: %s\n" % (f(key, "38;5;188"), text)
                    else:
                        data += "\t%s: %s\n" % (f(key, "38;5;228"), value)

        if self.tags:
            tags = list(self.tags)
            tags.sort()
            line = []
            while tags or line:
                line_len = 8 + sum([len(i) + 2 for i in line])
                if not tags or (line and line_len + len(tags[0]) + 2 > 80):
                    data += "\t+ %s\n" % f(", ".join(line), "38;5;13")
                    line = []
                if tags:
                    line.append(tags.pop(0))

        return data

    def to_structure(self):
        dis = dict()
        dis["_name"] = self.name
        dis["comment"] = self.comment
        dis["data"] = {key: list(val for val in self.attributes[key])
                for key in sort_attrs(self)}
        dis["lineno"] = self.lineno
        dis["tags"] = list(self.tags)
        dis["uuid"] = str(self.uuid)
        return dis

    def __str__(self):
        return self.dump()

    def __bool__(self):
        return bool((self.name and self.name != "(Unnamed)")
                or self.attributes or self.tags or self.comment)

    @property
    def normalized_name(self):
        return re.search(self.RE_COLL, self.name).group(0).lower()

    @property
    def oath_params(self):
        tmp = self.attributes.get("!2fa.oath.psk")
        if not tmp:
            return None

        psk = decode_psk(tmp[0])
        p = OATHParameters(psk)

        tmp = self.attributes.get("2fa.subject",
              self.attributes.get("login"))
        if tmp:
            p.login = tmp[0]
        else:
            p.login = self.name

        tmp = self.attributes.get("2fa.issuer")
        if tmp:
            p.issuer = tmp[0]
        else:
            p.issuer = self.name

        tmp = self.attributes.get("2fa.oath.type")
        if tmp:
            p.otype = tmp[0]

        tmp = self.attributes.get("2fa.oath.digits")
        if tmp:
            p.digits = int(tmp[0])

        tmp = self.attributes.get("2fa.oath.window")
        if tmp:
            p.window = int(tmp[0])

        return p

# }}}

# 'Interactive' {{{

class Interactive(cmd.Cmd):
    def __init__(self, *args, **kwargs):
        cmd.Cmd.__init__(self, *args, **kwargs)
        self.prompt = "\001\033[34m\002" "accdb>" "\001\033[m\002" " "
        self.banner = "Using %s" % db_path

    def emptyline(self):
        pass

    def default(self, line):
        lib.die("unknown command %r" % line.split()[0])

    def _show_entry(self, entry, recurse=False, indent=False, depth=0, **kwargs):
        text = entry.dump(color=sys.stdout.isatty(), **kwargs)
        if indent:
            for line in text.split("\n"):
                print("\t"*depth + line)
        else:
            print(text)
        if recurse:
            for key in entry.attributes:
                if attr_is_reflink(key):
                    for value in entry.attributes[key]:
                        try:
                            sub_entry = db.find_by_uuid(value)
                            self._show_entry(sub_entry,
                                             indent=indent,
                                             depth=depth+1,
                                             **kwargs)
                        except KeyError:
                            pass

    def do_EOF(self, arg):
        """Save changes and exit"""
        return True

    def do_help(self, arg):
        """Print this text"""
        cmds = [k for k in dir(self) if k.startswith("do_")]
        for cmd in cmds:
            doc = getattr(self, cmd).__doc__ or "?"
            print("    %-14s  %s" % (cmd[3:], doc))

    def do_copy(self, arg):
        """Copy password to clipboard"""
        arg = int(arg)

        entry = db.find_by_itemno(arg)
        self._show_entry(entry)
        if "pass" in entry.attributes:
            print("(Password copied to clipboard.)")
            Clipboard.put(entry.attributes["pass"][0])
        else:
            print("No password found!",
                file=sys.stderr)

    def do_dump(self, arg, db=None):
        """Dump the database to stdout (yaml, json, safe)"""
        if db is None:
            db = globals()["db"]

        if arg == "":
            db.dump()
        elif arg == "yaml":
            db.dump_yaml()
        elif arg == "json":
            db.dump_json()
        elif arg == "safe":
            db.dump(storage=False)
        else:
            print("Unsupported export format: %r" % arg,
                file=sys.stderr)

    def do_rgrep(self, arg):
        """Search for entries and export their full contents"""
        return self.do_grep(arg, full=True)

    def do_ls(self, arg):
        """Search for entries and list their names"""
        return self.do_grep(arg, ls=True)

    def do_grep(self, arg, full=False, ls=False):
        """Search for entries"""

        tty = sys.stdout.isatty()

        if tty:
            f = lambda arg, fmt: "\033[%sm%s\033[m" % (fmt, arg)
        else:
            f = lambda arg, fmt: arg

        if full and not tty:
            print(db._modeline)

        filter = Filter._cli_compile(arg)
        results = db.find(filter)

        num = 0
        for entry in results:
            if ls:
                name = entry.name
                user = entry.attributes.get("login",
                       entry.attributes.get("email", []))
                if user:
                    name += f(" (%s)" % ellipsize(user[0], 18), "38;5;244")
                print("%5d │ %s" % (entry.itemno, name))
            elif full:
                print(entry.dump(color=tty, storage=True, conceal=False, itemno=tty))
            else:
                print(entry.dump(color=tty))
            num += 1

        if sys.stdout.isatty():
            print("(%d %s matching '%s')" % \
                (num, ("entry" if num == 1 else "entries"), filter))

    def do_convert(self, arg):
        """Read entries from stdin and dump to stdout"""

        newdb = Database()
        newdb.parseinto(sys.stdin)
        self.do_dump(arg, newdb)

    def do_merge(self, arg):
        """Read entries from stdin and merge to main database"""

        newdb = Database()
        outdb = Database()

        newdb.parseinto(sys.stdin)

        for newentry in newdb:
            if newentry._broken:
                print("(warning: skipped broken entry)", file=sys.stderr)
                print(newentry.dump(storage=True), file=sys.stderr)
                continue

            try:
                entry = db.replace(newentry)
            except KeyError:
                entry = db.add(newentry)
            outdb.add(entry)

        db.modified = True

        self.do_dump("", outdb)

    def do_reveal(self, arg):
        """Display entry (including sensitive information)"""
        for entry in Filter._cli_compile_and_search(arg):
            self._show_entry(entry, recurse=True, conceal=False)

    def do_show(self, arg):
        """Display entry (safe)"""
        for entry in Filter._cli_compile_and_search(arg):
            self._show_entry(entry)

    def do_rshow(self, arg):
        """Display entry (safe, recursive)"""
        for entry in Filter._cli_compile_and_search(arg):
            self._show_entry(entry, recurse=True, indent=True)

    def do_qr(self, arg):
        """Display the entry's OATH PSK as a Qr code"""
        for entry in Filter._cli_compile_and_search(arg):
            self._show_entry(entry)
            params = entry.oath_params
            if params is None:
                print("\t(No OATH preshared key for this entry.)")
            else:
                uri = params.make_uri()
                _debug("Qr code for %r" % uri)
                with subprocess.Popen(["qrencode", "-tUTF8", uri],
                                      stdout=subprocess.PIPE) as proc:
                    for line in proc.stdout:
                        print("\t" + line.decode("utf-8"), end="")
                print()

    def do_totp(self, arg):
        """Generate an OATH TOTP response"""
        for entry in Filter._cli_compile_and_search(arg):
            params = entry.oath_params
            if params:
                otp = params.generate()
                print(otp)
            else:
                print("(No OATH preshared key for this entry.)", file=sys.stderr)
                sys.exit(1)

    def do_t(self, arg):
        """Copy OATH TOTP response to clipboard"""
        items = list(Filter._cli_compile_and_search(arg))
        if len(items) > 1:
            lib.die("too many arguments")
        entry = items[0]
        self._show_entry(entry)
        params = entry.oath_params
        if params:
            otp = params.generate()
            Clipboard.put(str(otp))
            print("; OATH response copied to clipboard")
        else:
            print("(No OATH preshared key for this entry.)", file=sys.stderr)
            sys.exit(1)

    def do_touch(self, arg):
        """Rewrite the accounts.db file"""
        db.modified = True

    def do_sort(self, arg):
        """Sort and rewrite the database"""
        db.sort()
        db.modified = True

    def do_tags(self, arg):
        """List all tags used by the database's entries"""
        for tag in sorted(db.tags()):
            print(tag)

    def do_retag(self, arg):
        """Rename tags on all entries"""
        tags = shlex.split(arg)

        new_tags = {t[1:] for t in tags if t.startswith("+")}
        old_tags = {t[1:] for t in tags if t.startswith("-")}
        bad_args = [t for t in tags if not (t.startswith("+") or t.startswith("-"))]

        if bad_args:
            lib.die("bad arguments: %r" % bad_args)
        elif not old_tags:
            lib.die("no old tags specified")

        query = "OR " + " ".join(["+%s" % tag for tag in old_tags])
        items = Filter._compile_and_search(query)
        num   = 0

        for entry in items:
            entry.tags -= old_tags
            entry.tags |= new_tags
            num += 1
            self._show_entry(entry, itemno=False, show_contents=False)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        db.modified = True

    def do_tag(self, arg):
        """Add or remove tags to an entry"""
        query, *tags = shlex.split(arg)

        add_tags = {t[1:] for t in tags if t.startswith("+")}
        rem_tags = {t[1:] for t in tags if t.startswith("-")}
        bad_args = [t for t in tags if not (t.startswith("+") or t.startswith("-"))]

        if bad_args:
            lib.die("bad arguments: %r" % bad_args)

        items = Filter._compile_and_search(query)
        tags  = set(tags)
        num   = 0

        for entry in items:
            entry.tags |= add_tags
            entry.tags -= rem_tags
            num += 1
            self._show_entry(entry, itemno=False, show_contents=False)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        db.modified = True

    def do_set(self, arg):
        """Change attributes of an entry"""
        query, *args = shlex.split(arg)
        num = 0

        changes = Changeset(args, key_alias=attr_names)
        for entry in Filter._compile_and_search(query):
            changes.apply_to(entry.attributes)
            num += 1
            self._show_entry(entry)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        db.modified = True

    def do_comment(self, arg):
        query, *args = shlex.split(arg)
        num = 0

        changes = TextChangeset(args)
        for entry in Filter._compile_and_search(query):
            entry.comment = changes.apply(entry.comment)
            num += 1
            self._show_entry(entry)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        db.modified = True

    def do_rm(self, arg):
        """Delete an entry"""
        for entry in Filter._cli_compile_and_search(arg):
            entry.deleted = True
            self._show_entry(entry)

        db.modified = True

    do_c     = do_copy
    do_g     = do_grep
    do_re    = do_reveal
    do_s     = do_show
    do_w     = do_touch

# }}}

# site-specific backup functions {{{

def db_git_backup(db):
    db_dir = os.path.dirname(db.path)
    repo_dir = os.path.join(db_dir, ".git")

    if not os.path.exists(repo_dir):
        subprocess.call(["git", "-C", db_dir, "init"])

    with open("/dev/null", "r+b") as null_fh:
        subprocess.call(["git", "-C", db_dir,
                         "commit", "-m", "snapshot", db.path],
                        stdout=null_fh)

def db_gpg_backup(db, backup_path):
    if backup_path == db.path:
        return

    with open(backup_path, "wb") as backup_fh:
        with subprocess.Popen(["gpg", "--encrypt", "--no-encrypt-to"],
                              stdin=subprocess.PIPE,
                              stdout=backup_fh) as proc:
            with TextIOWrapper(proc.stdin, "utf-8") as backup_in:
                db.dump(backup_in)

# }}}

db_path = os.environ.get("ACCDB", os.path.expanduser("~/accounts.db.txt"))

db_backup_path = os.path.expanduser("~/Dropbox/Notes/Personal/accounts.gpg")

ss = SecretStore(key=open("/mnt/keycard/grawity/accdb.key", "rb").read())

try:
    db = Database.from_file(db_path)
except FileNotFoundError:
    db = Database()
    db.path = db_path
    if sys.stderr.isatty():
        print("(Database is empty.)", file=sys.stderr)

interp = Interactive()

if len(sys.argv) > 1:
    interp.onecmd(subprocess.list2cmdline(sys.argv[1:]))
else:
    interp.cmdloop()

if db.modified and not debug:
    db.flush()

    if "backup" in db.flags:
        db_git_backup(db)
        db_gpg_backup(db, db_backup_path)

# vim: fdm=marker
