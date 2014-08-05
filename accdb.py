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
import nullroute.oath as xoath

debug = os.environ.get("DEBUG", "")

field_names = {
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
}

field_groups = {
    "object":   ["entity", "host", "uri", "realm"],
    "username": ["login", "login.", "nic-hdl", "principal"],
    "password": ["pass", "!pass"],
    "email":    ["email"],
}

field_order = ["object", "username", "password", "email"]

field_prefix_re = re.compile(r"^\W+")

def trace(msg, *args):
    print("accdb: %s" % msg, *args, file=sys.stderr)

def strip_field_prefix(name):
    return field_prefix_re.sub("", name)

def sort_fields(entry):
    names = []
    for group in field_order:
        for field in field_groups[group]:
            names += sorted([k for k in entry.attributes \
                               if (k == field or (field.endswith(".")
                                                  and k.startswith(field)))],
                            key=strip_field_prefix)
    names += sorted([k for k in entry.attributes if k not in names],
            key=strip_field_prefix)
    return names

def translate_field(name):
    return field_names.get(name, name)

def split_ranges(string):
    for i in string.split():
        for j in i.split(","):
            if "-" in j:
                x, y = j.split("-", 1)
                yield int(x), int(y)+1
            else:
                yield int(j), int(j)+1

def split_tags(string):
    string = string.strip(" ,\n")
    items = re.split(Entry.RE_TAGS, string)
    return set(items)

def expand_range(string):
    items = []
    for m, n in split_ranges(string):
        items.extend(range(m, n))
    return items

def split_kvlist(string):
    items = {}
    for token in string.split():
        if "=" in token:
            k, v = token.split("=", 1)
            items[k] = v
        else:
            items[token] = None
    return items

def re_compile_glob(glob, flags=None):
    if flags is None:
        flags = re.I | re.U
    return re.compile(fnmatch.translate(glob), flags)

def pad(s, c):
    n = len(s)
    if n % c:
        s = s.ljust(n + c - (n % c), "=")
    return s

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
        s = pad(s, 4)
        return base64.b64decode(s)
    else:
        s = s.upper()
        s = s.replace(" ", "")
        s = pad(s, 8)
        return base64.b32decode(s)

class OATHParameters(object):
    def __init__(self, raw_psk, digits=6, otype="totp", window=30,
                 login=None, issuer=None):
        if otype not in {"totp", "dynadot-totp"}:
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
        if debug:
            trace("generating OTP from:", base64.b32encode(self.raw_psk).decode("us-ascii"))

        if self.otype == "totp":
            return oath.TOTP(self.raw_psk, digits=self.digits, window=self.window)
        elif self.otype == "dynadot-totp":
            return xoath.DynadotTOTP(self.raw_psk, digits=6, window=60)
        else:
            lib.err("OATH %r is not supported yet" % self.otype)

def start_editor(path):
    if "VISUAL" in os.environ:
        editor = shlex.split(os.environ["VISUAL"])
    elif "EDITOR" in os.environ:
        editor = shlex.split(os.environ["EDITOR"])
    elif sys.platform == "win32":
        editor = ["notepad.exe"]
    elif sys.platform == "linux2":
        editor = ["vi"]

    editor.append(path)

    proc = subprocess.Popen(editor)

    if sys.platform == "linux2":
        proc.wait()

class FilterSyntaxError(Exception):
    pass

def split_filter(text):
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

def compile_filter(pattern):
    tokens = split_filter(pattern)
    if debug:
        trace("parsing filter %r -> %r" % (pattern, tokens))

    if len(tokens) > 1:
        # boolean operators
        if tokens[0] in {"AND", "and"}:
            filters = [compile_filter(x) for x in tokens[1:]]
            return ConjunctionFilter(*filters)
        elif tokens[0] in {"OR", "or"}:
            filters = [compile_filter(x) for x in tokens[1:]]
            return DisjunctionFilter(*filters)
        elif tokens[0] in {"NOT", "not"}:
            if len(tokens) > 2:
                raise FilterSyntaxError("too many arguments for 'NOT'")
            filter = compile_filter(tokens[1])
            return NegationFilter(filter)
        # search filters
        elif tokens[0] in {"ITEM", "item"}:
            if len(tokens) > 2:
                raise FilterSyntaxError("too many arguments for 'ITEM'")
            return ItemNumberFilter(tokens[1])
        elif tokens[0] in {"PATTERN", "pattern"}:
            if len(tokens) > 2:
                raise FilterSyntaxError("too many arguments for 'PATTERN'")
            return PatternFilter(tokens[1])
        # etc.
        else:
            raise FilterSyntaxError("unknown operator %r in (%s)" % (tokens[0], pattern))
    elif " " in tokens[0] or "(" in tokens[0] or ")" in tokens[0]:
        return compile_filter(tokens[0])
    elif tokens[0].startswith("#"):
        return ItemNumberFilter(tokens[0][1:])
    elif tokens[0].startswith("{"):
        return ItemUuidFilter(tokens[0])
    else:
        return PatternFilter(tokens[0])

def compile_pattern(pattern):
    if debug:
        trace("compiling pattern %r" % pattern)

    func = None

    if pattern == "*":
        func = lambda entry: True
    elif pattern.startswith("#"):
        func = ItemNumberFilter(pattern[1:])
    elif pattern.startswith("+"):
        regex = re_compile_glob(pattern[1:])
        func = lambda entry: any(regex.match(tag) for tag in entry.tags)
    elif pattern.startswith("@"):
        if "=" in pattern:
            attr, glob = pattern[1:].split("=", 1)
            attr = translate_field(attr)
            regex = re_compile_glob(glob)
            func = lambda entry:\
                attr in entry.attributes \
                and any(regex.match(value)
                    for value in entry.attributes[attr])
        elif "~" in pattern:
            attr, regex = pattern[1:].split("~", 1)
            attr = translate_field(attr)
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
            attr = translate_field(pattern[1:])
            func = lambda entry: attr in entry.attributes
    elif pattern.startswith("~"):
        try:
            regex = re.compile(pattern[1:], re.I | re.U)
        except re.error as e:
            lib.die("invalid regex %r (%s)" % (pattern[1:], e))
        func = lambda entry: regex.search(entry.name)
    elif pattern.startswith("{"):
        func = ItemUuidFilter(pattern)
    else:
        if "*" not in pattern:
            pattern = "*" + pattern + "*"
        regex = re_compile_glob(pattern)
        func = lambda entry: regex.match(entry.name)

    return func

class Filter(object):
    def __call__(self, entry):
        return bool(self.test(entry))

class PatternFilter(Filter):
    def __init__(self, pattern):
        self.pattern = pattern
        self.func = compile_pattern(self.pattern)

    def test(self, entry):
        if self.func:
            return self.func(entry)

    def __repr__(self):
        if isinstance(self.func, Filter):
            return repr(self.func)
        else:
            return "(PATTERN %s)" % self.pattern

class ItemNumberFilter(Filter):
    def __init__(self, pattern):
        try:
            self.value = int(pattern)
        except ValueError:
            raise FilterSyntaxError("integer value expected for 'ITEM'")

    def test(self, entry):
        return entry.itemno == self.value

    def __repr__(self):
        return "(ITEM %d)" % self.value

class ItemUuidFilter(Filter):
    def __init__(self, pattern):
        try:
            self.value = uuid.UUID(pattern)
        except ValueError:
            raise FilterSyntaxError("integer value expected for 'UUID'")

    def test(self, entry):
        return entry.uuid == self.value

    def __repr__(self):
        return "(UUID %s)" % self.value

class ConjunctionFilter(Filter):
    def __init__(self, *filters):
        self.filters = list(filters)

    def test(self, entry):
        return all(filter.test(entry) for filter in self.filters)

    def __repr__(self):
        return "(AND %s)" % " ".join(repr(f) for f in self.filters)

class DisjunctionFilter(Filter):
    def __init__(self, *filters):
        self.filters = list(filters)

    def test(self, entry):
        return any(filter.test(entry) for filter in self.filters)

    def __repr__(self):
        return "(OR %s)" % " ".join(repr(f) for f in self.filters)

class NegationFilter(Filter):
    def __init__(self, filter):
        self.filter = filter

    def test(self, entry):
        return not self.filter.test(entry)

    def __repr__(self):
        return "(NOT %r)" % self.filter

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
        self._adduuids = True

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
                if entry:
                    self.add(entry)
                data = line
                lastno = lineno
            else:
                data += line

        if data:
            entry = Entry.parse(data, lineno=lastno)
            if entry:
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

        # Two uuid.UUID objects for the same UUID will also have the same hash.
        # Hence, it is okay to use an uuid.UUID as a dict key. For now, anyway.
        # TODO: Can this be relied upon? Not documented anywhere.
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
                p = "%s (until %s)" % (p.dump(), time.strftime("%Y-%m-%d"))
                entry.attributes["!pass.old"].append(PrivateAttribute(p))

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
            print("(Discarding changes, database read-only)",
                file=sys.stderr)
            return
        if self.path is None:
            return
        #print("(Storing database)", file=sys.stderr)
        self.to_file(self.path)
        self.modified = False

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

                if val.startswith("<private[") and val.endswith("]>"):
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
                        pass # leave the old value assigned
                elif key.startswith("date.") and val in {"now", "today"}:
                    val = time.strftime("%Y-%m-%d")

                key = translate_field(key)

                if self.is_private_attr(key):
                    attr = PrivateAttribute(val)
                else:
                    attr = Attribute(val)

                if key in self.attributes:
                    self.attributes[key].append(attr)
                else:
                    self.attributes[key] = [attr]

            lineno += 1

        if not self.name:
            self.name = "(Unnamed)"

        return self

    def is_private_attr(self, key):
        return key == "pass" or key.startswith("!")

    def is_link_attr(self, key):
        return key.startswith("ref.")

    # Export

    def dump(self, storage=False, conceal=True, color=False, itemno=None):
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

        if color:
            f = lambda arg, fmt: "\033[%sm%s\033[m" % (fmt, arg)
        else:
            f = lambda arg, fmt: arg

        data = ""

        if itemno:
            if self.itemno:
                data += f("(item %d)\n" % self.itemno, "38;5;8")
            elif self.lineno:
                data += f("(line %d)\n" % self.lineno, "38;5;8")

        data += "= %s\n" % f(self.name, "38;5;50")

        for line in self.comment.splitlines():
            data += "%s%s\n" % (f(";", "38;5;8"), f(line, "38;5;30"))

        if self.uuid:
            data += "\t%s\n" % f("{%s}" % self.uuid, "38;5;8")

        for key in sort_fields(self):
            for value in self.attributes[key]:
                if storage or not conceal:
                    value = value.dump()
                if self.is_private_attr(key):
                    if storage and conceal and not value.startswith("<base64> "):
                        value = value.encode("utf-8")
                        value = base64.b64encode(value)
                        value = value.decode("utf-8")
                        value = "<base64> %s" % value
                    data += "\t%s: %s\n" % (f(key, "38;5;216"), f(value, "34"))
                elif self.is_link_attr(key):
                    if not (storage or not conceal):
                        sub_entry = db.find_by_uuid(value)
                        if sub_entry:
                            value = sub_entry.name
                    data += "\t%s: %s\n" % (f(key, "38;5;188"), f(value, "32"))
                else:
                    data += "\t%s: %s\n" % (f(key, "38;5;228"), value)

        if self.tags:
            tags = list(self.tags)
            tags.sort()
            line = []
            while tags or line:
                linelen = 8 + sum([len(i) + 2 for i in line])
                if not tags or (line and linelen + len(tags[0]) + 2 > 80):
                    data += "\t+ %s\n" % f(", ".join(line), "38;5;13")
                    line = []
                if tags:
                    line.append(tags.pop(0))

        return data

    def to_structure(self):
        dis = dict()
        dis["name"] = self.name
        dis["comment"] = self.comment
        dis["data"] = {key: list(val.dump() for val in self.attributes[key])
                for key in sort_fields(self, False)}
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

        psk = decode_psk(tmp[0].dump())
        p = OATHParameters(psk)

        tmp = self.attributes.get("2fa.subject",
              self.attributes.get("login"))
        if tmp:
            p.login = tmp[0].dump()
        else:
            p.login = self.name

        tmp = self.attributes.get("2fa.issuer")
        if tmp:
            p.issuer = tmp[0].dump()
        else:
            p.issuer = self.name

        tmp = self.attributes.get("2fa.oath.type")
        if tmp:
            p.otype = tmp[0].dump()

        tmp = self.attributes.get("2fa.oath.digits")
        if tmp:
            p.digits = int(tmp[0].dump())

        tmp = self.attributes.get("2fa.oath.window")
        if tmp:
            p.window = int(tmp[0].dump())

        return p

class Attribute(str):
    # Nothing special about this class. Exists only for consistency
    # with PrivateAttribute providing a dump() method.

    def dump(self):
        return str.__str__(self)

class PrivateAttribute(Attribute):
    # Safeguard class to prevent accidential disclosure of private values.
    # Inherits a dump() method from Attribute for obtaining the actual data.

    def __repr__(self):
        if self == "<private[data lost]>":
            return self.dump()
        return "<private[%d]>" % len(self)

    def __str__(self):
        if self == "<private[data lost]>":
            return self.dump()
        return "<private[%d]>" % len(self)

class Interactive(cmd.Cmd):
    def __init__(self, *args, **kwargs):
        cmd.Cmd.__init__(self, *args, **kwargs)
        self.prompt = "\001\033[34m\002" "accdb>" "\001\033[m\002" " "
        self.banner = "Using %s" % db_path

    def emptyline(self):
        pass

    def default(self, line):
        lib.die("unknown command %r" % line.split()[0])

    def _show_entry(self, entry, recurse=False, **kwargs):
        print(entry.dump(color=sys.stdout.isatty(), **kwargs))
        if recurse:
            for attr in entry.attributes:
                if attr.startswith("ref."):
                    for value in entry.attributes[attr]:
                        sub_entry = db.find_by_uuid(value)
                        self._show_entry(sub_entry, **kwargs)

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
            Clipboard.put(entry.attributes["pass"][0].dump())
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

    def do_edit(self, arg):
        """Launch an editor"""
        db.flush()
        db.modified = False
        start_editor(db_path)
        return True

    def do_rgrep(self, arg):
        """Search for entries and export their full contents"""
        return self.do_grep(arg, full=True)

    def do_ls(self, arg):
        """Search for entries and list their names"""
        return self.do_grep(arg, ls=True)

    def do_grep(self, arg, full=False, ls=False):
        """Search for entries"""

        tty = sys.stdout.isatty()

        if full and not tty:
            print(db._modeline)

        args = shlex.split(arg)
        try:
            if len(args) > 1:
                arg = "AND"
                for x in args:
                    arg += (" (%s)" if " " in x else " %s") % x
                filters = [compile_filter(x) for x in args]
                filter = ConjunctionFilter(*filters)
            elif len(args) > 0:
                arg = args[0]
                filter = compile_filter(arg)
            else:
                arg = "*"
                filter = compile_filter(arg)
        except FilterSyntaxError as e:
            trace("syntax error in filter:", *e.args)
            sys.exit(1)

        if debug:
            trace("compiled filter:", filter)

        results = db.find(filter)

        num = 0
        for entry in results:
            if entry.deleted:
                continue
            if full:
                print(entry.dump(color=tty, storage=True, conceal=False, itemno=tty))
            elif ls:
                print("%5d │ %s" % (entry.itemno, entry.name))
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
        newdb.parseinto(sys.stdin)

        outdb = Database()

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
        for itemno in expand_range(arg):
            entry = db.find_by_itemno(itemno)
            self._show_entry(entry, recurse=True, conceal=False)

    def do_show(self, arg):
        """Display entry (safe)"""
        for itemno in expand_range(arg):
            entry = db.find_by_itemno(itemno)
            self._show_entry(entry, recurse=True)

    def do_qr(self, arg):
        """Display the entry's OATH PSK as a Qr code"""
        for itemno in expand_range(arg):
            entry = db.find_by_itemno(itemno)
            self._show_entry(entry)
            params = entry.oath_params
            if params is None:
                print("\t(No OATH preshared key for this entry.)")
            else:
                uri = params.make_uri()
                with subprocess.Popen(["qrencode", "-o-", "-tUTF8", uri],
                                      stdout=subprocess.PIPE) as proc:
                    for line in proc.stdout:
                        print("\t" + line.decode("utf-8"), end="")
                print()

    def do_totp(self, arg):
        """Generate an OATH TOTP response"""
        for itemno in expand_range(arg):
            entry = db.find_by_itemno(itemno)
            params = entry.oath_params
            if params:
                otp = params.generate()
                print(otp)
            else:
                print("(No OATH preshared key for this entry.)", file=sys.stderr)
                sys.exit(1)

    def do_t(self, arg):
        """Copy OATH TOTP response to clipboard"""
        items = expand_range(arg)
        if len(items) > 1:
            lib.die("too many arguments")
        entry = db.find_by_itemno(items[0])
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

    def do_tag(self, arg):
        """Add or remove tags to an entry"""
        arg      = arg.split()
        items    = expand_range(arg[0])
        all_tags = set(arg[1:])

        add_tags = {t[1:] for t in all_tags if t.startswith("+")}
        rem_tags = {t[1:] for t in all_tags if t.startswith("-")}
        bad_args = [t for t in all_tags if not (t.startswith("+") or t.startswith("-"))]

        if bad_args:
            lib.die("bad arguments: %r" % bad_args)

        for item in items:
            entry = db.find_by_itemno(item)
            entry.tags |= add_tags
            entry.tags -= rem_tags
            self._show_entry(entry)

        if sys.stdout.isatty():
            print("(%d %s updated)" % \
                (len(items), ("entry" if len(items) == 1 else "entries")))

        db.modified = True

    do_c    = do_copy
    do_g    = do_grep
    do_re   = do_reveal
    do_s    = do_show
    do_w    = do_touch

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

db_path = os.environ.get("ACCDB",
            os.path.expanduser("~/accounts.db.txt"))

db_newcache_path = os.path.expanduser("~/Private/accounts.cache.txt")
db_oldcache_path = os.path.expanduser("~/Private/accounts.cache.txt~")

db_backup_path = os.path.expanduser("~/Dropbox/Notes/Personal/accdb/accounts.%s.gpg" \
                                    % time.strftime("%Y-%m-%d"))

if os.path.exists(db_path):
    db = Database.from_file(db_path)
else:
    db = Database.from_file(db_newcache_path)
    db.readonly = True
    if sys.stderr.isatty():
        print("(Using read-only cache.)", file=sys.stderr)

interp = Interactive()

if len(sys.argv) > 1:
    line = subprocess.list2cmdline(sys.argv[1:])
    interp.onecmd(line)
else:
    interp.cmdloop()

want_backup = db.modified

db.flush()

if want_backup:
    if "cache" in db.flags and db.path != db_newcache_path:
        try:
            os.rename(db_newcache_path, db_oldcache_path)
        except:
            pass
        db.to_file(db_newcache_path)

    if "backup" in db.flags and db.path != db_backup_path:
        with open(db_backup_path, "wb") as db_backup_fh:
            with subprocess.Popen(["gpg", "--encrypt", "--no-encrypt-to"],
                                  stdin=subprocess.PIPE,
                                  stdout=db_backup_fh) as proc:
                with TextIOWrapper(proc.stdin, "utf-8") as backup_in:
                    db.dump(backup_in)
