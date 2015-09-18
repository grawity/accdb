# -*- coding: utf-8 -*-
# accdb - account database using human-editable flat files as storage

from __future__ import print_function
import cmd
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from collections import OrderedDict
from io import TextIOWrapper
from nullroute import ui as lib
from . import hotpie as oath

from .changeset import Changeset, TextChangeset
from .clipboard import Clipboard
from .filter import Filter
from .oath_util import OATHParameters
from .string import *
from .util import _debug
from .util import *

# string functions {{{

def split_tags(string):
    string = string.strip(" ,\n")
    items = re.split(Entry.RE_TAGS, string)
    return set(items)

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

# 'SecretStore' {{{

class UnknownAlgorithmError(Exception):
    pass

class SecretStore(object):
    default_algo = "aes-128-cfb"

    def __init__(self, key):
        self.key = key

    def get_key(self, nbits) -> "bytes":
        nbytes = int(nbits >> 3)
        return self.key[:nbytes]

    def wrap(self, clear: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")

        if algo == "none":
            return clear

        elif algo[0] == "aes":
            from Crypto.Cipher import AES

            if algo[1] in {"128", "192", "256"}:
                nbits = int(algo[1])
                key = self.get_key(nbits)

                if algo[2] == "cfb":
                    iv = os.urandom(AES.block_size)
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                    return iv + cipher.encrypt(clear)

        raise UnknownAlgorithmError()

    def unwrap(self, wrapped: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")

        if algo == "none":
            return wrapped

        elif algo[0] == "aes":
            from Crypto.Cipher import AES

            if algo[1] in {"128", "192", "256"}:
                nbits = int(algo[1])
                key = self.get_key(nbits)

                if algo[2] == "cfb":
                    iv = wrapped[:AES.block_size]
                    buf = wrapped[AES.block_size:]
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                    return cipher.decrypt(buf)

        raise UnknownAlgorithmError()

# @clear: (string) plain data
# -> (base64-encoded string) encrypted data

def wrap_secret(clear: "str") -> "base64: str":
    global ss

    if ss:
        algo = ss.default_algo
        clear = clear.encode("utf-8")
        wrapped = ss.wrap(clear, algo)
        wrapped = base64.b64encode(wrapped)
        wrapped = wrapped.decode("utf-8")
        wrapped = "%s;%s" % (algo, wrapped)
        return wrapped
    else:
        lib.die("encryption not available")

# @wrapped: (base64-encoded string) encrypted data
# -> (string) plain data

def unwrap_secret(wrapped):
    global ss

    if ss:
        algo, wrapped = wrapped.split(";", 1)
        wrapped = wrapped.encode("utf-8")
        wrapped = base64.b64decode(wrapped)
        clear = ss.unwrap(wrapped, algo)
        clear = clear.decode("utf-8")
        return clear
    else:
        return wrapped

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
                print("; dbflags: %s" % ", ".join(sorted(self.flags)),
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

    def clone(self):
        new = Entry()
        new.attributes = {k: v[:] for k, v in self.attributes.items()}
        new.comment = self.comment
        new.deleted = self.deleted
        new.name = self.name
        new.tags = set(self.tags)
        return new

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
            elif line.startswith("-- "):
                # per-attribute comments
                pass
                #line = line[3:]
                #if line.startswith("{") and line.endswith("}"):
                #    pass
                #else:
                #    todo
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
                    desc = None
                    if attr_is_private(key):
                        key_fmt = "38;5;216"
                        value_fmt = "34"
                        if conceal:
                            if storage:
                                _v = value
                                #value = value.encode("utf-8")
                                value = wrap_secret(value)
                                #value = base64.b64encode(value)
                                #value = value.decode("utf-8")
                                #value = "<base64> %s" % value
                                value = "<wrapped> %s" % value
                                #print("maybe encoding %r as %r" % (_v, value))
                                #value = _v
                            else:
                                value = "<private>"
                    elif attr_is_reflink(key):
                        key_fmt = "38;5;250"
                        value_fmt = key_fmt
                        if not storage:
                            try:
                                sub_entry = db.find_by_uuid(value)
                            except KeyError:
                                value_fmt = "33"
                            else:
                                desc = "-- %s" % value
                                value = "%d (%s)" % (sub_entry.itemno, sub_entry.name)
                    elif attr_is_metadata(key):
                        key_fmt = "38;5;244"
                        value_fmt = key_fmt
                    else:
                        key_fmt = "38;5;228"
                        value_fmt = ""
                        if key.startswith("date.") and value in {"now", "today"}:
                            value = time.strftime("%Y-%m-%d")

                    data += "\t%s %s\n" % (f("%s:" % key, key_fmt), f(value, value_fmt))
                    if desc and not storage:
                        data += "\t%s\n" % f(desc, "38;5;244")

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
              self.attributes.get("login",
              self.attributes.get("email")))
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
        for entry in Filter._cli_compile_and_search(db, arg):
            self._show_entry(entry, conceal=False)

    def do_show(self, arg):
        """Display entry (safe)"""
        for entry in Filter._cli_compile_and_search(db, arg):
            self._show_entry(entry)

    def do_rshow(self, arg):
        """Display entry (safe, recursive)"""
        for entry in Filter._cli_compile_and_search(db, arg):
            self._show_entry(entry, recurse=True, indent=True)

    def do_qr(self, arg):
        """Display the entry's OATH PSK as a Qr code"""
        for entry in Filter._cli_compile_and_search(db, arg):
            self._show_entry(entry)
            params = entry.oath_params
            if params is None:
                print("\t(No OATH preshared key for this entry.)")
            else:
                uri = params.make_uri()
                _debug("Qr code for %r", uri)
                with subprocess.Popen(["qrencode", "-tUTF8", uri],
                                      stdout=subprocess.PIPE) as proc:
                    for line in proc.stdout:
                        print("\t" + line.decode("utf-8"), end="")
                print()

    def do_totp(self, arg):
        """Generate an OATH TOTP response"""
        for entry in Filter._cli_compile_and_search(db, arg):
            params = entry.oath_params
            if params:
                otp = params.generate()
                print(otp)
            else:
                print("(No OATH preshared key for this entry.)", file=sys.stderr)
                sys.exit(1)

    def do_t(self, arg):
        """Copy OATH TOTP response to clipboard"""
        items = list(Filter._cli_compile_and_search(db, arg))
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
        tags = str_split_qwords(arg)

        new_tags = {t[1:] for t in tags if t.startswith("+")}
        old_tags = {t[1:] for t in tags if t.startswith("-")}
        bad_args = [t for t in tags if not (t.startswith("+") or t.startswith("-"))]

        if bad_args:
            lib.die("bad arguments: %r" % bad_args)
        elif not old_tags:
            lib.die("no old tags specified")

        query = "OR " + " ".join(["+%s" % tag for tag in old_tags])
        items = Filter._compile_and_search(db, query)
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
        query, *tags = str_split_qwords(arg)

        add_tags = {t[1:] for t in tags if t.startswith("+")}
        rem_tags = {t[1:] for t in tags if t.startswith("-")}
        bad_args = [t for t in tags if not (t.startswith("+") or t.startswith("-"))]

        if bad_args:
            lib.die("bad arguments: %r" % bad_args)

        items = Filter._compile_and_search(db, query)
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
        query, *args = str_split_qwords(arg)
        num = 0

        changes = Changeset(args, key_alias=attr_names)
        for entry in Filter._compile_and_search(db, query):
            changes.apply_to(entry.attributes)
            num += 1
            self._show_entry(entry)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        db.modified = True

    def _do_create(self, basearg, args):
        if basearg:
            entry = db.find_by_itemno(int(basearg)).clone()
            attrs = []
        else:
            entry = Entry()
            entry.name = args.pop(0)
            attrs = ["date.signup=now"]

        for arg in args:
            if arg.startswith("+"):
                entry.tags.add(arg[1:])
            else:
                attrs.append(arg)

        changes = Changeset(attrs, key_alias=attr_names)
        changes.apply_to(entry.attributes)

        db.add(entry)
        self._show_entry(entry, conceal=False)
        if sys.stdout.isatty():
            print("(entry added)")

        db.modified = True

    def do_new(self, arg):
        print("<- args", arg)
        args = str_split_qwords(arg)
        print("-> args", args)
        return self._do_create(None, args[:])

    def do_clone(self, arg):
        args = str_split_qwords(arg)
        return self._do_create(args[0], args[1:])

    def do_comment(self, arg):
        query, *args = str_split_qwords(arg)
        num = 0

        changes = TextChangeset(args)
        for entry in Filter._compile_and_search(db, query):
            entry.comment = changes.apply(entry.comment)
            num += 1
            self._show_entry(entry)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        db.modified = True

    def do_rm(self, arg):
        """Delete an entry"""
        for entry in Filter._cli_compile_and_search(db, arg):
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

def db_git_backup(db, summary="snapshot", body=""):
    db_dir = os.path.dirname(db.path)
    repo_dir = os.path.join(db_dir, ".git")

    if not os.path.exists(repo_dir):
        subprocess.call(["git", "-C", db_dir, "init"])

    with open("/dev/null", "r+b") as null_fh:
        subprocess.call(["git", "-C", db_dir,
                         "commit", "-m", summary, "-m", body, db.path],
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

def main():
    global db_path
    global db

    db_path = os.environ.get("ACCDB", os.path.expanduser("~/accounts.db.txt"))

    db_backup_path = os.path.expanduser("~/Dropbox/Notes/Personal/accounts.gpg")

    try:
        ss = SecretStore(key=open("/mnt/keycard/grawity/accdb.key", "rb").read())
    except FileNotFoundError:
        ss = None

    try:
        db = Database.from_file(db_path)
    except FileNotFoundError:
        db = Database()
        db.path = db_path
        if sys.stderr.isatty():
            print("(Database is empty.)", file=sys.stderr)

    interp = Interactive()

    if len(sys.argv) > 1:
        cmd = subprocess.list2cmdline(sys.argv[1:])
        interp.onecmd(cmd)
    else:
        cmd = "[interactive]"
        interp.cmdloop()

    if db.modified and not debug:
        db.flush()

        if "backup" in db.flags:
            db_git_backup(db, summary="accdb %s" % cmd)
            db_gpg_backup(db, db_backup_path)

if __name__ == "__main__":
    main()

# vim: fdm=marker
