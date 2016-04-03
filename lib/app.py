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
from nullroute.core import Core

from .changeset import Changeset, TextChangeset
from .clipboard import Clipboard
from .database import Database
from .entry import Entry
from .entry_util import *
from .filter import Filter
from .string import *
from .util import _debug
from .util import *

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
        Core.die("encryption not available")

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

# 'Interactive' {{{

class Interactive(cmd.Cmd):
    def __init__(self, *args, **kwargs):
        cmd.Cmd.__init__(self, *args, **kwargs)
        self.prompt = "\001\033[34m\002" "accdb>" "\001\033[m\002" " "
        self.banner = "Using %s" % db_path

    def emptyline(self):
        pass

    def default(self, line):
        Core.die("unknown command %r" % line.split()[0])

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
        items = list(Filter._cli_compile_and_search(db, arg))
        if len(items) > 1:
            Core.die("too many arguments")
        entry = items[0]
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

        filter = Filter._cli_compile(db, arg)
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
            Core.die("too many arguments")
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

    def do_undo(self, arg):
        """Revert the last commit to accounts.db"""
        call_git(db, "revert", "--no-edit", "HEAD")

    def do_git(self, arg):
        args = str_split_qwords(arg)
        call_git(db, *args)

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
            Core.die("bad arguments: %r" % bad_args)
        elif not old_tags:
            Core.die("no old tags specified")

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
            Core.die("bad arguments: %r" % bad_args)

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
            changes.apply_to(entry.attributes, transform_cb=entry.expand_attr_cb)
            entry.sync_names()
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
            entry = Entry(database=db)
            entry.name = args.pop(0)
            attrs = ["date.signup=now"]

        for arg in args:
            if arg.startswith("+"):
                entry.tags.add(arg[1:])
            else:
                attrs.append(arg)

        changes = Changeset(attrs, key_alias=attr_names)
        changes.apply_to(entry.attributes, transform_cb=entry.expand_attr_cb)
        entry.sync_names()

        db.add(entry)
        self._show_entry(entry, conceal=False)
        if sys.stdout.isatty():
            print("(entry added)")

        db.modified = True

    def do_new(self, arg):
        args = str_split_qwords(arg)
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

def call_git(db, *args, **kwargs):
    db_dir = os.path.dirname(db.path)

    subprocess.call(["git", "-C", db_dir] + list(args), **kwargs)

def db_git_backup(db, summary="snapshot", body=""):
    db_dir = os.path.dirname(db.path)
    repo_dir = os.path.join(db_dir, ".git")

    if not os.path.exists(repo_dir):
        call_git(db, "init")

    with open("/dev/null", "r+b") as null_fh:
        call_git(db, "commit", "-m", summary, "-m", body, db.path,
                 stdout=null_fh)

        if "autopush" in db.flags:
            call_git(db, "push", "-q")

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

    db_path = os.environ.get("ACCDB",
                os.path.join(
                    os.environ.get("XDG_DATA_HOME",
                        os.path.expanduser("~/.local/share")),
                    "nullroute.eu.org",
                    "accounts.db.txt"))

    db_backup_path = os.path.expanduser("~/Dropbox/Notes/Personal/accounts.gpg")

    try:
        ss = SecretStore(key=open("/mnt/keycard/grawity/accdb.key", "rb").read())
    except FileNotFoundError:
        ss = None

    _debug("loading database from %r" % db_path)
    try:
        db = Database.from_file(db_path)
    except FileNotFoundError:
        db = Database()
        db.path = db_path
        if sys.stderr.isatty():
            print("(Database is empty.)", file=sys.stderr)

    interp = Interactive()

    if len(sys.argv) > 1:
        cmd = str_join_qwords(sys.argv[1:])
        interp.onecmd(cmd)
    else:
        cmd = "[interactive]"
        interp.cmdloop()

    if db.modified:
        if not debug:
            db.flush()
            if "git" in db.flags:
                db_git_backup(db, summary="accdb %s" % cmd)
            if "backup" in db.flags:
                db_gpg_backup(db, db_backup_path)
        else:
            _debug("skipping db.flush()")
            if "git" in db.flags:
                _debug("skipping Git commit")
            if "backup" in db.flags:
                _debug("skipping GPG backup")

if __name__ == "__main__":
    main()

# vim: fdm=marker
