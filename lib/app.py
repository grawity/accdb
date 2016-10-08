# -*- coding: utf-8 -*-
# accdb - account database using human-editable flat files as storage

from __future__ import print_function
import os
import re
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
from .xdg_secret import *

# 'SecretStore' {{{

# todo:
#
#   class SecureKeyring - retrieve arbitrary keys from GNOME Keyring or files
#
#   class SecureStorage -
#       obtain key from SecureKeyring or prompt for PBKDF2
#       wrap/unwrap

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

# 'Cmd' {{{

class Cmd(object):
    def call(self, argv):
        if argv:
            func = getattr(self, "do_%s" % argv[0].replace("-", "_"), None)
            if func:
                func(argv[1:])
            else:
                Core.die("unknown command %r" % argv[0])
        else:
            Core.die("no command given")

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

    def do_help(self, argv):
        """Print this text"""
        cmds = [k for k in dir(self) if k.startswith("do_")]
        for cmd in cmds:
            doc = getattr(self, cmd).__doc__ or "?"
            print("    %-14s  %s" % (cmd[3:], doc))

    def do_copy(self, argv):
        """Copy password to clipboard"""
        items = list(Filter._cli_compile_and_search(db, argv))
        if not items:
            Core.die("no entries found")
        elif len(items) > 1:
            Core.notice("using first result out of %d" % len(items))
        entry = items[0]
        self._show_entry(entry)
        if "pass" in entry.attributes:
            print("(Password copied to clipboard.)")
            Clipboard.put(entry.attributes["pass"][0])
        else:
            Core.err("entry has no password")

    def do_dump(self, argv, db=None):
        """Dump the database to stdout (yaml, json, safe)"""
        if db is None:
            db = globals()["db"]

        if not argv:
            db.dump()
        elif argv[0] == "yaml":
            db.dump_yaml()
        elif argv[0] == "json":
            db.dump_json()
        elif argv[0] == "safe":
            db.dump(storage=False)
        else:
            Core.err("export format %r not supported" % argv[0])

    def do_convert(self, argv):
        """Read entries from stdin and dump to stdout"""

        newdb = Database()
        newdb.parseinto(sys.stdin)
        self.do_dump(argv, newdb)

    def do_merge(self, argv):
        """Read entries from stdin and merge to main database"""

        newdb = Database()
        outdb = Database()

        newdb.parseinto(sys.stdin)

        for newentry in newdb:
            if newentry._broken:
                Core.warn("skipped broken entry")
                print(newentry.dump(storage=True), file=sys.stderr)
                continue

            try:
                entry = db.replace(newentry)
            except KeyError:
                entry = db.add(newentry)
            outdb.add(entry)

        db.modified = True

        self.do_dump("", outdb)

    def do_raw(self, argv):
        """Display entries for exporting"""
        db.dump_header(sys.stdout)
        for entry in Filter._cli_compile_and_search(db, argv):
            # TODO: remove conceal=False when wrap_secret is defined
            self._show_entry(entry, storage=True)

    def do_show(self, argv):
        """Display entries (safe)"""
        for entry in Filter._cli_compile_and_search(db, argv):
            self._show_entry(entry)

    do_grep = do_show

    def do_reveal(self, argv):
        """Display entries (including sensitive information)"""
        for entry in Filter._cli_compile_and_search(db, argv):
            self._show_entry(entry, conceal=False)

    def do_rshow(self, argv):
        """Display entries (safe, recursive)"""
        for entry in Filter._cli_compile_and_search(db, argv):
            self._show_entry(entry, recurse=True, indent=True)

    def do_ls(self, argv):
        """Display entries (names only)"""
        if sys.stdout.isatty():
            f = lambda arg, fmt: "\033[%sm%s\033[m" % (fmt, arg)
        else:
            f = lambda arg, fmt: arg
        for entry in Filter._cli_compile_and_search(db, argv):
            name = entry.name
            user = entry.attributes.get("login",
                   entry.attributes.get("username",
                   entry.attributes.get("email", [])))
            line_max = 70
            user_max = line_max // 3
            user_fmt = " (%s)"
            if user:
                user = user[0]
                line_max -= len(user_fmt % "")
                if len(name) + len(user) > line_max:
                    user = ellipsize(user, max(user_max, line_max - len(name)))
                    name = ellipsize(name, line_max - len(user))
                name += f(user_fmt % user, "38;5;244")
            else:
                name = ellipsize(name, line_max)
            print("%5d │ %s" % (entry.itemno, name))

    def do_qr(self, argv):
        """Display the entry's OATH PSK as a Qr code"""
        for entry in Filter._cli_compile_and_search(db, argv):
            self._show_entry(entry)
            if entry.oath_params:
                data = entry.oath_params.make_uri()
            elif entry.wpa_params:
                data = entry.wpa_params.make_uri()
            else:
                data = None

            if data:
                Core.debug("Qr code for %r", data)
                with subprocess.Popen(["qrencode", "-tUTF8", data],
                                      stdout=subprocess.PIPE) as proc:
                    for line in proc.stdout:
                        print("\t" + line.decode("utf-8"), end="")
                print()
            else:
                Core.err("cannot generate Qr code: entry has no WPA PSK (!wifi.psk)")

    def do_totp(self, argv):
        """Generate an OATH TOTP response"""
        for entry in Filter._cli_compile_and_search(db, argv, Entry.FILTER_OATH):
            params = entry.oath_params
            if params:
                otp = params.generate()
                print(otp)
            else:
                Core.err("cannot generate OTP: entry has no OATH PSK (!2fa.oath.psk)")

    def do_t(self, argv):
        """Copy OATH TOTP response to clipboard"""
        items = list(Filter._cli_compile_and_search(db, argv, Entry.FILTER_OATH))
        if not items:
            Core.die("no entries found")
        elif len(items) > 1:
            Core.notice("using first result out of %d" % len(items))
        entry = items[0]
        self._show_entry(entry)
        params = entry.oath_params
        if params:
            otp = params.generate()
            Clipboard.put(str(otp))
            Core.notice("OATH response copied to clipboard")
        else:
            Core.err("cannot generate OTP: entry has no OATH PSK")

    def do_touch(self, argv):
        """Rewrite the accounts.db file"""
        db.modified = True

    def do_git(self, argv):
        call_git(db, *argv)

    def do_undo(self, argv):
        """Revert the last commit to accounts.db"""
        if db.modified:
            Core.die("cannot revert unsaved database")
        call_git(db, "revert", "--no-edit", "HEAD")

    def do_commit(self, argv):
        if db.modified:
            Core.die("cannot commit unsaved database")
        call_git(db, "add", "--all")
        call_git(db, "commit", *argv)

    def do_sort(self, argv):
        """Sort and rewrite the database"""
        db.sort()
        db.modified = True

    def do_tags(self, argv):
        """List all tags used by the database's entries"""
        for tag in sorted(db.tags()):
            print(tag)

    def do_retag(self, argv):
        """Rename tags on all entries"""
        tags = argv

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

    def do_tag(self, argv):
        """Add or remove tags to an entry"""
        try:
            query, *tags = argv
        except ValueError:
            Core.die("not enough arguments")

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

    def do_set(self, argv):
        """Change attributes of an entry"""
        try:
            query, *args = argv
        except ValueError:
            Core.die("not enough arguments")

        changes = Changeset(args, key_alias=attr_names)
        num = 0
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

    def do_new(self, argv):
        return self._do_create(None, argv[:])

    def do_clone(self, argv):
        return self._do_create(argv[0], argv[1:])

    def do_comment(self, argv):
        query, *args = argv
        num = 0

        changes = TextChangeset(args)
        for entry in Filter._compile_and_search(db, query):
            entry.comment = changes.apply(entry.comment)
            num += 1
            self._show_entry(entry)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        db.modified = True

    def do_rm(self, argv):
        """Delete an entry"""
        for entry in Filter._cli_compile_and_search(db, argv):
            entry.deleted = True
            self._show_entry(entry)

        db.modified = True

    def do_parse_filter(self, argv):
        """Parse a filter and dump it as text"""
        print(Filter._cli_compile(db, argv))

    def _entry_kind(self, entry):
        kind = entry.attributes.get("@kind")
        if kind:
            return kind[0]
        elif "luks" in entry.tags:
            return "luks"
        elif "pgp" in entry.tags:
            return "pgp"

    def _do_keyring_query(self, argv, action):
        if action not in {"clear", "search", "lookup", "store"}:
            raise ValueError("unknown keyring action %r" % action)

        for entry in Filter._cli_compile_and_search(db, argv):
            self._show_entry(entry)
            kind = self._entry_kind(entry)

            if action == "store":
                try:
                    label = entry.name
                    secret = entry.attributes["pass"][0]
                except KeyError as e:
                    Core.err("entry has no secret to store (no %s field)" % e)
                    continue

            try:
                if kind == "luks":
                    set_attrs = [
                        "xdg:schema", "org.gnome.GVfs.Luks.Password",
                    ]
                    get_attrs = [
                        "gvfs-luks-uuid", entry.attributes["uuid"][0],
                    ]
                elif kind == "pgp":
                    set_attrs = [
                        "xdg:schema", "org.gnupg.Passphrase",
                    ]
                    get_attrs = [
                        "keygrip", "n/%s" % entry.attributes["fingerprint"][0],
                    ]
                else:
                    Core.err("couldn't determine entry schema (unknown kind %r)" % kind)
                    continue
            except KeyError as e:
                Core.err("entry has no %s field (required for its kind %r)" % (e, kind))
                continue

            if action == "store":
                Core.debug("store entry %r" % label)
                Core.debug("set attrs %r" % set_attrs)
                Core.debug("get attrs %r" % get_attrs)
                if xdg_secret_store(label, secret, [*get_attrs, *set_attrs]):
                    Core.info("stored %s secret in keyring" % kind)
                else:
                    Core.err("secret-tool %s failed for %r" % (action, get_attrs))
            elif action == "search":
                Core.debug("get attrs %r" % get_attrs)
                if xdg_secret_search_stdout(get_attrs):
                    pass
                else:
                    Core.warn("secret-tool %s failed for %r" % (action, get_attrs))
            elif action == "clear":
                Core.debug("get attrs %r" % get_attrs)
                if xdg_secret_clear(get_attrs):
                    Core.info("removed matching %s secrets from keyring" % kind)
                else:
                    Core.err("secret-tool %s failed for %r" % (action, get_attrs))
            else:
                raise ValueError("BUG: unhandled keyring action %r" % action)

    def do_keyring_store(self, argv):
        return self._do_keyring_query(argv, "store")

    def do_keyring_search(self, argv):
        return self._do_keyring_query(argv, "search")

    def do_keyring_forget(self, argv):
        return self._do_keyring_query(argv, "clear")

    do_c     = do_copy
    do_g     = do_grep
    do_re    = do_reveal
    do_rgrep = do_reveal
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
                    Env.xdg_data_home(),
                    "nullroute.eu.org",
                    "accounts.db.txt"))

    db_backup_path = os.path.expanduser("~/Dropbox/Notes/Personal/accounts.gpg")

    try:
        ss = SecretStore(key=open("/mnt/keycard/grawity/accdb.key", "rb").read())
    except FileNotFoundError:
        ss = None

    Core.debug("loading database from %r" % db_path)
    try:
        db = Database.from_file(db_path)
    except FileNotFoundError:
        db = Database()
        db.path = db_path
        if sys.stderr.isatty():
            Core.warn("database is empty")

    interp = Cmd()
    interp.call(sys.argv[1:])

    if db.modified:
        if not Core._in_debug_mode():
            db.flush()
            if "git" in db.flags:
                db_git_backup(db, summary="accdb %s" % str_join_qwords(sys.argv[1:]))
            if "backup" in db.flags:
                db_gpg_backup(db, db_backup_path)
        else:
            Core.notice("discarding changes made in debug mode")
            Core.debug("skipping db.flush()")
            if "git" in db.flags:
                Core.debug("skipping Git commit")
            if "backup" in db.flags:
                Core.debug("skipping GPG backup")

    Core.exit()

if __name__ == "__main__":
    main()

# vim: fdm=marker
