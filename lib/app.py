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
from .keyring import *
from .string import *

class Cmd():
    def __init__(self, app, db):
        self.app = app
        self.db = db

    def call(self, argv):
        if argv:
            func = getattr(self, "do_%s" % argv[0].replace("-", "_"), None)
            if func:
                func(argv[1:])
            else:
                Core.die("unknown command %r" % argv[0])
        else:
            Core.die("no command given")

    def do_help(self, argv):
        """Print this text"""
        cmds = [k for k in dir(self) if k.startswith("do_")]
        for cmd in cmds:
            doc = getattr(self, cmd).__doc__ or "?"
            print("    %-14s  %s" % (cmd[3:].replace("_", "-"), doc))

    ### Lookup commands (display)

    def do_ls(self, argv):
        """Display entries (names only)"""
        if sys.stdout.isatty():
            f = lambda arg, fmt: "\033[%sm%s\033[m" % (fmt, arg)
        else:
            f = lambda arg, fmt: arg
        for entry in Filter.cli_search_argv(self.db, argv):
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
                            sub_entry = self.db.find_by_uuid(value)
                            self._show_entry(sub_entry, indent=indent,
                                             depth=depth+1, **kwargs)
                        except KeyError:
                            pass

    def do_show(self, argv):
        """Display entries (safe)"""
        for entry in Filter.cli_search_argv(self.db, argv):
            self._show_entry(entry)

    def do_rshow(self, argv):
        """Display entries (safe, recursive)"""
        for entry in Filter.cli_search_argv(self.db, argv):
            self._show_entry(entry, recurse=True, indent=True)

    def do_reveal(self, argv):
        """Display entries (including sensitive information)"""
        for entry in Filter.cli_search_argv(self.db, argv):
            self._show_entry(entry, conceal=False)

    def do_raw(self, argv):
        """Display entries for exporting"""
        self.db.dump_header(sys.stdout)
        for entry in Filter.cli_search_argv(self.db, argv):
            self._show_entry(entry, storage=True, encrypt=False)

    def do_qr(self, argv):
        """Display the entry's OATH PSK as a Qr code"""
        for entry in Filter.cli_search_argv(self.db, argv):
            self._show_entry(entry, show_contents=False)
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

    ### Lookup commands (single-target)

    def do_get_pass(self, argv):
        """Display the 'pass' field of the first matching entry"""
        attr = argv.pop() if argv[-1].startswith("!") else "pass"
        entry = Filter.cli_findfirst_argv(self.db, argv)
        secret = entry.attributes.get(attr)
        if secret:
            if len(secret) > 1:
                Core.notice("entry has %d values for %r, using first" \
                            % (len(secret), attr))
            print(secret[0])
        else:
            Core.err("entry has no %r attribute" % attr)

    def do_copy_pass(self, argv):
        """Copy password to clipboard"""
        attr = argv.pop() if argv[-1].startswith("!") else "pass"
        entry = Filter.cli_findfirst_argv(self.db, argv)
        self._show_entry(entry)
        secret = entry.attributes.get(attr)
        if secret:
            if len(secret) > 1:
                Core.notice("entry has %d values for %r, using first" \
                            % (len(secret), attr))
            Clipboard.put(secret[0])
            Core.info("%r attribute copied to clipboard" % attr)
        else:
            Core.err("entry has no %r attribute" % attr)

    def do_get_totp(self, argv):
        """Generate an OATH TOTP response"""
        entry = Filter.cli_findfirst_argv(self.db, argv, Entry.FILTER_OATH)
        params = entry.oath_params
        if params:
            print(params.generate())
        else:
            Core.err("entry has no OATH PSK")

    def do_copy_totp(self, argv):
        """Copy OATH TOTP response to clipboard"""
        entry = Filter.cli_findfirst_argv(self.db, argv)
        self._show_entry(entry)
        params = entry.oath_params
        if params:
            Clipboard.put(str(params.generate()))
            Core.info("OATH response copied to clipboard")
        else:
            Core.err("entry has no OATH PSK")

    do_get      = do_get_pass
    do_totp     = do_get_totp
    do_c        = do_copy_pass
    do_t        = do_copy_totp

    ### Lookup commands (keyring)

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

        kr = XdgKeyring()

        for entry in Filter.cli_search_argv(self.db, argv):
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
                    attrs = [
                        "xdg:schema", "org.gnome.GVfs.Luks.Password",
                        "gvfs-luks-uuid", entry.attributes["uuid"][0],
                    ]
                elif kind == "pgp":
                    attrs = [
                        "xdg:schema", "org.gnupg.Passphrase",
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
                Core.debug("attrs %r" % attrs)
                if kr.store(label, secret, attrs):
                    Core.info("stored %s secret in keyring" % kind)
                else:
                    Core.err("secret-tool %s failed for %r" % (action, attrs))
            elif action == "clear":
                Core.debug("attrs %r" % attrs)
                if kr.clear(attrs):
                    Core.info("removed matching %s secrets from keyring" % kind)
                else:
                    Core.err("secret-tool %s failed for %r" % (action, attrs))
            else:
                raise ValueError("BUG: unhandled keyring action %r" % action)

    def do_keyring_store(self, argv):
        """Store an entry's password to system keyring"""
        return self._do_keyring_query(argv, "store")

    def do_keyring_forget(self, argv):
        """Remove all secrets matching an entry from system keyring"""
        return self._do_keyring_query(argv, "clear")

    ### Entry modification commands

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
        items = Filter.cli_search_str(self.db, query)
        num   = 0

        for entry in items:
            entry.tags -= old_tags
            entry.tags |= new_tags
            num += 1
            self._show_entry(entry, show_itemno=False, show_contents=False)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        self.db.modified = True

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

        items = Filter.cli_search_str(self.db, query)
        tags  = set(tags)
        num   = 0

        for entry in items:
            entry.tags |= add_tags
            entry.tags -= rem_tags
            num += 1
            self._show_entry(entry, show_itemno=False, show_contents=False)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        self.db.modified = True

    def do_set(self, argv):
        """Change attributes of an entry"""
        try:
            query, *args = argv
        except ValueError:
            Core.die("not enough arguments")

        changes = Changeset(args, key_alias=attr_names)
        num = 0
        for entry in Filter.cli_search_str(self.db, query):
            entry.apply_changeset(changes)
            num += 1
            self._show_entry(entry)

        if sys.stdout.isatty():
            print("(%d %s updated)" % (num, ("entry" if num == 1 else "entries")))

        self.db.modified = True

    def _do_create(self, basearg, args):
        if basearg:
            entry = self.db.find_by_itemno(int(basearg)).clone()
            attrs = []
        else:
            entry = Entry(database=self.db)
            entry.name = args.pop(0)
            attrs = ["date.signup=now"]

        for arg in args:
            if arg.startswith("+"):
                entry.tags.add(arg[1:])
            else:
                attrs.append(arg)

        changes = Changeset(attrs, key_alias=attr_names)
        entry.apply_changeset(changes)

        self.db.add(entry)
        self._show_entry(entry, conceal=False)
        if sys.stdout.isatty():
            print("(entry added)")

        self.db.modified = True

    def do_new(self, argv):
        """Create a new entry with given name and attributes"""
        return self._do_create(None, argv[:])

    def do_clone(self, argv):
        """Create a duplicate of given entry, with different attributes"""
        return self._do_create(argv[0], argv[1:])

    def do_rm(self, argv):
        """Delete an entry"""
        for entry in Filter.cli_search_argv(self.db, argv):
            entry.deleted = True
            self._show_entry(entry)

        self.db.modified = True

    ### Database commands

    def do_dump(self, argv, db=None):
        """Dump the database to stdout (yaml, json, safe)"""
        if db is None:
            db = self.db

        if not argv:
            db.dump()
        elif argv[0] == "yaml":
            db.dump_yaml()
        elif argv[0] == "json":
            db.dump_json()
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
                entry = self.db.replace(newentry)
            except KeyError:
                entry = self.db.add(newentry)
            outdb.add(entry)

        self.db.modified = True

        self.do_dump("", outdb)

    def do_set_features(self, argv):
        feat = set(self.db.features)

        for arg in argv:
            if len(arg) < 2 or arg[0] not in "+-":
                Core.err("invalid parameter %r" % arg)
            elif arg.startswith("+"):
                feat.add(arg[1:])
            elif arg.startswith("-"):
                feat.discard(arg[1:])

        r = feat - self.db.SUPPORTED_FEATURES
        if r:
            Core.die("refusing to enable unsupported features %r" % r)

        self.db.set_encryption("encrypted" in feat)
        self.db.features = feat
        self.db.modified = True

    def do_change_password(self, argv):
        """Set or change the master password (KEK) for database encryption"""
        db = self.db
        if not argv:
            passwd = db.keyring.get_password("Input new master password:")
            if passwd:
                db.change_password(passwd)
                Core.info("master password changed, database is encrypted")
            else:
                Core.warn("password change cancelled")
        elif argv[0] == "--store":
            if db.sec.kek_cipher.key:
                db.keyring.store_kek(db.uuid, db.sec.kek_cipher.key)
                Core.info("master password stored in keyring")
            else:
                Core.err("master password is not enabled for this database")
        elif argv[0] == "--forget":
            db.keyring.clear_kek(db.uuid)
            Core.info("master password cleared from keyring")
        elif argv[0] in {"--remove", "--decrypt"}:
            if "encrypted" in db.features:
                db.change_password(None)
            if "--decrypt" in argv:
                db.set_encryption(False)
                db.modified = True
            if "encrypted" in db.features:
                Core.info("master password disabled (database remains encrypted)")
            else:
                Core.info("database fully decrypted")
        else:
            Core.die("unrecognized args %r" % argv[0])

    def do_touch(self, argv):
        """Rewrite the accounts.db file"""
        self.db.modified = True

    def do_git(self, argv):
        """Invoke 'git' inside the database repository"""
        self.app.run_git(*argv)

    def do_undo(self, argv):
        """Revert the last commit to accounts.db"""
        if self.db.modified:
            Core.die("cannot revert unsaved database")
        self.app.run_git("revert", "--no-edit", "HEAD")

    def do_commit(self, argv):
        """Commit all external changes to accounts.db"""
        self.app.run_git("add", "--all")
        self.app.run_git("commit", *argv)

    def do_sort(self, argv):
        """Sort and rewrite the database"""
        self.db.sort()
        self.db.modified = True

    def do_tags(self, argv):
        """List all tags used by the database's entries"""
        for tag in sorted(self.db.tags()):
            print(tag)

    def do_info(self, argv):
        from pprint import pprint
        print("UUID:", self.db.uuid)
        print("Items:", len(self.db.entries))
        print("Encryption:", bool(self.db.sec.dek_cipher.key))
        print("Master pwd:", bool(self.db.sec.kek_cipher.key))
        print("Compatible options:", " ".join(sorted(self.db.options)))
        print("Incompatible options:", " ".join(sorted(self.db.features)))
        print("Header:")
        self.db.dump_header(sys.stdout)

    def do_parse_filter(self, argv):
        """Parse a filter and dump it as text"""
        print(Filter.cli_compile_argv(self.db, argv))

    do_g        = do_show
    do_grep     = do_show
    do_r        = do_reveal
    do_re       = do_reveal
    do_rgrep    = do_reveal
    do_s        = do_show
    do_chpw     = do_change_password

class AccdbApplication():
    def __init__(self):
        self.db = None

    def db_path(self):
        return os.environ.get("ACCDB",
                              os.path.join(Env.xdg_data_home(),
                                           "nullroute.eu.org",
                                           "accdb",
                                           "accounts.txt"))

    def load_db_from_file(self, db_path):
        Core.debug("loading database from %r" % db_path)
        db = Database()
        db.path = db_path
        db.keyring = default_keyring()
        try:
            fh = open(db_path)
        except FileNotFoundError:
            if sys.stderr.isatty():
                Core.warn("database is empty")
        else:
            db.parseinto(fh)
            fh.close()
        return db

    def run_git(self, *args, **kwargs):
        return subprocess.call(["git", "-C", os.path.dirname(self.db.path), *args],
                               **kwargs)

    def git_backup(self, summary="snapshot"):
        db_dir = os.path.dirname(self.db.path)
        repo_dir = os.path.join(db_dir, ".git")

        if not os.path.exists(repo_dir):
            self.run_git("init")

        self.run_git("commit", "-m", summary, self.db.path,
                     stdout=subprocess.DEVNULL)

        if "autopush" in self.db.options:
            self.run_git("push", "-q")

    def run(self, argv):
        self.db = self.load_db_from_file(self.db_path())

        interp = Cmd(self, self.db)
        interp.call(argv)

        if self.db.modified:
            if not os.environ.get("DRYRUN"):
                self.db.flush()
                if "git" in self.db.options:
                    self.git_backup(summary="accdb %s" % str_join_qwords(argv))
            else:
                Core.notice("discarding changes made in debug mode")
                Core.debug("skipping db.flush()")
                if "git" in self.db.options:
                    Core.debug("skipping Git commit")

def main():
    app = AccdbApplication()
    app.run(sys.argv[1:])
    Core.exit()

if __name__ == "__main__":
    main()

# vim: fdm=marker
