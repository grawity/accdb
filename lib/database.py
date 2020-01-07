from collections import OrderedDict
import sys
import uuid
import time

from .entry import *
from .encryption import CipherInstance, SecureStorage, MessageAuthenticationError

class Database():
    SUPPORTED_FEATURES = {
        "b64value",
        "encrypted",
    }

    def __init__(self):
        self.count = 0
        self.path = None
        self.sec = SecureStorage()
        self.keyring = None
        self.header = OrderedDict()
        self.uuid = None
        self.modeline = "; vim: ft=accdb:"
        self.entries = dict()
        self.order = list()
        self.modified = False
        self.readonly = False
        self.options = set()
        self.features = set()

    # Import

    def _process_header(self):
        header = self.header

        if "uuid" in header:
            self.uuid = uuid.UUID(header["uuid"])
            Core.debug("database has UUID {%s}", self.uuid)
        else:
            self.uuid = uuid.uuid4()
            Core.debug("database doesn't have an UUID; assigned {%s}", self.uuid)

        if "encrypted" in self.features:
            kek = None
            if "dek" in header:
                dek = header["dek"]

            if dek.startswith("none;"):
                Core.debug("found plaintext DEK; setting null KEK")
                self.sec.set_raw_kek(None)
            else:
                if not kek:
                    Core.debug("retrieving KEK for {%s} from keyring", self.uuid)
                    try:
                        kek = self.keyring.lookup_kek(self.uuid)
                    except FileNotFoundError:
                        kek = None
                if not kek:
                    Core.debug("didn't find KEK in keyring; prompting for password")
                    try:
                        passwd = self.keyring.get_password("Input master database password:")
                    except FileNotFoundError:
                        passwd = None
                    if not passwd:
                        Core.die("database encrypted but password not provided")
                    kek = self.sec.kdf(passwd)
                self.sec.set_raw_kek(kek)

            try:
                self.sec.set_wrapped_dek(dek)
            except MessageAuthenticationError:
                Core.debug("DEK unwrap failed; clearing invalid KEK from keyring")
                self.keyring.clear_kek(self.uuid)
                Core.die("master password incorrect")
            else:
                if kek:
                    Core.debug("DEK unwrapped; caching verified KEK in keyring")
                    self.keyring.cache_kek(self.uuid, kek)
                else:
                    Core.debug("DEK not wrapped; we don't have any KEK to cache")

    def _get_header(self):
        header = self.header.copy()

        if self.uuid:
            header["uuid"] = str(self.uuid)

        if "encrypted" in self.features:
            if self.sec.dek_cipher:
                header["dek"] = self.sec.get_wrapped_dek()

        return header

    def set_encryption(self, enable):
        if enable > ("encrypted" in self.features):
            if not self.sec.kek_cipher:
                self.sec.set_raw_kek(None)
            self.sec.generate_dek()
            self.features.add("encrypted")
        elif enable < ("encrypted" in self.features):
            self.sec.dek_cipher = None
            self.features.discard("encrypted")

    def change_password(self, passwd):
        """Enable database encryption and set the KEK from original password"""
        if passwd:
            kek = self.sec.kdf(passwd)
            if self.sec.kek_cipher:
                self.sec.change_raw_kek(kek)
            else:
                self.sec.set_raw_kek(kek)
                self.set_encryption(True)
        else:
            self.sec.change_raw_kek(None)
        self.keyring.clear_kek(self.uuid)
        self.modified = True

    @classmethod
    def parse(self, *args, **kwargs):
        return self().parseinto(*args, **kwargs)

    def parseinto(self, fh):
        data = ""
        lineno = 0
        lastno = 1
        entry = None
        header = True
        A = time.time()

        for line in fh:
            lineno += 1
            if line.startswith("; vim:"):
                self.modeline = line.strip()
            elif line.strip() == ";; end":
                pass
            elif line.startswith(";; "):
                if entry is None:
                    try:
                        key, val = line[3:].strip().split(": ", 1)
                    except ValueError:
                        Core.err("line %d: malformed header: %r" % (lineno, line))
                        continue
                    if key == "options":
                        self.options = split_tags(val)
                    elif key == "features":
                        self.features = split_tags(val)
                        r = self.features - self.SUPPORTED_FEATURES
                        if r:
                            Core.die("line %d: unsupported features %r are used in this file" % (lineno, r))
                    else:
                        self.header[key] = val
                else:
                    Core.warn("line %d: header after data: %r" % (lineno, line))
            elif line.startswith("="):
                if header:
                    self._process_header()
                    header = False
                if data:
                    entry = Entry.parse(data, lineno=lastno, database=self)
                    if entry and not entry.deleted:
                        self.add(entry)
                data = line
                lastno = lineno
            else:
                data += line
        if data:
            entry = Entry.parse(data, lineno=lastno, database=self)
            if entry and not entry.deleted:
                self.add(entry)

        B = time.time()
        Core.trace("processed %d lines in %.5fs", lineno, B-A)
        return self

    def add(self, entry, lineno=None):
        if entry.uuid is None:
            entry.uuid = uuid.uuid4()
        elif entry.uuid in self:
            raise KeyError("Duplicate UUID %s" % entry.uuid)

        entry.itemno = self.count + 1
        entry.db = self
        # XXX: either clone the entry, or show a warning about overwriting these values

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
        entry.db = self
        # XXX: either clone the entry, or show a warning about overwriting these values

        self.entries[entry.uuid] = entry

        return entry

    # Lookup

    def __contains__(self, key):
        return key in self.entries

    def __getitem__(self, key):
        return self.entries[key]

    def find_by_itemno(self, itemno):
        Core.debug("searching item number %r", itemno)
        uuid = self.order[itemno-1]
        entry = self.entries[uuid]
        assert entry.itemno == itemno
        return entry

    def find_by_uuid(self, uuid_str):
        Core.debug("searching UUID %r", uuid_str)
        uuid_parsed = uuid.UUID(uuid_str)
        return self[uuid_parsed]

    def has_uuid(self, uuid_str):
        try:
            uuid_parsed = uuid.UUID(uuid_str)
            return uuid_parsed in self.entries
        except:
            return False

    def find(self, filter):
        Core.debug("searching filter %s", filter)
        for entry in self:
            if filter(entry):
                yield entry

    def expand_attr_cb(self, attr, value):
        if attr_is_reflink(attr) and value and value.startswith("#"):
            try:
                idx = int(value.split()[0][1:])
                entry = self.find_by_itemno(idx)
            except IndexError:
                pass
            except ValueError:
                pass
            else:
                value = "{%s}" % entry.uuid
        elif attr.startswith("date.") and value and (value in {"now", "today"}
                                                     or value.startswith("now+")
                                                     or value.startswith("now-")):
            tmp = date_parse(value)
            value = str(tmp.date())
        return value

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

    def dump_header(self, fh, encrypt=True):
        tty = getattr(fh, "isatty", lambda: True)()
        if tty:
            fh.write("\033[38;5;244m")
        if self.modeline:
            print(self.modeline, file=fh)
        if self.options:
            print(";; options: %s" % ", ".join(sorted(self.options)), file=fh)
        if self.features:
            print(";; features: %s" % ", ".join(sorted(self.features)), file=fh)
        for key, val in self._get_header().items():
            if encrypt == False:
                if key == "dek":
                    kek = self.keyring.lookup_kek(self.uuid)
                    val = CipherInstance(kek).unwrap_bytes(val)
                    val = CipherInstance(None).wrap_bytes(val)
                elif key in {"uuid", "salt"}:
                    continue
            print(";; %s: %s" % (key, val), file=fh)
        if tty:
            fh.write("\033[m")
        print(file=fh)

    def dump(self, fh=sys.stdout, encrypt=True):
        self.dump_header(fh, encrypt=encrypt)
        for entry in self:
            if not entry.deleted:
                print(entry.dump(storage=True, encrypt=encrypt), file=fh)
        print(";; end", file=fh)

    def to_structure(self):
        return {
            "header": dict(self._get_header()),
            "entries": [entry.to_structure() for entry in self],
        }

    def dump_yaml(self, fh=sys.stdout):
        import yaml
        try:
            from yaml import CDumper as Dumper
        except ImportError:
            from yaml import Dumper
        print(yaml.dump(self.to_structure(), Dumper=Dumper), file=fh)

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
            Core.notice("discarding changes, database is read-only")
            return
        if self.path is None:
            return
        self.to_file(self.path)
        self.modified = False
