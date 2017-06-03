import sys
from collections import OrderedDict

from .entry import *

# 'Database' {{{

class Database(object):
    SUPPORTED_FEATURES = {
        "b64value",
        "encrypted",
    }

    def __init__(self):
        self.count = 0
        self.path = None
        self.sec = None
        self.header = OrderedDict()
        self.modeline = "; vim: ft=accdb:"
        self.entries = dict()
        self.order = list()
        self.modified = False
        self.readonly = False
        self.options = set()
        self.features = set()

    # Import

    @classmethod
    def from_file(self, path, sec):
        db = self()
        db.path = path
        db.sec = sec
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
        entry = None
        header = True

        for line in fh:
            lineno += 1
            if line.startswith("; vim:"):
                self.modeline = line.strip()
            elif line.startswith("; dbflags:"):
                key, val = line[2:].strip().split(": ", 1)
                self.options = split_tags(val)
            elif line.strip() == ";; end":
                pass
            elif line.startswith(";; "):
                if entry is None:
                    try:
                        key, val = line[3:].strip().split(": ", 1)
                    except ValueError:
                        Core.err("line %d: malformed header: %r" % (lineno, line))
                        continue
                    if key in {"options", "dbflags"}:
                        self.options = split_tags(val)
                    elif key == "features":
                        self.features = split_tags(val)
                        r = self.features - self.SUPPORTED_FEATURES
                        if r:
                            Core.die("line %d: unsupported features %r are used in this file" % (lineno, r))
                    elif key == "dek":
                        self.sec.set_wrapped_dek(val)
                    else:
                        self.header[key] = val
                else:
                    Core.warn("line %d: header after data: %r" % (lineno, line))
            elif line.startswith("="):
                if header:
                    if (not self.sec.dek_cipher) and ("encrypted" in self.features):
                        Core.die("database encrypted but DEK not found in header")
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

        if (not self.sec.dek_cipher) and ("encrypt" in self.options):
            Core.notice("generating data encryption key")
            self.sec.generate_dek()
            self.features.add("encrypted")
            self.options.remove("encrypt")

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

    def has_uuid(self, uuid_str):
        try:
            uuid_parsed = uuid.UUID(uuid_str)
            return uuid_parsed in self.entries
        except:
            return False

    def find(self, filter):
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

    def _get_header(self):
        header = self.header.copy()
        if self.sec.dek_cipher:
            header["dek"] = self.sec.get_wrapped_dek()
        return header

    def dump_header(self, fh):
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
            print(";; %s: %s" % (key, val), file=fh)
        if tty:
            fh.write("\033[m")
        print(file=fh)

    def dump(self, fh=sys.stdout):
        self.dump_header(fh)
        for entry in self:
            if not entry.deleted:
                print(entry.dump(storage=True), file=fh)
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

# }}}
