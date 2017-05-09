import re
import sys
import time
import uuid

from .entry_util import *
from .oath_util import OATHParameters
from .string import *

def split_tags(string):
    string = string.strip(" ,\n")
    items = re.split(Entry.RE_TAGS, string)
    return set(items)

# 'Entry' {{{

class Entry(object):
    RE_TAGS = re.compile(r'\s*,\s*|\s+')
    RE_KEYVAL = re.compile(r'=|: ')

    RE_COLL = re.compile(r'\w.*$')

    FILTER_OATH = "AND %s @!2fa.oath.psk"

    DEFAULT_HIDDEN_ATTRS = ["@*", "!2fa.*", "2fa.oath.*"]

    def __init__(self, database=None):
        self.attributes = dict()
        self.comment = ""
        self.deleted = False
        self.itemno = None
        self.lineno = None
        self.name = None
        self.tags = set()
        self.uuid = None
        self._broken = False
        self.db = database

    def clone(self):
        new = Entry()
        new.attributes = {k: v[:] for k, v in self.attributes.items()}
        new.comment = self.comment
        new.deleted = self.deleted
        new.name = self.name
        new.tags = set(self.tags)
        new.db = self.db
        return new

    # Import

    @classmethod
    def parse(self, *args, **kwargs):
        return self().parseinto(*args, **kwargs)

    def parseinto(self, data, lineno=1, database=None):
        # lineno is passed here for use in syntax error messages
        self.lineno = lineno
        self.db = database

        for line in data.splitlines():
            line = line.lstrip()
            if not line:
                pass
            elif line.startswith("="):
                if self.name:
                    # Ensure that Database only passes us single entries
                    Core.warn("line %d: ignoring multiple name headers" % lineno)
                self.name = line[1:].strip()
            elif line.startswith("+"):
                self.tags |= split_tags(line[1:])
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
                    Core.warn("line %d: ignoring multiple UUID headers" % lineno)
                    continue

                try:
                    self.uuid = uuid.UUID(line)
                except ValueError:
                    Core.warn("line %d: ignoring badly formed UUID %r" % (lineno, line))
                    self.comment += line + "\n"
            elif line.startswith("-- "):
                # per-attribute comments
                pass
            else:
                try:
                    key, val = re.split(self.RE_KEYVAL, line, 1)
                except ValueError:
                    Core.err("line %d: could not parse line %r" % (lineno, line))
                    self.comment += line + "\n"
                    continue

                if val == "<private>":
                    Core.err("line %d: private data has been lost" % lineno)
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
            output private data
            output metadata (UUIDs, etc.)
            do not output line numbers
        conceal
            do not display private data
        """

        if itemno is None:
            itemno = not storage

        if storage:
            conceal = False

        if color:
            f = lambda arg, fmt: "\033[%sm%s\033[m" % (fmt, arg)
        else:
            f = lambda arg, fmt: arg

        paren_fmt = "38;5;244"
        paren_del_fmt = "38;5;202"
        comment_fmt = "38;5;30"
        uuid_fmt = "38;5;8"

        data = ""

        if itemno and self.itemno:
            if self.deleted:
                data += "%s\n" % f("(deleted item %s)" % self.itemno, paren_del_fmt)
            else:
                data += "%s\n" % f("(item %s)" % self.itemno, paren_fmt)

        data += "= %s\n" % f(self.name, "38;5;50")

        if show_contents:
            for line in self.comment.splitlines():
                data += "%s%s\n" % (f(";", uuid_fmt), f(line, comment_fmt))

            if self.uuid:
                data += "\t%s\n" % f("{%s}" % self.uuid, uuid_fmt)

            if conceal:
                hidden_attrs = self.DEFAULT_HIDDEN_ATTRS[:]
                hidden_attrs += self.attributes.get("@hidden", [])
            else:
                hidden_attrs = []
            n_hidden = 0

            for key in sort_attrs(self):
                for value in self.attributes[key]:
                    key = translate_attr(key)
                    desc = None
                    if match_globs(key, hidden_attrs):
                        n_hidden += 1
                        continue
                    elif attr_is_private(key):
                        key_fmt = "38;5;216"
                        value_fmt = "34"
                        if storage:
                            if "encrypt" in self.db.flags:
                                #value = value.encode("utf-8")
                                value = wrap_secret(value)
                                #value = base64.b64encode(value)
                                #value = value.decode("utf-8")
                                value = "<wrapped> %s" % value
                            else:
                                # store the value unencrypted
                                pass
                        elif conceal:
                            value = "<private>"
                    elif attr_is_reflink(key):
                        key_fmt = "38;5;250"
                        value_fmt = key_fmt
                        try:
                            sub_entry = self.db.find_by_uuid(value)
                        except KeyError:
                            value_fmt = "33"
                        except ValueError:
                            value_fmt = "33"
                        else:
                            desc = "#%d (%s)" % (sub_entry.itemno, sub_entry.name)
                            if conceal:
                                value, desc = desc, None
                    elif attr_is_metadata(key):
                        key_fmt = "38;5;244"
                        value_fmt = key_fmt
                    else:
                        key_fmt = "38;5;228"
                        value_fmt = ""
                        if key.startswith("date."):
                            if conceal:
                                value += f(" (%s)" % relative_date(value), paren_fmt)

                    data += "\t%s %s\n" % (f("%s:" % key, key_fmt), f(value, value_fmt))
                    if desc:
                        data += "\t%s\n" % f("-- %s" % desc, "38;5;244")

            if n_hidden:
                data += "\t%s\n" % f("(%s hidden attributes)" % n_hidden, paren_fmt)

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
    def names(self):
        n = [self.name]
        n += self.attributes.get("@aka", [])
        n += self.attributes.get("wifi.essid", [])
        return n

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

        tmp = self.attributes.get("@2fa.subject",
              self.attributes.get("2fa.subject",
              self.attributes.get("login",
              self.attributes.get("username",
              self.attributes.get("email")))))
        if tmp:
            p.login = tmp[0]
        else:
            p.login = self.name

        tmp = self.attributes.get("@2fa.issuer",
              self.attributes.get("2fa.issuer"))
        if tmp:
            p.issuer = tmp[0]
        else:
            p.issuer = self.name

        tmp = self.attributes.get("@2fa.oath.type",
              self.attributes.get("2fa.oath.type"))
        if tmp:
            p.otype = tmp[0]

        tmp = self.attributes.get("@2fa.oath.digits",
              self.attributes.get("2fa.oath.digits"))
        if tmp:
            p.digits = int(tmp[0])

        tmp = self.attributes.get("@2fa.oath.window",
              self.attributes.get("2fa.oath.window"))
        if tmp:
            p.window = int(tmp[0])

        tmp = self.attributes.get("@icon")
        if tmp:
            p.image = tmp[0]

        return p

    @property
    def wpa_params(self):
        essid = self.attributes.get("wifi.essid")
        psk = self.attributes.get("!wifi.psk")
        sec = self.attributes.get("wifi.security", [None])
        hidden = self.attributes.get("wifi.hidden")

        if essid and psk:
            return WiFiParameters(essid[0], psk[0], sec[0], hidden)

    def has_bad_references(self):
        if not self.db:
            return False

        return any(any(not self.db.has_uuid(v) for v in vs)
                   for k, vs in self.attributes.items()
                   if attr_is_reflink(k))

    def sync_names(self, export=False):
        if export:
            self.attributes["@name"] = [self.name]
        else:
            if "@name" in self.attributes:
                self.name = self.attributes["@name"][0]
                del self.attributes["@name"]

    def expand_attr_cb(self, attr, value):
        return self.db.expand_attr_cb(attr, value)

# }}}
