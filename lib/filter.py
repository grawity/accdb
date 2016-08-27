from nullroute.core import *
import uuid

from .entry_util import *
from .string import *

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
        quoted = None
        qstart = -1
        Core.debug("parse input: %r" % text)
        for pos, char in enumerate(text):
            #Core.debug("char %r [%d]" % (char, pos))
            if quoted:
                if char == quoted:
                    quoted = None
                    Core.debug("tokens += quoted %r" % text[qstart:pos])
                    tokens.append(text[qstart:pos])
                else:
                    pass
            elif char == "\"":
                if depth == 0:
                    quoted = char
                    qstart = pos+1
            elif char == "(":
                if depth == 0:
                    if start >= 0:
                        # handle "AND(foo)" when there's no whitespace
                        Core.debug("tokens += prefix-word %r" % text[start:pos])
                        tokens.append(text[start:pos])
                    start = pos+1
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and start >= 0:
                    Core.debug("tokens += grouped %r" % text[start:pos])
                    tokens.append(text[start:pos])
                    start = -1
            elif char in " \t\r\n":
                if depth == 0 and start >= 0:
                    Core.debug("tokens += word %r" % text[start:pos])
                    tokens.append(text[start:pos])
                    start = -1
            else:
                if start < 0:
                    start = pos
        Core.debug("after parsing, depth=%r start=%r" % (depth, start))
        if quoted:
            raise FilterSyntaxError("unclosed %r quote" % quoted)
        elif depth > 0:
            raise FilterSyntaxError("unclosed '(' (depth %d)" % depth)
        elif depth < 0:
            raise FilterSyntaxError("too many ')'s (depth %d)" % depth)
        else:
            if start >= 0 and start <= pos:
                Core.debug("tokens += final %r" % text[start:])
                tokens.append(text[start:])
            Core.debug("parse output: %r" % tokens)
            return tokens

    @staticmethod
    def quote(token):
        if "(" in token or ")" in token:
            return "\"%s\"" % token
        elif " " in token:
            return "(%s)" % token
        else:
            return token

    @staticmethod
    def compile(db, pattern):
        tokens = Filter.parse(pattern)
        Core.debug("parsing filter %r -> %r", pattern, tokens)

        op, *args = tokens
        if len(args) > 0:
            # boolean operators
            if op in {"AND", "and", "&"}:
                filters = [Filter.compile(db, x) for x in args]
                return ConjunctionFilter(*filters)
            elif op in {"OR", "or", "|"}:
                filters = [Filter.compile(db, x) for x in args]
                return DisjunctionFilter(*filters)
            elif op in {"NOT", "not", "!"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'NOT'")
                filter = Filter.compile(db, args[0])
                return NegationFilter(filter)
            # search filters
            elif op in {"ATTR", "attr"}:
                if len(args) < 1:
                    raise FilterSyntaxError("not enough arguments for '%r'" % op)
                elif len(args) > 3:
                    raise FilterSyntaxError("too many arguments for '%r'" % op)
                return AttributeFilter(*args)
            elif op in {"ITEM", "item"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'ITEM'")
                return ItemNumberFilter(args[0])
            elif op in {"ITEMRANGE", "itemrange"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'ITEMRANGE'")
                return ItemNumberRangeFilter(args[0])
            elif op in {"NAME", "name"}:
                if len(args) > 2:
                    raise FilterSyntaxError("too many arguments for '%r'" % op)
                return ItemNameFilter(*args)
            elif op in {"PATTERN", "pattern"}:
                return PatternFilter(db, " ".join(args))
            elif op in {"TAG", "tag"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'TAG'")
                return TagFilter(args[0])
            elif op in {"UUID", "uuid"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'UUID'")
                return ItemUuidFilter(args[0])
            # etc.
            elif op in {"TRUE", "true", "FALSE", "false"}:
                raise FilterSyntaxError("too many arguments for %r" % op)
            else:
                Core.debug("unknown operator %r in (%s), assuming AND" % (op, pattern))
                filters = [Filter.compile(db, x) for x in tokens]
                return ConjunctionFilter(*filters)
        # constant filters
        elif op in {"TRUE", "true", "FALSE", "false"}:
            return ConstantFilter(op[0] in "Tt")
        # shortcut syntaxes
        elif " " in op or "(" in op or ")" in op:
            return Filter.compile(db, op)
        elif op.startswith("#"):
            return ItemNumberFilter(op[1:])
        elif op.startswith("{"):
            return ItemUuidFilter(op)
        elif op.startswith("="):
            return ItemNameFilter(":exact", op[1:])
        elif op.startswith("@"):
            return AttributeFilter.compile(db, op[1:])
        elif op.startswith("+"):
            return TagFilter(op[1:])
        elif op.isdecimal():
            return ItemNumberFilter(op)
        elif re.match(r"^[0-9,-]+$", op):
            return ItemNumberRangeFilter(op)
        elif "=" in op:
            return AttributeFilter.compile(db, op)
        else:
            return PatternFilter(db, op)

    @staticmethod
    def _compile_and_search(db, text):
        try:
            filter = Filter.compile(db, text)
        except FilterSyntaxError as e:
            Core.die("syntax error in filter: %s" % e.args)
        Core.debug("compiled filter: %s", filter)
        return db.find(filter)

    @staticmethod
    def _cli_compile(db, argv):
        try:
            if len(argv) > 1:
                filters = [Filter.compile(db, x) for x in argv]
                filter = ConjunctionFilter(*filters)
            elif len(argv) > 0:
                filter = Filter.compile(db, argv[0])
            else:
                filter = Filter.compile(db, "*")
        except FilterSyntaxError as e:
            Core.die("syntax error in filter: %s" % e.args)
        Core.debug("compiled filter: %s", filter)
        return filter

    @staticmethod
    def _cli_compile_and_search(db, arg, fmt=None):
        filter = Filter._cli_compile(db, arg)
        if fmt:
            Core.debug("applying extra filter: %r", fmt)
            filter = Filter.compile(db, fmt % filter)
            Core.debug("recompiled filter: %s", filter)
        return db.find(filter)

class PatternFilter(Filter):
    def __init__(self, db, pattern):
        self.pattern = pattern
        self.func = PatternFilter.compile(db, self.pattern)

    def test(self, entry):
        if self.func:
            return self.func(entry)

    def __str__(self):
        if isinstance(self.func, Filter):
            return str(self.func)
        else:
            return "(PATTERN %s)" % Filter.quote(self.pattern)

    @staticmethod
    def compile(db, pattern):
        Core.debug("PatternFilter: compiling %r", pattern)

        if pattern == "*":
            return ConstantFilter(True)
        elif pattern.startswith("@"):
            return AttributeFilter.compile(db, pattern[1:])
        elif pattern.startswith("~"):
            try:
                return ItemNameFilter(":regex", pattern[1:])
            except re.error as e:
                Core.die("invalid regex %r (%s)" % (pattern[1:], e))
        elif pattern.startswith("="):
            return ItemNameFilter(":exact", pattern[1:])
        elif pattern.startswith(":"):
            if pattern == ":dead":
                return Filter.compile(db, "AND (NOT +dead) @date.shutdown<now+3")
            elif pattern == ":dying":
                return Filter.compile(db, "AND (NOT +dead) @date.shutdown")
            elif pattern == ":expired":
                return Filter.compile(db, "OR"
                                            " (AND (NOT +expired) @date.expiry<now+30)"
                                            " (AND (NOT +dead) @date.shutdown<now+3)")
            elif pattern == ":expiring":
                return Filter.compile(db, "AND (NOT +expired) @date.expiry<now+30")
            elif pattern == ":untagged":
                return Filter.compile(db, "NOT (TAG *)")
            else:
                Core.die("unrecognized pattern %r" % pattern)
        elif pattern.startswith("{"):
            return ItemUuidFilter(pattern)
        else:
            if not is_glob(pattern):
                pattern = "*%s*" % pattern
            return ItemNameFilter(":glob", pattern)

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
        return "(ITEMRANGE %s)" % self.pattern

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

class ItemNameFilter(Filter):
    def __init__(self, *args):
        if len(args) == 1:
            value, = args
            mode = ":glob"
        elif len(args) == 2:
            mode, value = args
        elif len(args) >= 3:
            raise FilterSyntaxError("too many arguments for %r" % "NAME")
        else:
            raise FilterSyntaxError("not enough arguments for %r" % "NAME")

        self.mode = mode
        self.value = value

        if mode == ":exact":
            value = value.casefold()
            self.test = lambda entry: any(v.casefold() == value for v in entry.names)
        elif mode == ":glob":
            regex = re_compile_glob(value)
            self.test = lambda entry: any(regex.search(v) for v in entry.names)
        elif mode == ":regex":
            regex = re.compile(value, re.I | re.U)
            self.test = lambda entry: any(regex.search(v) for v in entry.names)
        else:
            raise FilterSyntaxError("unknown mode %r for %r" % (mode, "NAME"))

    def __str__(self):
        if self.mode == ":glob":
            return "(NAME %s)" % self.value
        else:
            return "(NAME %s %s)" % (self.mode, self.value)

class AttributeFilter(Filter):
    def __init__(self, *args):
        if len(args) == 1:
            mode = ":exact"
            attr, = args
            value = None
        elif len(args) == 2:
            mode, attr = args
            value = None
        elif len(args) == 3:
            attr, mode, value = args
        elif len(args) >= 4:
            raise FilterSyntaxError("too many arguments for %r" % "ATTR")
        else:
            raise FilterSyntaxError("not enough arguments for %r" % "ATTR")

        self.attr = attr
        self.mode = mode
        self.value = value

        if value is None:
            if mode == ":exact":
                self.test = lambda entry: attr in entry.attributes
                Core.trace("compiled to [%r present]" % attr)
            elif mode == ":glob":
                regex = re_compile_glob(attr)
                self.test = lambda entry: any(regex.match(k) for k in entry.attributes)
                Core.trace("compiled to [attrs ~ %r]" % regex)
            elif mode == ":regex":
                regex = re.compile(attr)
                self.test = lambda entry: any(regex.match(k) for k in entry.attributes)
                Core.trace("compiled to [attrs ~ %r]" % regex)
            else:
                raise FilterSyntaxError("unknown attr-mode %r for 'ATTR'" % mode)
        elif attr == "*":
            if mode in {":exact", "="}:
                self.mode = ":exact"
                self.test = lambda entry: any(value in vs
                                              for vs in entry.attributes.values())
                Core.trace("compiled to [any = %r]" % value)
            elif mode in {":glob", "*="}:
                self.mode = ":glob"
                regex = re_compile_glob(value)
                self.test = lambda entry: any(any(regex.search(v) for v in vs)
                                              for vs in entry.attributes.values())
                Core.trace("compiled to [any * %r]" % regex)
            elif mode in {":regex", "~"}:
                self.mode = ":regex"
                regex = re.compile(value, re.I | re.U)
                self.test = lambda entry: any(any(regex.search(v) for v in vs)
                                              for vs in entry.attributes.values())
                Core.trace("compiled to [any ~ %r]" % regex)
        else:
            if mode in {":exact", "="}:
                self.mode = ":exact"
                self.test = lambda entry: value in entry.attributes.get(attr, [])
                Core.trace("compiled to [%r = %r]" % (attr, value))
            elif mode in {":glob", "*="}:
                self.mode = ":glob"
                regex = re_compile_glob(value)
                self.test = lambda entry: any(regex.search(v)
                                              for v in entry.attributes.get(attr, []))
                Core.trace("compiled to [%r * %r]" % (attr, regex))
            elif mode in {":regex", "~"}:
                self.mode = ":regex"
                regex = re.compile(value, re.I | re.U)
                self.test = lambda entry: any(regex.search(v)
                                              for v in entry.attributes.get(attr, []))
                Core.trace("compiled to [%r ~ %r]" % (attr, regex))
            elif mode in {":lt", "<"}:
                self.mode = "<"
                if attr.startswith("date."):
                    self.test = lambda entry: any(date_cmp(v, value) < 0
                                                  for v in entry.attributes.get(attr, []))
                    Core.trace("compiled to [%r < %r]" % (attr, value))
                else:
                    raise FilterSyntaxError("unsupported op %r %r " % (attr, mode))
            elif mode in {":gt", ">"}:
                self.mode = ">"
                if attr.startswith("date."):
                    self.test = lambda entry: any(date_cmp(v, value) > 0
                                                  for v in entry.attributes.get(attr, []))
                    Core.trace("compiled to [%r > %r]" % (attr, value))
                else:
                    raise FilterSyntaxError("unsupported op %r %r " % (attr, mode))
            else:
                raise FilterSyntaxError("unknown value-mode %r for 'ATTR'" % mode)

    def __str__(self):
        if self.value is None:
            return "(ATTR %s %s)" % (self.mode, self.attr)
        else:
            return "(ATTR %s %s %s)" % (self.attr, self.mode, self.value)

    @staticmethod
    def compile(db, arg):
        Core.debug("AttributeFilter: compiling %r", arg)

        if "=" in arg:
            attr, glob = arg.split("=", 1)
            attr = translate_attr(attr)
            if attr_is_reflink(attr) and glob.startswith("#"):
                try:
                    value = db.expand_attr_cb(attr, glob)
                    Core.trace("-- expanded match value %r to %r" % (glob, value))
                    return AttributeFilter(attr, ":exact", value)
                except IndexError:
                    Core.trace("-- failed to expand match value %r" % glob)
                    return ConstantFilter(False)
            elif is_glob(glob):
                return AttributeFilter(attr, ":glob", glob)
            else:
                return AttributeFilter(attr, ":exact", glob)
        elif "~" in arg:
            attr, regex = arg.split("~", 1)
            attr = translate_attr(attr)
            try:
                return AttributeFilter(attr, ":regex", regex)
            except re.error as e:
                Core.die("invalid regex %r (%s)" % (regex, e))
        elif "<" in arg:
            attr, match = arg.split("<", 1)
            return AttributeFilter(attr, "<", match)
        elif ">" in arg:
            attr, match = arg.split(">", 1)
            return AttributeFilter(attr, ">", match)
        elif "*" in arg:
            return AttributeFilter(":glob", arg)
        else:
            attr = translate_attr(arg)
            return AttributeFilter(":exact", attr)

class TagFilter(Filter):
    def __init__(self, *args):
        if len(args) == 1:
            mode = None
            value, = args
        elif len(args) == 2:
            mode, value = args
        elif len(args) >= 3:
            raise FilterSyntaxError("too many arguments for %r" % "TAG")
        else:
            raise FilterSyntaxError("not enough arguments for %r" % "TAG")

        self.mode = mode
        self.value = value

        if mode is None:
            if value == "":
                self.test = lambda entry: len(entry.tags) == 0
            elif value == "*":
                self.test = lambda entry: len(entry.tags) > 0
            elif is_glob(value):
                self.mode = ":glob"
                regex = re_compile_glob(self.value)
                self.test = lambda entry: any(regex.match(t) for t in entry.tags)
            else:
                self.mode = ":exact"
                self.test = lambda entry: value in entry.tags
        else:
            if mode in {":exact", "="}:
                self.mode = ":exact"
                self.test = lambda entry: value in entry.tags
            elif mode in {":glob"}:
                self.mode = ":glob"
                regex = re_compile_glob(value)
                self.test = lambda entry: any(regex.match(t) for t in entry.tags)
            elif mode in {":regex", "~"}:
                self.mode = ":regex"
                regex = re.compile(value, re.I)
                self.test = lambda entry: any(regex.match(t) for t in entry.tags)
            else:
                raise FilterSyntaxError("unknown mode %r for %r" % (mode, "TAG"))

    def __str__(self):
        if self.mode is None:
            if self.value:
                return "(TAG %s)" % self.value
            else:
                return "(NOT (TAG *))"
        else:
            return "(TAG %s %s)" % (self.mode, self.value)

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

class ConstantFilter(Filter):
    def __init__(self, result):
        self.result = bool(result)

    def test(self, entry):
        return self.result

    def __str__(self):
        return "(TRUE)" if self.result else "(FALSE)"

# }}}
