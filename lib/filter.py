from nullroute.core import Core
import uuid

from .entry_util import *
from .string import *

class FilterSyntaxError(Exception):
    pass

class Filter():
    def __call__(self, entry):
        return bool(self.test(entry))

    @staticmethod
    def parse(text):
        token = ""
        tokens = []
        depth = 0
        start = -1
        esc = False
        Core.trace("parse input: %r" % text)
        for pos, char in enumerate(text):
            if Core._log_level >= Core.LOG_TRACE:
                Core.trace("  [%s] char=%r, pos=%d, start=%r, token=%r",
                           colour_repr(text, start, pos), char, pos, start, token)
            if char == "(" and not esc:
                if depth == 0:
                    if start >= 0:
                        # don't lose the initial "foo" in "foo(bar"
                        Core.trace("    tokens += prefix-word %r" % token)
                        tokens.append(token)
                    start = pos + 1
                    token = ""
                else:
                    token += char
                Core.trace("    found opening paren; incr depth=%r", depth)
                depth += 1
            elif char == ")" and not esc:
                Core.trace("    found closing paren; decr depth=%r", depth)
                depth -= 1
                if depth == 0 and start >= 0:
                    Core.trace("    tokens += grouped %r" % token)
                    tokens.append(token)
                    start = -1
                    token = ""
                else:
                    token += char
            elif char in " \t\r\n" and not esc:
                if depth == 0 and start >= 0:
                    Core.trace("    tokens += word %r" % token)
                    tokens.append(token)
                    start = -1
                    token = ""
                    Core.trace("    found whitespace at d>0; unset start")
                else:
                    token += char
            elif char == "\\" and not esc:
                esc = True
            else:
                if start < 0:
                    start = pos
                    token = ""
                    Core.trace("    found normal char; set start=%r", pos)
                token += char
                esc = False
        if depth > 0:
            raise FilterSyntaxError("unclosed '(' (depth %d)" % depth)
        elif depth < 0:
            raise FilterSyntaxError("too many ')'s (depth %d)" % depth)
        else:
            if start >= 0 and start <= pos:
                Core.trace("    tokens += final %r" % token)
                tokens.append(token)
            Core.trace("parse output: %r" % tokens)
            return tokens

    @staticmethod
    def quote(token):
        if "(" in token or ")" in token:
            return "(%s)" % token.replace("(", "\\(").replace(")", "\\)")
        elif " " in token:
            return "(%s)" % token
        elif token:
            return token
        else:
            return "()"

    @staticmethod
    def compile(db, pattern):
        Core.debug("Filter: compiling %r", pattern)

        tokens = Filter.parse(pattern)
        if not tokens:
            return ConstantFilter(False)
        op, *args = tokens
        Core.trace("  parsed to op=%r args=%r", op, args)
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
                    raise FilterSyntaxError("too many arguments for %r" % op)
                filter = Filter.compile(db, args[0])
                return NegationFilter(filter)
            # search filters
            elif op in {"ATTR", "attr"}:
                if len(args) > 3:
                    raise FilterSyntaxError("too many arguments for %r" % op)
                return AttributeFilter(*args)
            elif op in {"ITEM", "item"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for %r" % op)
                return ItemNumberFilter(*args)
            elif op in {"ITEMRANGE", "itemrange"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for %r" % op)
                return ItemNumberRangeFilter(*args)
            elif op in {"NAME", "name"}:
                if len(args) > 2:
                    raise FilterSyntaxError("too many arguments for %r" % op)
                return ItemNameFilter(*args)
            elif op in {"PATTERN", "pattern"}:
                return PatternFilter(db, " ".join(args))
            elif op in {"TAG", "tag"}:
                if len(args) > 2:
                    raise FilterSyntaxError("too many arguments for %r" % op)
                return TagFilter(*args)
            elif op in {"UUID", "uuid"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for %r" % op)
                return ItemUuidFilter(*args)
            # etc.
            elif op in {"ANY", "any"}:
                if len(args) == 1:
                    mode = ":glob" if is_glob(args[0]) else ":exact"
                    return AnyFilter(mode, *args)
                elif len(args) == 2:
                    return AnyFilter(*args)
                elif len(args) >= 3:
                    raise FilterSyntaxError("too many arguments for %r" % op)
                else:
                    raise FilterSyntaxError("not enough arguments for %r" % op)
            elif op in {"TRUE", "true", "FALSE", "false"}:
                raise FilterSyntaxError("too many arguments for %r" % op)
            elif op.startswith("="):
                Core.debug("unknown operator %r in (%s), trying name match" % (op, pattern))
                return ItemNameFilter(":exact", pattern[1:])
            elif "=" in op or "~" in op:
                Core.debug("unknown operator %r in (%s), trying attribute match" % (op, pattern))
                return AttributeFilter.compile(db, pattern[1:])
            else:
                Core.debug("unknown operator %r in (%s), assuming AND" % (op, pattern))
                filters = [Filter.compile(db, x) for x in tokens]
                return ConjunctionFilter(*filters)
        # constant filters
        elif op in {"TRUE", "true", "FALSE", "false"}:
            return ConstantFilter(op[0] in "Tt")
        # shortcut syntaxes
        elif " " in op or "(" in op or ")" in op:
            Core.debug("whitespace in operator %r in (%s), recursing" % (op, pattern))
            return Filter.compile(db, op)
        elif op.startswith("!"):
            Core.debug("operator with '!' prefix, recursing as (NOT %s)", op[1:])
            return NegationFilter(Filter.compile(db, op[1:]))
        # maybe these *should* be part of PatternFilter
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
        elif op.startswith("?"):
            return AnyFilter(":regex", op[1:])
        elif op.isdecimal():
            return ItemNumberFilter(op)
        elif re.match(r"^[0-9,-]+$", op):
            return ItemNumberRangeFilter(op)
        elif "=" in op[1:] or "~" in op[1:]:
            return AttributeFilter.compile(db, op)
        else:
            Core.debug("no known prefix, trying PatternFilter(%r)" % op)
            return PatternFilter(db, op)

    @staticmethod
    def cli_search_str(db, text):
        return Filter.cli_search_argv(db, [text])

    @staticmethod
    def cli_compile_argv(db, argv):
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
        except re.error as e:
            Core.die("syntax error in regex: %s" % e.args)
        return filter

    @staticmethod
    def cli_search_argv(db, argv, fmt=None):
        filter = Filter.cli_compile_argv(db, argv)
        if fmt:
            Core.debug("applying extra filter: %r", fmt)
            filter = Filter.compile(db, fmt % filter)
        return db.find(filter)

    @staticmethod
    def cli_findfirst_argv(db, argv, fmt=None):
        items = list(Filter.cli_search_argv(db, argv, fmt))
        if not items:
            Core.die("no entries found")
        elif len(items) > 1:
            Core.notice("using first result out of %d" % len(items))
        return items[0]

def AnyFilter(*args):
    return DisjunctionFilter(ItemNameFilter(*args),
                             AttributeFilter(*args),
                             AttributeFilter("*", *args),
                             TagFilter(*args))

class PatternFilter(Filter):
    def __init__(self, db, pattern):
        self.pattern = pattern
        self.func = PatternFilter.compile(db, self.pattern)

    def test(self, entry):
        return self.func(entry)

    def __str__(self):
        if isinstance(self.func, Filter):
            return str(self.func)
        else:
            return "(PATTERN %s)" % Filter.quote(self.pattern)

    @staticmethod
    def compile(db, arg):
        Core.debug("PatternFilter: compiling %r", arg)

        if arg == "*":
            return ConstantFilter(True)
        elif arg.startswith("@"):
            return AttributeFilter.compile(db, arg[1:])
        elif arg.startswith("~"):
            try:
                return ItemNameFilter(":regex", arg[1:])
            except re.error as e:
                Core.die("invalid regex %r (%s)" % (arg[1:], e))
        elif arg.startswith("="):
            return ItemNameFilter(":exact", arg[1:])
        elif arg.startswith(":"):
            if arg == ":active":
                return Filter.compile(db, "NOT :inactive")
            elif arg == ":inactive":
                return Filter.compile(db, "OR +cancelled +dead +expired +gone")
            elif arg == ":dead":
                return Filter.compile(db, "AND (NOT +dead) @date.shutdown<now+3")
            elif arg == ":dying":
                return Filter.compile(db, "AND (NOT +dead) @date.shutdown")
            elif arg == ":expired":
                return Filter.compile(db, "OR"
                                            " (AND (NOT +expired) @date.expiry<now+30)"
                                            " (AND (NOT +dead) @date.shutdown<now+3)")
            elif arg == ":expiring":
                return Filter.compile(db, "AND (NOT +expired) @date.expiry<now+30")
            elif arg == ":untagged":
                return Filter.compile(db, "NOT (TAG *)")
            elif arg == ":badref":
                return lambda entry: entry.has_bad_references()
            else:
                Core.die("unrecognized pattern %r" % arg)
        elif arg.startswith("{"):
            return ItemUuidFilter(arg)
        else:
            return ItemNameFilter(":glob", arg)

class ItemNameFilter(Filter):
    def __init__(self, *args):
        if len(args) == 1:
            mode = ":glob"
            value, = args
        elif len(args) == 2:
            mode, value = args
        elif len(args) >= 3:
            raise FilterSyntaxError("too many arguments for %r" % "NAME")
        else:
            raise FilterSyntaxError("not enough arguments for %r" % "NAME")

        self.mode = mode
        self.value = value

        if mode in {":exact", "="}:
            self.mode = ":exact"
            value = value.casefold()
            self.test = lambda entry: any(v.casefold() == value for v in entry.names)
            Core.trace("compiled to [name = %r]", value)
        elif mode in {":glob", "?"}:
            self.mode = ":glob"
            regex = re_compile_glob(value)
            self.test = lambda entry: any(regex.fullmatch(str(v)) for v in entry.names)
            Core.trace("compiled to [name ~ %r]", regex)
        elif mode in {":regex", "~"}:
            self.mode = ":regex"
            regex = re.compile(value, re.I)
            self.test = lambda entry: any(regex.search(str(v)) for v in entry.names)
            Core.trace("compiled to [name ~ %r]", regex)
        else:
            raise FilterSyntaxError("unknown mode %r for %r" % (mode, "NAME"))

    def __str__(self):
        return "(NAME %s %s)" % (self.mode, Filter.quote(self.value))

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
            if mode in {":exact", "="}:
                self.mode = ":exact"
                self.test = lambda entry: attr in entry.attributes
                Core.trace("compiled to [key %r present]" % attr)
            elif mode in {":glob", "?"}:
                self.mode = ":glob"
                regex = re_compile_glob(attr)
                self.test = lambda entry: any(regex.fullmatch(k) for k in entry.attributes)
                Core.trace("compiled to [keys ~ %r]" % regex)
            elif mode in {":regex", "~"}:
                self.mode = ":regex"
                regex = re.compile(attr, re.I)
                self.test = lambda entry: any(regex.search(k) for k in entry.attributes)
                Core.trace("compiled to [keys ~ %r]" % regex)
            else:
                raise FilterSyntaxError("unknown attr-mode %r for %r" % (mode, "ATTR"))
        elif value == "":
            raise FilterSyntaxError("empty match value after %r" % attr)
        elif attr == "*":
            if mode in {":exact", "="}:
                self.mode = ":exact"
                self.test = lambda entry: any(value in vs
                                              for vs in entry.attributes.values())
                Core.trace("compiled to [values = %r]" % value)
            elif mode in {":glob", "?"}:
                self.mode = ":glob"
                regex = re_compile_glob(value)
                self.test = lambda entry: any(any(regex.fullmatch(str(v)) for v in vs)
                                              for vs in entry.attributes.values())
                Core.trace("compiled to [values ~ %r]" % regex)
            elif mode in {":regex", "~"}:
                self.mode = ":regex"
                regex = re.compile(value, re.I)
                self.test = lambda entry: any(any(regex.search(str(v)) for v in vs)
                                              for vs in entry.attributes.values())
                Core.trace("compiled to [values ~ %r]" % regex)
            else:
                raise FilterSyntaxError("unknown value-mode %r for %r" % (mode, "ATTR"))
        else:
            if mode in {":exact", "="}:
                self.mode = ":exact"
                self.test = lambda entry: value in entry.attributes.get(attr, [])
                Core.trace("compiled to [%r = %r]" % (attr, value))
            elif mode in {":glob", "?"}:
                self.mode = ":glob"
                regex = re_compile_glob(value)
                self.test = lambda entry: any(regex.fullmatch(str(v))
                                              for v in entry.attributes.get(attr, []))
                Core.trace("compiled to [%r ~ %r]" % (attr, regex))
            elif mode in {":regex", "~"}:
                self.mode = ":regex"
                regex = re.compile(value, re.I)
                self.test = lambda entry: any(regex.search(str(v))
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
                raise FilterSyntaxError("unknown value-mode %r for %r" % (mode, "ATTR"))

    def __str__(self):
        if self.value is None:
            return "(ATTR %s %s)" % (self.mode, Filter.quote(self.attr))
        else:
            return "(ATTR %s %s %s)" % (Filter.quote(self.attr), self.mode,
                                        Filter.quote(self.value))

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
                self.mode = ":exact"
                self.test = lambda entry: len(entry.tags) == 0
            elif value == "*":
                self.mode = ":glob"
                self.test = lambda entry: len(entry.tags) > 0
            elif is_glob(value):
                self.mode = ":glob"
                regex = re_compile_glob(self.value)
                self.test = lambda entry: any(regex.fullmatch(t) for t in entry.tags)
            else:
                self.mode = ":exact"
                self.test = lambda entry: value in entry.tags
        else:
            if mode in {":exact", "="}:
                self.mode = ":exact"
                self.test = lambda entry: value in entry.tags
            elif mode in {":glob", "?"}:
                self.mode = ":glob"
                regex = re_compile_glob(value)
                self.test = lambda entry: any(regex.fullmatch(t) for t in entry.tags)
            elif mode in {":regex", "~"}:
                self.mode = ":regex"
                regex = re.compile(value, re.I)
                self.test = lambda entry: any(regex.search(str(t)) for t in entry.tags)
            else:
                raise FilterSyntaxError("unknown mode %r for %r" % (mode, "TAG"))

    def __str__(self):
        if self.value == "":
            return "(NOT %s)" % "(TAG %s)" % "*"
        elif self.value == "*":
            return "(TAG %s)" % self.value
        elif self.mode == ":exact":
            return "(TAG %s)" % Filter.quote(self.value)
        else:
            return "(TAG %s %s)" % (self.mode, Filter.quote(self.value))

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
            raise FilterSyntaxError("malformed value for %r" % "UUID")

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

class ConstantFilter(Filter):
    def __init__(self, result):
        self.result = bool(result)

    def test(self, entry):
        return self.result

    def __str__(self):
        return "(TRUE)" if self.result else "(FALSE)"
