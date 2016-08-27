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
            elif op in {"ITEM", "item"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'ITEM'")
                return ItemNumberFilter(args[0])
            elif op in {"ITEMRANGE", "itemrange"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'ITEMRANGE'")
                return ItemNumberRangeFilter(args[0])
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
        elif op.startswith("+"):
            return TagFilter(op[1:])
        elif op.isdecimal():
            return ItemNumberFilter(op)
        elif re.match(r"^[0-9,-]+$", op):
            return ItemNumberRangeFilter(op)
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
        Core.debug("compiling pattern %r", pattern)

        func = None

        if pattern == "*":
            func = ConstantFilter(True)
        elif pattern.startswith("@"):
            if "=" in pattern:
                attr, glob = pattern[1:].split("=", 1)
                attr = translate_attr(attr)
                if attr_is_reflink(attr) and glob.startswith("#"):
                    try:
                        value = db.expand_attr_cb(attr, glob)
                        Core.trace("-- expanded match value %r to %r" % (glob, value))
                        func = lambda entry: value in entry.attributes.get(attr, [])
                        Core.trace("-- compiled to (%r in entry[%r])" % (value, attr))
                    except IndexError:
                        Core.trace("-- failed to expand match value %r" % glob)
                        func = ConstantFilter(False)
                else:
                    regex = re_compile_glob(glob)
                    func = lambda entry: any(regex.match(v)
                                             for v in entry.attributes.get(attr, []))
                    Core.trace("-- compiled to (entry[%r] =~ %r)" % (attr, regex))
            elif "~" in pattern:
                attr, regex = pattern[1:].split("~", 1)
                attr = translate_attr(attr)
                try:
                    regex = re.compile(regex, re.I | re.U)
                except re.error as e:
                    Core.die("invalid regex %r (%s)" % (regex, e))
                func = lambda entry: any(regex.search(v)
                                         for v in entry.attributes.get(attr, []))
                Core.trace("-- compiled to (entry[%r] =~ %r)" % (attr, regex))
            elif "<" in pattern:
                attr, match = pattern[1:].split("<", 1)
                if attr.startswith("date."):
                    func = lambda entry: any(date_cmp(v, match) < 0
                                             for v in entry.attributes.get(attr, []))
                    Core.trace("-- compiled to (entry[%r] < %r)" % (attr, match))
                else:
                    Core.die("unsupported operator '%s<'" % attr)
            elif ">" in pattern:
                attr, match = pattern[1:].split(">", 1)
                if attr.startswith("date."):
                    func = lambda entry: any(date_cmp(value, match) > 0
                                             for value in entry.attributes.get(attr, []))
                    Core.trace("-- compiled to (entry[%r] > %r)" % (attr, match))
                else:
                    Core.die("unsupported operator '%s>'" % attr)
            elif "*" in pattern:
                regex = re_compile_glob(pattern[1:])
                func = lambda entry: any(regex.match(k) for k in entry.attributes)
                Core.trace("-- compiled to (entry.attrs =~ %r)" % regex)
            else:
                attr = translate_attr(pattern[1:])
                func = lambda entry: attr in entry.attributes
                Core.trace("-- compiled to (%r in entry)" % attr)
        elif pattern.startswith("~"):
            try:
                regex = re.compile(pattern[1:], re.I | re.U)
            except re.error as e:
                Core.die("invalid regex %r (%s)" % (pattern[1:], e))
            func = lambda entry: any(regex.search(v) for v in entry.names)
            Core.trace("-- compiled to (entry.names =~ %r)" % regex)
        elif pattern.startswith("="):
            match = pattern[1:].casefold()
            func = lambda entry: any(v.casefold() == match for v in entry.names)
            Core.trace("-- compiled to (%r in entry.names)" % match)
        elif pattern.startswith(":"):
            if pattern == ":expired":
                func = ConjunctionFilter(
                    Filter.compile(db, "NOT +expired"),
                    Filter.compile(db, "@date.expiry<now+30")
                )
            elif pattern == ":untagged":
                func = lambda entry: not len(entry.tags)
                Core.trace("-- compiled to (entry.tags is empty)")
            else:
                Core.die("unrecognized pattern %r" % pattern)
        elif pattern.startswith("{"):
            func = ItemUuidFilter(pattern)
        else:
            if "*" not in pattern:
                pattern = "*" + pattern + "*"
            regex = re_compile_glob(pattern)
            func = lambda entry: any(regex.search(v) for v in entry.names)
            Core.trace("-- compiled to (entry.names =~ %r)" % regex)

        return func

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

class TagFilter(Filter):
    def __init__(self, pattern):
        self.value = pattern

        if self.value == "":
            self.test = lambda entry: len(entry.tags) == 0
        elif self.value == "*":
            self.test = lambda entry: len(entry.tags) > 0
        elif "*" in self.value:
            self.regex = re_compile_glob(self.value)
            self.test = lambda entry: any(self.regex.match(tag) for tag in entry.tags)
        else:
            self.test = lambda entry: self.value in entry.tags

    def __str__(self):
        if self.value == "":
            return "(NOT (TAG *))"
        else:
            return "(TAG %s)" % self.value

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
