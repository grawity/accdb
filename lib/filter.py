from .string import *
from .util import _debug

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
        for pos, char in enumerate(text):
            if char == "(":
                if depth == 0:
                    if start >= 0:
                        tokens.append(text[start:pos])
                    start = pos+1
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and start >= 0:
                    tokens.append(text[start:pos])
                    start = -1
            elif char in " \t\r\n":
                if depth == 0 and start >= 0:
                    tokens.append(text[start:pos])
                    start = -1
            else:
                if start < 0:
                    start = pos
        if depth == 0:
            if start >= 0:
                tokens.append(text[start:])
            return tokens
        elif depth > 0:
            raise FilterSyntaxError("unclosed '(' (depth %d)" % depth)
        elif depth < 0:
            raise FilterSyntaxError("too many ')'s (depth %d)" % depth)

    @staticmethod
    def compile(pattern):
        tokens = Filter.parse(pattern)
        _debug("parsing filter %r -> %r", pattern, tokens)

        op, *args = tokens
        if len(args) > 0:
            # boolean operators
            if op in {"AND", "and"}:
                filters = [Filter.compile(x) for x in args]
                return ConjunctionFilter(*filters)
            elif op in {"OR", "or"}:
                filters = [Filter.compile(x) for x in args]
                return DisjunctionFilter(*filters)
            elif op in {"NOT", "not"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'NOT'")
                filter = Filter.compile(args[0])
                return NegationFilter(filter)
            # search filters
            elif op in {"ITEM", "item"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'ITEM'")
                return ItemNumberFilter(args[0])
            elif op in {"PATTERN", "pattern"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'PATTERN'")
                return PatternFilter(args[0])
            elif op in {"RANGE", "item"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'RANGE'")
                return ItemNumberRangeFilter(args[0])
            elif op in {"UUID", "uuid"}:
                if len(args) > 1:
                    raise FilterSyntaxError("too many arguments for 'UUID'")
                return ItemUuidFilter(args[0])
            # etc.
            else:
                raise FilterSyntaxError("unknown operator %r in (%s)" % (op, pattern))
        elif " " in op or "(" in op or ")" in op:
            return Filter.compile(op)
        elif op.startswith("#"):
            return ItemNumberFilter(op[1:])
        elif op.startswith("{"):
            return ItemUuidFilter(op)
        elif op.isdecimal():
            return ItemNumberFilter(op)
        elif re.match(r"^[0-9,-]+$", op):
            return ItemNumberRangeFilter(op)
        else:
            return PatternFilter(op)

    @staticmethod
    def _compile_and_search(db, text):
        try:
            filter = Filter.compile(text)
        except FilterSyntaxError as e:
            lib.err("syntax error in filter: %s" % e.args)
            sys.exit(1)
        _debug("compiled filter: %s", filter)
        return db.find(filter)

    @staticmethod
    def _cli_compile(arg):
        args = str_split_qwords(arg)
        try:
            if len(args) > 1:
                arg = "AND"
                for x in args:
                    arg += (" (%s)" if " " in x else " %s") % x
                filters = [Filter.compile(x) for x in args]
                filter = ConjunctionFilter(*filters)
            elif len(args) > 0:
                arg = args[0]
                filter = Filter.compile(arg)
            else:
                arg = "*"
                filter = Filter.compile(arg)
        except FilterSyntaxError as e:
            lib.err("syntax error in filter: %s" % e.args)
            sys.exit(1)
        _debug("compiled filter: %s", filter)
        return filter

    @staticmethod
    def _cli_compile_and_search(db, arg):
        return db.find(Filter._cli_compile(arg))

class PatternFilter(Filter):
    def __init__(self, pattern):
        self.pattern = pattern
        self.func = PatternFilter.compile(self.pattern)

    def test(self, entry):
        if self.func:
            return self.func(entry)

    def __str__(self):
        if isinstance(self.func, Filter):
            return str(self.func)
        else:
            return "(PATTERN %s)" % self.pattern

    @staticmethod
    def compile(pattern):
        _debug("compiling pattern %r", pattern)

        func = None

        if pattern == "*":
            func = lambda entry: True
        elif pattern.startswith("#"):
            func = ItemNumberFilter(pattern[1:])
        elif pattern == "+":
            func = lambda entry: len(entry.tags) == 0
        elif pattern.startswith("+"):
            if pattern[1:] == "*":
                func = lambda entry: len(entry.tags) > 0
            else:
                regex = re_compile_glob(pattern[2:])
                func = lambda entry: any(regex.match(tag) for tag in entry.tags)
        elif pattern.startswith("@"):
            if "=" in pattern:
                attr, glob = pattern[1:].split("=", 1)
                attr = translate_attr(attr)
                regex = re_compile_glob(glob)
                func = lambda entry:\
                    attr in entry.attributes \
                    and any(regex.match(value)
                        for value in entry.attributes[attr])
            elif "~" in pattern:
                attr, regex = pattern[1:].split("~", 1)
                attr = translate_attr(attr)
                try:
                    regex = re.compile(regex, re.I | re.U)
                except re.error as e:
                    lib.die("invalid regex %r (%s)" % (regex, e))
                func = lambda entry:\
                    attr in entry.attributes \
                    and any(regex.search(value)
                        for value in entry.attributes[attr])
            elif "*" in pattern:
                regex = re_compile_glob(pattern[1:])
                func = lambda entry:\
                    any(regex.match(attr) for attr in entry.attributes)
            else:
                attr = translate_attr(pattern[1:])
                func = lambda entry: attr in entry.attributes
        elif pattern.startswith("~"):
            try:
                regex = re.compile(pattern[1:], re.I | re.U)
            except re.error as e:
                lib.die("invalid regex %r (%s)" % (pattern[1:], e))
            func = lambda entry: any(regex.search(value) for value in entry.names)
        elif pattern.startswith("="):
            match = pattern[1:].casefold()
            func = lambda entry: any(value.casefold() == match for value in entry.names)
        elif pattern.startswith("{"):
            func = ItemUuidFilter(pattern)
        else:
            if "*" not in pattern:
                pattern = "*" + pattern + "*"
            regex = re_compile_glob(pattern)
            func = lambda entry: any(regex.search(value) for value in entry.names)

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
        return "(RANGE %s)" % self.pattern

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

# }}}