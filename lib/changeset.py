from .util import _debug

# 'Changeset' {{{

class Changeset(list):
    def __init__(self, args, key_alias=None):
        self._key_alias = key_alias
        _ops = {
            "+": "add",
            "-": "rem",
            ":": "set",
            "«": "copy",
            "<": "move",
            "|": "merge",
        }
        dwim = set()
        for a in args:
            _debug("arg %r", a)
            if a.startswith("-"):
                k = a[1:]
                self.append(("del", k, None))
                _debug("  del-key %r", k)
            elif "=" in a:
                k, v = a.split("=", 1)
                if k[-1] in _ops:
                    op = _ops[k[-1]]
                    k = k[:-1]
                    _debug("  %s: %r = %r", op, k, v)
                else:
                    if k in dwim:
                        op = "add"
                        _debug("  set-value %r = %r, DWIM to add-value", k, v)
                    else:
                        op = "set"
                        _debug("  set-value %r = %r", k, v)
                self.append((op, k, v))
                dwim.add(k)
            else:
                lib.err("syntax error in %r" % a)
        _debug("changes: %r", self)

    def apply_to(self, target):
        for op, k, v in self:
            if self._key_alias:
                k = self._key_alias.get(k, k)
            _debug("changeset: key %r op %r val %r", k, op, v)
            if op == "set":
                target[k] = [v]
            elif op == "add":
                if k not in target:
                    target[k] = [v]
                if v not in target[k]:
                    target[k].append(v)
            elif op == "rem":
                if k not in target:
                    continue
                if v in target[k]:
                    target[k].remove(v)
            elif op == "copy":
                if self._key_alias:
                    v = self._key_alias.get(v, v)
                if v in target:
                    target[k] = target[v][:]
                else:
                    if k in target:
                        del target[k]
            elif op == "move":
                if self._key_alias:
                    v = self._key_alias.get(v, v)
                if v in target:
                    target[k] = target[v]
                    del target[v]
                else:
                    if k in target:
                        del target[k]
            elif op == "merge":
                if self._key_alias:
                    v = self._key_alias.get(v, v)
                if v not in target:
                    continue
                if k in target:
                    target[k] += [val for val in target[v]
                                  if val not in target[k]]
                else:
                    target[k] = target[v][:]
            elif op == "del":
                if k in target:
                    del target[k]
            else:
                lib.die("unknown changeset operation %r" % op)
        return target

# }}}

# 'TextChangeset' {{{

class TextChangeset(list):
    def __init__(self, args):
        for arg in args:
            _debug("arg %r", arg)
            if arg == "-":
                _debug("  empty");
                self.append(("empty",))
            elif arg.startswith("+"):
                arg = arg[1:]
                _debug("  add-line %r", arg)
                self.append(("append", arg))
            elif arg.startswith("s/"):
                arg = arg[2:]
                if arg.endswith("/"):
                    arg = arg[:-1]
                arg = str_split_escaped(arg, "/", 1)
                if len(arg) == 2:
                    from_re, to_str = arg
                    _debug("  regex %r to %r", from_re, to_str)
                    self.append(("resub", from_re, to_str))
                else:
                    lib.die("not enough parameters: %r" % arg)
            else:
                self.append(("empty",))
                self.append(("append", arg))

    def apply(self, target):
        lines = target.rstrip("\n").split("\n")

        for op, *rest in self:
            _debug("text changeset: op %r rest %r", op, rest)
            if op == "empty":
                lines = []
            elif op == "append":
                lines.append(rest[0])
            elif op == "resub":
                rx = re.compile(rest[0])
                lines = [rx.sub(rest[1], _) for _ in lines]
            else:
                lib.die("unknown operation %r" % op)

        _debug("text changeset: lines %r", lines)
        return "\n".join(lines)

# }}}
