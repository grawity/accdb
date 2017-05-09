from nullroute.core import *

# 'Changeset' {{{

class Changeset(list):
    def __init__(self, args, key_alias=None):
        self._key_alias = key_alias
        _ops = {
            ":": "set",
            "?": "tryset",
            "+": "add",
            "-": "rem",
            "«": "copy",
            "<": "move",
            "|": "merge",
        }
        dwim = set()
        Core.debug("parsing %r", args)
        for a in args:
            Core.debug(" arg %r", a)
            if a.startswith("-"):
                k = a[1:]
                Core.debug("  del-key %r", k)
                if not k:
                    Core.err("empty key name in change %r" % a)
                    continue
                self.append(("del", k, None))
            elif "=" in a:
                k, v = a.split("=", 1)
                if k and k[-1] in _ops:
                    op = _ops[k[-1]]
                    k = k[:-1]
                    Core.debug("  %s: %r = %r", op, k, v)
                else:
                    if k in dwim:
                        op = "add"
                        Core.debug("  set-value %r = %r, DWIM to add-value", k, v)
                    else:
                        op = "set"
                        Core.debug("  set-value %r = %r", k, v)
                if not k:
                    Core.err("empty key name in change %r" % a)
                    continue
                self.append((op, k, v))
                dwim.add(k)
            else:
                Core.err("syntax error in change %r" % a)
        Core.debug("parsed changes: %r", self)

    def apply_to(self, target, transform_cb=None):
        Core.debug("applying to %r", target)
        for op, k, v in self:
            # keep original key, value for use in error messages
            _k, _v = k, v
            if self._key_alias:
                k = self._key_alias.get(k, k)
            if transform_cb:
                v = transform_cb(k, v)
            Core.debug(" key %r op %r val %r", k, op, v)
            if op == "set":
                # set value, discarding previous values
                target[k] = [v]
            elif op == "tryset":
                # set value, but only if k1 has no values
                if k not in target:
                    target[k] == [v]
            elif op == "add":
                # add value if not present (ignore duplicates)
                if k not in target:
                    target[k] = [v]
                elif v not in target[k]:
                    target[k].append(v)
            elif op == "rem":
                # remove value if present
                if k not in target:
                    continue
                elif v in target[k]:
                    target[k].remove(v)
            elif op == "copy":
                # copy/overwrite all values from k1 to k2
                #   - k1: unchanged
                #   - k2: equal to k1
                if self._key_alias:
                    v = self._key_alias.get(v, v)
                if v in target:
                    target[k] = target[v][:]
                else:
                    if k in target:
                        del target[k]
            elif op == "move":
                # move all values from k1 to k2
                #  - k1: deleted after move
                #  - k2: contents of k1 (all previous values discarded)
                if self._key_alias:
                    v = self._key_alias.get(v, v)
                if k == v:
                    Core.err("destination is the same as source: %r = %r" % (_k, _v))
                    continue
                    # note to future self: if this check is not done, then 'del target[v]'
                    #                      can lose the attribute entirely when k == v.
                if v in target:
                    target[k] = target[v]
                    del target[v]
                else:
                    if k in target:
                        del target[k]
            elif op == "merge":
                # copy/merge all values from k1 to k2
                #   - k1: unchanged
                #   - k2: unique values from both (k1 ∪ old_k2)
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
                # delete k1 entirely
                if k in target:
                    del target[k]
            else:
                Core.die("BUG: unknown changeset operation %r" % op)
        return target

# }}}

# 'TextChangeset' {{{

class TextChangeset(list):
    def __init__(self, args):
        Core.debug("parsing %r", args)
        for arg in args:
            Core.debug(" arg %r", arg)
            if arg == "-":
                Core.debug("  empty");
                self.append(("empty",))
            elif arg.startswith("+"):
                arg = arg[1:]
                Core.debug("  add-line %r", arg)
                self.append(("append", arg))
            elif arg.startswith("s/"):
                arg = arg[2:]
                if arg.endswith("/"):
                    arg = arg[:-1]
                arg = str_split_escaped(arg, "/", 1)
                if len(arg) == 2:
                    from_re, to_str = arg
                    Core.debug("  regex %r to %r", from_re, to_str)
                    self.append(("resub", from_re, to_str))
                else:
                    Core.die("not enough parameters: %r" % arg)
            else:
                self.append(("empty",))
                self.append(("append", arg))

    def apply(self, target):
        lines = target.rstrip("\n").split("\n")

        for op, *rest in self:
            Core.debug("text changeset: op %r rest %r", op, rest)
            if op == "empty":
                lines = []
            elif op == "append":
                lines.append(rest[0])
            elif op == "resub":
                rx = re.compile(rest[0])
                lines = [rx.sub(rest[1], _) for _ in lines]
            else:
                Core.die("unknown operation %r" % op)

        Core.debug("text changeset: lines %r", lines)
        return "\n".join(lines)

# }}}
