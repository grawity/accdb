## Search query language

### Quirks

 * Parens act as balanced quotes _except_ in shortcuts. Thus it's impossible to do `@name=Fred Foobar`, but `ATTR name = (Fred Foobar)` or even `ATTR(name)=(Fred Foobar)` works fine.

 * It is however impossible to use parens within a string, e.g. you cannot search for `ATTR name = foo(bar`. (I'll try harder to implement that.)

### AND

Syntax: `AND <filter>...`

Shortcut: `& <filter>...`

### ANY

Syntax: `ANY [modifier] <text>`

Modifier: `:exact`, `:glob` (default), `:regex`

Experimental. Combines `NAME`, `ATTR`, `ATTR *`, and `TAG` filters, essentially
searching anywhere in the item's data.

### ATTR (names)

Syntax: `ATTR [modifier] <name>`

Modifier: `:exact` (default), `:glob`, `:regex`

Shortcut: `@name`

Search for entries which match this attribute name.

### ATTR (values)

Syntax: `ATTR <name> <modifier> <value>`

Modifier: `:exact =`, `:glob`, `:regex ~`, `:gt >`, `:lt <`

Shortcut: `@name=value` (glob), `@name~value` (regex), `@name>value` (gt), `@name<value` (lt)

Search for entries where this attribute matches the given value.

Only date attributes currently support `:gt` and `:lt` matches; the value can
be an absolute date in `YYYY-MM-DD` format, or a relative date like `now` or
`now±D`.

Experimental: If name is `*`, all attributes' values are checked.

### ITEM

Syntax: `ITEM <number>`

Shortcut: `number`, `#number`

Match entry with the given number.

### ITEMRANGE

Syntax: `ITEMRANGE <ranges>`

Shortcut: `ranges`

Match entries within the given number range (accepts a comma-separated list of numbers or start-end ranges).

### NAME

Syntax: `NAME [modifier] <name>`

Modifier: `:exact` (default), `:glob`, `:regex`

Shortcut: `=name`, `name`, `~name`

### NOT

Syntax: `NOT <filter>`

Shortcut: `! <filter>`

Invert the match results.

### OR

Syntax: `OR <filter>...`

Shortcut: `| <filter>...`

### PATTERN

Syntax: `PATTERN <pattern>`

Shortcut: `pattern`

Legacy syntax wrapping ATTR, NAME, TAG, UUID filters.

### TAG

Syntax: `TAG [modifier] <name>`

Modifier: `:exact`, `:glob`, `:regex`

Shortcut: `+name`

Search for entries which have this tag (glob match).

### TAG

Syntax: `TAG ()` ⇒ `NOT (TAG *)`

Shortcut: `:untagged`

Search for entries which do not have any tags.

### TRUE

Syntax: `TRUE`

Shortcut: `*`

Match all entries.

### UUID

Syntax: `UUID <uuid>`

Shortcut: `{uuid}`

Match entry having the specified UUID.
