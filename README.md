# accdb

It's like passwords.txt but better.

Seriously.

  - I want my password list to be editable anywhere I go.
  - I want to edit it with Vim and Notepad2.
  - I want to use my own field names for everything.
  - But I don't want to be annoyed with strict syntax requirements.
  - I want it to be searchable from command line, conveniently.

So yes, I have a `passwords.txt`.

Of course, it has large downsides such as complete lack of encryption, and all passwords visible in my editor. So far, neither is a large problem to me – I have become fairly paranoid about the storage media it's on, and I usually avoid editing it in public. Who knows, maybe I'll add some scrambling later, or import it to KeePass, but so far this does the job for me.

## Syntax

    (metadata)
    = Title
    ; Comment.
        {entry-uuid}
        field: value
        field: value
        !field: secretvalue
        !field: <base64> c2VjcmV0dmFsdWU=
        ref.field: {other-entry-uuid}
        + tag, tag, tag

A simpler example:

    = Gmail
        login: grawity@gmail.com
        pass: nottelling
        date.signup: 2009-02-31
        + is:email

`accdb touch` takes care of messed up syntax – adjusts indentation, parses `field=value`, puts certain fields on top, so I don't have to bother with all that when adding new entries.

When saving the database (e.g. `ad touch`), accdb will dump all entries nicely reformatted. Fields are sorted, indents adjusted, missing UUIDs autogenerated.

This is more convenient for me than YAML or such stuff. I even wrote myself a Vim syntax file, it's in the `dotfiles` repo.

Basic syntax features:

  * Fields starting with `!` are hidden by `accdb grep` when displaying search results, showing just `!field: <private>` by default. (The same applies to the `pass` field due to reasons.)

  * Fields starting with `ref.` must contain UUID references to other entries; `accdb grep` will look up the name, and `accdb rshow` will show the referenced entries as well.

Weirder stuff:

  * For convenience, `field=value` is also accepted (but translated to `field: value` when saving).

  * Field values starting with "`<base64> `" will be Base64-decoded when reading (see the `conceal` flag below).

  * In fields named `date.*`, the values "now" and "today" are expanded to current date.

  * Entries tagged `\deleted` will be discarded when writing or merging. So you can remove entries in a pipeline, not just add/modify.

  * Entry UUIDs are used by `ad merge` and by `ref.*` fields.

  * Lines starting with `(` and ending with `)` are ignored when reading. They contain such information as "item 243" or "found 2 search results" that doesn't need to be preserved.

  * A comment line starting with `vim:` is the Vim modeline. It's not used by accdb directly, but will be preserved when saving the database.

  * A comment line starting with `dbflags:` is parsed as a list of flags.

    If the `cache` flag is set, accdb will write a second copy of the database at `~/Private/accounts.cache.txt` when updating the main database. accdb uses this cache when the main database is not found.

    If the `conceal` flag is set, accdb will base64-encode private fields when saving the database. This _doesn't_ really add security, it just helps against people glancing at my screen.

Some OATH TOTP support:

  * Running `ad totp <id>` will generate an OATH TOTP password based on the `!2fa.oath.psk` attribute. (`2fa.oath.type` can be set to "dynadot-totp" for Dynadot's broken TOTP, `2fa.oath.digits` to 8 for Battle.net, `2fa.oath.window` to 60 for some sites.)

  * Running `ad qr <id>` will generate a Qr code for importing the OATH TOTP key into a softtoken, including the `login` and optional `2fa.issuer` attributes.

  * The PSK can be prefixed with `{hex} `, `{b64} `, or `{raw} ` (e.g. the latter for Dynadot token serial numbers), otherwise it's in Base32.

  * Yes, **I know** this is so stupid it hurts. It's for testing only. I promise. (I have future plans for this though.) Don't actually use it.

## Usage

Searching for a title prefix:

    ad grep amaz

Searching for a tag:

    ad grep +is:hosting

Searching for tags and attributes, with boolean operators:

    ad grep "AND +is:irc (OR @host=*.net* @uri=*.net*)"

Displaying passwords in a search result:

    ad reveal 64
    # short: ad re 64

Copying a password to clipboard:

    ad copy 64
    # short: ad c 64

Editing a few entries:

    ad set 64 2fa="pass + (u2f | otp-oath)"
    ad set +sso:google ref.sso+={ee4b5502-eeda-410e-8076-1f6d05a7f581}

    ad tag 123 +shared-account

    ad rgrep +TODO | vipe | ad merge

Editing the entire database:

    ad retag -is:forum +forum

    vim $ACCDB

Dumping the entire database:

    ad dump          # default storage format
    ad rgrep         # default editable format
    ad dump json     # as JSON (no import yet)
    ad dump yaml     # as YAML (      〃     )

## Search patterns

  - `foo` – matching title (glob)

  - `~foo` – matching title (regex)

  - `=foo` – matching title (exact CI match)

  - `@foo` – attribute `foo` present (glob)

  - `@foo=bar` – attribute `foo` present (exact) and has value matching `bar` (glob)

  - `@foo~bar` – attribute `foo` present (exact) and has value matching `bar` (regex)

  - `@foo<bar`, `@foo>bar` – attribute `foo` present and is greater or less than `bar`

  - `+foo` – tag present (glob)

  - `123` or `#123` – item number

  - `123,456,78-89` – range of item numbers

  - `{foo}` – item UUID

  - `AND x y ...`, `OR x y ...`, `NOT x` – boolean operators

  - `(` and `)` for grouping patterns (Lisp/Logo style)

For `ref.*` attributes, `@foo=#123` can be used to match by referenced item
number instead of UUID.

For `date.*` attributes, `@foo<bar` and `@foo>bar` will use date comparisons
(currently time is discarded, only ISO 8601 Y-m-d is parsed). The shortcut
`@foo<now` and `@foo>now` is also supported.

For example:

    ad ls '(OR #123 (TAG is:hosting) {0a1588fd-84e7-427c-8c7b-f8534e7635e1} @nicname
           +is:license Weibo (AND (OR @id.pgp-key @pgp.key-id +is:payment))'

## Edit syntax

Synopsis: `ad set <filter> <operation...>`

  - `key:=value` – set value
  - `key+=value` – add value (unique)
  - `key-=value` – remove value
  - `key=value` – set (first occurence), then add (unique)
  - `-key` – remove all values (delete key)
  - `key<=key` – move from another key (i.e. rename key)
  - `key«=key` – copy from another key
  - `key|=key` – merge from another key

Synopsis: `ad tag <filter> <operation...>`

  - `+tag` – add tag
  - `-tag` – remove tag

Synopsis: `ad retag <remove...> <add...>`

  - `-tag` – existing tags
  - `+tag` – replacement tags

<!-- vim: set ts=8 sw=8 et: -->
