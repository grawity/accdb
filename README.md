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

    = Title
    ; Comment.
        field: value
	field: value
	!field: secretvalue
	+ tag, tag, tag

`accdb touch` takes care of messed up syntax – adjusts indentation, parses `field=value`, puts certain fields on top, so I don't have to bother with all that when adding new entries. !fields are hidden by `accdb grep`.

This is more convenient for me than YAML or such stuff. I even wrote myself a Vim syntax file, it's in the `dotfiles` repo.
