#!/usr/bin/env python
# -*- coding: utf-8 -*-
# accdb - account database using human-editable flat files as storage

from __future__ import print_function
import cmd
import fnmatch
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from collections import OrderedDict

field_names = {
	"hostname":	"host",
	"machine":	"host",
	"url":		"uri",
	"website":	"uri",
	"user":		"login",
	"username":	"login",
	"nicname":	"nic-hdl",
	"password":	"pass",
	"mail":		"email",
}

field_groups = {
	"object":	["host", "uri"],
	"username":	["login", "nic-hdl"],
	"password":	["pass"],
	"email":	["email"],
}

field_order = ["object", "username", "password", "email"]

def sort_fields(entry, terse=False):
	names = []
	for group in field_order:
		names += sorted(k for k in field_groups[group] if k in entry.attributes)
	if not terse:
		names += sorted(k for k in entry.attributes if k not in names)
	return names

def translate_field(name):
	return field_names.get(name, name)

def split_ranges(string):
	for i in string.split():
		for j in i.split(","):
			if "-" in j:
				x, y = j.split("-", 1)
				yield int(x), int(y)+1
			else:
				yield int(j), int(j)+1

def split_tags(string):
	string = string.strip(" ,")
	items = re.split(Entry.RE_TAGS, string)
	return set(items)

def expand_range(string):
	items = []
	for m, n in split_ranges(string):
		items.extend(range(m, n))
	return items

def start_editor(path):
	if "VISUAL" in os.environ:
		editor = shlex.split(os.environ["VISUAL"])
	elif "EDITOR" in os.environ:
		editor = shlex.split(os.environ["EDITOR"])
	elif sys.platform == "win32":
		editor = ["notepad.exe"]
	elif sys.platform == "linux2":
		editor = ["vi"]

	editor.append(path)

	proc = subprocess.Popen(editor)

	if sys.platform == "linux2":
		proc.wait()

class Database(object):
	def __init__(self):
		self.count = 0
		self.path = None
		self.entries = dict()
		self.order = list()
		self.modified = False
		self.readonly = False
		self._modeline = "; vim: ft=accdb:"
		self.flags = set()
		self._adduuids = True

	# Import

	@classmethod
	def from_file(self, path):
		db = self()
		db.path = path
		with open(path, "r", encoding="utf-8") as fh:
			db.parseinto(fh)
		return db

	@classmethod
	def parse(self, *args, **kwargs):
		return self().parseinto(*args, **kwargs)

	def parseinto(self, fh):
		data = ""
		lineno = 0
		lastno = 1

		for line in fh:
			lineno += 1
			if line.startswith("; vim:"):
				self._modeline = line.strip()
			elif line.startswith("; dbflags:"):
				self.flags = split_tags(line[10:])
			elif line.startswith("="):
				entry = Entry.parse(data, lineno=lastno)
				if entry:
					self.add(entry)
				data = line
				lastno = lineno
			else:
				data += line

		if data:
			entry = Entry.parse(data, lineno=lastno)
			if entry:
				self.add(entry)

		return self

	def add(self, entry, lineno=None):
		if entry.itemno is None:
			entry.itemno = self.count + 1
		if entry.lineno is None:
			entry.lineno = lineno

		if entry.uuid is None:
			entry.uuid = uuid.uuid4()
		elif entry.uuid in self:
			raise KeyError("Duplicate UUID %s" % entry.uuid)

		self.count += 1

		# Two uuid.UUID objects for the same UUID will also have the same hash.
		# Hence, it is okay to use an uuid.UUID as a dict key. For now, anyway.
		# TODO: Can this be relied upon? Not documented anywhere.
		self.entries[entry.uuid] = entry
		self.order.append(entry.uuid)

	# Lookup

	def find_by_itemno(self, itemno):
		uuid = self.order[itemno-1]
		entry = self.entries[uuid]
		assert entry.itemno == itemno
		return entry

	def find_by_name(self, pattern):
		regex = fnmatch.translate(pattern)
		reobj = re.compile(regex, re.I | re.U)
		for entry in self:
			if re.match(reobj, entry.name):
				yield entry

	def find_by_tag(self, pattern, exact=True):
		if exact:
			func = lambda tags: pattern in tags
		else:
			regex = fnmatch.translate(pattern)
			reobj = re.compile(regex, re.I | re.U)
			func = lambda tags: any(reobj.match(tag) for tag in tags)
		for entry in self:
			if func(entry.tags):
				yield entry

	def find_by_uuid(self, uuid):
		return self[uuid]

	# Aggregate lookup

	def tags(self):
		tags = set()
		for entry in self:
			tags |= entry.tags
		return tags

	# Maintenance

	def sort(self):
		self.order.sort(key=lambda uuid: self.entries[uuid].normalized_name)

	# Export

	def __iter__(self):
		for uuid in self.order:
			entry = self.entries[uuid]
			if not entry.deleted:
				yield entry

	def dump(self, fh=sys.stdout, storage=True):
		for entry in self:
			if entry.deleted:
				continue
			print(entry.dump(storage=storage), file=fh)
		if storage:
			print("(last-write: %s)" % \
				time.strftime("%Y-%m-%d %H:%M:%S"), file=fh)
			if self.flags:
				print("; dbflags: %s" % \
					", ".join(sorted(self.flags)),
					file=fh)
			if self._modeline:
				print(self._modeline, file=fh)

	def to_structure(self):
		return [entry.to_structure() for entry in self]

	def dump_yaml(self, fh=sys.stdout):
		import yaml
		print(yaml.dump(self.to_structure()), file=fh)

	def dump_json(self, fh=sys.stdout):
		import json
		print(json.dumps(self.to_structure(), indent=4), file=fh)

	def to_file(self, path):
		with open(path, "w", encoding="utf-8") as fh:
			self.dump(fh)

	def flush(self):
		if not self.modified:
			return
		if self.readonly:
			print("Discarding changes (database read-only)",
				file=sys.stderr)
			return
		if self.path is None:
			return
		print("Storing database")
		self.to_file(self.path)
		self.modified = False

class Entry(object):
	RE_TAGS = re.compile(r'\s*,\s*|\s+')
	RE_KEYVAL = re.compile(r'=|: ')

	RE_COLL = re.compile(r'\w.*$')

	def __init__(self):
		self.attributes = dict()
		self.comment = ""
		self.deleted = False
		self.itemno = None
		self.lineno = None
		self.name = None
		self.tags = set()
		self.uuid = None

	# Import

	@classmethod
	def parse(self, *args, **kwargs):
		return self().parseinto(*args, **kwargs)

	def parseinto(self, data, lineno=1):
		# lineno is passed here for use in syntax error messages
		self.lineno = lineno

		for line in data.splitlines():
			line = line.lstrip()
			if not line:
				pass
			elif line.startswith("="):
				if self.name:
					# Ensure that Database only passes us single entries
					print("Line %d: ignoring multiple name headers" \
						% lineno,
						file=sys.stderr)
				self.name = line[1:].strip()
			elif line.startswith("+"):
				self.tags |= split_tags(line[1:])
			elif line.startswith(";"):
				self.comment += line[1:] + "\n"
			elif line.startswith("(") and line.endswith(")"):
				# annotations in search output
				pass
			elif line.startswith("{") and line.endswith("}"):
				if self.uuid:
					print("Line %d: ignoring multiple UUID headers" \
						% lineno,
						file=sys.stderr)

				try:
					self.uuid = uuid.UUID(line)
				except ValueError:
					print("Line %d: ignoring badly formed UUID %r" \
						% (lineno, line),
						file=sys.stderr)
					self.comment += line + "\n"
			else:
				try:
					key, val = re.split(self.RE_KEYVAL, line, 1)
				except ValueError:
					print("Line %d: could not parse line %r" \
						% (lineno, line),
						file=sys.stderr)
					self.comment += line + "\n"
					continue

				if val.startswith("<private[") and val.endswith("]>"):
					# trying to load a safe dump
					print("Line %d: lost private data, you're fucked" \
						% lineno,
						file=sys.stderr)
					val = "<private[data lost]>"

				key = translate_field(key)

				if self.is_private_attr(key):
					attr = PrivateAttribute(val)
				else:
					attr = Attribute(val)

				if key in self.attributes:
					self.attributes[key].append(attr)
				else:
					self.attributes[key] = [attr]

			lineno += 1

		return self

	def is_private_attr(self, key):
		return key == "pass" or key.startswith("!")

	# Export

	def dump(self, storage=False, terse=False, reveal=False):
		"""
		storage: dump metadata and private data, never skip fields
		terse: skip fields not listed in groups
		reveal: display private data
		"""

		if storage:
			terse = False
			reveal = True

		data = ""

		if not storage:
			if self.itemno:
				data += "(item %d)\n" % self.itemno
			elif self.lineno:
				data += "(line %d)\n" % self.lineno

		data += "= %s\n" % (self.name or "(unnamed)")

		for line in self.comment.splitlines():
			data += ";%s\n" % line

		if self.uuid and storage:
			data += "\t{%s}\n" % self.uuid

		for key in sort_fields(self, terse):
			for value in self.attributes[key]:
				if reveal:
					value = value.dump()
				data += "\t%s: %s\n" % (key, value)

		if self.tags:
			tags = sorted(self.tags)
			# TODO: fold lines
			data += "\t+ %s\n" % ", ".join(tags)

		return data

	def to_structure(self):
		dis = dict()
		dis["name"] = self.name
		dis["comment"] = self.comment
		dis["data"] = {key: list(val.dump() for val in self.attributes[key])
				for key in sort_fields(self, False)}
		dis["lineno"] = self.lineno
		dis["tags"] = list(self.tags)
		dis["uuid"] = str(self.uuid)
		return dis

	def __str__(self):
		return self.dump(storage=False)

	def __bool__(self):
		return bool(self.name or self.attributes or self.tags or self.comment)

	@property
	def normalized_name(self):
		return re.search(self.RE_COLL, self.name).group(0).lower()

class Attribute(str):
	# Nothing special about this class. Exists only for consistency
	# with PrivateAttribute providing a dump() method.

	def __init__(self, value):
		str.__init__(self, value)

	def dump(self):
		return str.__str__(self)

class PrivateAttribute(Attribute):
	# Safeguard class to prevent accidential disclosure of private values.
	# Inherits a dump() method from Attribute for obtaining the actual data.

	def __repr__(self):
		if self == "<private[data lost]>":
			return self.dump()
		return "<private[%d]>" % len(self)

	def __str__(self):
		if self == "<private[data lost]>":
			return self.dump()
		return "<private[%d]>" % len(self)

class Interactive(cmd.Cmd):
	def __init__(self, *args, **kwargs):
		cmd.Cmd.__init__(self, *args, **kwargs)
		self.prompt = "accdb> "
		self.banner = "Using %s" % db_path

	def emptyline(self):
		pass

	def default(self, line):
		print("Are you on drugs?", file=sys.stderr)

	def do_EOF(self, arg):
		"""Save changes and exit"""
		return True

	def do_help(self, arg):
		"""Well, duh."""
		cmds = [k for k in dir(self) if k.startswith("do_")]
		for cmd in cmds:
			doc = getattr(self, cmd).__doc__ or "?"
			print("    %-14s  %s" % (cmd[3:], doc))

	def do_copy(self, arg):
		"""Copy password to clipboard"""
		arg = int(arg)

		entry = db.find_by_itemno(arg)
		print(entry)
		if "pass" in entry.attributes:
			Clipboard.put(entry.attributes["pass"][0].dump())
		else:
			print("No password found!",
				file=sys.stderr)

	def do_dump(self, arg):
		"""Dump the database to stdout (yaml, json, safe)"""
		if arg == "":
			db.dump()
		elif arg == "yaml":
			db.dump_yaml()
		elif arg == "json":
			db.dump_json()
		elif arg == "safe":
			db.dump(storage=False)
		else:
			print("Unsupported export format: %r" % arg,
				file=sys.stderr)

	def do_edit(self, arg):
		"""Launch an editor"""
		db.flush()
		db.modified = False
		start_editor(db_path)
		return True

	def do_grep(self, arg):
		"""Search for an entry"""
		if arg.startswith('+'):
			results = db.find_by_tag(arg[1:], exact=False)
		else:
			arg += '*'
			results = db.find_by_name(arg)
		num = 0
		for entry in results:
			if entry.deleted:
				continue
			print(entry)
			num += 1
		print("(%d entr%s matching '%s')" % (num, ("y" if num == 1 else "ies"), arg))

	def do_reveal(self, arg):
		"""Display entry (including sensitive information)"""
		for itemno in expand_range(arg):
			entry = db.find_by_itemno(itemno)
			print(entry.dump(reveal=True))

	def do_show(self, arg):
		"""Display entry (safe)"""
		for itemno in expand_range(arg):
			entry = db.find_by_itemno(itemno)
			print(entry.dump(reveal=False))

	def do_touch(self, arg):
		"""Rewrite the accounts.db file"""
		db.modified = True

	def do_dbsort(self, arg):
		"""Sort and rewrite the database"""
		db.sort()
		db.modified = True

	do_c	= do_copy
	do_g	= do_grep
	do_re	= do_reveal
	do_s	= do_show

class Clipboard():
	@classmethod
	def get(self):
		if sys.platform == "win32":
			import win32clipboard as clip
			clip.OpenClipboard()
			# TODO: what type does this return?
			data = clip.GetClipboardData(clip.CF_UNICODETEXT)
			print("clipboard.get =", repr(data))
			clip.CloseClipboard()
			return data
		else:
			raise RuntimeError("Unsupported platform")

	@classmethod
	def put(self, data):
		if sys.platform == "win32":
			import win32clipboard as clip
			clip.OpenClipboard()
			clip.EmptyClipboard()
			clip.SetClipboardText(data, clip.CF_UNICODETEXT)
			clip.CloseClipboard()
		elif sys.platform.startswith("linux"):
			proc = subprocess.Popen(("xsel", "-i", "-b", "-l", "/dev/null"),
						stdin=subprocess.PIPE)
			proc.stdin.write(data.encode("utf-8"))
			proc.stdin.close()
			proc.wait()
		else:
			raise RuntimeError("Unsupported platform")

db_path = os.environ.get("ACCDB",
			os.path.expanduser("~/accounts.db.txt"))

db_cache_path = os.path.expanduser("~/Private/accounts.cache.txt")

if os.path.exists(db_path):
	db = Database.from_file(db_path)
else:
	db = Database.from_file(db_cache_path)
	db.readonly = True
	print("Database not found; reading from read-only cache", file=sys.stderr)

interp = Interactive()

if len(sys.argv) > 1:
	line = subprocess.list2cmdline(sys.argv[1:])
	interp.onecmd(line)
else:
	interp.cmdloop()

db.flush()

if "cache" in db.flags and db.path != db_cache_path:
	print("Updating cache at %s" % db_cache_path, file=sys.stderr)
	db.to_file(db_cache_path)
