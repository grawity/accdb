#!/usr/bin/env python2
# Account and password database. For my own internal use.

"""
General syntax:

= entry name
; comments
<tab>	key = value
<tab>	+ flag, other:flag, another:flag

Shorthands:
 * Lines starting with "+" will be added as flags.
 * 'u', 'p', and '@' expand to 'login', 'password', and 'uri'.

Misc syntax notes:
 * Both "=" and ": " are accepted as separators. (Only one, however, is output
   when rewriting the database.)

Database will be rewritten and all shorthands expanded if any change is made,
also when doing 'accdb touch'.
"""
import os
import sys
import fnmatch

class Record(dict):
	def __init__(self, *args, **kwargs):
		self.flags = set()
		self.comment = []
		dict.__init__(self, *args, **kwargs)

	def __str__(self, full=True):
		sep = ": "
		out = ""
		out += "= %s\n" % self["Name"]
		for line in self.comment:
			out += "; %s\n" % line
		for key in sort_fields(self.keys(), full):
			if key in ("Name", "comment"):
				continue
			if isinstance(self[key], str):
				values = [self[key]]
			else:
				values = self[key]
			for val in values:
				out += "\t%s\n" % sep.join((key, val))
		if full and len(self.flags) > 0:
			cur = []
			for f in sorted(self.flags):
				if sum(len(x)+2 for x in cur) + len(f) >= 70:
					out += "\t+ %s\n" % ", ".join(cur)
					cur = []
				cur.append(f)
			if len(cur):
				out += "\t+ %s\n" % ", ".join(cur)
		return out

	def keys(self):
		return dict.keys(self)

	def names(self):
		n = [self["Name"]]
		for f in fields["object"]:
			if f in self:
				n.extend(self[f])
		return n

def parse(file):
	data, cur, lineno = [], Record(), 0

	for line in open(file, "r"):
		line = line.strip()
		lineno += 1

		if line == "":
			if len(cur) > 0:
				data.append(cur)
				cur = Record()

		elif line[0] == "=":
			val = line[1:].strip()
			if val.startswith("!"):
				val = val[1:].strip()
				cur.flags.add("deleted")

			if len(cur) > 0:
				data.append(cur)
			cur = Record(Name=val)
			cur.line = lineno

		elif line[0] == ";":
			val = line[1:].strip()
			cur.comment.append(val)

		elif line[0] == "(" and line[-1] == ")":
			pass

		elif line[0] == "+":
			val = line[1:].lower().replace(",", " ").split()
			cur.flags |= set(val)

		else:
			sep = ": " if ": " in line else "="
			try:
				key, val = line.split(sep, 1)
			except ValueError:
				print >> sys.stderr, "{%d} not in key=value format" % lineno
				continue
			# normalize input
			key, val = key.strip(), val.strip()
			key = fix_field_name(key)
			if val == "(none)" or val == "(null)":
				val = None

			if key in ("login", "pass"):
				cur[key] = val
			else:
				try:
					cur[key].append(val)
				except KeyError:
					cur[key] = [val]

	if len(cur) > 0:
		data.append(cur)

	return data

def dump(file, data):
	map(str, data) # make sure __str__() does not fail
	with open(file, "w") as fh:
		for item in data:
			if "deleted" in item.flags:
				continue
			print >> fh, item

fields = dict(
	object		= ("host", "uri"),
	username	= ("login", "nic-hdl"),
	password	= ("pass",),
	email		= ("email",),
)
field_order = "object", "username", "password", "email"

def sort_fields(input, full=True):
	output = []
	for group in field_order:
		output += [k for k in fields[group] if k in input]
	if full:
		output += [k for k in input if k not in output]
	return output

# Expand field name aliases when reading db
def fix_field_name(name):
	name = name.lower()
	return {
		"h":		"host",
		"hostname":	"host",
		"machine":	"host",

		"@":		"uri",
		"url":		"uri",
		"website":	"uri",

		"l":		"login",
		"u":		"login",
		"user":		"login",
		"username":	"login",

		"p":		"pass",
		"password":	"pass",
	}.get(name, name)

def grep_named(pattern):
	for item in db:
		if fnmatch.filter(item.names(), pattern):
			yield item

def grep_flagged(pattern, exact=True):
	if exact:
		test = lambda i, p: p.lower() in i.flags
	else:
		test = lambda i, p: fnmatch.filter(i.flags, p)

	for item in db:
		if test(item, pattern):
			yield item

def find_database():
	if "ACCDB" in os.environ:
		return os.environ["ACCDB"]
	else:
		return os.path.expanduser("~/accounts.db.txt")

def run_editor(file):
	from subprocess import Popen
	Popen((os.environ.get("EDITOR", "notepad.exe"), file))

dbfile = find_database()
db = parse(dbfile)
modified = False
try:
	command = sys.argv.pop(1).lower()
except IndexError:
	command = None

if command is None:
	print "file: %s" % dbfile
	print "items: %s" % len(db)
elif command in ("g", "grep", "a", "auth", "l", "ls"):
	listonly = command in ("ls", "list")
	authonly = command in ("a", "auth")
	option = None
	try:
		pattern = sys.argv.pop(1).lower()
		while pattern.startswith("-") or pattern.startswith("/"):
			option = pattern[1:]
			pattern = sys.argv.pop(1).lower()
		exact = pattern.startswith("=")
		if exact: pattern = pattern[1:]
	except IndexError:
		pattern = "*"
		exact = False

	if option == "f":
		results = grep_flagged(pattern, exact)
	else:
		results = grep_named("*%s*" % pattern)

	num_results = 0
	for item in results:
		num_results += 1
		if listonly:
			print item["Name"]
		elif authonly:
			print item.__str__(False)
		else:
			print "(line %d)" % item.line
			print item
	if not listonly:
		print "(%d entr%s matching '%s')" % (
			num_results,
			("y" if num_results == 1 else "ies"),
			pattern)
elif command == "dump":
	for item in db:
		print item
elif command == "dump:json":
	import json
	dbx = []
	for item in db:
		itemx = dict(item)
		if len(item.flags):
			itemx["flags"] = list(item.flags)
		dbx.append(itemx)
	print json.dumps(dbx, indent=4)
elif command == "dump:yaml":
	import yaml
	dbx = []
	for item in db:
		itemx = dict(item)
		if len(item.flags):
			itemx["flags"] = list(item.flags)
		dbx.append(itemx)
	print yaml.dump(dbx)
elif command == "touch":
	print "Rewriting database"
	modified = True
elif command == "sort":
	print "Rewriting database"
	db.sort(key=lambda x: x["Name"].lower())
	modified = True
elif command == "edit":
	run_editor(dbfile)
else:
	print "Unknown command."

if modified:
	dump(dbfile, db)
