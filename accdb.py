#!/usr/bin/python
# Account and password database. For my own internal use.

"""
General syntax:

= entry name
; comments
<tab>	key = value

Flags:
 * Can be separated by spaces or commas.
 * Can have prefixes such as "auth:" or "is:":
       flags = auth:openid, auth:sslcert, is:apikey
 * Multiple flags with same prefix can be grouped:
       flags:auth = openid, sslcert

Shorthands:
 * Lines starting with "http://" or "https://" will be converted to an 'uri' field.
 * Lines starting with "+" will be added as flags.
 * 'u', 'p', and '@' expand to 'login', 'password', and 'uri'.

Misc syntax notes:
 * Both "=" and ": " are accepted as separators. (Only one, however, is output
   when rewriting the database.)

Database will be rewritten and all shorthands expanded if any change is made,
also when doing 'accdb touch'.
"""

import sys, os
import uuid
import fnmatch as fnm

# TODO: can filter() stop after one match?
#File = filter(os.path.exists, (

Files = (
	r"Q:\Private\accounts.db.txt",
	"/home/grawity/fs/pqi/private/accounts.db.txt",
)
File = None
for f in Files:
	if os.path.exists(f):
		File = f
if File is None:
	raise BaseException, "Database not found"

fields = dict(
	object = ("host", "uri"),
	username = ("login", "nic-hdl"),
	password = ("pass",),
	email = ("email",),
	flags = ("flags",),
	)

fieldorder = "object", "username", "password", "email", "flags"

multivalue = fields['object'] + fields['email']

def fix_fieldname(name):
	name = name.lower()
	return {
		"h": "host",
		"hostname": "host",
		"machine": "host",

		"@": "uri",
		"url": "uri",
		"website": "uri",

		"u": "login",
		"user": "login",

		"p": "pass",
		"password": "pass",
		}.get(name, name)

def sortfields(input, full=True):
	fixed = [fix_fieldname(k) for k in input]
	output = []

	# first add the standard fields, by group
	for group in fieldorder:
		for k in fields[group]:
			if k in fixed or fix_fieldname(k) in fixed:
				rk = input[fixed.index(k)]
				output.append(rk)
	if full:
		for k in input:
			if k not in output:
				output.append(k)
	return output

def chunks(list, size):
	for i in xrange(0, len(list), size):
		yield list[i:i+size]

class Record(dict):
	def __init__(self, *args, **kwargs):
		self.id = uuid.uuid4()
		self.name = None
		# .comment is list to make things easier for __str__
		self.comment = []
		self.flags = set()

		if "Name" in kwargs:
			self.name = kwargs["Name"]
			del kwargs["Name"]
		dict.__init__(self, *args, **kwargs)

	def __repr__(self):
		rep = "<Record"
		if self.name:
			rep += " %s" % repr(self.name)
		for fname in fields["object"]:
			if fname in self:
				rep += " for %s" % repr(self[fname])
		rep += ">"
		return rep

	def __str__(self):
		fieldsep = " = "
		fieldsep = ": "
		s = ""
		if self.name:
			s += "= %s\n" % self.name
		else:
			for id in self.identifier():
				s += "= %s\n" % id
		for line in self.comment:
			s += "; %s\n" % line
		for key in sortfields(self.keys()):
			if key == "flags":
				pass
			else:
				key, data = fix_fieldname(key), list(self[key])
			
			if data is None:
				s += "\t%s\n" % fieldsep.join((key, "(none)"))
			else:
				for value in data:
					s += "\t%s\n" % fieldsep.join((key, value))
				#values = ", ".join(data)
				#s += "\t%s\n" % fieldsep.join((key, values))

		if len(self.flags) > 0:
			value = list(self.flags)
			value.sort()

			## group by prefix
			flags = {}
			for i in value:
				prefix, suffix = i.split(":", 1) if ":" in i else (None, i)
				flags[prefix] = flags.get(prefix, []) + [suffix]

			for prefix, values in flags.items():
				if prefix is None:
					continue
				if len(prefix)*len(values) + sum(len(x)+3 for x in values) < 60:
					flags[None] = flags.get(None, []) + ["%s:%s" % (prefix, v) for v in values]
				else:
					values = ", ".join(values)
					#s += "\t%s\n" % fieldsep.join(("flags:%s" % prefix, values))
					s += "\t+ %s\n" % values

			if None in flags:
				flags[None].sort()
				for ch in chunks(flags[None], 4):
					ch = ", ".join(ch)
					#s += "\t%s\n" % fieldsep.join(("flags", ch))
					s += "\t+ %s\n" % ch
					
		return s

	def setflags(self, *flags):
		flags = [x.lower() for x in flags]
		self.flags |= set(flags)
	def unsetflags(self, *flags):
		flags = [x.lower() for x in flags]
		self.flags -= set(flags)

	def flaglist(self):
		return sorted(list(self.flags))

	def identifier(self):
		id = []
		for k in fields["object"]:
			if k in self:
				id.extend(self[k])
		#return [self[k] for k in fields["object"] if k in self]
		return id

def read(file):
	data, current = [], Record()
	lineno = 0
	skip = False
	with open(file, "r") as inputfile:
		for line in inputfile:
			lineno += 1
			line = line.strip()
			if line == "":
				if len(current) > 0:
					data.append(current)
					current = Record()

			elif line[0] == "=":
				if len(current) > 0:
					data.append(current)
				current = Record()

				value = line[1:].strip()
				if value.startswith("!"):
					value = value[1:].strip()
					current.setflags("deleted")
				current.name = value
				current.position = lineno

			elif line[0] == "!":
				value = line[1:].strip()
				current.id = uuid.UUID(value)

			elif line[0] == ";":
				value = line[1:].strip()
				current.comment.append(value)

			elif line[0] == "(" and line[-1] == ")":
				pass

			elif line[0] == "+":
				value = line[1:].lower().replace(",", " ").split()
				value.sort()
				current.setflags(*value)

			elif line.startswith("http://") or line.startswith("https://"):
				current["uri"] = line.strip()

			else:
				separator = ": " if ": " in line else "="
				#if ": " in line: separator = ": "
				#elif " -> " in line: separator = "->"
				#elif " => " in line: separator = "=>"
				#else: separator = "="
				try:
					key, value = line.split(separator, 1)
				except ValueError:
					print >> sys.stderr, "db[%d]: line not in key=value format" % lineno
					continue

				key, value = key.strip(), value.strip()
				key = fix_fieldname(key)
				if value == "(none)" or value == "(null)":
					value = None

				if key == "flags" or key.startswith("flags:"):
					key, sep, valueprefix = key.partition(":")
					value = value.lower().replace(",", " ").split()
					if valueprefix:
						value = ["%s:%s" % (valueprefix, i) for i in value]
					value.sort()
					current.setflags(*value)
				
				elif key in multivalue:
					value = value.split(", ")
					try:
					#	current[key].append(value)
						current[key].extend(value)
					except KeyError:
					#	current[key] = [value]
						current[key] = value
				else:
					current[key] = [value]
	if len(current) > 0:
		data.append(current)

	return data

def dump(file, data):
	map(str, data) # make sure __str__() does not fail

	with open(file, "w") as fh:
		for rec in data:
			if "deleted" in rec.flags: continue
			fh.write(str(rec))
			fh.write("\n")

def find_identifier(data, pattern):
	for record in data:
		ids = record.identifier()
		if record.name:
			ids.append(record.name)
		if fnm.filter(ids, pattern):
			yield record

def find_flagged(data, flag, exact=True):
	if exact:
		check = lambda record, flag: flag.lower() in record.flags
	else:
		check = lambda record, flag: fnm.filter(record.flags, flag)

	for record in data:
		if check(record, flag):
			yield record

def run_editor(file):
	from subprocess import Popen
	Popen((os.environ.get("EDITOR", "notepad.exe"), file))

data = read(File)
Modified = False

try: command = sys.argv.pop(1).lower()
except IndexError: command = None

if command is None:
	print "db file: %s" % File
	print "records: %d" % len(data)
elif command in ("a", "add"):
	#try: input = raw_input
	#except: pass
	#dx = read("con:")
	#print dx
	from subprocess import Popen
	Popen(("notepad.exe", "/g", "-1", File))
elif command in ("g", "grep", "a", "auth", "ls", "list"):
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

	if option == "flag":
		results = find_flagged(data, pattern, exact)
	else:
		results = find_identifier(data, "*%s*" % pattern)
	
	num_results = 0
	for record in results:
		num_results += 1
		if listonly:
			print record.name
		elif authonly:
			fieldsep = ": "
			print record.name
			for key in sortfields(record.keys(), False):
				key, data = fix_fieldname(key), list(record[key])
				if data is None:
					print "\t%s" % fieldsep.join((key, "(none)"))
				else:
					values = ", ".join(data)
					print "\t%s" % fieldsep.join((key, values))
			print
		else:
			print "(line %d)" % record.position
			print record
	
	if not listonly:
		print "(%d entr%s matching '%s')" % (num_results, ("y" if num_results == 1 else "ies"), pattern)
	
elif command == "dump":
	for record in data:
		print record
elif command == "ls":
	for record in data:
		print record.name
elif command == "touch":
	print "Rewriting database"
	Modified = True
elif command == "db:sort":
	print "Rewriting database"
	data.sort(key=lambda x: x.name.lower())
	Modified = True
elif command == "edit":
	run_editor(File)
elif command == "help":
	print "Commands:"
	for command, desc in (
		("grep", "search for <pattern> in name, host, and URI"),
		("  /flag", "search for <flag>"),
		("edit", "run $EDITOR"),
		("dump", "write database to stdout"),
		("touch", "load and rewrite database"),
		("db:sort", "sort and rewrite database"),
	):
		print "%(command)-12s: %(desc)s" % locals()
else:
	print "Unknown command."

if Modified:
	dump(File, data)
