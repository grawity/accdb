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

File = r"Q:\Private\accounts.db.txt"

fields = dict(
	object = ("host", "uri"),
	username = ("login", "nic-hdl"),
	password = ("pass",),
	flags = ("flags",),
	)

fieldorder = "object", "username", "password", "flags"

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

def sortfields(input):
	fixed = [fix_fieldname(k) for k in input]
	output = []
	
	# first add the standard fields, by group
	for group in fieldorder:
		for k in fields[group]:
			if k in fixed or fix_fieldname(k) in fixed:
				rk = input[fixed.index(k)]
				output.append(rk)
	for k in input:
		if k not in output:
			output.append(k)
	return output

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
		s = ""
		if self.name:
			s += "= %s\n" % self.name
		else:
			for id in self.identifier():
				s += "= %s\n" % id
		for line in self.comment:
			s += "\t; %s\n" % line
		for key in sortfields(self.keys()):
			if key == "flags":
				value = list(self.flags)
				if len(value) == 0:
					continue
				value.sort()
				value = ", ".join(value)
			else:
				key, value = fix_fieldname(key), self[key]
			if value == None: value = "(none)"
			s += "\t%s\n" % fieldsep.join((key, value))
		
		if len(self.flags) > 0:
			value = list(self.flags)
			value.sort()
			
			## group by prefix
			prefixes = {}
			for i in value:
				p, v = i.split(":", 2) if ":" in i else (None, i)
				prefixes[p] = prefixes.get(p, []) + [v]
				
			unprinted = []
			for p, v in prefixes.items():
				if len(v) >= 3:
					v = ", ".join(v)
					s += "\t%s\n" % fieldsep.join(("flags:%s" % p, v))
				else:
					unprinted.extend([("%s:%s" % (p,f) if p is not None else f) for f in v])
			value = unprinted
			
			value = ", ".join(value)
			s += "\t%s\n" % fieldsep.join(("flags", value))
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
		return [self[k] for k in fields["object"] if k in self]

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
					if ":" in key:
						key, valueprefix = key.split(":", 2)
					else:
						valueprefix = None
						
					value = value.lower().replace(",", " ").split()
					if valueprefix is not None:
						value = ["%s:%s" % (valueprefix, i) for i in value]
					value.sort()
					current.setflags(*value)
				else:
					current[key] = value
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
if command in ("a", "add"):
	try: input = raw_input
	except: pass
	dx = read("con:")
	print dx
elif command in ("g", "grep", "ls", "list"):
	listonly = command in ("ls", "list")
	option = None
	try:
		pattern = sys.argv.pop(1).lower()
		while pattern.startswith("-"):
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
		results = find_identifier(data, pattern)
		
	for record in results:
		if listonly:
			print record.name
		else:
			print "(line %d)" % record.position
			print record
	
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
	print "db file: %s" % File
	print "records: %d" % len(data)
if Modified:
	dump(File, data)