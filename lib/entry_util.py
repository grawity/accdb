import re

from .string import match_globs

attr_names = {
    "@alias":   "@aka",
    "hostname": "host",
    "machine":  "host",
    "url":      "uri",
    "website":  "uri",
    "user":     "username",
    "nicname":  "nic-hdl",
    "password": "pass",
    "!pass":    "pass",
    "mail":     "email",
    "tel":      "phone",
}

attr_groups = {
    "object":   ["entity", "host", "uri", "realm"],
    "username": ["login", "login.", "username", "nic-hdl", "principal"],
    "password": ["pass", "!pass"],
    "email":    ["email", "phone"],
}

attr_order = ["object", "username", "password", "email"]

attr_prefix_re = re.compile(r"^\W+")

def attr_is_metadata(name):
    return name.startswith("@")

def attr_is_private(name):
    return name.startswith("!") or name == "pass"

def attr_is_reflink(name):
    return name.startswith("ref.")

def attr_is_hidden(name, globs=None):
    return match_globs(name, globs) \
        or attr_is_metadata(name)

def translate_attr(name):
    return attr_names.get(name, name)

def sort_attrs(entry):
    canonicalize = lambda k: attr_prefix_re.sub("", translate_attr(k))
    names = []
    names += sorted([k for k in entry.attributes
                       if attr_is_metadata(k)])
    for group in attr_order:
        for attr in attr_groups[group]:
            names += sorted([k for k in entry.attributes \
                               if (k == attr
                                   or (attr.endswith(".") and k.startswith(attr)))],
                            key=canonicalize)
    names += sorted([k for k in entry.attributes if k not in names],
                    key=canonicalize)
    return names

class WiFiParameters(object):
    def __init__(self, essid, psk):
        self.essid = essid
        self.psk = psk

    def make_uri(self):
        # TODO: handle escaping if any
        return "WIFI:T:WPA;S:%s;P:%s;;" % (self.essid, self.psk)
