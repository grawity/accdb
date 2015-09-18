import re

attr_names = {
    "@alias":   "@aka",
    "hostname": "host",
    "machine":  "host",
    "url":      "uri",
    "website":  "uri",
    "user":     "login",
    "username": "login",
    "nicname":  "nic-hdl",
    "password": "pass",
    "!pass":    "pass",
    "mail":     "email",
    "tel":      "phone",
}

attr_groups = {
    "object":   ["entity", "host", "uri", "realm"],
    "username": ["login", "login.", "nic-hdl", "principal"],
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
