import re

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
    "ssid":     "wifi.essid",
    "essid":    "wifi.essid",
    "wifi.ssid":"wifi.essid",
}

attr_groups = {
    "object":   ["entity", "host", "uri", "realm", "wifi.essid"],
    "username": ["login", "login.", "username", "nic-hdl", "principal"],
    "password": ["pass"],
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

def attr_is_sortable(name):
    base = name.split(".")[0]
    return any([base in group for group in attr_groups.values()])

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

def val_is_unsafe(value):
    return ("\n" in value) \
           or value.startswith("<base64> ") \
           or value.startswith("<wrapped> ")

class WiFiParameters():
    # https://github.com/zxing/zxing/wiki/Barcode-Contents

    def __init__(self, essid, psk, sectype=None, hidden=False):
        if sectype is None:
            sectype = "WPA" if psk else "nopass"
        elif sectype not in {"WPA", "WEP", "nopass"}:
            raise ValueError("unknown Wi-Fi security type %r" % sectype)

        self.essid = essid
        self.psk = psk
        self.sectype = sectype
        self.hidden = hidden

    def _escape(self, text, quote=True):
        for char in "\\;,:\"":
            text = text.replace(char, "\\" + char)
        if quote and re.match(r"^([0-9A-F][0-9A-F])+$", text, re.I):
            text = "\"" + text + "\""
        return text

    def make_uri(self):
        data = ["S:" + self._escape(self.essid)]
        if self.sectype != "nopass":
            data += [
                "T:" + self.sectype,
                "P:" + self._escape(self.psk),
            ]
        if self.hidden:
            data += ["H:true"]
        return "WIFI:" + ";".join(data) + ";"

class SecureStr():
    def __init__(self, value, sec):
        self.raw = value
        self.clear = None
        self.sec = sec

    def __str__(self):
        if self.clear is None:
            self.clear = self.sec.unwrap_data(self.raw)
        return self.clear

    def __repr__(self):
        return "SecureStr(%r)" % self.clear

    def __lt__(self, other):
        return str(self) < str(other)
