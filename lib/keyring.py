import os

class SecureKeyring(object):
    pass

class GnomeKeyring(SecureKeyring):
    app_name = "accdb"

    def __init__(self):
        try:
            import gi
            gi.require_version("GnomeKeyring", "1.0")
            from gi.repository import GLib, GnomeKeyring
            GLib.set_application_name(self.app_name)
            self.gkr = GnomeKeyring
            self.use_gi = True
        except ImportError:
            try:
                import glib, gnomekeyring
                glib.set_application_name(self.app_name)
                self.gkr = gnomekeyring
                self.use_gi = False
            except ImportError:
                self.gkr = None
                self.use_gi = False

    def _fmt_name(self, name):
        return "accdb: %s" % name

    def _make_attribute_list(self, attrs):
        attr_list = self.gkr.Attribute.list_new()
        if attrs:
            for key, val in attrs.items():
                self.gkr.Attribute.list_append_string(attr_list, key, val)
        return attr_list

    def store(self, name, secret, attrs=None):
        attrs = attrs or {}
        attrs["accdb:name"] = name

        display_name = self._fmt_name(name)

        if self.use_gi:
            attr_list = self._make_attribute_list(attrs)
            r = self.gkr.get_default_keyring_sync()
            r = self.gkr.item_create_sync(r.keyring,
                                          self.gkr.ItemType.GENERIC_SECRET,
                                          display_name,
                                          attr_list,
                                          secret,
                                          True)

        else:
            r = self.gkr.get_default_keyring_sync()
            r = self.gkr.item_create_sync(r,
                                          self.gkr.ITEM_GENERIC_SECRET,
                                          display_name,
                                          attrs,
                                          secret,
                                          True)

    def get(self, name, attrs=None):
        attrs = attrs or {}
        attrs["accdb:name"] = name

        if self.use_gi:
            attr_list = self._make_attribute_list(attrs)
            r = self.gkr.find_items_sync(self.gkr.ItemType.GENERIC_SECRET, attr_list)
            if r[0] == self.gkr.Result.OK:
                return r.found[0].secret
            else:
                raise KeyError("no match for %r" % attrs)
        else:
            r = self.gkr.find_items_sync(self.gkr.ITEM_GENERIC_SECRET, attrs)
            if r:
                return r[0].secret
            else:
                raise KeyError("no match for %r" % attrs)

def default_keyring():
    if os.name == "posix":
        #xdg1 = os.environ.get("DESKTOP_SESSION")
        #xdg2 = os.environ.get("XDG_SESSION_DESKTOP")
        #xdg3 = os.environ.get("XDG_CURRENT_DESKTOP")
        return GnomeKeyring()
