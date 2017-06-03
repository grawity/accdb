import base64

from .xdg_secret import *

class Keyring(object):
    def get_kek(self, uuid):
        raise NotImplementedError()

    def store_kek(self, uuid, kek):
        raise NotImplementedError()


class XdgKeyring(Keyring):
    def get_kek(self, uuid):
        attrs = [
            "xdg:schema", "lt.nullroute.Accdb.Kek",
            "uuid", str(uuid),
        ]
        secret = xdg_secret_lookup_secret(attrs)
        if secret:
            return base64.b64decode(secret)
        else:
            return None

    def store_kek(self, uuid, kek):
        label = "accdb master key for %s" % uuid
        secret = base64.b64encode(kek).decode()
        attrs = [
            "xdg:schema", "lt.nullroute.Accdb.Kek",
            "uuid", str(uuid),
        ]
        if xdg_secret_store(label, secret, attrs):
            return True
        else:
            raise Exception("failed to store master key in keyring")
