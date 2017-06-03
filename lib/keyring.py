import base64
import subprocess

from .xdg_secret import *

class Keyring(object):
    def get_kek(self, uuid):
        raise NotImplementedError()

    def store_kek(self, uuid, kek):
        raise NotImplementedError()

class Prompter(object):
    def get_password(self, desc, **kwargs):
        raise NotImplementedError()

class PinentryPrompter(Prompter):
    def get_password(self, desc, **kwargs):
        with subprocess.Popen(["askpin",
                               "-t", "accdb",
                               "-d", desc,
                               "-p", "Password:"],
                              stdout=subprocess.PIPE) as proc:
            (out, err) = proc.communicate()
            if proc.wait() == 0:
                return out.decode().rstrip("\n")
            else:
                return None

class XdgKeyring(Keyring, PinentryPrompter):
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
        label = "accdb master key for {%s}" % uuid
        secret = base64.b64encode(kek).decode()
        attrs = [
            "xdg:schema", "lt.nullroute.Accdb.Kek",
            "uuid", str(uuid),
        ]
        if xdg_secret_store(label, secret, attrs):
            return True
        else:
            raise Exception("failed to store master key in keyring")
