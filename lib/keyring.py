import base64
import io
import subprocess

class Keyring():
    KEK_SCHEMA = "org.eu.nullroute.Accdb.MasterKey"

    def _make_attrs(self, uuid):
        raise NotImplementedError()

    def _store_kek(self, label, secret, uuid):
        return self.store(label, secret, self._make_attrs(uuid))

    def _lookup_kek(self, uuid):
        return self.lookup(self._make_attrs(uuid))

    def _clear_kek(self, uuid):
        return self.clear(self._make_attrs(uuid))

    def store_kek(self, uuid, kek):
        label = "accdb master key for {%s}" % uuid
        secret = base64.b64encode(kek).decode()
        if not self._store_kek(label, secret, str(uuid)):
            raise Exception("failed to store master key in keyring")

    def lookup_kek(self, uuid):
        secret = self._lookup_kek(str(uuid))
        return base64.b64decode(secret) if secret else None

    def cache_kek(self, uuid, kek):
        pass

    def clear_kek(self, uuid):
        return self._clear_kek(str(uuid))

class GitKeyring(Keyring):
    def __init__(self, helper="cache"):
        self.helper = helper

    def _talk(self, action, attrs):
        for a in ["host", "username"]:
            if a not in attrs:
                raise ValueError("attribute %r is required" % a)

        if action == "get":
            stdout = subprocess.PIPE
        else:
            stdout = subprocess.DEVNULL

        with subprocess.Popen(["git", "credential-%s" % self.helper, action],
                              stdin=subprocess.PIPE,
                              stdout=stdout) as proc:
            buf = "".join(["%s=%s\n" % (k, v) for k, v in attrs.items()])
            out, err = proc.communicate(buf.encode())
            if out is None:
                return proc.wait() == 0
            else:
                ret = [l.split("=", 1) for l in out.decode().splitlines()]
                ret = {i[0]: i[1] for i in ret}
                return ret or None

    def store(self, label, secret, attrs):
        attrs["label"] = label
        attrs["password"] = secret
        return self._talk("store", attrs)

    def search(self, attrs):
        return self._talk("get", attrs)

    def lookup(self, attrs):
        ret = self.search(attrs)
        return ret["password"] if ret else None

    def clear(self, attrs):
        return self._talk("erase", attrs)

    def _make_attrs(self, uuid):
        return {
            "host": "accdb://%s" % uuid,
            "protocol": Keyring.KEK_SCHEMA,
            "username": uuid,
        }

class XdgKeyring(Keyring):
    @property
    def available(self):
        return subprocess.call(["secret-tool", "search", "", ""],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0

    def store(self, label, secret, attrs):
        if not self.available:
            return False
        with subprocess.Popen(["secret-tool", "store", "--label", label] + attrs,
                               stdin=subprocess.PIPE) as proc:
            proc.communicate(secret.encode())
            return proc.wait() == 0

    def lookup(self, attrs):
        if not self.available:
            return None
        with subprocess.Popen(["secret-tool", "lookup"] + attrs,
                               stdout=subprocess.PIPE) as proc:
            out, err = proc.communicate()
            return out.decode().rstrip("\n")

    def clear(self, attrs):
        if not self.available:
            return False
        return subprocess.call(["secret-tool", "clear"] + attrs) == 0

    def _make_attrs(self, uuid):
        return [
            "xdg:schema", Keyring.KEK_SCHEMA,
            "uuid", uuid,
        ]

class Prompter():
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

class ShimKeyring(Keyring, PinentryPrompter):
    def __init__(self):
        self.store = XdgKeyring()
        self.cache = GitKeyring("cache")

    def store_kek(self, uuid, kek):
        return self.store.store_kek(uuid, kek)

    def cache_kek(self, uuid, kek):
        return self.cache.store_kek(uuid, kek)

    def lookup_kek(self, uuid):
        return self.cache.lookup_kek(uuid) or self.store.lookup_kek(uuid)

    def clear_kek(self, uuid):
        sr = self.store.clear_kek(uuid)
        cr = self.cache.clear_kek(uuid)
        return sr

def default_keyring():
    return ShimKeyring()
