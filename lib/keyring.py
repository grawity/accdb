import base64
import io
import subprocess

class Keyring(object):
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
        if not self._clear_kek(str(uuid)):
            raise Exception("failed to remove master key from keyring")

class GitKeyring(Keyring):
    def __init__(self, helper="cache"):
        self.helper = helper

    def store(self, label, secret, attrs):
        for a in ["host", "username"]:
            if a not in attrs:
                raise ValueError("attribute %r is required" % a)
        attrs["label"] = label
        attrs["password"] = secret
        with subprocess.Popen(["git", "credential-%s" % self.helper, "store"],
                              stdin=subprocess.PIPE) as proc:
            with io.TextIOWrapper(proc.stdin) as stdin:
                for k, v in attrs.items():
                    stdin.write("%s=%s\n" % (k, v))
            return proc.wait() == 0

    def search(self, attrs):
        for a in ["host"]:
            if a not in attrs:
                raise ValueError("attribute %r is required" % a)
        with subprocess.Popen(["git", "credential-%s" % self.helper, "get"],
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE) as proc:
            with io.TextIOWrapper(proc.stdin) as stdin:
                for k, v in attrs.items():
                    stdin.write("%s=%s\n" % (k, v))
            ret = {}
            with io.TextIOWrapper(proc.stdout) as stdout:
                for line in stdout:
                    k, v = line.rstrip("\n").split("=", 1)
                    ret[k] = v
            return ret or None

    def lookup(self, attrs):
        ret = self.search(attrs)
        return ret["password"] if ret else None

    def _make_attrs(self, uuid):
        return {
            "host": "accdb://%s" % uuid,
            "protocol": Keyring.KEK_SCHEMA,
            "username": uuid,
        }

class XdgKeyring(Keyring):
    def store(self, label, secret, attrs):
        with subprocess.Popen(["secret-tool", "store", "--label", label] + attrs,
                               stdin=subprocess.PIPE) as proc:
            proc.communicate(secret.encode("utf-8"))
            return proc.wait() == 0

    def lookup(self, attrs):
        with subprocess.Popen(["secret-tool", "lookup"] + attrs,
                               stdout=subprocess.PIPE) as proc:
            return proc.stdout.read().rstrip(b"\n")

    def clear(self, attrs):
        return subprocess.call(["secret-tool", "clear"] + attrs) == 0

    def _make_attrs(self, uuid):
        return [
            "xdg:schema", Keyring.KEK_SCHEMA,
            "uuid", uuid,
        ]

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
