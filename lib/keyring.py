import base64
import io
import subprocess

class Keyring(object):
    def get_kek(self, uuid):
        secret = self._get_kek(str(uuid))
        return base64.b64decode(secret) if secret else None

    def store_kek(self, uuid, kek):
        label = "accdb master key for {%s}" % uuid
        secret = base64.b64encode(kek).decode()
        if not self._store_kek(label, secret, str(uuid)):
            raise Exception("failed to store master key in keyring")

    def cache_kek(self, uuid, kek):
        pass

class GitKeyring(Keyring):
    def __init__(self, helper="cache"):
        self.helper = helper

    def lookup(self, attrs):
        return self.search(attrs)["password"]

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

    def _store_kek(self, label, secret, uuid):
        attrs = {
            "host": "accdb://%s" % uuid,
            "username": uuid,
        }
        return self.store(label, secret, attrs)

    def _get_kek(self, uuid):
        attrs = {
            "host": "accdb://%s" % uuid,
        }
        return self.lookup(attrs)

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

    def _search_stdout(self, attrs):
        return subprocess.call(["secret-tool", "search"] + attrs) == 0

    def clear(self, attrs):
        return subprocess.call(["secret-tool", "clear"] + attrs) == 0

    def _store_kek(self, label, secret, uuid):
        attrs = [
            "xdg:schema", "lt.nullroute.Accdb.Kek",
            "uuid", uuid,
        ]
        return self.store(label, secret, attrs)

    def _get_kek(self, uuid):
        attrs = [
            "xdg:schema", "lt.nullroute.Accdb.Kek",
            "uuid", uuid,
        ]
        return self.lookup(attrs)

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

    def get_kek(self, uuid):
        return self.cache.get_kek(uuid) or self.store.get_kek(uuid)

    def store_kek(self, uuid, kek):
        return self.store.store_kek(uuid, kek)

    def cache_kek(self, uuid, kek):
        return self.cache.store_kek(uuid, kek)

def default_keyring():
    return ShimKeyring()
