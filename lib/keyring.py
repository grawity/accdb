import base64
import subprocess

class Keyring(object):
    def get_kek(self, uuid):
        secret = self._get_kek(str(uuid))
        return base64.b64decode(secret) if secret else None

    def store_kek(self, uuid, kek):
        label = "accdb master key for {%s}" % uuid
        secret = base64.b64encode(kek).decode()
        if not self._store_kek(self, label, secret, str(uuid)):
            raise Exception("failed to store master key in keyring")

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

    def _store_kek(self, label, secret, attrs):
        attrs = [
            "xdg:schema", "lt.nullroute.Accdb.Kek",
            "uuid", uuid,
        ]
        return xdg_secret_store(label, secret, attrs)

    def _get_kek(self, uuid):
        attrs = [
            "xdg:schema", "lt.nullroute.Accdb.Kek",
            "uuid", uuid,
        ]
        return xdg_secret_lookup_secret(attrs)

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
