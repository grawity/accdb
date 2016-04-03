# 'SecretStore' {{{

# todo:
#
#   class SecureKeyring - retrieve arbitrary keys from GNOME Keyring or files
#
#   class SecureStorage -
#       obtain key from SecureKeyring or prompt for PBKDF2
#       wrap/unwrap

class UnknownAlgorithmError(Exception):
    pass

class SecretStore(object):
    default_algo = "aes-128-cfb"

    def __init__(self, key):
        self.key = key

    def get_key(self, nbits) -> "bytes":
        nbytes = int(nbits >> 3)
        return self.key[:nbytes]

    def wrap(self, clear: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")
        if algo[0] == "none":
            return clear
        elif algo[0] == "aes":
            from Crypto.Cipher import AES
            if algo[1] in {"128", "192", "256"}:
                nbits = int(algo[1])
                key = self.get_key(nbits)
                if algo[2] == "cfb":
                    iv = os.urandom(AES.block_size)
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                    return iv + cipher.encrypt(clear)

        raise UnknownAlgorithmError()

    def unwrap(self, wrapped: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")
        if algo[0] == "none":
            return wrapped
        elif algo[0] == "aes":
            from Crypto.Cipher import AES
            if algo[1] in {"128", "192", "256"}:
                nbits = int(algo[1])
                key = self.get_key(nbits)
                if algo[2] == "cfb":
                    iv = wrapped[:AES.block_size]
                    buf = wrapped[AES.block_size:]
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                    return cipher.decrypt(buf)

        raise UnknownAlgorithmError()

# @clear: (string) plain data
# -> (base64-encoded string) encrypted data

def wrap_secret(clear: "str") -> "base64: str":
    global ss

    if ss:
        algo = ss.default_algo
        clear = clear.encode("utf-8")
        wrapped = ss.wrap(clear, algo)
        wrapped = base64.b64encode(wrapped)
        wrapped = wrapped.decode("utf-8")
        wrapped = "%s;%s" % (algo, wrapped)
        return wrapped
    else:
        Core.die("encryption not available")

# @wrapped: (base64-encoded string) encrypted data
# -> (string) plain data

def unwrap_secret(wrapped):
    global ss

    if ss:
        algo, wrapped = wrapped.split(";", 1)
        wrapped = wrapped.encode("utf-8")
        wrapped = base64.b64decode(wrapped)
        clear = ss.unwrap(wrapped, algo)
        clear = clear.decode("utf-8")
        return clear
    else:
        return wrapped

# }}}
