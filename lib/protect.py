import base64
import os

class UnknownAlgorithmError(Exception):
    pass

class Cipher(object):
    def __init__(self, key, algo="aes-128-cfb"):
        self.key = key
        self.algo = algo

    def _generate_key(self, nbits) -> "bytes":
        if nbits % 8:
            raise ValueError("nbits not divisible by 8")
        return os.urandom(nbits // 8)

    def _get_key_bits(self, nbits) -> "bytes":
        if nbits % 8:
            raise ValueError("nbits not divisible by 8")
        nbytes = nbits // 8
        if len(self.key) < nbytes:
            raise ValueError("key too short (%d < %d)" % (len(self.key), nbytes))
        return self.key[:nbits // 8]

    def _encrypt_data(self, clear: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")
        if algo[0] == "none":
            return clear
        elif algo[0] == "aes":
            from Crypto.Cipher import AES
            if algo[1] in {"128", "192", "256"}:
                nbits = int(algo[1])
                key = self._get_key_bits(nbits)
                if algo[2] == "cfb":
                    iv = os.urandom(AES.block_size)
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                    return iv + cipher.encrypt(clear)
        raise UnknownAlgorithmError()

    def _decrypt_data(self, wrapped: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")
        if algo[0] == "none":
            return wrapped
        elif algo[0] == "aes":
            from Crypto.Cipher import AES
            if algo[1] in {"128", "192", "256"}:
                nbits = int(algo[1])
                key = self._get_key_bits(nbits)
                if algo[2] == "cfb":
                    iv = wrapped[:AES.block_size]
                    buf = wrapped[AES.block_size:]
                    cipher = AES.new(key, AES.MODE_CFB, iv)
                    return cipher.decrypt(buf)
        raise UnknownAlgorithmError()

    def wrap_bytes(self, clear: "bytes") -> "str":
        wrapped = self._encrypt_data(clear, self.algo)
        wrapped = base64.b64encode(wrapped).decode("utf-8")
        wrapped = "%s;%s" % (self.algo, wrapped)
        return wrapped

    def unwrap_bytes(self, wrapped: "str") -> "str":
        algo, wrapped = wrapped.split(";", 1)
        wrapped = base64.b64decode(wrapped.encode("utf-8"))
        clear = self._decrypt_data(wrapped, algo)
        return clear

    def wrap_str(self, clear: "str") -> "str":
        return self.wrap_bytes(clear.encode("utf-8"))

    def unwrap_str(self, wrapped: "str") -> "str":
        return self.unwrap_bytes(wrapped).decode("utf-8")

class SecureStorage(object):
    def __init__(self):
        self.kdf_salt = b"\x25\xa9\x7b\xc5\x7a\x59\x0d\xa6"
        self.kek_cipher = None
        self.dek_cipher = None

    # KEK

    def set_raw_kek(self, kek):
        if self.kek_cipher:
            raise Exception("KEK already set")
        else:
            self.kek_cipher = Cipher(kek)

    def kdf(self, passwd):
        from Crypto.Protocol import KDF
        return KDF.PBKDF2(passwd, self.kdf_salt, 16)

    # DEK

    def generate_dek(self):
        if self.dek_cipher:
            raise Exception("DEK already set")
        elif not self.kek_cipher:
            raise Exception("KEK not yet set")
        else:
            dek = os.urandom(16)
            self.dek_cipher = Cipher(dek)

    def set_wrapped_dek(self, wrapped_dek):
        if self.dek_cipher:
            raise Exception("DEK already set")
        elif not self.kek_cipher:
            raise Exception("KEK not yet set, cannot decrypt DEK")
        else:
            dek = self.kek_cipher.unwrap_bytes(wrapped_dek)
            self.dek_cipher = Cipher(dek)

    def get_wrapped_dek(self):
        if not self.dek_cipher:
            raise Exception("DEK not yet set")
        elif not self.kek_cipher:
            raise Exception("KEK not yet set, cannot encrypt DEK")
        else:
            return self.kek_cipher.wrap_bytes(self.dek_cipher.key)

    def wrap_data(self, data):
        if not self.dek_cipher:
            raise Exception("DEK not yet set")
        else:
            return self.dek_cipher.wrap_str(data)

    def unwrap_data(self, data):
        if not self.dek_cipher:
            raise Exception("DEK not yet set")
        else:
            return self.dek_cipher.unwrap_str(data)

def default_enc(keyring):
    enc = SecureStorage()
    kek = enc.kdf("TEST PASSWORD") # XXX
    enc.set_raw_kek(kek)
    return enc
