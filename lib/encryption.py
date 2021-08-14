import base64

from .crypto_backend import *

class UnknownAlgorithmError(Exception):
    pass

class MessageAuthenticationError(Exception):
    pass

class CipherInstance():
    def __init__(self, key, algo=None):
        self.key = key
        self.algo = algo or ("aes-128-cfb8-siv" if key else "none")

    def _generate_key(self, nbits) -> "bytes":
        if nbits % 8:
            raise ValueError("nbits not divisible by 8")
        return random_bytes(nbits // 8)

    def _get_key_bits(self, nbits) -> "bytes":
        if nbits % 8:
            raise ValueError("nbits not divisible by 8")
        nbytes = nbits // 8
        if len(self.key) < nbytes:
            raise ValueError("key too short (%d < %d)" % (len(self.key), nbytes))
        return self.key[:nbits // 8]

    def _deterministic_iv(self, clear: "bytes", nbytes) -> "bytes":
        mac = hmac_sha256(clear, self.key)
        if len(mac) < nbytes:
            raise ValueError("resulting mac too short (%d < %d)" % (len(mac), nbytes))
        return mac[:nbytes]

    def _encrypt_data(self, clear: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")
        if algo[0] == "none":
            return clear
        elif algo[0] == "aes":
            if algo[1] in {"128", "192", "256"}:
                nbits = int(algo[1])
                key = self._get_key_bits(nbits)
                if algo[2] in {"cbc", "cfb", "cfb8", "cfb128"}:
                    if "siv" in algo[3:]:
                        iv = self._deterministic_iv(clear, AES_BLOCK_BYTES)
                    else:
                        iv = random_bytes(AES_BLOCK_BYTES)
                    if algo[2] == "cbc":
                        return iv + aes_cbc_pkcs7_encrypt(clear, key, iv)
                    elif algo[2] in {"cfb", "cfb8"}:
                        return iv + aes_cfb8_encrypt(clear, key, iv)
                    elif algo[2] == "cfb128":
                        return iv + aes_cfb128_encrypt(clear, key, iv)
        else:
            raise UnknownAlgorithmError()

    def _decrypt_data(self, wrapped: "bytes", algo: "str") -> "bytes":
        algo = algo.split("-")
        if algo[0] == "none":
            return wrapped
        elif algo[0] == "aes":
            if algo[1] in {"128", "192", "256"}:
                nbits = int(algo[1])
                key = self._get_key_bits(nbits)
                if algo[2] in {"cbc", "cfb", "cfb8", "cfb128"}:
                    iv = wrapped[:AES_BLOCK_BYTES]
                    buf = wrapped[AES_BLOCK_BYTES:]
                    if algo[2] == "cbc":
                        clear = aes_cbc_pkcs7_decrypt(buf, key, iv)
                    elif algo[2] in {"cfb", "cfb8"}:
                        clear = aes_cfb8_decrypt(buf, key, iv)
                    elif algo[2] == "cfb128":
                        clear = aes_cfb128_decrypt(buf, key, iv)
                    if "siv" in algo[3:]:
                        if iv != self._deterministic_iv(clear, AES_BLOCK_BYTES):
                            raise MessageAuthenticationError()
                    return clear
        else:
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

class SecureStorage():
    def __init__(self):
        self.kek_cipher = None
        self.dek_cipher = None
        self.kdf_salt = None
        self.kdf_iter = 4096

    # KEK

    @property
    def has_kek(self):
        return bool(self.kek_cipher and self.kek_cipher.key)

    def set_raw_kek(self, kek):
        if self.kek_cipher:
            raise Exception("KEK already set")
        else:
            self.kek_cipher = CipherInstance(kek)

    def change_raw_kek(self, new_kek):
        if not self.kek_cipher:
            raise Exception("KEK not yet set")
        elif not self.dek_cipher:
            raise Exception("DEK not yet set")
        else:
            self.kek_cipher = CipherInstance(new_kek)

    def kdf(self, passwd, salt=None, iter=None):
        return pbkdf2_sha1(passwd.encode("utf-8"),
                           salt or self.kdf_salt,
                           iter or self.kdf_iter,
                           length=16)

    def reset_kdf_parameters(self):
        self.kdf_salt = random_bytes(16)
        self.kdf_iter = 4096

    # DEK

    @property
    def has_dek(self):
        return bool(self.dek_cipher and self.dek_cipher.key)

    def generate_dek(self):
        if self.dek_cipher:
            raise Exception("DEK already set")
        elif not self.kek_cipher:
            raise Exception("KEK not yet set")
        else:
            dek = random_bytes(16)
            self.dek_cipher = CipherInstance(dek)

    def set_wrapped_dek(self, wrapped_dek):
        if self.dek_cipher:
            raise Exception("DEK already set")
        elif not self.kek_cipher:
            raise Exception("KEK not yet set, cannot decrypt DEK")
        else:
            dek = self.kek_cipher.unwrap_bytes(wrapped_dek)
            self.dek_cipher = CipherInstance(dek)

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
