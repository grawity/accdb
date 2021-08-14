import os

backend = os.environ.get("CRYPTO_BACKEND", "cryptography")

if backend == "cryptodome":
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA1, SHA256
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util import Padding

    AES_BLOCK_BYTES = AES.block_size

    def aes_cbc_pkcs7_encrypt(data, key, iv):
        return AES.new(key, AES.MODE_CBC, iv).encrypt(Padding.pad(data, AES.block_size))

    def aes_cbc_pkcs7_decrypt(data, key, iv):
        return Padding.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), AES.block_size)

    def aes_cfb8_encrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv).encrypt(data)

    def aes_cfb8_decrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv).decrypt(data)

    def aes_cfb128_encrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv, segment_size=128).encrypt(data)

    def aes_cfb128_decrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv, segment_size=128).decrypt(data)

    def hmac_sha256(data, key):
        return HMAC.new(key, data, SHA256).digest()

    def pbkdf2_sha1(password, salt, iter, length):
        return PBKDF2(password, salt, length, iter, hmac_hash_module=SHA1)

elif backend == "cryptography":
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers.modes import CBC, CFB, CFB8
    from cryptography.hazmat.primitives.hashes import SHA1, SHA256
    from cryptography.hazmat.primitives.hmac import HMAC
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.padding import PKCS7

    AES_BLOCK_BYTES = AES.block_size // 8

    def aes_cbc_pkcs7_encrypt(data, key, iv):
        p = PKCS7(AES.block_size).padder()
        data = p.update(data) + p.finalize()
        c = Cipher(AES(key), CBC(iv)).encryptor()
        return c.update(data) + c.finalize()

    def aes_cbc_pkcs7_decrypt(data, key, iv):
        c = Cipher(AES(key), CBC(iv)).decryptor()
        data = c.update(data) + c.finalize()
        p = PKCS7(AES.block_size).unpadder()
        return p.update(data) + p.finalize()

    def aes_cfb8_encrypt(data, key, iv):
        c = Cipher(AES(key), CFB8(iv)).encryptor()
        return c.update(data) + c.finalize()

    def aes_cfb8_decrypt(data, key, iv):
        c = Cipher(AES(key), CFB8(iv)).decryptor()
        return c.update(data) + c.finalize()

    def aes_cfb128_encrypt(data, key, iv):
        c = Cipher(AES(key), CFB(iv)).encryptor()
        return c.update(data) + c.finalize()

    def aes_cfb128_decrypt(data, key, iv):
        c = Cipher(AES(key), CFB(iv)).decryptor()
        return c.update(data) + c.finalize()

    def hmac_sha256(data, key):
        h = HMAC(key, SHA256())
        h.update(data)
        return h.finalize()

    def pbkdf2_sha1(password, salt, iter, length):
        k = PBKDF2HMAC(SHA1(), length, salt, iter)
        return k.derive(password)

else:
    raise ValueError("unsupported backend %r" % backend)
