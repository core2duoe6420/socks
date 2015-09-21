# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


def encrypt(key, plaintext, iv=get_random_bytes(12), associated_data=""):
    encryptor = AES.new(key, AES.MODE_GCM, iv)
    encryptor.update(associated_data)
    ciphertext, mac = encryptor.encrypt_and_digest(plaintext)
    return iv + ciphertext + mac


def decrypt(key, ciphertext_with_iv_mac, associated_data=""):
    iv = ciphertext_with_iv_mac[:12]
    ciphertext = ciphertext_with_iv_mac[12:-16]
    mac = ciphertext_with_iv_mac[-16:]
    decryptor = AES.new(key, AES.MODE_GCM, iv)
    decryptor.update(associated_data)
    try:
        plaintext = decryptor.decrypt_and_verify(ciphertext, mac)
    except ValueError:
        return None
    return plaintext


def gen_key(password):
    salt = "yet another shadowsocks"
    for i in range(250):
        h = SHA256.new()
        h.update(salt + password)
        salt = h.digest()

    return salt[:16]


if __name__ == "__main__":
    key = gen_key("shabi")
    print(key)
    a = encrypt(key, "@4234")
    print(repr(a))
    print(decrypt(b'Sixteen byte key', a))