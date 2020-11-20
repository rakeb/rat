#
# basicRAT crypto module
# https://github.com/vesche/basicRAT
#
import base64
import hashlib
import os
import time

import pyDH as pyDH
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


def pad(s):
    return s.encode() + b'\0' * (AES.block_size - len(s) % AES.block_size)


# def encrypt(plaintext, key):
#     plaintext = pad(plaintext)
#     iv = Random.new().read(AES.block_size)
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     return iv + cipher.encrypt(plaintext)


# def decrypt(ciphertext, key):
#     print(ciphertext)
#     time.sleep(10)
#     iv = ciphertext[:AES.block_size]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     plaintext = cipher.decrypt(ciphertext[AES.block_size:])
#     return plaintext.rstrip(b'\0')


def diffiehellman(conn):
    me = pyDH.DiffieHellman()
    my_pubkey = me.gen_public_key()

    # print(my_pubkey)
    conn.send(long_to_bytes(my_pubkey))
    their_pubkey = bytes_to_long(conn.recv(4096))

    sharedkey = me.gen_shared_key(their_pubkey)
    # print(sharedkey.encode())
    # sharedkey = SHA256.new(sharedkey.encode()).digest()
    return sharedkey

# Diffie-Hellman Internet Key Exchange (IKE) - RFC 2631
# def diffiehellman_old(sock, bits=2048):
#     # using RFC 3526 MOPD group 14 (2048 bits)
#     p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF;
#     # p = 17
#     g = 2
#     a = bytes_to_long(os.urandom(32))  # a 256bit number, sufficiently large
#     # a = bytes_to_long(os.urandom(1))  # a 256bit number, sufficiently large
#     # print("g: {}, a: {}, p: {}".format(g, a, p))
#     xA = pow(g, a, p)
#
#     # print("diffiehellman sending to: {}".format(sock))
#     sock.send(long_to_bytes(xA))
#     b = bytes_to_long(sock.recv(256))
#
#     # print("diffiehellman received: {}".format(b))
#     s = pow(b, a, p)
#     digest = SHA256.new(long_to_bytes(s)).digest()
#     print("diffiehellman secret: {}".format(digest))
#     return digest
