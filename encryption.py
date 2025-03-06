import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64
import os

def xor_encrypt_decrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))


def rc4_encrypt_decrypt(text, key):
    S = list(range(256))
    j = 0
    out = []
    key = [ord(c) for c in key]
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for char in text:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
    return ''.join(out)


def des_encrypt_decrypt(text, key, mode, encrypt=True):
    key = key.ljust(8, ' ')[:8].encode()
    iv = b'12345678'
    if mode == DES.MODE_CBC:
        cipher = DES.new(key, mode, iv)
    elif mode == DES.MODE_CTR:
        ctr = Counter.new(64)
        cipher = DES.new(key, mode, counter=ctr)
    else:
        cipher = DES.new(key, mode)

    if encrypt:
        return base64.b64encode(cipher.encrypt(pad(text.encode(), DES.block_size))).decode()
    else:
        return unpad(cipher.decrypt(base64.b64decode(text)), DES.block_size).decode()


def aes_encrypt_decrypt(text, key, mode, encrypt=True):
    key = key.ljust(16, ' ')[:16].encode()
    iv = b'1234567812345678'
    if mode == AES.MODE_CBC:
        cipher = AES.new(key, mode, iv)
    elif mode == AES.MODE_CTR:
        ctr = Counter.new(128)
        cipher = AES.new(key, mode, counter=ctr)
    else:
        cipher = AES.new(key, mode)

    if encrypt:
        return base64.b64encode(cipher.encrypt(pad(text.encode(), AES.block_size))).decode()
    else:
        return unpad(cipher.decrypt(base64.b64decode(text)), AES.block_size).decode()