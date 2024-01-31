#!/usr/bin/env python

"""
Common functions and variables for the streams toolbelt.
"""

import base64
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto import Random

ENCODING_CHOICES = ['raw', 'hex', 'base64']

BS = AES.block_size
# _pad = lambda s: s + (BS - len(s) % BS) * bytearray(BS - len(s) % BS)
# _unpad = lambda s : s[:-ord(s[len(s)-1:])]

def _unpad(b):
    # print(repr(b))
    padding_byte = b[len(b) - 1]
    padding_len = int(padding_byte)
    return b[:padding_len]
    # print(repr(padding_byte))

def _pad(b):
    padding_needed = (BS - len(b) % BS)
    padding_byte = padding_needed.to_bytes(1, 'little')
    return b + (padding_needed * bytearray(padding_byte))

def aes_decrypt(raw, key, iv=None):
    # if an iv hasn't been provided, it's probably prepended to the cryptotext
    if not iv:
        iv = raw[:AES.block_size]
        raw = raw[AES.block_size:]

    # print(repr(raw))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(raw)
    # print(repr(plain))
    return _unpad(plain)

def aes_encrypt(raw, key, iv=None):
    # raw = raw.decode()
    # print(repr(raw))
    raw = _pad(raw)
    # print(repr(raw))

    if not iv:
        iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return iv + cipher.encrypt(raw)

def xor_bytes(key, input):
    key_len = len(key)
    input_len = len(input)

    buf = bytes()
    for input_idx in range(input_len):
        key_idx = input_idx % key_len
        c = input[input_idx] ^ key[key_idx]
        buf += c.to_bytes(1, 'little')

    return buf


def encode(in_bytes, enc_type):
    if enc_type not in ENCODING_CHOICES:
        raise ValueError('Invalid encoding type: {}'.format(enc_type))
    
    if enc_type == 'raw':
        return in_bytes

    if enc_type == 'base64':
        return base64.b64encode(in_bytes)
    
    if enc_type == 'hex':
        return hexlify(in_bytes)


def decode(in_bytes, enc_type):
    if enc_type not in ENCODING_CHOICES:
        raise ValueError('Invalid encoding type: {}'.format(enc_type))
    
    if enc_type == 'raw':
        return in_bytes

    if enc_type == 'base64':
        return base64.b64decode(in_bytes)
    
    if enc_type == 'hex':
        in_bytes = in_bytes.replace(' '.encode(),  ''.encode())
        in_bytes = in_bytes.replace('0x'.encode(), ''.encode())
        in_bytes = in_bytes.replace(','.encode(),  ''.encode())
        return unhexlify(in_bytes)
