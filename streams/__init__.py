#!/usr/bin/env python

"""
Common functions and variables for the streams toolbelt.
"""

import base64
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
import re
from requests_toolbelt import MultipartDecoder

ENCODING_CHOICES = ['raw', 'hex', 'base64']

BS = AES.block_size

def aes_decrypt(raw, key, iv=None):
    # if an iv hasn't been provided, it's probably prepended to the cryptotext
    if not iv:
        iv = raw[:AES.block_size]
        raw = raw[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(raw)
    return unpad(plain, AES.block_size)

def aes_encrypt(raw, key, iv=None):
    raw = pad(raw, AES.block_size)

    if not iv:
        iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return iv + cipher.encrypt(raw)

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

def mime_extract(name, in_bytes):
    """
    Example MIME content:
--d089ddf8bf654f4f81448b78f0be30d1
Content-Disposition: form-data; name="data"

Wz/AcWLJvO+yS7Yg9tiMV/WnJ4KNkHWR8d47ENus6Kqr...
--d089ddf8bf654f4f81448b78f0be30d1--
    """

    # discover MIME boundary
    # HACK typically the boundary is provided by something else, such
    # as HTTP headers. Here we make an educated guess.
    
    # boundary is hex and has to have len > 8 chars
    boundary_pat = '--(?P<boundary>[0-9A-Za-z]{8,})'

    in_str = in_bytes.decode()
    m = re.match(boundary_pat, in_str)
    if not m:
        return None
    
    boundary = m['boundary']
    content_type = 'multipart/form-data; boundary={}'.format(boundary)

    in_bytes = in_bytes.replace(b'\n', b'\r\n')
    decoder = MultipartDecoder(in_bytes, content_type)
    name_pat = '(.*);\s*name="(?P<name>[A-Za-z0-9\-_]+)"(.*)'
    for part in decoder.parts:
        cd = part.headers[b'Content-Disposition']
        m = re.match(name_pat, cd.decode())
        matched_name = m['name']
        if matched_name == name:
            return part.content

    return None

def xor_bytes(key, input):
    key_len = len(key)
    input_len = len(input)

    buf = bytes()
    for input_idx in range(input_len):
        key_idx = input_idx % key_len
        c = input[input_idx] ^ key[key_idx]
        buf += c.to_bytes(1, 'little')

    return buf
