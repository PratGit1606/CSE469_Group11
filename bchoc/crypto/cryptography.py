# cryptography.py
# AES utilities for case_id and item_id

import struct
import uuid
from Crypto.Cipher import AES

AES_KEY = b"R0chLi4uLi4uLi4="
BLOCK_SIZE = 16

def _new_cipher():
    return AES.new(AES_KEY, AES.MODE_ECB)



# Case ID (UUID)


def encrypt_case_id(case_id_str):
    u = uuid.UUID(case_id_str)
    plaintext = u.bytes  # 16 bytes
    cipher = _new_cipher()
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex().encode("ascii")  # 32 bytes


def decrypt_case_id(field_bytes):
    hex_str = field_bytes.decode("ascii")
    ciphertext = bytes.fromhex(hex_str)
    cipher = _new_cipher()
    plaintext = cipher.decrypt(ciphertext)
    u = uuid.UUID(bytes=plaintext)
    return str(u)



# Item ID (4-byte int)


def encrypt_item_id(item_id):
    raw = struct.pack(">I", item_id)  # 4 bytes
    padded = raw + bytes([0x0C]) * 12  # always pad to 16
    cipher = _new_cipher()
    ciphertext = cipher.encrypt(padded)
    return ciphertext.hex().encode("ascii")  # 32 bytes


def decrypt_item_id(field_bytes):
    hex_str = field_bytes.decode("ascii")
    ciphertext = bytes.fromhex(hex_str)
    cipher = _new_cipher()
    padded = cipher.decrypt(ciphertext)
    raw = padded[:4]
    padding = padded[4:]
    if padding != bytes([0x0C]) * 12:
        raise ValueError("Invalid padding for item_id")
    return struct.unpack(">I", raw)[0]
