# cryptography.py
# AES-ECB + block hash helpers

import hashlib
from Crypto.Cipher import AES

AES_KEY = b"R0chLi4uLi4uLi4="  # from spec
BLOCK_SIZE = 16


def crypto_init():
    # basic sanity check
    return len(AES_KEY) in (16, 24, 32)


def _new_cipher():
    return AES.new(AES_KEY, AES.MODE_ECB)


def encrypt_id(plaintext):
    # plaintext:
    #   - 16 bytes: UUID (case_id)
    #   - 4 bytes:  int (item_id)
    n = len(plaintext)

    if n == 16:
        block = plaintext
    elif n == 4:
        # 4 bytes + 12 bytes of 0x0C padding
        block = plaintext + bytes([0x0C]) * 12
    else:
        raise ValueError("encrypt_id expects 4 or 16 bytes, got %d" % n)

    cipher = _new_cipher()
    return cipher.encrypt(block)  # 16-byte ciphertext


def decrypt_id(ciphertext):
    if len(ciphertext) != 16:
        raise ValueError("decrypt_id expects 16 bytes, got %d" % len(ciphertext))

    cipher = _new_cipher()
    block = cipher.decrypt(ciphertext)

    head = block[:4]
    tail = block[4:]

    # item_id pattern: 4 bytes + 12 bytes of 0x0C
    if tail == bytes([0x0C]) * 12:
        return head  # 4-byte int
    else:
        return block  # 16-byte UUID


def compute_block_hash(block_bytes):
    # SHA-256 -> 32-byte hash for prev_hash field
    return hashlib.sha256(block_bytes).digest()
