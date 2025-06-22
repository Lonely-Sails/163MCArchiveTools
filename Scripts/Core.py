from typing import Optional

from Const import MAGIC_NUMBER_ALT, MAGIC_NUMBER, DEFAULT_KEY


def check_file_is_encrypt(data: bytes) -> bool:
    if len(data) < 4:
        return False
    magic = int.from_bytes(data[:4], 'big')
    return magic == MAGIC_NUMBER or magic == MAGIC_NUMBER_ALT


def encrypt_file(data: bytes) -> Optional[bytes]:
    if len(data) < 4 or check_file_is_encrypt(data):
        return
    result = bytearray(data)
    for index in range(len(result)):
        result[index] ^= DEFAULT_KEY[index % 8]
    return MAGIC_NUMBER.to_bytes(4, 'big') + bytes(result)


def decrypt_file(data: bytes, key: Optional[bytes] = None) -> Optional[bytes]:
    if len(data) < 4 or not check_file_is_encrypt(data):
        return
    result = bytearray(data[4:])
    decryption_key = key if key is not None else DEFAULT_KEY
    for index in range(len(result)):
        result[index] ^= decryption_key[index % 8]
    return bytes(result)
