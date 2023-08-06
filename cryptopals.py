#!/usr/bin/env python3
"""Cryptopals sulotions."""

import base64
import random
import secrets
import struct
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sha1 import Sha1Hash
from md4 import MD4
import hashlib


class MyException(Exception):
    """My Exception class."""


def hex_to_base64(hex_str):
    """Convert hex string to base64 bytes."""
    bins = base64.b16decode(hex_str, True)
    result = base64.b64encode(bins)
    return result


def challenge1():
    """Challenge 1"""
    str1 = b"49276d206b696c6c696e6720796f757220627261696e206c696b6520612070"\
            b"6f69736f6e6f7573206d757368726f6f6d"
    expected = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2"\
            b"hyb29t"
    result = hex_to_base64(str1)
    assert result == expected


def fixed_xor(bins1, bins2):
    """Xor two bytes object of equal length."""
    result_bins = bytes(a ^ b for a, b in zip(bins1, bins2))
    return result_bins


def challenge2():
    """Challenge 2."""
    str1 = b"1c0111001f010100061a024b53535009181c"
    str2 = b"686974207468652062756c6c277320657965"
    expected = b"746865206b696420646f6e277420706c6179"

    bins1 = base64.b16decode(str1, True)
    bins2 = base64.b16decode(str2, True)
    result = base64.b16encode(fixed_xor(bins1, bins2)).lower()
    assert result == expected


# https://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html
LETTER_FREQ = {
    b"a": 0.08167, b"b": 0.01492, b"c": 0.02782, b"d": 0.04253,
    b"e": 0.12702, b"f": 0.02228, b"g": 0.02015, b"h": 0.06094,
    b"i": 0.06966, b"j": 0.00153, b"k": 0.00772, b"l": 0.04025,
    b"m": 0.02406, b"n": 0.06749, b"o": 0.07507, b"p": 0.01929,
    b"q": 0.00095, b"r": 0.05987, b"s": 0.06327, b"t": 0.09056,
    b"u": 0.02758, b"v": 0.00978, b"w": 0.02360, b"x": 0.00150,
    b"y": 0.01974, b"z": 0.00074,
    # space frequency from: http://www.fitaly.com/board/domper3/posts/136.html
    b" ": 0.17166,
    }

"""
LETTER_FREQ = {
    b'a': 0.0651738, b'b': 0.0124248, b'c': 0.0217339, b'd': 0.0349835,
    b'e': 0.1041442, b'f': 0.0197881, b'g': 0.0158610, b'h': 0.0492888,
    b'i': 0.0558094, b'j': 0.0009033, b'k': 0.0050529, b'l': 0.0331490,
    b'm': 0.0202124, b'n': 0.0564513, b'o': 0.0596302, b'p': 0.0137645,
    b'q': 0.0008606, b'r': 0.0497563, b's': 0.0515760, b't': 0.0729357,
    b'u': 0.0225134, b'v': 0.0082903, b'w': 0.0171272, b'x': 0.0013692,
    b'y': 0.0145984, b'z': 0.0007836, b' ': 0.1918182
}
"""

def score_english(text):
    """Score helper function."""
    score = 0.0
    for byte in text:
        score += LETTER_FREQ.get(bytes([byte]).lower(), 0)
    return score


def break_single_byte_xor(cipher):
    """Brute-forcing single byte xor encryption."""
    plain = None
    score = 0.0
    key = None
    for i in range(0, 256):
        candidate = bytes(i ^ c for c in cipher)
        candidate_score = score_english(candidate)
        if candidate_score > score:
            score = candidate_score
            plain = candidate
            key = i
    return plain, score, key


def challenge3():
    """Challenge 3."""
    cipher = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a39"\
             b"3b3736"
    bins = base64.b16decode(cipher, True)
    plain = break_single_byte_xor(bins)[0]
    # print(plain)
    assert plain == b"Cooking MC's like a pound of bacon"


def challenge4():
    """Challenge 4."""
    plain = None
    score = 0.0
    with open("4.txt", "r", encoding="utf-8") as f:
        for line in f:
            # strip "\n"
            cipher = base64.b16decode(line[:-1], True)
            cand, cand_score, _ = break_single_byte_xor(cipher)
            if cand_score > score:
                score = cand_score
                plain = cand
    # print(plain)
    assert plain == b"Now that the party is jumping\n"


def repeating_key_xor(plain, key):
    """Repeating xor encryption."""
    key_len = len(key)
    repeated_key = bytes(key[i % key_len] for i in range(0, len(plain)))
    #result = bytes(k ^ ord(c) for k, c in zip(repeated_key, plain))
    result = fixed_xor(plain, repeated_key)
    return result


def challenge5():
    """Challenge 5."""
    plain = b"Burning 'em, if you ain't quick and nimble\n"\
            b"I go crazy when I hear a cymbal"
    key = b"ICE"
    expected = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2"\
            b"6226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c6"\
            b"92b20283165286326302e27282f"
    cipher = repeating_key_xor(plain, key)
    result = base64.b16encode(cipher).lower()
    # print(result)
    assert result == expected


def hamming_distance(str1, str2):
    """Calculate hamming distance."""
    assert len(str1) == len(str2)
    dist = 0
    for i, j in zip(str1, str2):
        k = i ^ j
        while k != 0:
            dist += k & 1
            k >>= 1
    return dist


def hamming_distance_normalize(str1, str2):
    """Calculate average hamming distance."""
    return hamming_distance(str1, str2) / len(str1)


def break_repeating_key_xor(cipher):
    """6."""
    # Calculate possible key size
    size_map = {}
    for ks in range(2, 41):
        dist = 0.0
        for block in range(0, 4):
            dist += hamming_distance_normalize(
                cipher[block * ks : (block + 1) * ks],
                cipher[(block + 1) * ks : (block + 2) * ks])
        size_map[dist] = ks
        sorted_dist = sorted(size_map.keys())
    # Try the first four key size
    key0_score = 0.0
    key_size = 0
    for i in range(0, 4):
        cand_key_size = size_map[sorted_dist[i]]
        first_group = bytes(cipher[i] for i in range(0, len(cipher),
                                                     cand_key_size))
        _, cand_score, _ = break_single_byte_xor(first_group)
        cand_score /= len(first_group)
        if cand_score > key0_score:
            key0_score = cand_score
            key_size = cand_key_size

    # Decrypt
    plain = bytearray(len(cipher))
    for i in range(0, key_size):
        group = bytes(cipher[i + j] for j in range(0, len(cipher), key_size)\
                      if i + j < len(cipher))
        cand_plain, cand_score, _ = break_single_byte_xor(group)
        j = 0
        for byte in cand_plain:
            plain[j * key_size + i] = byte
            j += 1
    return plain


def challenge6():
    """Challeng 6."""
    str1 = b"this is a test"
    str2 = b"wokka wokka!!!"
    assert hamming_distance(str1, str2) == 37

    with open("6.txt", "r", encoding="utf-8") as f:
        cipher = base64.b64decode(f.read())
    result = break_repeating_key_xor(cipher)
    with open("6-plain.txt", "rb") as f:
        expected = f.read()
    assert result == expected


def aes_ecb_decrypt(cipher, key):
    """Aes ecb by hand.
    The caller must make sure that cipher is correctly padded.
    """
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(cipher) + decryptor.finalize()


def challenge7():
    """Challenge 7."""
    key = b"YELLOW SUBMARINE"
    with open("7.txt", "r", encoding="utf-8") as f:
        cipher = base64.b64decode(f.read())
    result = aes_ecb_decrypt(cipher, key)
    with open("7-plain.txt", "rb") as f:
        expected = f.read()
    assert result == expected


def detect_aes_ecb(cipher):
    """Detect if cipher is encrypted using ECB mode."""
    block_map = {}
    blocks = len(cipher) // 16
    for i in range(0, blocks):
        block = cipher[i * 16 : (i + 1) * 16]
        if block in block_map:
            return True
        else:
            block_map[block] = 1
    return False


def challenge8():
    """Challenge 8."""
    expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744c"\
            "d283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744"\
            "cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c74"\
            "4cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c7"\
            "44cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b0"\
            "6fba186a\n"

    result = None
    with open("8.txt", "r", encoding="utf-8") as f:
        for line in f:
            cipher = base64.b64decode(line[:-1])
            if detect_aes_ecb(cipher):
                result = line
                break
    assert result == expected


def pkcs7padding(data, block_size):
    """A pkcs7padding implementation."""
    data_len = len(data)
    padding_size = block_size - data_len % block_size
    padding_bytes = bytes([padding_size]) * padding_size
    return data + padding_bytes


def pkcs7depadding(plain, block_size):
    """A pkcs7padding implementation for depadding."""
    return validate_pkcs7(plain, block_size)


def challenge9():
    """Challenge 9."""
    block = b"YELLOW SUBMARINE"
    expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    result = pkcs7padding(block, 20)
    assert result == expected


def aes_cbc_pkcs7_decrypt_by_ecb(cipher, key, iv):
    """Implement aes cbc mode decryption by ecb mode."""
    saved_iv = iv
    plain = bytearray()
    for i in range(0, len(cipher), 16):
        block = cipher[i: i + 16]
        plain_block = aes_ecb_decrypt(block, key)
        plain_block = fixed_xor(iv, plain_block)
        iv = block
        plain.extend(plain_block)
    plain = pkcs7depadding(plain, 16)
    return bytes(plain)


def challenge10():
    """Challenge 10."""
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * 16
    with open("10.txt", "rb") as f:
        cipher = base64.b64decode(f.read())
    plain = aes_cbc_pkcs7_decrypt_by_ecb(cipher, key, iv)
    with open("10-plain.txt", "rb") as f:
        expected = f.read()
    assert plain == expected


def aes_ecb_encrypt(plain, key):
    """Aes encryption with ecb mode.
    The caller must make sure that plain is correctly padded.
    """
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(plain) + encryptor.finalize()


def aes_ecb_pkcs7_encrypt(plain, key):
    """As function name says."""
    return aes_ecb_encrypt(pkcs7padding(plain, 16), key)


def aes_ecb_pkcs7_decrypt(cipher, key):
    """As function name says."""
    return pkcs7depadding(aes_ecb_decrypt(cipher, key), 16)


def aes_cbc_pkcs7_encrypt_by_ecb(plain, key, iv):
    """Implement aes cbc mode encryption by ecb mode."""
    cipher = bytearray()
    padded = pkcs7padding(plain, 16)
    for i in range(0, len(padded), 16):
        block = fixed_xor(padded[i: i + 16], iv)
        block_cipher = aes_ecb_encrypt(block, key)
        iv = block_cipher
        cipher.extend(block_cipher)
    return cipher


def encryption_oracle(plain):
    """encryption oracle."""
    key = secrets.token_bytes(16)
    ecb_mode = secrets.randbelow(2) == 0 # 0 for ecb, 1 for cbc
    prefix_len = secrets.randbelow(6) + 5 # [5, 10]
    prefix = secrets.token_bytes(prefix_len)
    postfix_len = secrets.randbelow(6) + 5 # [5, 10]
    postfix = secrets.token_bytes(postfix_len)
    plain = prefix + plain + postfix
    if ecb_mode: # ecb
        return aes_ecb_pkcs7_encrypt(plain, key), ecb_mode
    else: # cbc
        iv = secrets.token_bytes(16)
        return aes_cbc_pkcs7_encrypt_by_ecb(plain, key, iv), ecb_mode

def challenge11():
    """Challenge 11."""
    plain = b"a" * (11 + 32)
    def is_ecb(cipher):
        return cipher[16:32] == cipher[32:48]

    for _ in range(10):
        cipher, aes_mode = encryption_oracle(plain)
        assert is_ecb(cipher) == aes_mode


AES_ECB_ORACLE_KEY = secrets.token_bytes(16)
UNKOWN_STRING = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"\
                b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"\
                b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"\
                b"YnkK"
def aes_ecb_oracle(plain):
    """Aes ecb oracle."""
    plain += base64.b64decode(UNKOWN_STRING)
    return aes_ecb_pkcs7_encrypt(plain, AES_ECB_ORACLE_KEY)


def get_detector_dict(detector):
    """Get detector dict."""
    detector_dict = {}
    length = len(detector)
    prefix = bytearray(detector)
    prefix.append(0)
    for i in range(256):
        prefix[length] = i
        cipher = aes_ecb_oracle(prefix)
        detector_dict[cipher[:16]] = i
    return detector_dict


def challenge12():
    """Challenge 12."""
    # Detect block size and if it is ECB mode
    ecb = False
    block_size = 0
    for bs in range(1, 20):
        if detect_aes_ecb(aes_ecb_oracle(b"A" * 2 * bs)):
            ecb = True
            block_size = bs
            break
    assert (ecb, block_size) == (True, 16)

    # Get lenght of UNKOWN_STRING
    unkown_str_len = len(aes_ecb_oracle(b""))
    prev_len = unkown_str_len
    padding_size = 0
    for i in range(1, block_size + 1):
        curr_len = len(aes_ecb_oracle(b"A" * i))
        if curr_len != prev_len:
            padding_size = i
            break
        else:
            prev_len = curr_len
    unkown_str_len -= padding_size

    # Decrypt UNKOWN_STRING
    plain = bytearray(unkown_str_len)
    detector = b"A" * (block_size - 1)
    for i in range(unkown_str_len):
        block, offset = divmod(i, block_size)
        detector_dict = get_detector_dict(detector)
        prefix = b"A" * (block_size - 1 - offset)
        cipher = aes_ecb_oracle(prefix)
        idx = block * block_size
        plain[i] = detector_dict[cipher[idx:idx+16]]
        detector = detector[1:] + plain[i].to_bytes(1, "little")
    # print(plain)
    expected = b"Rollin\' in my 5.0\nWith my rag-top down so my hair can blow"\
            b"\nThe girlies on standby waving just to say hi\nDid you stop? "\
            b"No, I just drove by\n"
    assert plain == expected


def parse_profile(kv_bytes):
    """Parse a key value profile."""
    kv_items = {}
    kvs = kv_bytes.split(b"&")
    for item in kvs:
        kv = item.split(b"=")
        kv_items[kv[0]] = kv[1]
    return kv_items


def profile_for(email):
    """profile_for"""
    prefix = b"email="
    post = b"&uid=10&role=user"
    kv_bytes = prefix + email.replace(b"&", b"").replace(b"=", b"") + post
    return kv_bytes


PROFILE_KEY = secrets.token_bytes(16)
def encrypt_profile(email):
    """encrypt_profile"""
    kv_bytes = profile_for(email)
    cipher = aes_ecb_pkcs7_encrypt(kv_bytes, PROFILE_KEY)
    return cipher


def decrypt_profile(cipher):
    """decrypt_profile"""
    profile = aes_ecb_pkcs7_decrypt(cipher, PROFILE_KEY)
    # print(profile)
    return parse_profile(profile)


def challenge13():
    """Challenge 13."""
    length1 = len(b"email=&uid=10&role=")
    email = b"A@B"
    email_len = len(email)
    target_len = 16 - length1 % 16
    if target_len < email_len:
        target_len += 16
    if target_len > email_len:
        padding_len = target_len - email_len
    email += b"B" * padding_len
    cipher1 = encrypt_profile(email)
    length2 = len(b"email=")
    email = b"A" * (16 - length2)
    email += b"admin" + b"\x0b" * 0x0b
    cipher2 = encrypt_profile(email)
    cipher = cipher1[:target_len + length1] + cipher2[16:32]

    profile = decrypt_profile(cipher)
    assert b"role" in profile
    assert profile[b"role"] == b"admin"


RANDOM_PREFIX_LEN = secrets.randbelow(32) + 1 # 1 ~ 32
RANDOM_PREFIX = secrets.token_bytes(RANDOM_PREFIX_LEN)
def aes_ecb_oracle_with_prefix(plain):
    """Aes ecb oracle with random prefix."""
    plain = RANDOM_PREFIX + plain + base64.b64decode(UNKOWN_STRING)
    return aes_ecb_pkcs7_encrypt(plain, AES_ECB_ORACLE_KEY)


def get_detector_dict_with_prefix(detector, idx, size):
    """Get detector dict."""
    detector_dict = {}
    length = len(detector)
    prefix = bytearray(detector)
    prefix.append(0)
    for i in range(256):
        prefix[length] = i
        cipher = aes_ecb_oracle_with_prefix(prefix)
        detector_dict[cipher[idx:idx+size]] = i
    return detector_dict


def challenge14():
    """Challenge 14."""
    block_size = 16

    # Get length of prefix
    prefix_size = 0
    for i in range(block_size):
        cipher = aes_ecb_oracle_with_prefix(b"A" * (block_size * 2 + i))
        prev = cipher[:block_size]
        for j in range(block_size, len(cipher), block_size):
            curr = cipher[j:j+block_size]
            if prev == curr:
                prefix_size = j - block_size - i
                break
            else:
                prev = curr
        if prefix_size != 0:
            break

    # Get lenght of UNKOWN_STRING
    unkown_str_len = len(aes_ecb_oracle_with_prefix(b""))
    prev_len = unkown_str_len
    padding_size = 0
    for i in range(1, block_size + 1):
        curr_len = len(aes_ecb_oracle_with_prefix(b"A" * i))
        if curr_len != prev_len:
            padding_size = i
            break
        else:
            prev_len = curr_len
    unkown_str_len -= padding_size + prefix_size

    # Break
    plain = bytearray(unkown_str_len)
    prefix_padding_size = (block_size - prefix_size % block_size) % block_size
    prefix_padding = b"A" * prefix_padding_size
    detector = b"A" * (block_size - 1)
    for i in range(unkown_str_len):
        block, offset = divmod(i, block_size)
        idx = prefix_size + prefix_padding_size + (block * block_size)
        detector_dict = get_detector_dict_with_prefix(prefix_padding + detector, prefix_size + prefix_padding_size, block_size)
        middle = b"A" * (block_size - 1 - offset)
        cipher = aes_ecb_oracle_with_prefix(prefix_padding + middle)
        plain[i] = detector_dict[cipher[idx:idx+block_size]]
        detector = detector[1:] + plain[i].to_bytes(1, "little")
    # print(plain)

    expected = base64.b64decode(UNKOWN_STRING)
    assert plain == expected


BAD_MSG = "Bad padding"
def validate_pkcs7(data, block_size):
    """Validate if data is pkcs7 padding."""
    length = len(data)
    if length == 0:
        raise MyException(BAD_MSG)
    last = data[-1]
    if last == 0 or last > block_size:
        raise MyException(BAD_MSG)
    if length < last:
        raise MyException(BAD_MSG)
    for i in range(length - last, length):
        if data[i] != last:
            raise MyException(BAD_MSG)
    return data[:-last]


def challenge15():
    """Challeng 15."""
    data = b"ICE ICE BABY\x04\x04\x04\x04"
    expected = b"ICE ICE BABY"
    result = validate_pkcs7(data, 16)
    assert result == expected

    expected = BAD_MSG

    result = None
    try:
        data = b"ICE ICE BABY\x05\x05\x05\x05"
        validate_pkcs7(data, 16)
    except MyException as err:
        result = err.args[0]
    assert result == expected

    result = None
    try:
        data = b"ICE ICE BABY\x01\x02\x03\x04"
        validate_pkcs7(data, 16)
    except MyException as err:
        result = err.args[0]
    assert result == expected


CBC_BITFLIPPING_KEY = secrets.token_bytes(16)
CBC_BITFLIPPING_IV = secrets.token_bytes(16)
def cbc_bitflipping_enc(plain):
    """For challenge 16"""
    plain = plain.replace(b";", b"").replace(b"=", b"")
    prefix = b"comment1=cooking%20MCs;userdata="
    postfix = b";comment2=%20like%20a%20pound%20of%20bacon"
    return aes_cbc_pkcs7_encrypt_by_ecb(prefix + plain + postfix,
                                        CBC_BITFLIPPING_KEY,
                                        CBC_BITFLIPPING_IV)


def has_admin(cipher):
    """Decrypt and find b";admin=true;"."""
    plain = aes_cbc_pkcs7_decrypt_by_ecb(cipher, CBC_BITFLIPPING_KEY,
                                         CBC_BITFLIPPING_IV)
    return plain.find(b";admin=true;") > 0


def challenge16():
    """Challenge 16."""
    prefix = b"comment1=cooking%20MCs;userdata="
    prefix_size = len(prefix)
    prefix_padding_size = (16 - prefix_size % 16) % 16

    payload = b":admin<true"
    plain = b"A" * (prefix_padding_size + 16) + payload
    cipher = cbc_bitflipping_enc(plain)
    malformed = bytearray(cipher)
    malformed[prefix_size + prefix_padding_size + payload.find(b":")] ^= 1
    malformed[prefix_size + prefix_padding_size + payload.find(b"<")] ^= 1
    result = has_admin(malformed)
    assert result is True


CBC_PADDING_ORACLE_PLAINS = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]
CBC_PADDING_ORACLE_KEY = secrets.token_bytes(16)
def cbc_padding_oracle_encrypt(plain):
    """Encryption."""
    # iv = secrets.token_bytes(16)
    iv = b's\x1fy)\x04\xa5\xfbB\xe9\xff\xfdMt\xb6\xed\x1c'
    cipher = aes_cbc_pkcs7_encrypt_by_ecb(plain, CBC_PADDING_ORACLE_KEY, iv)
    return cipher, iv


def cbc_padding_oracle_decrypt(cipher, iv):
    """Decryption."""
    try:
        plain = aes_cbc_pkcs7_decrypt_by_ecb(cipher, CBC_PADDING_ORACLE_KEY, iv)
        return True
    except MyException:
        return False


def break_cbc_padding_oracle(cipher, iv, block_size):
    """Break the cbc padding oracle funtions."""
    plain = bytearray(len(cipher))
    blocks = len(cipher) // block_size
    orig_prev_block = bytearray(iv)
    prev_block = orig_prev_block[:]
    for i in range(blocks):
        intermediate = bytearray(block_size)
        cipher_block = cipher[i * block_size: i * block_size + block_size]
        for j in range(block_size - 1, -1, -1):
            padding_byte = block_size - j
            for k in range(j + 1, block_size):
                prev_block[k] = intermediate[k] ^ padding_byte
            for k in range(256):
                prev_block[j] = k
                if j > 0:
                    prev_block[j-1] = (k + 1) % 256
                if cbc_padding_oracle_decrypt(cipher_block, prev_block) is True:
                    if j > 0:
                        prev_block[j-1] = (k + 2) % 256
                    if cbc_padding_oracle_decrypt(cipher_block, prev_block) is True:
                        intermediate[j] = prev_block[j] ^ padding_byte
                        plain[i * block_size + j] = intermediate[j] ^ orig_prev_block[j]
                        break
        orig_prev_block = bytearray(cipher_block)
        prev_block = orig_prev_block[:]
    return pkcs7depadding(plain, 16)


def challenge17():
    """Challenge 17."""
    for expected in CBC_PADDING_ORACLE_PLAINS:
        expected = base64.b64decode(expected)
        cipher, iv = cbc_padding_oracle_encrypt(expected)
        plain = break_cbc_padding_oracle(cipher, iv, 16)
        # print(plain)
        assert plain == expected


def aes_ctr_encrypt(plain, key, nonce):
    """AES encrytion with ctr mode."""
    nonce_bytes = nonce.to_bytes(8, "little")
    blocks, remainds = divmod(len(plain), 16)
    cipher = b""
    for i in range(blocks):
        nonce_counter = nonce_bytes + i.to_bytes(8, "little")
        nonce_counter_cipher = aes_ecb_encrypt(nonce_counter, key)
        cipher += fixed_xor(nonce_counter_cipher, plain[i*16: (i+1)*16])
    if remainds:
        nonce_counter = nonce_bytes + blocks.to_bytes(8, "little")
        nonce_counter_cipher = aes_ecb_encrypt(nonce_counter, key)
        cipher += fixed_xor(nonce_counter_cipher[:remainds], plain[blocks*16:])
    return cipher


def aes_ctr_decrypt(cipher, key, nonce):
    """AES decrytion with ctr mode."""
    nonce_bytes = nonce.to_bytes(8, "little")
    blocks, remainds = divmod(len(cipher), 16)
    plain = b""
    for i in range(blocks):
        nonce_counter = nonce_bytes + i.to_bytes(8, "little")
        nonce_counter_cipher = aes_ecb_encrypt(nonce_counter, key)
        plain += fixed_xor(nonce_counter_cipher, cipher[i*16: (i+1)*16])
    if remainds:
        nonce_counter = nonce_bytes + blocks.to_bytes(8, "little")
        nonce_counter_cipher = aes_ecb_encrypt(nonce_counter, key)
        plain += fixed_xor(nonce_counter_cipher[:remainds], cipher[blocks*16:])
    return plain


def challenge18():
    """Challenge 18."""
    msg = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSv"\
        b"oOLSFQ=="
    cipher = base64.b64decode(msg)
    result = aes_ctr_decrypt(cipher, b"YELLOW SUBMARINE", 0)
    expected = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    assert result == expected

    result = base64.b64encode(aes_ctr_encrypt(expected, b"YELLOW SUBMARINE", 0))
    expected = msg
    assert result == expected


def break_fixed_nonce_ctr(ciphers, length):
    """Break fixed-nonce ctr."""
    key_stream = b""
    num_ciphers = len(ciphers)
    for i in range(length):
        cipher_bytes = [ciphers[j][i] for j in range(num_ciphers)]
        _, _, key = break_single_byte_xor(cipher_bytes)
        key_stream += key.to_bytes(1, "little")

    plains = [fixed_xor(key_stream, ciphers[i]) for i in range(num_ciphers)]
    return plains


def challenge19():
    """Challenge 19."""
    msgs = [
        b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        b"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        b"U2hlIHJvZGUgdG8gaGFycmllcnM/",
        b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        b"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
    ]
    key = secrets.token_bytes(16)
    ciphers = [aes_ctr_encrypt(base64.b64decode(msg), key, 0) for msg in msgs]
    min_length = min([len(cipher) for cipher in ciphers])
    plains = break_fixed_nonce_ctr(ciphers, min_length)

    plains = [plain.lower() for plain in plains]
    expected = [base64.b64decode(msg)[:min_length].lower() for msg in msgs]

    assert plains == expected


def challenge20():
    """Challenge 20."""
    ciphers = []
    with open("20.txt", "r", encoding="utf-8") as f:
        min_length = 100000
        for line in f:
            if line[-1] == "\n":
                line = line[:-1]
            cipher = base64.b64decode(line)
            cipher_len = len(cipher)
            if cipher_len < min_length:
                min_length = cipher_len
            ciphers.append(cipher)

    plains = break_fixed_nonce_ctr(ciphers, min_length)
    expected = []
    with open("20-plain.txt", "r", encoding="utf-8") as f:
        for line in f:
            if line[-1] == "\n":
                line = line[:-1]
            expected.append(line.encode())
    assert plains == expected


class MT19937:
    """Mersenne Twister 19937."""
    N = 624
    M = 397

    def __init__(self, seed, as_python = False):
        self.state = []
        self.index = 0
        if as_python:
            self._as_python_initialize(seed)
        else:
            self._initialize_generator(seed)

    def _as_python_initialize(self, seed):
        self._initialize_generator(19650218)
        mt = self.state
        i=1
        for _ in range(self.N):
            mt[i] = ((mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525)) + seed) & 0xffffffff
            i += 1
            if i >= self.N:
                mt[0] = mt[self.N - 1]
                i=1

        for _ in range(self.N - 1):
            mt[i] = ((mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941)) - i) & 0xffffffff
            i += 1
            if i >= self.N:
                mt[0] = mt[self.N-1]
                i=1
        mt[0] = 0x80000000

    def _initialize_generator(self, seed):
        """Initialize generator."""
        self.state.append(seed & 0xffffffff)
        for i in range(1, 624):
            prev = self.state[i - 1]
            curr = (1812433253 * (prev ^ (prev >> 30)) + i)
            self.state.append(curr & 0xffffffff)

    def extract_number(self):
        """Extract a tempered pseudorandom number based on the index-th value.
        calling generate_numbers() every 624 numbers"""

        if self.index == 0:
            self._generate_numbers()
        num = self.state[self.index]
        self.index = (self.index + 1) % 624
        return self._temper(num)

    def _generate_numbers(self):
        """Generate an array of 624 untempered numbers."""
        for i in range(624):
            j = (i + 1) % 624
            k = (i + 397) % 624
            y = (self.state[i] & 0x80000000) + (self.state[j] & 0x7fffffff)
            self.state[i] = (self.state[k] ^ (y >> 1)) & 0xffffffff
            if y % 2 != 0:
                self.state[i] = (self.state[i] ^ 2567483615) & 0xffffffff

    def _temper(self, num):
        """Temper the number."""
        num ^= num >> 11
        num ^= (num << 7) & 2636928640
        num ^= (num << 15) & 4022730752
        num ^= num >> 18
        return num & 0xffffffff


def challenge21():
    """Challenge 21."""
    seed = 100
    mt19937 = MT19937(seed, True)
    random.seed(seed)
    for _ in range(10000):
        my = mt19937.extract_number()
        expected = random.getrandbits(32)
        assert my == expected


def challenge22():
    """Challenge 22."""
    expected = int(time.time()) & 0xffffffff
    mt19937 = MT19937(expected)

    fake_timestamp = expected + secrets.randbelow(10000)
    first = mt19937.extract_number()
    result = 0
    for ts in range(fake_timestamp, -1, -1):
        tester = MT19937(ts)
        if tester.extract_number() == first:
            result = ts
            break
    # print(result, expected)
    assert result == expected


def reverse_rshift_xor(y, n):
    """Reverse right shift xor operation."""
    assert n != 0

    if n >= 32:
        return y

    x = y & ~((1 << (32-n)) - 1)
    for i in range(31 - n, -1, -1):
        x |= (y ^ (x >> n)) & (1 << i)

    return x


def reverse_lshift_xor(y, n, m):
    """Reverse right shift xor and magic operation."""
    assert n != 0

    if n >= 32:
        return y

    x = y & ((1 << n) - 1)
    for i in range(n, 32):
        x |= (y ^ ((x << n) & m)) & (1 << i)

    return x


def untemper(y):
    """Untemper mt19937."""
    y = reverse_rshift_xor(y, 18)
    y = reverse_lshift_xor(y, 15, 0xefc60000)
    y = reverse_lshift_xor(y, 7, 0x9d2c5680)
    y = reverse_rshift_xor(y, 11)
    return y


def challenge23():
    """Challenge 23."""
    x = 0xdeadbeef
    for n in range(1, 34):
        y = x ^ (x >> n)
        result = reverse_rshift_xor(y, n)
        assert result == x

    m = 0x9d2c5680
    for n in range(1, 34):
        m = (m & ((1 << n) - 1))
        y = x ^ ((x << n) & m)
        result = reverse_lshift_xor(y, n, m)
        assert result == x

    prng1 = MT19937(100)
    state = []
    for i in range(624):
        tempered = prng1.extract_number()
        num = untemper(tempered)
        state.append(num)
    prng2 = MT19937(0)
    prng2.state = state
    for _ in range(10000):
        num1 = prng1.extract_number()
        num2 = prng2.extract_number()
        assert num1 == num2


def mt19937_encrypt(plain, key):
    """Encrpytion using mt19937 prng."""
    prng = MT19937(key)
    cipher = b""
    idx = 0
    for b in plain:
        if idx == 0:
            keystream = prng.extract_number().to_bytes(4, "little")
        cipher += (b ^ keystream[idx]).to_bytes(1, "little")
        idx = (idx + 1) % 4
    return cipher


def mt19937_decrypt(cipher, key):
    """Decryption using mt19937 prng."""
    prng = MT19937(key)
    plain = b""
    idx = 0
    for b in cipher:
        if idx == 0:
            keystream = prng.extract_number().to_bytes(4, "little")
        plain += (b ^ keystream[idx]).to_bytes(1, "little")
        idx = (idx + 1) % 4
    return plain


def challenge24():
    """Challenge 24."""
    prefix = secrets.token_bytes(secrets.randbelow(32))
    plain = prefix + b"A" * 14
    key = secrets.randbelow(2 ** 16)
    cipher = mt19937_encrypt(plain, key)

    result = None
    for i in range(2 ** 16):
        curr = mt19937_decrypt(cipher, i)
        if curr.endswith(b"A" * 14):
            result = i
    # print(result, key)
    assert result == key


CTR_BITFLIPPING_KEY = secrets.token_bytes(16)
CTR_BITFLIPPING_NONCE = secrets.randbelow(0xffffffff)
def ctr_bitflipping_enc(plain):
    """For challenge 26"""
    plain = plain.replace(b";", b"").replace(b"=", b"")
    prefix = b"comment1=cooking%20MCs;userdata="
    postfix = b";comment2=%20like%20a%20pound%20of%20bacon"
    return aes_ctr_encrypt(prefix+plain+postfix, CTR_BITFLIPPING_KEY, CTR_BITFLIPPING_NONCE)


def ctr_has_admin(plain):
    """Decrypt and find b";admin=true;"."""
    return plain.find(b";admin=true;") > 0


def challenge26():
    """Challenge 26."""
    prefix = b"comment1=cooking%20MCs;userdata="
    plen = len(prefix)
    plain = b":admin<true"
    cipher = ctr_bitflipping_enc(plain)
    malformed = bytearray(cipher)
    malformed[plen + plain.find(b":")] ^= 1
    malformed[plen + plain.find(b"<")] ^= 1
    plain = aes_ctr_decrypt(malformed, CTR_BITFLIPPING_KEY, CTR_BITFLIPPING_NONCE)
    result = ctr_has_admin(plain)
    assert result is True


def challenge27():
    """Challenge 27."""
    target_key = secrets.token_bytes(16)
    plain = b"A" * 64
    cipher = aes_cbc_pkcs7_encrypt_by_ecb(plain, target_key, target_key)
    print(len(cipher))

    payload = cipher[:16] + b"\x00" * 16 + cipher[:16] + cipher[48:] # + padding block
    print(len(payload))
    plain = aes_cbc_pkcs7_decrypt_by_ecb(payload, target_key, target_key)
    result_key = fixed_xor(plain[:16], plain[32:])
    assert result_key == target_key


def sha1_mac(key, msg):
    """Sha1 mac."""
    sha1 = Sha1Hash()
    return sha1.update(key + msg).digest()


SHA1_MAC_ORACLE_KEY_LEN = 16 + secrets.randbelow(16)
SHA1_MAC_ORACLE_KEY = secrets.token_bytes(SHA1_MAC_ORACLE_KEY_LEN)
def sha1_mac_oracle(msg):
    """Sha1 mac with a fixed key."""
    return sha1_mac(SHA1_MAC_ORACLE_KEY, msg)


def is_valid_sha1_mac(msg, digest):
    """Validate digest of msg."""
    expected = sha1_mac_oracle(msg)
    return digest == expected


def challenge28():
    """Challenge 28."""
    msg = b"cryptopals-sulution"
    dgst = sha1_mac_oracle(msg)

    assert is_valid_sha1_mac(msg, dgst) is True
    assert is_valid_sha1_mac(msg + b"a", dgst) is False


def challenge29():
    """Challenge 29."""
    def hash_padding(msg, prefix_len):
        msg_len = len(msg) + prefix_len
        padding = b"\x80"
        padding_len = (56 - msg_len - 1) % 64
        padding += b"\x00" * padding_len
        padding += struct.pack(">Q", msg_len * 8)
        return padding

    orig_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    orig_dgst = sha1_mac_oracle(orig_msg)
    sha1_state = struct.unpack(">IIIII", orig_dgst)

    postfix = b";admin=true"

    key_len_max = 40
    found = False
    for i in range(key_len_max):
        padding = hash_padding(orig_msg, i)
        msg = orig_msg + padding + postfix
        sha1 = Sha1Hash()
        processed = i + len(orig_msg) + len(padding)
        sha1.reinit(sha1_state, processed)
        dgst = sha1.update(postfix).digest()
        if is_valid_sha1_mac(msg, dgst) is True:
            found = True
            break

    assert found is True


def md4_mac(key, msg):
    """MD4 mac."""
    md4 = MD4(key + msg)
    return md4.bytes()


MD4_MAC_ORACLE_KEY_LEN = 16 + secrets.randbelow(16)
MD4_MAC_ORACLE_KEY = secrets.token_bytes(MD4_MAC_ORACLE_KEY_LEN)
def md4_mac_oracle(msg):
    """Md4 mac with a fixed key."""
    return md4_mac(MD4_MAC_ORACLE_KEY, msg)


def is_valid_md4_mac(msg, digest):
    """Validate digest of msg."""
    expected = md4_mac_oracle(msg)
    return digest == expected


def challenge30():
    """Challenge 30."""
    def hash_padding(msg, prefix_len):
        msg_len = len(msg) + prefix_len
        padding = b"\x80"
        padding_len = (56 - msg_len - 1) % 64
        padding += b"\x00" * padding_len
        padding += struct.pack("<Q", msg_len * 8)
        return padding

    orig_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    orig_dgst = md4_mac_oracle(orig_msg)
    md4_state = [x for x in struct.unpack("<IIII", orig_dgst)]

    postfix = b";admin=true"

    key_len_max = 40
    found = False
    for i in range(key_len_max):
        padding = hash_padding(orig_msg, i)
        msg = orig_msg + padding + postfix
        processed = i + len(orig_msg) + len(padding)
        md4 = MD4(postfix, md4_state, processed)
        dgst = md4.bytes()
        if is_valid_md4_mac(msg, dgst) is True:
            found = True
            break

    assert found is True


def hmac_sha1(key, msg):
    """Hmac-sha1."""
    key_len = len(key)
    if key_len > 64:
        key = hashlib.sha1(key).digest()
    else:
        key += b"\x00" * (64 - key_len)

    o_pad = fixed_xor(key, b"\x5c" * key_len)
    i_pad = fixed_xor(key, b"\x36" * key_len)
    return hashlib.sha1(o_pad + hashlib.sha1(i_pad + msg).digest()).digest()


INSECURE_COMPARE_WAIT = 50
def my_sleep(ms):
    """My sleep function."""
    bef = time.time_ns() // 1000000
    while True:
        time.sleep(0.001)
        cur = time.time_ns() // 1000000
        if cur - bef >= ms:
            return


def insecure_compare(a, b):
    """An insecure compare function."""
    if len(a) != len(b):
        return False

    for x, y in zip(a, b):
        if x != y:
            return False
        # time.sleep(INSECURE_COMPARE_WAIT / 1000)
        my_sleep(INSECURE_COMPARE_WAIT)
    return True


HMAC_SHA1_ORACLE_KEY = secrets.token_bytes(64)
# print("key: ", HMAC_SHA1_ORACLE_KEY)
def hmac_sha1_oracle(msg):
    """hmac sha1 with a fixed key."""
    return hmac_sha1(HMAC_SHA1_ORACLE_KEY, msg)


def is_valid_hmac_sha1(msg, dgst, debug=None):
    """Check mac validation"""
    if debug:
        expected = debug
    else:
        expected = hmac_sha1_oracle(msg)
    return insecure_compare(dgst, expected)


def challenge31():
    """Challenge 31."""
    file_content = secrets.token_bytes(128)
    expected = hmac_sha1_oracle(file_content)
    # print("exp: ", expected)

    dgst = b""
    for i in range(1, 21):
        for j in range(256):
            bytej = bytes([j])
            curr = dgst + bytej + b"a" * (20 - i)
            beg = time.time_ns() // 1000000
            valid = is_valid_hmac_sha1(file_content, curr, expected)
            duaration = time.time_ns() // 1000000 - beg
            #print(duaration)
            if valid:
                # print(f"found: hmac_sha1({HMAC_SHA1_ORACLE_KEY}, {file_content}) is {curr}")
                assert curr == expected
                return
            else:
                if duaration >= i * INSECURE_COMPARE_WAIT:
                    dgst += bytej
                    break
        else:
            # print(f"not found for {i}")
            return
        # print(i, dgst)
    # print(f"found: hmac_sha1({HMAC_SHA1_ORACLE_KEY}, {file_content}) is {dgst}")
    assert dgst == expected


def challenge32():
    """Challenge 32."""
    file_content = secrets.token_bytes(128)
    expected = hmac_sha1_oracle(file_content)
    # print("exp: ", expected)

    global INSECURE_COMPARE_WAIT
    """
    Get the "slightly less artificial timing leak"
    interval_max = INSECURE_COMPARE_WAIT + 1
    for interval in range(5, interval_max, 5):
        INSECURE_COMPARE_WAIT = interval
        dgst = b""
        for i in range(1, 21):
            for j in range(256):
                bytej = bytes([j])
                curr = dgst + bytej + b"a" * (20 - i)
                beg = time.time_ns() // 1000000
                valid = is_valid_hmac_sha1(file_content, curr, expected)
                duaration = time.time_ns() // 1000000 - beg
                #print(duaration)
                if valid:
                    # print(f"found: hmac_sha1({HMAC_SHA1_ORACLE_KEY}, {file_content}) is {curr}")
                    assert curr == expected
                    print(f"{interval} OK")
                    return
                else:
                    if duaration >= i * interval:
                        dgst += bytej
                        break
            else:
                print(f"not found for {i}")
            # print(i, dgst)
        # print(f"found: hmac_sha1({HMAC_SHA1_ORACLE_KEY}, {file_content}) is {dgst}")
        if dgst == expected:
            print(f"{interval} OK")
        else:
            print(f"{interval} not OK")
    """
    INSECURE_COMPARE_WAIT = 15
    dgst = b""
    count = 10
    for i in range(1, 21):
        max_time = 0
        max_j = None
        for j in range(256):
            bytej = bytes([j])
            curr = dgst + bytej + b"a" * (20 - i)
            total = 0
            for _ in range(count):
                beg = time.time_ns() // 1000000
                is_valid_hmac_sha1(file_content, curr, expected)
                duaration = time.time_ns() // 1000000 - beg
                total += duaration
                #print(duaration)
            if total > max_time:
                max_time = total
                max_j = bytej
        dgst += max_j
    # print(f"found: hmac_sha1({HMAC_SHA1_ORACLE_KEY}, {file_content}) is {dgst}")
    assert dgst == expected


def main():
    """Main entry."""
    if False:
        challenge1()
        challenge2()
        challenge3()
        challenge4()
        challenge5()
        challenge6()
        challenge7()
        challenge8()

        challenge9()
        challenge10()
        challenge11()
        challenge12()
        challenge13()
        challenge14()
        challenge15()
        challenge16()

        challenge17()
        challenge18()
        challenge19()
        challenge20()
        challenge21()
        challenge22()
        challenge23()
        challenge24()

        challenge26()
        challenge27()
        challenge28()
        challenge29()
        challenge30()
        challenge31()
        challenge32()


if __name__ == "__main__":
    main()
