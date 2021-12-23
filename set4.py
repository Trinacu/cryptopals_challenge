import os
import codecs

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from util import *


run = [True]

print("SET 4")

def edit_ciphertext(ciphertext, key, offset, newtext):
    new_ciphertext = aes_ctr(b'0' * offset + newtext, key, 0)
    suffix = b'' if (len(newtext) > len(ciphertext) - offset) else ciphertext[len(new_ciphertext):]
    return ciphertext[:offset] + new_ciphertext[offset:] + suffix

if run[0]:
    print("\n-----------")
    print("Challenge 25 - 'Break random access r/w' AES CTR")

    with open(os.path.join('txt', 'challenge7.txt'), 'r') as f:
        strIn = f.read()
    strIn = codecs.decode(bytes(strIn, 'utf-8'), 'base64')
    key = "YELLOW SUBMARINE"
    cipher = AES.new(codecs.encode(key, 'utf-8'), AES.MODE_ECB)
    data = cipher.decrypt(strIn)

    key = get_random_bytes(16)
    encrypted = aes_ctr(data, key, 0)

    edited = edit_ciphertext(encrypted, key, 43, b' LOL HAHA ')
    print(aes_ctr(edited, key, 0).decode())






