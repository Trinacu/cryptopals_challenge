import random
import util

import re
import hashlib
import math
import itertools
import codecs

import os

from Crypto.Random import get_random_bytes

print("SET 7")

run = [True, False, False, False, False, False, False]

def bank_api(data, IV, MAC):
    global key
    c = util.aes_cbc_encrypt(data, key, IV)
    # MAC = last block of encrypted data
    if MAC != util.get_blocks(c, 16)[-1]:
        print('wrong MAC!')
        return False
    d = {key:val for key,val in [field.split('=#') for field in data.decode().split('&')]}
    print('Transfered {} from {} to {}'.format(d['amount'], d['from'], d['to']))
    return True

def send_money(sender, receiver, amount):
    global key    
    # message format: from=#{from_id}&to=#{to_id}&amount=#{amount}
    msg = "from=#{}&to=#{}&amount=#{}".format(sender, receiver, amount)
    data = msg.encode()

    IV = get_random_bytes(blocksize)
    c = util.aes_cbc_encrypt(data, key, IV)
    MAC = util.get_blocks(c, blocksize)[-1]
    bank_api(data, IV, MAC)
    return data+IV+MAC

if run[0]:
    print("\n-----------")
    print("Challenge 49 - CBC MAC message forgery)")

    blocksize = 16
    key = b'YELLOW SUBMARINE'

    # attacker can send his money and has access to the request sent
    request = send_money(123, 456, 7)
    request, MAC = request[:-blocksize], request[-blocksize:]
    m, IV = request[:-blocksize], request[-blocksize:]
    print(m, IV, MAC)
    print(len(m))
    
    # forgery
    msg = "from=#123&to=#456&amount=#777"
    data = msg.encode()

    IV = b'asd'

    bank_api(data, IV, b'asd')


    
