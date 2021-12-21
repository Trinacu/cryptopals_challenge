import numpy as np
from collections import Counter

from itertools import zip_longest

ENG_CHAR_FREQ_TABLE = {
        b'a':    0.08167, b'b':    0.01492, b'c':    0.02782,
        b'd':    0.04253, b'e':    0.12700, b'f':    0.02228,
        b'g':    0.02015, b'h':    0.06094, b'i':    0.06966,
        b'j':    0.00153, b'k':    0.00772, b'l':    0.04025,
        b'm':    0.02406, b'n':    0.06749, b'o':    0.07507,
        b'p':    0.01929, b'q':    0.00095, b'r':    0.05987,
        b's':    0.06327, b't':    0.09056, b'u':    0.02758,
        b'v':    0.00978, b'w':    0.02360, b'x':    0.00150,
        b'y':    0.01974, b'z':    0.00074, b' ':    0.28
}



def transpose_bytearrays(data, fillvalue='%'):
    arr = [[chr(char) for char in line] for line in data]
    transposed = zip_longest(*arr, fillvalue=fillvalue)
    #transposed = zip(*arr)
    return [bytes([ord(char) for char in line]) for line in transposed]

def englishness(data):
    try:
        string_to_score = data.decode()
    except Exception:
        return 0
    
    c = Counter(string_to_score.lower())
    
    coefficient = sum(
        np.sqrt(ENG_CHAR_FREQ_TABLE.get(char.encode(), 0) * y/len(string_to_score))
        for char, y in c.items()
        )
    return coefficient

# string input
"""
def englishness(string_to_score):
    c = Counter(string_to_score.lower())
    
    coefficient = sum(
        np.sqrt(ENG_CHAR_FREQ_TABLE.get(char.encode(), 0) * y/len(string_to_score))
        for char, y in c.items()
        )
    return coefficient
"""
