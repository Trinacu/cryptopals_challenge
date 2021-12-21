from collections import Counter

from util import *

with open(os.path.join('txt', 'char_freq.txt'), 'r') as f:
    text = f.read()
    
print(text)

tmp = ''.join(list([val for val in text if \
                    (ord(val) == 32 or (ord(val) > 64 and ord(val) < 91)\
                     or (ord(val) > 96 and ord(val) < 123))]))

c = Counter(tmp.lower())

print(c)
size = len(tmp)
for char, occurence in c.items():
   print('{} {:.5f}'.format(char, occurence/size))

dict_to_json(c, 'eng_char_frequency.json')
