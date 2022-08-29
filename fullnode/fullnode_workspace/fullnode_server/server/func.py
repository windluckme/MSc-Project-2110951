from random import choice
from pprint import pprint
from asn1crypto import cms, x509
import os, json

tests_root = os.path.dirname(__file__)
derfile_dir = os.path.join(tests_root, 'derfile')

xor = lambda a, b:list(map(lambda x, y: x ^ y, a, b))

rotl = lambda x, n:((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)

get_uint32_be = lambda key_data:((key_data[0] << 24) | (key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))

put_uint32_be = lambda n:[((n>>24)&0xff), ((n>>16)&0xff), ((n>>8)&0xff), ((n)&0xff)]

padding = lambda data, block=16: data + [(16 - len(data) % block)for _ in range(16 - len(data) % block)]

unpadding = lambda data: data[:-data[-1]]

list_to_bytes = lambda data: b''.join([bytes((i,)) for i in data])

bytes_to_list = lambda data: [i for i in data]

random_hex = lambda x: ''.join([choice('0123456789abcdef') for _ in range(x)])

random_int = lambda x: ''.join([choice('0123456789') for _ in range(x)])



def hex_to_point(hex_str, para_len):
    """
    The hexadecimal value of a point is converted to a binary of (x, y)
    para_len = len(ecc_table['n'])
    """
    l = len(hex_str)
    len_2 = 2 * para_len
    if l < para_len * 2:
        return None
    else:
        x = int(hex_str[0:para_len], 16)
        y = int(hex_str[para_len:len_2], 16)
        return(x,y)

def point_to_hex(point):
    """
    The binary of (x, y) of the point is converted to hexadecimal value
    """
    x = point[0]
    y = point[1]
    hex_str = hex(x)[2:]+hex(y)[2:]
    return hex_str.upper()

def get_ca_info():

    with open(os.path.join(tests_root,'cainfo/ca_info.json'), 'r') as f:
        user_info = json.loads(f.read())
        
    return user_info