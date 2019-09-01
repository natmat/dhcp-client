import struct
from random import randint
from uuid import getnode as get_mac


def get_MAC_in_bytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12:
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2):
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb


def new_transaction_ID(transaction_id):
    # Computer a random transaction ID, incremented from a random seed starter
    if transaction_id is None:
        transaction_id = randint(0, 2 ** 32)
    else:
        transaction_id += 1
        if transaction_id >= 2 ** 32:
            transaction_id = 0
    transaction_id = transaction_id.to_bytes(4, byteorder='big')
    return transaction_id


