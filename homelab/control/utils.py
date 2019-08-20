import logging
import os
import socket
import struct

from appdirs import user_data_dir
from netaddr import IPNetwork


def get_cache_path():
    path = user_data_dir("HomeLab", "NilsWe")
    logging.info("using " + path + " as local cache directory")
    if not os.path.exists(path):
        os.makedirs(path)
    return path

def ip2int(addr):
    if(len(addr)<1):
        return 0
    return struct.unpack("!I", socket.inet_aton(addr))[0]
