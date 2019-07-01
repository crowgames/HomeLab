import logging
import os

from appdirs import user_data_dir


def get_cache_path():
    path = user_data_dir("HomeLab", "NilsWe")
    logging.info("using " + path + " as local cache directory")
    if not os.path.exists(path):
        os.makedirs(path)
    return path