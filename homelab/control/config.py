import logging
import shelve

from homelab.control.utils import get_cache_path

USE_DNS = "use_dns"

instance = None

def getConfig():
    global instance
    if(instance == None):
        instance = Config()
    return instance


class Config:
    def __init__(self):
        with shelve.open(get_cache_path() + '/config.db', writeback=True) as db:
            if ("config" in db):
                self.config = db["config"]
            else:
                self.config = self.getDefaultConfig()
        logging.info("restored config: " + str(self.config))

    def getDefaultConfig(self):
        defconf = {}
        defconf[USE_DNS] = 1
        return defconf

    def getConfig(self):
        return self.config