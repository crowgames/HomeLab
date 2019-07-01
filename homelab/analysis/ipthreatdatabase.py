"""
Copyright 2019, Nils Wenzler, All rights reserved.
nils.wenzler@crowgames.de
"""

import logging
import os

instance = None

def getIPThreatDatabase():
    global instance
    if(instance == None):
        instance = IPTreatDatabase()
    return instance

class IPTreatDatabase:
    ips = {}
    def __init__(self):
        logging.info("[*] Initializing threat database ")
        # recursively traverse threats folder
        """for cur, _dirs, files in os.walk("threats"):
            pref = 'threats/'
            head, tail = os.path.split(cur)
            while head:
                pref += tail+'/'
                head, _tail = os.path.split(head)
            for file in files:
                if file.endswith(".ipset"):
                    filepath = pref+file
                    print(".", end='')
                    with open(filepath, "r") as ins:
                        for line in ins:
                            if "#" not in line:
                                line = line.strip('\n\r ')
                                if(line not in self.ips):
                                    self.ips[line] = {"lists":[]}
                                self.ips[line]["lists"].append(filepath)
        print(" done.")
        print("Loaded "+str(len(self.ips.keys()))+" unique IPs")"""

    def check_IPs(self, ips):
        result = {}
        """for cur, _dirs, files in os.walk("threats"):
            pref = 'threats/'
            head, tail = os.path.split(cur)
            while head:
                pref += tail+'/'
                head, _tail = os.path.split(head)
            for file in files:
                if file.endswith(".ipset"):
                    filepath = pref+file
                    print(".", end='')
                    with open(filepath, "r") as ins:
                        for line in ins:
                            if "#" not in line:
                                line = line.strip('\n\r ')
                                if(line in ips):
                                    if(line not in result):
                                        result[line] = {"lists":[]}
                                    result[line]["lists"].append(filepath)
                                    #self.ips[line] = {"lists":[]}
                                    #self.ips[line]["lists"].append(filepath)"""
        return result

if __name__ == "__main__":
    test = getIPThreatDatabase()
    print(test.check_IP("91.215.103.64"))