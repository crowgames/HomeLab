"""
Copyright 2019, Nils Wenzler, All rights reserved.
nils.wenzler@crowgames.de
"""
import logging
import platform
import shelve
import socket
import time
from uuid import getnode as get_mac

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

from homelab.analysis import nmap
from homelab.analysis.database import getDatabase
from homelab.analysis.networkscanner import getNetworkScanner

from appdirs import *

from homelab.control.utils import get_cache_path

instance = None

def getDeviceLibrary():
    global instance
    if(instance == None):
        instance = DeviceLibrary()
    return instance

class DeviceLibrary:

    device_list = []
    history = []

    def __init__(self):
        with shelve.open(get_cache_path()+'/device.db', writeback=True) as db:
            if ("devices" in db):
                self.device_list = db["devices"]
            else:
                self.device_list = []
            if ("history" in db):
                self.history = db["history"]
            else:
                self.history = []
        logging.info("restored device list: "+str(self.device_list))

    def save_device_list(self):
        with shelve.open(get_cache_path()+'/device.db', writeback=True) as db:
            db["devices"] = self.device_list

    def save_scan_result(self, scan_result):
        self.history.append(scan_result)
        with shelve.open(get_cache_path()+'/device.db', writeback=True) as db:
            db["history"] = self.history

    def get_device_by_ip(self, ip):
        for device in self.device_list:
            if device["ip"] == ip:
                return device
        return None

    def arp_scan_network_for_devices(self):
        """ Returns a list of devices which are currently active on the network """
        devices = []
        default_gateway = getNetworkScanner().get_default_gateway()
        ip = getDatabase().get_config("home_cidr")
        logging.info("[*] Scanning network ("+str(ip)+") for devices (this takes up to 30 seconds)")

        answered_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=10)[0]

        for element in answered_list:
            if element[1].psrc != default_gateway:
                device = {}
                device["ip"] = element[1].psrc
                device["mac"] = element[1].hwsrc.upper()
                device["name"] = ""
                device["scanning"] = 0
                devices.append(device)

        #self.save_device_list()
        getDatabase().save_network_scan(devices)
        return devices

    def nmap_scan_and_fingerprint(self):
        devices = []
        default_gateway = getNetworkScanner().get_default_gateway()
        cidr = getDatabase().get_config("home_cidr")
        print("[*] Scanning network ("+str(cidr)+") for devices (this takes up to 60 seconds)")
        nm = nmap.PortScanner()
        # for name detection
        nm.scan(cidr, arguments='-sV -T4 -O -F --version-light')
        for ip in nm._scan_result['scan']:
            if('mac' in nm[ip]['addresses']):
                client_dict = {"ip": ip, "mac": (nm[ip]['addresses']['mac']).upper(), "scanning": 0}
                already_found = False
                for device in devices:
                    if(device["ip"] == ip):
                        client_dict = device
                        already_found = True
                if(len(nm[ip]['hostnames'])>0):
                    client_dict["name"] = nm[ip]['hostnames'][0]['name'].replace(".lan","")
                if('portsused' in nm[ip]):
                    client_dict["ports"] = nm[ip]['portsused']
                if ('tcp' in nm[ip]):
                    client_dict["tcp"] = nm[ip]['tcp']
                if ('osmatch' in nm[ip]):
                    client_dict["osmatch"] = nm[ip]['osmatch']

                devices.append(client_dict)
            else:
                own_ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][
                          : 1]
                #TODO make it work
                if (ip in own_ips or True):
                    client_dict = {"ip": ip, "mac": str(get_mac()), "scanning": 0}
                    if (len(nm[ip]['hostnames']) > 0):
                        client_dict["name"] = nm[ip]['hostnames'][0]['name'].replace(".lan", "")
                    if ('portsused' in nm[ip]):
                        client_dict["ports"] = nm[ip]['portsused']
                    if ('tcp' in nm[ip]):
                        client_dict["tcp"] = nm[ip]['tcp']
                    if ('osmatch' in nm[ip]):
                        client_dict["osmatch"] = nm[ip]['osmatch']
                else:
                    print("WARNING: a device ("+ip+") has been ignored because no MAC address was found")

        del nm
        #self.save_device_list()
        getDatabase().save_network_scan(devices)
        return devices

    def enhance_device_list(self, device_list):
        for device in device_list:
            os = self.fingerprint_device(device["ip"])
            if("hostnames" in os and len(os["hostnames"])>0):
                device["name"] = os["hostnames"][0]["name"].replace(".lan","")

    def fingerprint_device(self, device):
        """
        returns information concerning device and OS for a given IP
        :param ip: to scan (schould be reachable)
        :return: {"hostnames": [{"name":value}]}
        """

        # check whether scanning device
        own_ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][: 1]
        if(device["ip"] in own_ips):
            return {"hostnames": [{"name":platform.node()}]}

        # otherwise perform scan
        try:
            logging.info("trying to perform deep scan and fingerprinting on "+device["ip"])
            nm = nmap.PortScanner()
            # for name detection
            #nm.scan(ip, arguments='-A')
            # for OS detection
            #nm.scan(device["ip"], arguments='-p 1-65535 -T4 -A -v ')
            nm.scan(device["ip"], arguments='-T4 -A -v')
            if not (nm[device["ip"]]["status"] == "down"):
                logging.info("deep scan and fingerprinting successfull for "+device["ip"])
                sc_res = nm[device["ip"]]
                if (len(sc_res['hostnames']) > 0):
                    device["name"] = sc_res['hostnames'][0]['name'].replace(".lan", "")
                if ('portsused' in sc_res):
                    device["ports"] = sc_res['portsused']
                if ('tcp' in sc_res):
                    device["tcp"] = sc_res['tcp']
                if ('osmatch' in sc_res):
                    device["osmatch"] = sc_res['osmatch']
                if ('vendor' in sc_res):
                    device["vendor"] = sc_res['vendor']
                device["fingerprint"] = 1
                #self.save_device_list()
                device["last_time_deep_scan"] = time.time()
                getDatabase().update_device_in_db(device, time.time())
            else:
                logging.info("deep scan and fingerprinting failed (down) for " + device["ip"])
            return device
        except KeyError:
            print(KeyError)
            return {}


if __name__ == "__main__":
    test = DeviceLibrary()
    #res = test.fingerprint_device('192.168.8.113')
    res = test.fingerprint_device({"ip": "192.168.8.1"})
    print(res)