"""
Copyright 2019, Nils Wenzler, All rights reserved.
nils.wenzler@crowgames.de
"""
import logging
import platform
import shelve
import threading
import time

import requests
from scapy.config import conf
from scapy.layers.dns import DNSRR
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sr1, sr, send, sniff, sendp
from scapy.utils import wrpcap
import ctypes, os, sys

from homelab.analysis.database import getDatabase
from homelab.control.utils import get_cache_path

instance = None

def getNetworkScanner():
    global instance
    if(instance == None):
        instance = NetworkScanner()
    return instance

class NetworkScanner:

    still_poisoning = False
    REG_PATH = r"System\CurrentControlSet\Services\Tcpip\Parameters"
    packet_count = 10000
    conf.verb = 0
    p_count = {}

    def enforce_admin(self):
        """
        Checks whether windows administrator rights are available and enforces them if not
        :return:
        """
        if ctypes.windll.shell32.IsUserAnAdmin() == False:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)

    def set_reg(self, name, value):
        import winreg
        """
        sets a registry value
        :param name:
        :param value:
        :return:
        """
        try:
            winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.REG_PATH)
            registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.REG_PATH, 0,
                                          winreg.KEY_WRITE)
            winreg.SetValueEx(registry_key, name, 0, winreg.REG_DWORD, value)
            winreg.CloseKey(registry_key)
            return True
        except WindowsError:
            print(WindowsError)
            return False

    def get_default_gateway(self):
        import netifaces

        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        logging.info("[*] Default gateway identified: " + str(default_gateway))
        if(getDatabase().get_config("home_mac") == None):
            mac = self.get_mac(default_gateway)
            getDatabase().insert_or_ignore_config("home_mac", mac)
            getDatabase().insert_or_ignore_config("home_cidr", default_gateway+"/24")
        return default_gateway

    def print_device_list(self, results_list):
        logging.info("IP\t\t\tMAC Address")
        logging.info("----------------------------------------------------")
        for client in results_list:
            logging.info(client["ip"] + "\t\t" + "XX:XX:XX:XX:XX:XX")

    # Given an IP, get the MAC. Broadcast ARP Request for a IP Address. Should recieve
    # an ARP reply with MAC Address
    def get_mac(self, ip_address):
        # ARP request is constructed. sr function is used to send/ receive a layer 3 packet
        # Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
        resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=1, timeout=2)
        for s, r in resp:
            return r[ARP].hwsrc
        return None

    # Restore the network by reversing the ARP poison attack. Broadcast ARP Reply with
    # correct MAC and IP Address information
    def restore_network(self, gateway_ip, gateway_mac, target_ip, target_mac):
        if target_mac is None:
            logging.info("[!] Unable to get target MAC address. ")
        else:
            logging.info("[*] Restoring ARP for MAC address: "+str(target_mac))

        for i in range(5):
            sendp(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
            sendp(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
        #logging.info("[*] Disabling IP forwarding")
        # Disable IP Forwarding on a mac
        # os.system("sysctl -w net.inet.ip.forwarding=0")
        # kill process on a mac
        # os.kill(os.getpid(), signal.SIGTERM)

    # Keep sending false ARP replies to put our machine in the middle to intercept packets
    # This will use our interface MAC address as the hwsrc for the ARP reply
    def arp_poison(self, gateway_ip, gateway_mac, target_ip):
        target_mac = self.get_mac(target_ip)
        if target_mac is None:
            logging.info("[!] Unable to get target MAC address. ")
            sys.exit(0)
        else:
            logging.info("[*] Target MAC address: "+str(target_mac))

        logging.info("[*] Started ARP poison attack: "+str(target_mac))
        try:
            while self.still_poisoning:
                sendp(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
                sendp(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
                time.sleep(2)
        except KeyboardInterrupt:
            logging.info("[*] Stopped ARP poison attack. Restoring network")
        thread1 = threading.Thread(target=self.restore_network, args=(gateway_ip, gateway_mac, target_ip, target_mac,))
        thread1.start()

    def querysniff(self,pkt):
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            if (ip_src in self.p_count):
                if (ip_dst not in self.p_count[ip_src]):
                    self.p_count[ip_src][ip_dst] = 1
                else:
                    self.p_count[ip_src][ip_dst] += 1

            if (ip_dst in self.p_count):
                if (ip_src not in self.p_count[ip_dst]):
                    self.p_count[ip_dst][ip_src] = 1
                else:
                    self.p_count[ip_dst][ip_src] += 1
        if pkt.haslayer(DNSRR):
            # If the an(swer) is a DNSRR, print the name it replied with.
            if isinstance(pkt.an, DNSRR):
                print(pkt.an.rrname)

    def set_devices_scanning(self, device_list, value):
        for device in device_list:
            device["scanning"] = value

    def sniff_devices(self, device_list, timeout):
        """
        Perform ARP-poisoning to a set of devices and capture their traffic
        :param device_list: list of devices to monitor
        :param timeout: number of seconds to sniff
        :return: the captured packages
        """

        packets = []
        self.p_count = {}

        gateway_ip = self.get_default_gateway()
        gateway_mac = self.get_mac(gateway_ip)
        if gateway_mac is None:
            logging.info("[!] Unable to get gateway MAC address. Exiting..")
        else:
            logging.info("[*] Gateway MAC address: "+"XX:XX:XX:XX:XX:XX")

        # ARP poison thread
        self.still_poisoning = True
        for device in device_list:
            self.p_count[device["ip"]] = {}
            poison_thread = threading.Thread(target=self.arp_poison, args=(gateway_ip, gateway_mac, device["ip"]), name="ARP poison")
            poison_thread.start()

        # Sniff traffic and write to file. Capture is filtered on target machine
        ips = map(lambda x: "ip host " + x["ip"], device_list)
        sniff_filter = " or ".join(ips)
        logging.info("[*] Starting network capture.")
        #TODO: think about reintroducing filter
        logging.info("[*] Timeout:"+str(timeout))
        packets = sniff(iface=conf.iface, timeout=timeout)
        wrpcap(get_cache_path()+"/full_capture.pcap", packets)
        logging.info("[*] Stopping network capture..Restoring network")
        self.still_poisoning = False
        for device in device_list:
            self.restore_network(gateway_ip, gateway_mac, device["ip"], device["mac"])
        return packets

    def enable_ip_forwarding(self):
        logging.info("[*] Enabling IP-forwarding")
        if platform.system() == 'Windows':
            # enable ip forwarding on windows
            self.enforce_admin()
            self.set_reg("IPEnableRouter", 1)
            os.system("sc config RemoteAccess start= auto")
            os.system("net start RemoteAccess")
            logging.info("[*] Enabled IP-forwarding for Windows")
        elif (platform.system() == 'Linux'):
            self.enforce_root()
            logging.info("[*] Enabled IP-forwarding for Linux")
            os.system("sysctl -w net.ipv4.ip_forward=1")
        else:
            # enable ip forwarding on mac
            logging.info("[*] Enabled IP-forwarding for Mac")
            os.system("sysctl -w net.inet.ip.forwarding=1")



    def add_locations_to_device(self, device):
        """
        adds location entry to scan_results
        :param scan_result:
        :return:
        """
        device["location"] = getDatabase().ip2loc("")
        if("connections" in list(device.keys())):
            for remote in device["connections"].keys():
                device["connections"][remote]["location"] = getDatabase().ip2loc(remote)

    def enforce_root(self):
        return

    def generate_places_json(self, device_list, scan_result):
        """
        generate a plaaces json to visualize
        :return:
        """
        logging.info("[*] Lookup remote ips")
        place_list = []
        start = getDatabase().ip2loc("")
        start["count"] = 0
        start["src"] = ""
        place_list.append(start)
        for device in device_list:
            test = scan_result[device["ip"]]
            keys = scan_result[device["ip"]].items()
            for key, value in test.items():
                place = getDatabase().ip2loc(key)
                place["count"] = value["count"]
                place["threats"] = value["threats"]
                place["src"] = device["ip"]
                place_list.append(place)

        final_json = "{\"type\": \"FeatureCollection\", \"features\": ["
        final_json += ",".join(map(
            lambda x: "{ \"type\": \"Feature\", \"properties\": { \"count\": " + str(x["count"]) + ", \"device\":\"" +
                      x["src"] + "\"}, \"geometry\": { \"type\": \"Point\", \"coordinates\": [" + str(
                x["lat"]) + "," + str(x["lon"]) + "]}}", place_list))
        final_json += "]}"
        logging.info("[*] Write places")
        text_file = open("scan_places.json", "w")
        text_file.write(final_json)
        text_file.close()


