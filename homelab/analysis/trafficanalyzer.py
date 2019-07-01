"""
Copyright 2019, Nils Wenzler, All rights reserved.
nils.wenzler@crowgames.de
"""
import copy
import http
import logging
import socket
import time

from scapy.layers.dns import DNSRR
from scapy.layers.inet import IP

from homelab.analysis.ipthreatdatabase import getIPThreatDatabase
from homelab.analysis.networkscanner import getNetworkScanner
from homelab.control.config import getConfig, USE_DNS

instance = None

def getTrafficAnalyzer():
    global instance
    if(instance == None):
        instance = TrafficAnalyzer()
    return instance

class TrafficAnalyzer:
    tot_p_count = 0
    ana_res = {}

    def analyze(self, packets_test, device_list):
        #own_ip = get('https://api.ipify.org').text

        self.ana_res = {}

        for device in device_list:
            if(device["ip"] not in self.ana_res):
                self.ana_res[device["ip"]] = {}

        default_gateway = getNetworkScanner().get_default_gateway()
        cidr = default_gateway + "/24"

        logging.info("[*] Start traffic analysis")
        logging.info(" |--> IP traffic analysis")
        logging.info("packets: "+str(len(packets_test)))

        # acclumerate IP packet information
        self.tot_p_count += len(packets_test)
        for pkt in packets_test:
            """if HTTP in pkt:
                http_layer = pkt.getlayer(HTTP)
                pkt.show()"""

            if IP in pkt:
                send = True
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                foreign_ip = None
                local_ip = None

                if (ip_src in self.ana_res):
                    foreign_ip = ip_dst
                    local_ip = ip_src
                    send = True

                if (ip_dst in self.ana_res):
                    foreign_ip = ip_src
                    local_ip = ip_dst
                    send = False

                if(local_ip != None and foreign_ip != None):
                    if (foreign_ip not in self.ana_res[local_ip]):
                        if(send):
                            self.ana_res[local_ip][foreign_ip] = {"snd": 1, "rcv":0, "bsnd": len(pkt), "brcv":0, "domains": [], "threats": []}
                        else:
                            self.ana_res[local_ip][foreign_ip] = {"snd": 0, "rcv":1, "bsnd": len(pkt), "brcv":0, "domains": [], "threats": []}
                    else:
                        if(send):
                            self.ana_res[local_ip][foreign_ip]["snd"] += 1
                            self.ana_res[local_ip][foreign_ip]["bsnd"] += len(pkt)
                        else:
                            self.ana_res[local_ip][foreign_ip]["rcv"] += 1
                            self.ana_res[local_ip][foreign_ip]["brcv"] += len(pkt)


        # perform IP check
        #collect all ips
        all_ips = set()

        for key in self.ana_res.keys():
            for ip in self.ana_res[key]:
                all_ips.add(ip)

        ip_threats = getIPThreatDatabase().check_IPs(all_ips)

        for key in self.ana_res.keys():
            for ip in self.ana_res[key]:
                # Check for malicious ips
                if(ip in ip_threats):
                    self.ana_res[key][ip]["threats"].append(ip_threats[ip])

                # Perform reverse dns lookup
                if(len(self.ana_res[key][ip]["domains"])==0):
                    try:
                        reversed_dns = socket.gethostbyaddr(ip)
                        if(len(reversed_dns)>0):
                            self.ana_res[key][ip]["domains"].append(reversed_dns[0])
                    except Exception:
                        logging.exception("no reverse dns for "+ip)

        logging.info(" |--> DNS traffic analysis")
        if(getConfig().getConfig()[USE_DNS]>0):
            logging.info("      DNS traffic analysis enabled")
            for pkt in packets_test:
                if pkt.haslayer(DNSRR):
                    # If the answer is a DNSRR, print the name it replied with.
                    if isinstance(pkt.an, DNSRR):
                        for key in self.ana_res.keys():
                            if(pkt.an.rdata in self.ana_res[key]):
                                self.ana_res[key][pkt.an.rdata]["domains"].append(pkt.an.rrname.decode("utf-8"))
                                # TODO: perform malicious dns lookup
        else:
            logging.info("      DNS traffic analysis disabled")

        logging.info("[*] Traffic analysis completed")

        for device in device_list:
            device["connections"] = self.ana_res[device["ip"]]
            getNetworkScanner().add_locations_to_device(device)
        return {"devices":copy.deepcopy(device_list), "cidr": cidr, "time":time.time()}



#if __name__ == "__main__":
#    test = getTrafficAnalyzer()
#    packets = rdpcap('full_capture.pcap')
#    print(test.analyze(packets, [{"ip":"192.168.8.113"},{"ip":"192.168.8.101"},{"ip":"192.168.8.1"}]))