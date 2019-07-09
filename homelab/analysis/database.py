"""
Copyright 2019, Nils Wenzler, All rights reserved.
nils.wenzler@crowgames.de
"""
import logging
import shelve
import socket
import time
from uuid import getnode as get_mac

import sqlite3

import requests
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

from homelab.analysis import nmap

from appdirs import *

from homelab.control.utils import get_cache_path, ip2int

instance = None


def getDatabase():
    global instance
    if (instance == None):
        instance = Database()
    return instance


class Database:

    def __init__(self):
        self.library_path = get_cache_path() + '/database.db'

        if not os.path.exists(self.library_path):
            logging.info("[*] creating new database")
            self.initialize_db(self.library_path)

        logging.info("database can be found at " + self.library_path)

    def initialize_db(self, library_path):
        conn = sqlite3.connect(library_path)

        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS Device (
         device_id INTEGER PRIMARY KEY,
         mac TEXT NOT NULL,
         device_name TEXT,
         readable_name TEXT,
         first_seen INTEGER,
         last_active INTEGER,
         last_time_deep_scan INTEGER
        )''')

        self.execute = c.execute('''CREATE TABLE IF NOT EXISTS IPLease (
         device_id INTEGER,
         ip TEXT,
         time INTEGER,
         PRIMARY KEY (device_id, ip)
        )''')

        self.execute = c.execute('''CREATE TABLE IF NOT EXISTS IPLocation (
                 ip INTEGER PRIMARY KEY,
                 longitude RREAL,
                 latitude REAL,
                 city TEXT,
                 COUNTRY TEXT
                )''')

        self.execute = c.execute('''CREATE TABLE IF NOT EXISTS Communication (
                         device_id INTEGER,
                         external_ip INTEGER,
                         time INTEGER,
                         bsnd REAL,
                         brcv REAL,
                         psnd REAL,
                         prcv REAL,
                         protocol TEXT,
                         hports TEXT,
                         pports TEXT,
                         PRIMARY KEY (device_id, external_ip, time)
                        )''')

        self.execute = c.execute('''CREATE TABLE IF NOT EXISTS IPDNS (
                                 ip INTEGER,
                                 name TEXT,
                                 PRIMARY KEY (ip, name)
                                )''')

        conn.commit()
        conn.close()

    def save_scan_result(self, scan_result):
        time = scan_result["time"]
        devices = scan_result["devices"]

        for device in devices:
            self.update_device_in_db(device, time)

    def update_device_in_db(self, device, time):
        conn = sqlite3.connect(self.library_path)
        conn.row_factory = sqlite3.Row

        c = conn.cursor()
        c.execute("SELECT * FROM Device WHERE mac=?", (device["mac"],))

        entries = c.fetchall()

        data = {"mac": device["mac"], "name": device["name"], "first_seen": int(time), "last_active": int(time)}

        if len(entries) == 0:
            c.execute(
                "INSERT INTO Device (mac, device_name, first_seen, last_active) VALUES ('{mac}', '{name}', {first_seen}, {last_active}) ".format(
                    **data))
        else:
            data["device_id"] = entries[0]["device_id"]
            c.execute(
                "UPDATE Device SET mac='{mac}', device_name='{name}', last_active={last_active} WHERE device_id = {device_id}".format(
                    **data))

        c.execute("SELECT * FROM Device WHERE mac=?", (device["mac"],))
        entries = c.fetchall()

        db_device = entries[0]

        # update ip lease
        c.execute("SELECT * FROM IPLease WHERE device_id=? ORDER BY time DESC", (db_device["device_id"],))
        entries = c.fetchall()
        if len(entries) == 0 or entries[0]["ip"] != device["ip"]:
            c.execute(
                "INSERT INTO IPLease (device_id, ip, time) VALUES (?, ?, ?) ",
                (db_device["device_id"], device["ip"], int(time)))

        # insert connection information
        for rip in list(device["connections"].keys()):
            c.execute(
                "INSERT INTO Communication (device_id, external_ip, bsnd, brcv, psnd, prcv, time, hports, pports) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ",
                (db_device["device_id"], ip2int(rip), device["connections"][rip]["bsnd"],
                 device["connections"][rip]["brcv"], device["connections"][rip]["snd"],
                 device["connections"][rip]["rcv"], int(time), ",".join(map(str,device["connections"][rip]["hports"])), ",".join(map(str,device["connections"][rip]["pports"]))))

        conn.commit()

        conn.close()

    def ip2loc(self, ip):
        """
        returns the associated location for an IP adress
        :param ip: address to look up
        :return: {ip, lon, lat}
        """

        intip = ip2int(ip)

        conn = sqlite3.connect(self.library_path)
        conn.row_factory = sqlite3.Row

        c = conn.cursor()
        c.execute("SELECT * FROM IPLocation WHERE ip=?", (intip,))

        entries = c.fetchall()
        if len(entries) > 0:
            conn.close()
            return {"city": entries[0]["city"], "lon": entries[0]["longitude"], "lat": entries[0]["latitude"],
                    "cc": entries[0]["country"]}
        else:
            resp = requests.get('http://tcit.crowgames.de/iplocation.php?ip=' + ip)
            if resp.status_code != 200:
                logging.error("ip2loc request went wrong")
            else:
                try:
                    resp = resp.json()

                    c.execute("INSERT INTO IPLocation (ip, longitude, latitude, city, country) VALUES (?, ?, ?, ?, ?) ",
                              (intip, resp["lon"], resp["lat"], resp["city"], resp["cc"]))

                except Exception:
                    return {"city": "unknown", "lon": 0, "lat": 0, "cc": "??"}
                conn.commit()
                conn.close()
                return self.ip2loc(ip)

    def submit_ip_domain(self, ip, domain):
        conn = sqlite3.connect(self.library_path)
        conn.row_factory = sqlite3.Row

        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO IPDNS (ip, name) VALUES (?, ?) ",
            (ip2int(ip), domain))
        conn.commit()
        conn.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
        handlers=[
            logging.StreamHandler()
        ])
    test = getDatabase()

    scan_result = {"time": 10, "devices": [
        {"location": {"city": "Stuttgart", "ip": "141.58.37.74", "lat": 9.17702, "cc": "DE", "lon": 48.7823},
         "scanning": 0, "osmatch": [], "mac": "38:1d:d9:0f:52:3c", "ip": "192.168.8.111",
         "vendor": {"38:1D:D9:0F:52:3C": "Fn-link Technology Limited"}, "connections": {
            "40.67.251.132": {"snd": 26, "domains": [], "brcv": 10486, "threats": [], "rcv": 28,
                              "location": {"ip": "40.67.251.132", "city": "Dublin", "lat": -6.26719, "cc": "IE",
                                           "lon": 53.344}, "bsnd": 5324},
            "87.253.250.165": {"snd": 12, "domains": ["no-reverse.nexiu.net"], "brcv": 3740, "threats": [], "rcv": 14,
                               "location": {"ip": "87.253.250.165", "city": "Stuttgart", "lat": 9.17702, "cc": "DE",
                                            "lon": 48.7823}, "bsnd": 1958},
            "173.194.164.140": {"snd": 534, "domains": [], "brcv": 3603680, "threats": [], "rcv": 2503,
                                "location": {"ip": "173.194.164.140", "city": "Mountain View", "lat": -122.079,
                                             "cc": "US", "lon": 37.406}, "bsnd": 34834},
            "192.168.8.1": {"snd": 0, "domains": ["console.gl-inet.com"], "brcv": 1219, "threats": [], "rcv": 4,
                            "location": {"ip": "192.168.8.1", "city": "-", "lat": 0, "cc": "-", "lon": 0}, "bsnd": 385},
            "172.217.22.14": {"snd": 14, "domains": ["fra16s14-in-f14.1e100.net"], "brcv": 1832, "threats": [],
                              "rcv": 22,
                              "location": {"ip": "172.217.22.14", "city": "Amsterdam", "lat": 4.88969, "cc": "NL",
                                           "lon": 52.374}, "bsnd": 3382},
            "192.168.8.101": {"snd": 0, "domains": ["Crow.lan"], "brcv": 1603, "threats": [], "rcv": 8,
                              "location": {"city": "-", "ip": "192.168.8.101", "lat": 0, "cc": "-", "lon": 0},
                              "bsnd": 83}}, "name": "teclast", "fingerprint": 1}, {"tcp": {
            "80": {"conf": "10", "cpe": "cpe:/a:lighttpd:lighttpd:1.4.48", "reason": "syn-ack", "version": "1.4.48",
                   "name": "http", "extrainfo": "", "product": "lighttpd", "state": "open"},
            "139": {"conf": "10", "cpe": "cpe:/a:samba:samba", "reason": "syn-ack", "version": "3.X - 4.X",
                    "name": "netbios-ssn", "extrainfo": "workgroup: WORKGROUP", "product": "Samba smbd",
                    "state": "open"},
            "53": {"conf": "10", "cpe": "", "reason": "syn-ack", "version": "", "name": "domain", "extrainfo": "",
                   "product": "", "state": "open"},
            "22": {"conf": "10", "cpe": "", "reason": "syn-ack", "version": "", "name": "ssh",
                   "extrainfo": "protocol 2.0", "product": "", "state": "open"},
            "445": {"conf": "10", "cpe": "cpe:/a:samba:samba", "reason": "syn-ack", "version": "3.X - 4.X",
                    "name": "netbios-ssn", "extrainfo": "workgroup: WORKGROUP", "product": "Samba smbd",
                    "state": "open"}}, "location": {"city": "Stuttgart", "ip": "141.58.37.74", "lat": 9.17702,
                                                    "cc": "DE", "lon": 48.7823}, "scanning": 0, "osmatch": [{
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "3.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:3"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "97"},
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "4.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:4"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "97"}],
                                                                                                                "accuracy": "97",
                                                                                                                "line": "62027",
                                                                                                                "name": "Linux 3.2 - 4.6"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "3.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:3.18"],
                                                                                                                        "type": "WAP",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "97"},
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "4.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:4.1"],
                                                                                                                        "type": "WAP",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "97"}],
                                                                                                                "accuracy": "97",
                                                                                                                "line": "63610",
                                                                                                                "name": "OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1)"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "3.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:3.0"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "96"}],
                                                                                                                "accuracy": "96",
                                                                                                                "line": "59506",
                                                                                                                "name": "Linux 3.0"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "4.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:4.3"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "95"}],
                                                                                                                "accuracy": "95",
                                                                                                                "line": "63833",
                                                                                                                "name": "Linux 4.3"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "2.6.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:2.6"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "95"},
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "3.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:3"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "95"}],
                                                                                                                "accuracy": "95",
                                                                                                                "line": "53646",
                                                                                                                "name": "Linux 2.6.32 - 3.10"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "2.6.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:2.6.24"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "94"}],
                                                                                                                "accuracy": "94",
                                                                                                                "line": "49284",
                                                                                                                "name": "Linux 2.6.24"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "3.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:3"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "94"},
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "4.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:4"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "94"}],
                                                                                                                "accuracy": "94",
                                                                                                                "line": "60363",
                                                                                                                "name": "Linux 3.10 - 4.2"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "2.6.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:2.6"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "93"}],
                                                                                                                "accuracy": "93",
                                                                                                                "line": "56098",
                                                                                                                "name": "Linux 2.6.9 - 2.6.18"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "3.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:3.10"],
                                                                                                                        "type": "WAP",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "93"}],
                                                                                                                "accuracy": "93",
                                                                                                                "line": "63532",
                                                                                                                "name": "OpenWrt Barrier Breaker (Linux 3.10)"},
                                                                                                            {
                                                                                                                "osclass": [
                                                                                                                    {
                                                                                                                        "osfamily": "Linux",
                                                                                                                        "osgen": "3.X",
                                                                                                                        "cpe": [
                                                                                                                            "cpe:/o:linux:linux_kernel:3"],
                                                                                                                        "type": "general purpose",
                                                                                                                        "vendor": "Linux",
                                                                                                                        "accuracy": "93"}],
                                                                                                                "accuracy": "93",
                                                                                                                "line": "60853",
                                                                                                                "name": "Linux 3.13 - 3.16"}],
                                                                                   "mac": "E4:95:6E:45:27:92",
                                                                                   "ip": "192.168.8.1", "vendor": {
                "E4:95:6E:45:27:92": "Ieee Registration Authority"}, "connections": {
                "192.168.8.101": {"snd": 12, "domains": ["Crow.lan"], "brcv": 1250, "threats": [], "rcv": 13,
                                  "location": {"ip": "192.168.8.101", "city": "-", "lat": 0, "cc": "-", "lon": 0},
                                  "bsnd": 2664},
                "192.168.8.111": {"snd": 0, "domains": ["teclast.lan"], "brcv": 246, "threats": [], "rcv": 4,
                                  "location": {"ip": "192.168.8.111", "city": "-", "lat": 0, "cc": "-", "lon": 0},
                                  "bsnd": 82}}, "name": "console.gl-inet.com", "fingerprint": 1}],
                   "cidr": "192.168.8.1/24"}
    test.save_scan_result(scan_result)
    test.ip2loc("")

    print(test)
