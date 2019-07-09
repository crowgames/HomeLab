import logging
import threading
import time
from enum import Enum

from homelab.analysis.database import getDatabase
from homelab.analysis.devicelibrary import getDeviceLibrary
from homelab.analysis.networkscanner import getNetworkScanner
from homelab.analysis.trafficanalyzer import getTrafficAnalyzer


class Job(Enum):
    FINGERPRINT = 1
    DEVICE_SEARCH = 2
    NETWORK_CAPTURE = 3
    NETWORK_ANALYZE = 4
    IDLE = 5

instance = None

def getJobScheduler():
    global instance
    if(instance == None):
        instance = JobScheduler()
    return instance

class JobScheduler:
    curJob = Job.IDLE
    lastScan = 1
    lastSearch = 1
    thread = None

    def getLastUpdate(self):
        return max(self.lastScan, self.lastSearch)

    def __init__(self):
        self.thread = threading.Thread(target=self.work, name="JobScheduler")
        self.thread.start()

    def work(self):
        while(True):
            if(self.curJob == Job.IDLE):
                # if no device found go for device search
                if(len(getDeviceLibrary().device_list)==0):
                    self.startDeviceSearch()
                    continue

                # if lastScan more then 1 minutes ago scan
                if(time.time() - self.lastScan > 60*1):
                    self.startNetworkScan()
                    continue

                # if lastScan more then 5 minutes ago scan
                if (time.time() - self.lastSearch > 60 * 5):
                    self.startDeviceSearch()
                    continue

                # if devices exist that have not been fingerprinted fingerprint
                tmp_cnt = False
                for device in getDeviceLibrary().device_list:
                    if("fingerprint" not in device):
                        self.startDeviceFingerprint(device)
                        tmp_cnt = True
                        break
                if(tmp_cnt):
                    continue

                # otherwise idle for a minute
                self.startIdle()

    def startDeviceSearch(self):
        logging.info("[i] start device search job")
        self.curJob = Job.DEVICE_SEARCH
        device_list = getDeviceLibrary().arp_scan_network_for_devices()
        device_list = getDeviceLibrary().nmap_scan_and_fingerprint()
        self.lastSearch = time.time()
        self.curJob = Job.IDLE

    def startNetworkScan(self):
        logging.info("[i] start network scanning job")
        self.curJob = Job.NETWORK_CAPTURE
        getNetworkScanner().set_devices_scanning(getDeviceLibrary().device_list, 1)
        getNetworkScanner().print_device_list(getDeviceLibrary().device_list)
        packets = getNetworkScanner().sniff_devices(getDeviceLibrary().device_list, timeout=30)
        self.curJob = Job.NETWORK_ANALYZE
        getNetworkScanner().set_devices_scanning(getDeviceLibrary().device_list, 0)
        scan_result = getTrafficAnalyzer().analyze(packets, getDeviceLibrary().device_list)

        getDeviceLibrary().save_scan_result(scan_result)
        getDatabase().save_scan_result(scan_result)

        # remove packets from memory (can be huge!)
        del packets


        self.lastScan = time.time()
        self.curJob = Job.IDLE

    def startDeviceFingerprint(self, device):
        logging.info("[i] start device fingerpinting job")
        self.curJob = Job.FINGERPRINT
        getDeviceLibrary().fingerprint_device(device)
        logging.info("[i] finished device fingerpinting job")
        self.curJob = Job.IDLE

    def startIdle(self):
        logging.info("[i] start idling job")
        self.curJob = Job.IDLE
        time.sleep(60)
        self.curJob = Job.IDLE