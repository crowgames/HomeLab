import asyncio
import json
import logging
import os
import threading
import time

import websockets
from pympler import muppy, summary

from homelab.analysis.devicelibrary import getDeviceLibrary
from homelab.analysis.networkscanner import getNetworkScanner
from homelab.control.jobscheduler import getJobScheduler


class WebSocketServer:



    def print_memory(self):
        all_objects = muppy.get_objects()
        sum1 = summary.summarize(all_objects)
        # Prints out a summary of the large objects
        summary.print_(sum1)
        # Get references to certain types of objects such as dataframe
        #dataframes = [ao for ao in all_objects if isinstance(ao, pd.DataFrame)]
        #for d in dataframes:
        #    print(d.columns.values)
        #    print(len(d))

    def scan_trigger(self, websocket):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.scan(websocket))

    async def scan(self, websocket):
        cnt = 0
        default_gateway = getNetworkScanner().get_default_gateway()
        cidr = default_gateway + "/24"
        last_update = 0
        while(True):

            if(last_update < getJobScheduler().getLastUpdate()):
                last_update = getJobScheduler().getLastUpdate()
                scan_result = {"devices":getDeviceLibrary().device_list, "cidr": cidr}

                await websocket.send("{\"type\":\"scan_result\", \"payload\":" + json.dumps(scan_result) + "}")
                await websocket.send("{\"type\":\"history\", \"payload\":" + json.dumps(getDeviceLibrary().history) + "}")

            time.sleep(1)

    async def handle_connection(self, websocket, path):
        try:
            scanning_thread = threading.Thread(target=self.scan_trigger,
                                               args=(websocket,), name="Regular Transmit")
            scanning_thread.start()
            while(True):
                message = await websocket.recv()
                data = json.loads(message)
                if (data["type"] == "kill"):
                    os._exit(1)
        except Exception:
            logging.info("websocket died")



    def __init__(self):
        logging.info("[*] Start local websocket server for app interaction")
        self.start_server = websockets.serve(self.handle_connection, '192.168.8.107', 7463)

        asyncio.get_event_loop().run_until_complete(self.start_server)
        asyncio.get_event_loop().run_forever()


