"""
Copyright 2019, Nils Wenzler, All rights reserved.
nils.wenzler@crowgames.de
"""
import json
import threading
import time
import os
from pathlib import Path

from flask import Flask, send_from_directory, request
from flask_cors import CORS, cross_origin
from netaddr import IPNetwork

from homelab.analysis.database import getDatabase

root = os.path.join(str(Path(os.path.dirname(os.path.realpath(__file__))).parent), 'static')
app = Flask(__name__, static_folder=root, static_url_path='')
cors = CORS(app, resources={r"/rest/network_usage_history": {"origins": "localhost:3000"}, r"/rest/update_config": {"origins": "localhost:3000"},r"/rest/ingoing_outgoing": {"origins": "localhost:3000"}, r"/rest/communication_history": {"origins": "localhost:3000"}, r"/rest/devices": {"origins": "localhost:3000"}, r"/rest/internal_external": {"origins": "localhost:3000"}})
app.config['CORS_HEADERS'] = 'Content-Type'

recorded_data = []


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    app.logger.error("Path: " + str(path))
    if path != "" and os.path.exists(app.static_folder + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


@app.route('/rest/network_usage_history')
@cross_origin(origin='localhost', headers=['Content- Type', 'Authorization'])
def get_network_usage():
    timespan = 10000000
    if ("timespan" in request.args):
        timespan = int(request.args["timespan"])
    conn, c = getDatabase().get_conn_cursor()

    query = None

    if ("device" in request.args):
        query = c.execute(
            "SELECT Device.device_id, Device.device_name, Device.mac, time, SUM(brcv) as brcv, SUM(bsnd) as bsnd, SUM(prcv) as prcv, SUM(psnd) as psnd FROM Communication INNER JOIN Device ON Device.device_id=Communication.device_id WHERE time > ? AND Device.device_id = ? GROUP BY time, Communication.device_id  ORDER BY time DESC",
            (time.time() - timespan, int(request.args["device"])))
    else:
        query = c.execute(
            "SELECT Device.device_id, Device.device_name, Device.mac, time, SUM(brcv) as brcv, SUM(bsnd) as bsnd, SUM(prcv) as prcv, SUM(psnd) as psnd FROM Communication INNER JOIN Device ON Device.device_id=Communication.device_id WHERE time > ? GROUP BY time, Communication.device_id  ORDER BY time DESC",
            (time.time() - timespan,))

    entries = query.fetchall()

    conn.close()

    return json.dumps([dict(ix) for ix in entries])

@app.route('/rest/internal_external')
@cross_origin(origin='localhost', headers=['Content- Type', 'Authorization'])
def get_internal_external():
    timespan = 10000000
    if ("timespan" in request.args):
        timespan = int(request.args["timespan"])
    conn, c = getDatabase().get_conn_cursor()

    query = None

    cidr = getDatabase().get_config("home_cidr")
    first = IPNetwork(cidr).first
    last = IPNetwork(cidr).first

    if ("device" in request.args):
        query = c.execute(
            "SELECT Device.device_id, Device.device_name, Communication.internal, Device.mac, SUM(brcv) as brcv, SUM(bsnd) as bsnd, SUM(prcv) as prcv, SUM(psnd) as psnd FROM Communication INNER JOIN Device ON Device.device_id=Communication.device_id WHERE time > ? AND Device.device_id = ? GROUP BY Device.device_id, Communication.internal",
            (time.time() - timespan, int(request.args["device"])))
    else:
        query = c.execute(
            "SELECT Device.device_id, Device.device_name, Communication.internal,  Device.mac, time, SUM(brcv) as brcv, SUM(bsnd) as bsnd, SUM(prcv) as prcv, SUM(psnd) as psnd FROM Communication INNER JOIN Device ON Device.device_id=Communication.device_id WHERE time > ?  GROUP BY Device.device_id, Communication.internal",
            (time.time() - timespan,))

    entries = query.fetchall()

    conn.close()

    return json.dumps([dict(ix) for ix in entries])


@app.route('/rest/ingoing_outgoing')
@cross_origin(origin='localhost', headers=['Content- Type', 'Authorization'])
def get_ingoing_outgoing():
    timespan = 10000000
    if ("timespan" in request.args):
        timespan = int(request.args["timespan"])
    conn, c = getDatabase().get_conn_cursor()

    query = None

    cidr = getDatabase().get_config("home_cidr")
    first = IPNetwork(cidr).first
    last = IPNetwork(cidr).first

    if ("device" in request.args):
        query = c.execute(
            "SELECT Device.device_id, Device.device_name, Device.mac, SUM(brcv) as brcv, SUM(bsnd) as bsnd, SUM(prcv) as prcv, SUM(psnd) as psnd FROM Communication INNER JOIN Device ON Device.device_id=Communication.device_id WHERE time > ? AND Device.device_id = ? GROUP BY Device.device_id",
            (time.time() - timespan, int(request.args["device"])))
    else:
        query = c.execute(
            "SELECT Device.device_id, Device.device_name, Device.mac, time, SUM(brcv) as brcv, SUM(bsnd) as bsnd, SUM(prcv) as prcv, SUM(psnd) as psnd FROM Communication INNER JOIN Device ON Device.device_id=Communication.device_id WHERE time > ?  GROUP BY Device.device_id",
            (time.time() - timespan,))

    entries = query.fetchall()

    conn.close()

    return json.dumps([dict(ix) for ix in entries])

@app.route('/rest/communication_history')
@cross_origin(origin='localhost', headers=['Content- Type', 'Authorization'])
def get_communication_history():
    timespan = 10000000
    if ("timespan" in request.args):
        timespan = int(request.args["timespan"])
    conn, c = getDatabase().get_conn_cursor()

    query = c.execute("SELECT latitude as lat, longitude as lon, city, COUNTRY as CC FROM IPLocation WHERE ip = 0")
    locations = query.fetchall()
    if(len(locations)<1):
        return "[{},{}]"

    json_location = json.dumps([dict(ix) for ix in locations][0])


    query = None

    if ("device" in request.args):
        query = c.execute(
            "SELECT Device.device_id, GROUP_CONCAT(DISTINCT IPDNS.name) as domains, Device.device_name, external_ip, SUM(bsnd)/COUNT(external_ip) as bsnd_avg, SUM(brcv)/COUNT(external_ip) as brcv_avg, latitude as lat, longitude as lon, city, COUNTRY as CC , hports, pports FROM Communication INNER JOIN Device ON Communication.device_id = Device.device_id INNER JOIN IPLocation ON IPLocation.ip = Communication.external_ip INNER JOIN IPDNS ON IPDNS.ip = Communication.external_ip WHERE Communication.time > ? AND Device.device_id = ? GROUP BY external_ip ORDER BY bsnd_avg+brcv_avg DESC",
            (time.time() - timespan, int(request.args["device"])))
    else:
        query = c.execute(
            "SELECT Device.device_id, GROUP_CONCAT(DISTINCT IPDNS.name) as domains, Device.device_name, external_ip, SUM(bsnd)/COUNT(external_ip) as bsnd_avg, SUM(brcv)/COUNT(external_ip) as brcv_avg, latitude as lat, longitude as lon, city, COUNTRY as CC , hports, pports, mac FROM Communication INNER JOIN Device ON Communication.device_id = Device.device_id INNER JOIN IPLocation ON IPLocation.ip = Communication.external_ip  INNER JOIN IPDNS ON IPDNS.ip = Communication.external_ip  WHERE Communication.time > ? GROUP BY external_ip ORDER BY bsnd_avg+brcv_avg DESC",
            (time.time() - timespan,))

    entries = query.fetchall()

    conn.close()

    return "["+json_location+","+json.dumps([dict(ix) for ix in entries])+"]"

@app.route('/rest/devices')
@cross_origin(origin='localhost', headers=['Content- Type', 'Authorization'])
def get_devices():
    devices = getDatabase().get_basic_device_list()
    return json.dumps(devices)

@app.route('/rest/config')
@cross_origin(origin='localhost', headers=['Content- Type', 'Authorization'])
def get_config():
    configs = getDatabase().get_all_configs()
    return json.dumps(configs)

@app.route('/rest/update_config')
@cross_origin(origin='localhost', headers=['Content- Type', 'Authorization'])
def update_config():
    name = request.args.get('name')
    value = request.args.get('value')
    getDatabase().insert_or_replace_config(name, value)
    return ""

@app.route('/rest/get_data')
def get_data():
    return json.dumps(recorded_data)


@app.route('/rest/submit_data')
def submit_data():
    data_sample = json.loads(request.args["data"])
    data_sample["time"] = time.time()
    recorded_data.append(data_sample)
    return ""


def flask_run():
    app.run(host='0.0.0.0', port=80)


def run():
    thread = threading.Thread(target=flask_run, args=())
    thread.start()


if __name__ == "__main__":
    run()
    time.sleep(1000)
