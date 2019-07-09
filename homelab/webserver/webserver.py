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

root = os.path.join(str(Path(os.path.dirname(os.path.realpath(__file__))).parent), 'static')
app = Flask(__name__, static_folder=root, static_url_path='')

recorded_data = []

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    app.logger.error("Path: "+str(path))
    if path != "" and os.path.exists(app.static_folder + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


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