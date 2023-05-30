from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
from src.auxiliary.hostdiscovery import discoverhosts
from src.auxiliary.portscanner import tcpscan, finscan, nullscan
from src.config import services, validateport, validateaddress, packets_to_dict
from src.auxiliary.traceroute import traceroute
from src.auxiliary.packetsniffer import packetsniffer
from src.attacks.bruteforce import ftpbruteforce, bruteforce_ssh
from src.attacks.dos_attacks import udpflood, synflood, icmpflood, pingofdeath, httpflood
from src.attacks.dhcpstarvation import dhcpstarv
from src.attacks.arpspoofing import run_arps

app = Flask(__name__)
CORS(app,resources={r"/*": {"origins": "*"}})

@app.route('/host-discovery/<ip>/<mask>', methods=['GET'])
def hdisc(ip, mask):
    try:
        hosts = discoverhosts(ip, int(mask))
        return jsonify(hosts), 200
    except:
        return "Bad request", 400

@app.route('/dhcpstarvation/<time>', methods=['GET'])
def dhcps(time):
    try:
        dhcpstarv(int(time))
        return jsonify([{"t": time}]), 200
    except:
        return "Bad request", 400

@app.route('/pingofdeath/<ip>', methods=['GET'])
def pofd(ip):
    try:
        validateaddress(ip)
        pingofdeath(ip)
        return jsonify([{"attacked": ip}]), 200
    except:
        return "Bad request", 400

@app.route('/flood/<ip>/<p>/<type>/<a>/<s>', methods=['GET'])
def flood(ip, p, type, a, s):
    try:

        port = int(p)
        amount = int(a)
        size = int(s)
        validateaddress(ip)
        validateport(port)
        if type == 'U':
            udpflood(ip, port, amount, size)
        elif type == 'S':
            synflood(ip, port, amount, size)
        elif type == 'I':
            icmpflood(ip, port, amount, size)
        elif type == 'H':
            httpflood(ip, port, amount, size)
        return jsonify([{"attacked": ip}]), 200
    except:
        return "Bad request", 400

@app.route('/packetsniffer/<interface>/<duration>', methods=['GET'])
def packetsn(interface, duration):
    try:
        collected_data = packetsniffer(interface, int(duration))
        t2r = packets_to_dict(collected_data)
        return jsonify(t2r), 200
    except:
        return "Bad request", 400

@app.route('/arpspoof/<ip>/<gateway>/<mac>/<duration>', methods=['GET'])
def arpspoof(ip, gateway, mac, duration):
    try:
        validateaddress(ip)
        validateaddress(gateway)
        run_arps(ip, gateway, mac, int(duration))
        return jsonify([{"attacked": f"{duration} seconds"}]), 200
    except:
        return "Bad request", 400


@app.route('/bruteforce/<ip>/<service>/<username>/', methods=['POST'])
@cross_origin()
def bruteforce(ip, service, username):
    try:
        validateaddress(ip)
        passwords_list = list(request.get_json(force=True))
        password = None
        if service == 'ssh':
            password = bruteforce_ssh(ip, 22, username, passwords_list)
        elif service == 'ftp':
            password = ftpbruteforce(ip, username, passwords_list)

        if password is None:
            return jsonify([{"password": "password not found"}]), 204
        return jsonify([{"password": password}]), 200
    except:
        return "Bad request", 400

@app.route('/traceroute/<ip>', methods=['GET'])
def tracert(ip):
    try:
        validateaddress(ip)
        hosts = traceroute(ip)
        return jsonify(hosts), 200
    except:
        return "Bad request", 400


@app.route('/portscan/<ip>/<startport>/<endport>/<scantype>', methods=['GET'])
def portscan(ip, startport, endport, scantype):
    try:
        validateaddress(ip)
        validateport(int(startport))
        validateport(int(endport))
    except:
        return "Bad request", 400
    ports = [i for i in range(int(startport), int(endport))]
    t2r = []
    open_ports = []
    if scantype == 'T':
        open_ports = tcpscan(ip, ports)
    elif scantype == 'F':
        open_ports = finscan(ip, ports)
    elif scantype == 'N':
        open_ports = nullscan(ip, ports)
    for p in open_ports:
        try:
            t2r.append({
                "port": p,
                "service": services[p],
                "state": "open"
            })
        except:
            t2r.append({
                "port": p,
                "service": "unknown service",
                "state": "open"
            })
    return jsonify(t2r), 200