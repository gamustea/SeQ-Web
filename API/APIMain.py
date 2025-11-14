from src.persistence.dbmanaging import UserDBManager
from src.scanning.scanmanaging import NmapScanManager, NiktoScanManager

from flask import Flask, jsonify, request


USER = UserDBManager().get_user_by_id(1)
NMAP_MANAGER = NmapScanManager(USER)
NIKTO_MANAGER = NiktoScanManager(USER)

app = Flask(__name__)

# Definir un endpoint que responde a GET
@app.route('/api/say-hello', methods=['GET'])
def hello():
    return jsonify({"message": "You did it! You reached an endpoint!"})

@app.route('/api/scans/nmap/start', methods=['POST'])
def start_nmap_scan():
    host = request.headers.get('host')
    ports = request.headers.get('ports')
    if not host or not ports:
        return jsonify({"error": "Faltan cabeceras requeridas ('host' y 'ports')"}), 400
    # Aquí iría la lógica para el escaneo nmap

    scan_id = NMAP_MANAGER.run_task(host, ports)
    return jsonify(
        {
            "message": "Solicitud recibida", 
            "host": host, 
            "ports": ports, 
            "scanId": scan_id
        }
    ), 200

@app.route('/api/scans/nikto/start', methods=['POST'])
def start_nikto_scan():
    target = request.headers.get('target')
    if not target:
        return jsonify({"error": "Faltan cabeceras requeridas ('target')"}), 400
    
    scan_id = NIKTO_MANAGER.run_task(target, timeout = 180)
    return jsonify(
        {
            "message": "Solicitud recibida", 
            "target": target,
            "scanId": scan_id
        }
    ), 200

@app.route('/api/scans/nikto/progress', methods=['GET'])
def get_nikto_scan_progress():
    return ""

@app.route('/api/scans/nmap/results', methods=['GET'])
def retrieve_nmap_scans():
    results = NMAP_MANAGER.get_scans_for_user()
    better_results = [
        {
            "id": result.id, 
            "target": result.target,
            "targetedPorts": [
                port.protocol for port in result.target_ports
            ],
            "startedAt": result.started_at,
            "openPorts": [
                {
                    "port": port.port.protocol,
                    "reaseon": port.reason
                }
                for port in result.open_ports_relation
            ]
        } 
        for result in results
    ]
    return jsonify(
        {
            "message": "OK",
            "results": better_results 
        }
    ), 200

@app.route('/api/scans/nikto/results', methods=['GET'])
def retrieve_nikto_scans():
    results = NIKTO_MANAGER.get_scans_for_user()
    better_results = [
        {
            "id": result.id,
            "startedAt": result.started_at,
            "target": result.target,
            "incidents": [
                {
                    "osvdbId": incident.osvdb_id,
                    "method": incident.method,
                    "url": incident.url,
                    "description": incident.description,
                    "discoveredAt": incident.discovered_at
                }
                for incident in result.incidents
            ]
        }
        for result in results
    ]
    return jsonify(
        {
            "message": "OK",
            "results": better_results
        }
    )

if __name__ == '__main__':
    app.run(debug=True)