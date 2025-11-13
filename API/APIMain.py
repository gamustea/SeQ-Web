from src.persistence.dbmanaging import UserDBManager
from src.scanning.scanmanaging import NmapScanManager

from flask import Flask, jsonify, request


USER = UserDBManager().get_user_by_id(1)
NMAP_MANAGER = NmapScanManager(USER)

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

    NMAP_MANAGER.run_task(host, ports)
    return jsonify({"message": "Solicitud recibida", "host": host, "ports": ports}), 200

if __name__ == '__main__':
    app.run(debug=True)