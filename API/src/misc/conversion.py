import json
import re
import xmltodict

from typing import Any, Dict, List, Optional
from pathlib import Path

from src.model import NmapScan


class JSONManager:
    
    @staticmethod
    def convert_multi_niktoscan_xml_to_json(xml_path: str) -> Optional[List[Dict[str, Any]]]:
        xml_file = Path(xml_path)

        if not xml_file.is_file():
            print(f"Archivo {xml_file} no existe.")
            return None

        try:
            content = xml_file.read_text(encoding='utf-8')
            pattern = re.compile(r'(<niktoscan.*?>.*?</niktoscan>)', re.DOTALL)
            matches = pattern.findall(content)

            if not matches:
                print("No se encontraron bloques <niktoscan> válidos.")
                return None

            results = []
            for match in matches:
                doc_dict = xmltodict.parse(match)
                results.append(doc_dict)

            return results

        except Exception as e:
            print("Error al convertir XML a dict:", e)
            return None

    @staticmethod
    def convert_json_to_individual_data(json_data: str, scan: NmapScan) -> Dict:
        """
        Extrae información del resultado JSON de Nmap y lo estructura para el ORM.
        
        Args:
            json_data: String JSON con los resultados del escaneo Nmap
            scan: Instancia de NmapScan del ORM
        """
        if isinstance(json_data, str):
            try:
                result = json.loads(json_data)
            except json.JSONDecodeError as e:
                raise ValueError(f"JSON inválido: {e}")
        elif isinstance(json_data, dict):
            result = json_data
        else:
            raise TypeError(f"json_data debe ser str o dict, recibido: {type(json_data)}")
        
        # Extraer información básica
        command = result["nmap"]["command_line"]
        
        # Extraer hostname (con manejo de casos sin hostname)
        hostnames = result["scan"][scan.target]["hostnames"]
        hostname = hostnames[0]["name"] if hostnames else ""
        
        # Extraer puertos TCP
        ports = result["scan"][scan.target]["tcp"]
        
        # Crear tuplas con (protocolo, estado, razón)
        result_ports = [
            (f"{port}/tcp", ports[port]["state"], ports[port]["reason"]) 
            for port in ports.keys()
        ]
        
        return {
            "command": command,
            "hostname": hostname,
            "ports": result_ports
        }


