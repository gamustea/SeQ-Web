import json
import re
import os
import xmltodict

from typing import Any, Dict, List, Optional
from pathlib import Path

from src.core.model import NmapScan, NiktoScan


class JSONManager:
    
    @staticmethod
    def convert_multi_niktoscan_xml_to_json(xml_path: str) -> Optional[List[Dict[str, Any]]]:
        xml_file = Path(xml_path)

        if not xml_file.is_file():
            return None

        try:
            content = xml_file.read_text(encoding='utf-8')
            pattern = re.compile(r'(<niktoscan.*?>.*?</niktoscan>)', re.DOTALL)
            matches = pattern.findall(content)

            if not matches:
                return None

            results = []
            for match in matches:
                doc_dict = xmltodict.parse(match)
                results.append(doc_dict)
                
            return results

        except Exception as e:
            return None

    @staticmethod
    def convert_json_to_individual_nmap_data(json_data: str, scan: NmapScan) -> Dict:
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

        if scan.target not in result["scan"]:
            return {
                "command": command,
                "hostname": "",
                "ports": []
            }
            
        hostnames = result["scan"][scan.target]["hostnames"]
        name = hostnames[0]["name"] if hostnames else ""
        type = hostnames[0]["type"] if hostnames else ""

        addresses = result["scan"][scan.target]["addresses"]
        ipv4 = addresses["ipv4"] if hostnames else ""
        mac = addresses["mac"] if addresses else ""

        vendor = result["scan"][scan.target]["vendor"][mac]
        ports = result["scan"][scan.target]["tcp"]
        
        result_ports = [
            (f"{port}/tcp", ports[port]["state"], ports[port]["reason"], ports[port]["product"], ports[port]["version"], ports[port]["name"]) 
            for port in ports.keys()
        ]
        
        return {
            "command": command,
            "host": {
                "vendor": vendor,
                "name": name,
                "type": type,
                "addresses": {
                    "ipv4": ipv4,
                    "mac": mac
                }
            },
            "ports": result_ports
        }

    @staticmethod
    def convert_json_to_individual_nikto_data(json_data: dict) -> List:
        """Dado un diccionario resultado de Nikto, devuelve un array con las incidencias encontradas,
        incluyendo todos los campos que comienzan por '@'."""
        try:
            items = json_data['niktoscan']['scandetails']['item']

            if isinstance(items, dict):
                incidencia = {}
                for key, value in items.items():  # ← AÑADE .items()
                    incidencia[key.lstrip('@')] = value
                return [incidencia]

            incidencias = []
            for item in items:
                incidencia = {}
                for key, value in item.items():
                    incidencia[key.lstrip('@')] = value
                incidencias.append(incidencia)
            return incidencias
        except KeyError:
            return []

