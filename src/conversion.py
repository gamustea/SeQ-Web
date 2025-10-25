import json
import re
import xmltodict

from typing import Any, Dict, List, Optional
from pathlib import Path


class Conversion:
    @staticmethod
    def convert_multi_niktoscan_xml_to_json(xml_path: str, json_path: str) -> Optional[List[Dict[str, Any]]]:
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
