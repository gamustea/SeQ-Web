import json
import re
import os
import xmltodict

import xml.etree.ElementTree as etree
from typing import Any, Dict, List, Optional
from pathlib import Path

from src.core.model import NmapScan
from lxml import etree as lxml_etree


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
    def convert_json_to_individual_nmap_data(json_data: str, scan: NmapScan, logger=None) -> Dict:
        """
        Versión con logging detallado para debugging.
        """
        if logger:
            logger.debug(f"Tipo de json_data: {type(json_data)}")
            if isinstance(json_data, dict):
                logger.debug(f"Claves en json_data: {list(json_data.keys())}")
        
        # Normalizar input a dict
        if isinstance(json_data, str):
            try:
                result = json.loads(json_data)
                if logger:
                    logger.debug(f"JSON parseado exitosamente. Claves: {list(result.keys())}")
            except json.JSONDecodeError as e:
                if logger:
                    logger.error(f"Error parseando JSON: {e}")
                raise ValueError(f"JSON inválido: {e}")
        elif isinstance(json_data, dict):
            result = json_data
            if logger:
                logger.debug(f"json_data ya es dict. Claves: {list(result.keys())}")
        else:
            raise TypeError(f"json_data debe ser str o dict, recibido: {type(json_data)}")
        
        # Validar estructura básica
        if "nmap" not in result:
            if logger:
                logger.error(f"JSON no contiene 'nmap'. Claves disponibles: {list(result.keys())}")
            raise ValueError("JSON no contiene clave 'nmap'")
        
        if "scan" not in result:
            if logger:
                logger.error(f"JSON no contiene 'scan'. Claves disponibles: {list(result.keys())}")
            raise ValueError("JSON no contiene clave 'scan'")
        
        command = result.get("nmap", {}).get("command_line", "")
        
        # Verificar target
        scan_targets = list(result["scan"].keys())
        if logger:
            logger.debug(f"Target buscado: {scan.target}")
            logger.debug(f"Targets disponibles en scan: {scan_targets}")
        
        if scan.target not in result["scan"]:
            if not scan_targets:
                if logger:
                    logger.warning("No hay targets en el resultado del escaneo")
                return {
                    "command": command,
                    "host": {
                        "vendor": "",
                        "name": "",
                        "type": "",
                        "addresses": {"ipv4": "", "mac": ""}
                    },
                    "ports": []
                }
            
            target_key = scan_targets[0]
            if logger:
                logger.warning(f"Target {scan.target} no encontrado. Usando {target_key}")
        else:
            target_key = scan.target
            if logger:
                logger.debug(f"Target encontrado: {target_key}")
        
        scan_data = result["scan"][target_key]
        
        # Extraer datos con logging
        hostnames = scan_data.get("hostnames", [])
        if logger:
            logger.debug(f"Hostnames: {hostnames}")
        
        hostname = hostnames[0].get("name", "") if hostnames else ""
        hostname_type = hostnames[0].get("type", "") if hostnames else ""
        
        addresses = scan_data.get("addresses", {})
        if logger:
            logger.debug(f"Addresses: {addresses}")
        
        ipv4 = addresses.get("ipv4", "")
        mac = addresses.get("mac", "")
        
        vendor_dict = scan_data.get("vendor", {})
        vendor = vendor_dict.get(mac, "") if mac and vendor_dict else ""
        
        tcp_ports = scan_data.get("tcp", {})
        if logger:
            logger.debug(f"Puertos TCP encontrados: {len(tcp_ports)}")
        
        result_ports = []
        for port_number, port_info in tcp_ports.items():
            port_tuple = (
                f"{port_number}/tcp",
                port_info.get("state", "unknown"),
                port_info.get("reason", ""),
                port_info.get("product", ""),
                port_info.get("version", ""),
                port_info.get("name", "")
            )
            result_ports.append(port_tuple)
        
        if logger:
            logger.debug(f"Total puertos procesados: {len(result_ports)}")
        
        final_result = {
            "command": command,
            "host": {
                "vendor": vendor,
                "name": hostname,
                "type": hostname_type,
                "addresses": {
                    "ipv4": ipv4,
                    "mac": mac
                }
            },
            "ports": result_ports
        }
        
        if logger:
            logger.debug(f"Resultado final: {final_result}")
        
        return final_result

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

    @staticmethod
    def openvas_xml_to_json(report_xml):
        """
        Parsea el XML del reporte y extrae las vulnerabilidades en formato para los modelos ORM.
        
        Args:
            report_xml (str): Contenido XML del reporte
            
        Returns:
            dict: Datos estructurados para OpenVASScan, OpenVASVulnerability y OpenVASScanResult
        """
        try:
            # Asegurarse de parsear con lxml (que tiene soporte XPath)
            if isinstance(report_xml, str):
                root = lxml_etree.fromstring(report_xml.encode('utf-8'))
            elif isinstance(report_xml, bytes):
                root = lxml_etree.fromstring(report_xml)
            else:
                # Si es un Element de xml.etree, convertir a string primero
                import xml.etree.ElementTree as ET
                xml_str = ET.tostring(report_xml, encoding='unicode')
                root = lxml_etree.fromstring(xml_str.encode('utf-8'))
            
            # Extraer información general del escaneo
            report = root.xpath('//report')[0]
            report_id = report.get('id')
            
            # Extraer task_id
            task = root.xpath('//task')[0]
            task_id = task.get('id')
            task_name = task.xpath('name/text()')[0] if task.xpath('name/text()') else 'N/A'
            
            # Extraer información del scanner y config
            scan_config = root.xpath('//report/scan_run_status/config')
            scan_config_name = scan_config[0].xpath('name/text()')[0] if scan_config and scan_config[0].xpath('name/text()') else 'N/A'
            
            scanner = root.xpath('//report/scanner')
            scanner_name = scanner[0].xpath('name/text()')[0] if scanner and scanner[0].xpath('name/text()') else 'OpenVAS Default'
            
            # Datos para OpenVASScan
            scan_data = {
                'task_id': task_id,
                'report_id': report_id,
                'scan_config_name': scan_config_name,
                'scanner_name': scanner_name
            }
            
            # Extraer todos los results (vulnerabilidades encontradas)
            results = root.xpath('//report/results/result')
            
            vulnerabilities = {}  # Dict para evitar duplicados por nvt_oid
            scan_results = []     # Lista de detecciones
            hosts_found = set()   # IPs de hosts encontrados

            for result in results:
                # Información del host
                host_ip = result.xpath('host/text()')[0] if result.xpath('host/text()') else None
                if not host_ip:
                    continue
                
                hosts_found.add(host_ip)
                
                # Información de la vulnerabilidad (NVT)
                nvt = result.xpath('nvt')[0] if result.xpath('nvt') else None
                if nvt is None:
                    continue
                
                nvt_oid = nvt.get('oid')
                if not nvt_oid:
                    continue
                
                # Si no hemos procesado esta vulnerabilidad, extraer toda su info
                if nvt_oid not in vulnerabilities:
                    # Datos básicos
                    name = nvt.xpath('name/text()')[0] if nvt.xpath('name/text()') else 'Unknown'
                    family = nvt.xpath('family/text()')[0] if nvt.xpath('family/text()') else None
                    
                    # Severidad
                    severity = result.xpath('severity/text()')[0] if result.xpath('severity/text()') else '0.0'
                    severity_score = float(severity) if severity else 0.0
                    
                    # Clasificar severidad
                    severity_class = JSONManager._classify_severity(severity_score)
                    
                    # CVSS
                    cvss_base = nvt.xpath('cvss_base/text()')[0] if nvt.xpath('cvss_base/text()') else None
                    cvss_base_score = float(cvss_base) if cvss_base else severity_score
                    
                    # CVSS Vector (puede estar en tags o en xrefs)
                    cvss_vector = None
                    cvss_tags = nvt.xpath('tags/text()')
                    if cvss_tags:
                        tags_text = cvss_tags[0]
                        for tag in tags_text.split('|'):
                            if 'cvss_base_vector=' in tag.lower():
                                cvss_vector = tag.split('=', 1)[1].strip()
                                break
                    
                    # Referencias (CVEs, CERT, etc.)
                    refs = nvt.xpath('refs/ref')
                    cve_ids, cert_refs, bugtraq_ids, other_refs = JSONManager._extract_references(refs)
                    
                    # Descripción y otros textos (extraer de tags)
                    tags_dict = {}
                    if cvss_tags:
                        for tag in cvss_tags[0].split('|'):
                            if '=' in tag:
                                key, value = tag.split('=', 1)
                                tags_dict[key.strip().lower()] = value.strip()
                    
                    summary = tags_dict.get('summary', '')
                    description = result.xpath('description/text()')[0] if result.xpath('description/text()') else tags_dict.get('vuldetect', '')
                    impact = tags_dict.get('impact', '')
                    insight = tags_dict.get('insight', '')
                    affected = tags_dict.get('affected', '')
                    
                    # Solución
                    solution = tags_dict.get('solution', '')
                    solution_type = tags_dict.get('solution_type', 'Mitigation')
                    
                    # Quality of Detection
                    qod = nvt.xpath('qod')[0] if nvt.xpath('qod') else None
                    qod_value = int(qod.xpath('value/text()')[0]) if qod and qod.xpath('value/text()') else None
                    qod_type = qod.xpath('type/text()')[0] if qod and qod.xpath('type/text()') else None
                    
                    # Categoría
                    category = nvt.xpath('category/text()')[0] if nvt.xpath('category/text()') else None
                    
                    # Guardar vulnerabilidad
                    vulnerabilities[nvt_oid] = {
                        'nvt_oid': nvt_oid,
                        'name': name,
                        'severity_score': severity_score,
                        'severity_class': severity_class,
                        'cvss_base_score': cvss_base_score,
                        'cvss_vector': cvss_vector,
                        'cve_ids': ','.join(cve_ids) if cve_ids else None,
                        'cert_refs': ','.join(cert_refs) if cert_refs else None,
                        'bugtraq_ids': ','.join(bugtraq_ids) if bugtraq_ids else None,
                        'other_refs': ','.join(other_refs) if other_refs else None,
                        'summary': summary,
                        'description': description,
                        'impact': impact,
                        'insight': insight,
                        'affected_software': affected,
                        'solution_type': solution_type,
                        'solution': solution,
                        'qod_value': qod_value,
                        'qod_type': qod_type,
                        'family': family,
                        'category': category
                    }
                
                # Agregar resultado de detección (relación scan-vulnerability-host)
                scan_results.append({
                    'nvt_oid': nvt_oid,  # Para hacer el match con la vulnerabilidad
                    'host_ip': host_ip,
                    'port': result.xpath('port/text()')[0] if result.xpath('port/text()') else None,
                    'threat': result.xpath('threat/text()')[0] if result.xpath('threat/text()') else None
                })
            
            return {
                'success': True,
                'scan_data': scan_data,
                'vulnerabilities': list(vulnerabilities.values()),
                'scan_results': scan_results,
                'hosts': list(hosts_found),
                'summary': {
                    'total_vulnerabilities': len(vulnerabilities),
                    'total_detections': len(scan_results),
                    'hosts_affected': len(hosts_found)
                }
            }
            
        except Exception as e:
            import traceback
            return {
                'success': False,
                'error': f"Error al parsear el XML: {str(e)}",
                'traceback': traceback.format_exc()
            }
    
    @staticmethod
    def _classify_severity(severity_score):
        """
        Clasifica la severidad según el score CVSS.
        
        Args:
            severity_score (float): Score de severidad
            
        Returns:
            str: Clasificación de severidad
        """
        if severity_score == 0.0:
            return 'Log'
        elif severity_score < 4.0:
            return 'Low'
        elif severity_score < 7.0:
            return 'Medium'
        elif severity_score < 9.0:
            return 'High'
        else:
            return 'Critical'
    
    @staticmethod
    def _extract_references(refs):
        """
        Extrae y clasifica las referencias de vulnerabilidades.
        
        Args:
            refs (list): Lista de elementos de referencia XML
            
        Returns:
            tuple: (cve_ids, cert_refs, bugtraq_ids, other_refs)
        """
        cve_ids = []
        cert_refs = []
        bugtraq_ids = []
        other_refs = []
        
        for ref in refs:
            ref_type = ref.get('type', '').upper()
            ref_id = ref.get('id', '')
            
            if ref_type == 'CVE':
                cve_ids.append(ref_id)
            elif ref_type in ['CERT-BUND', 'DFN-CERT']:
                cert_refs.append(f"{ref_type}:{ref_id}")
            elif ref_type == 'BID':
                bugtraq_ids.append(ref_id)
            else:
                other_refs.append(f"{ref_type}:{ref_id}")
        
        return cve_ids, cert_refs, bugtraq_ids, other_refs