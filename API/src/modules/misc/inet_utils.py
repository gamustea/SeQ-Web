
import socket
import ipaddress
import itertools
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, TimeoutError

from urllib.parse import urlparse

# Lazy import to avoid circular import
from typing import Optional, Tuple, List


_DNS_TIMEOUT = 3.0


def _get_port():
    from src.modules.sentinel import Port
    return Port


def resolve_domain(domain: str) -> list[str]:
    """Resolve a domain name to its IP addresses."""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [answer.to_text() for answer in answers]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except Exception as e:
        raise e

def reverse_dns_lookup(ip_address: str) -> Optional[str]:
    """
    Realiza un reverse DNS lookup de una IP.
    
    Args:
        ip_address: Dirección IP (ej: "8.8.8.8")
    
    Returns:
        Hostname o None si no se encuentra
    """
    try:
        result = socket.gethostbyaddr(ip_address)
        hostname = result[0]  # Nombre principal
        aliases = result[1]   # Alias alternativos
        addresses = result[2] # Lista de direcciones IP
        
        return hostname
    except socket.herror:
        # No se encontró registro PTR
        return None
    except socket.gaierror as e:
        # IP inválida o error de resolución
        print(f"Error: {e}")
        return None

def _gethostbyaddr_with_timeout(ip: str, timeout: float = _DNS_TIMEOUT) -> Optional[str]:
    """
    Wrapper de socket.gethostbyaddr con timeout explícito.
    Devuelve el hostname o None si falla o supera el tiempo límite.
    """
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(socket.gethostbyaddr, ip)
        try:
            return future.result(timeout=timeout)[0]
        except TimeoutError:
            return None
        except (socket.herror, socket.gaierror):
            return None

def normalize_target(
    user_input: str,
    resolve_hostname: bool = False,
    dns_timeout: float = _DNS_TIMEOUT,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Normaliza el target del usuario a IP + hostname.
    Acepta IPs, dominios o URLs completas (http://, https://).

    Args:
        user_input:        IP, dominio o URL completa.
        resolve_hostname:  Si es True y el input es una IP, intenta resolver
                           el hostname vía reverse DNS (con timeout acotado).
                           Si es False, el hostname se omite (se devuelve la IP
                           también en esa posición). Por defecto False.
        dns_timeout:       Segundos máximos para la resolución DNS inversa.

    Returns:
        (ip, hostname): hostname == ip cuando no se resuelve o resolve_hostname=False.
    """
    cleaned_input = user_input.strip()

    # Extraer host de una URL completa
    if "://" in cleaned_input:
        parsed = urlparse(cleaned_input)
        if not parsed.netloc and parsed.path:
            cleaned_input = parsed.path.split('/')[0]
        else:
            cleaned_input = parsed.netloc.split(':')[0]
    else:
        cleaned_input = cleaned_input.split(':')[0].split('/')[0]

    ip: Optional[str] = None
    hostname: Optional[str] = None

    try:
        ip_obj = ipaddress.ip_address(cleaned_input)
        ip = str(ip_obj)

        if resolve_hostname:
            # Reverse lookup acotado en tiempo; fallback a la propia IP
            hostname = _gethostbyaddr_with_timeout(ip, dns_timeout) or ip
        else:
            hostname = ip   # No se necesita hostname: evitar la llamada bloqueante

    except ValueError:
        hostname = cleaned_input
        try:
            ip = socket.gethostbyname(hostname)  # Forward lookup: rápido y necesario
        except socket.gaierror as e:
            raise ValueError(f"No se pudo resolver '{user_input}': {e}")

    return ip, hostname

def _expand_octal(rango_str):
    """
    Expande un rango de octetos al estilo Nmap.
    Ejemplos:
    - "192.168.1.1-10" -> ["192.168.1.1", "192.168.1.2", ..., "192.168.1.10"]
    - "192.168.1-2.1-5" -> ["192.168.1.1", "192.168.1.2", ..., "192.168.2.5"]
    - "192.168.1.*" -> ["192.168.1.0", "192.168.1.1", ..., "192.168.1.255"]
    """

    # Reemplazar wildcards por rangos completos
    rango_str = rango_str.replace("*", "0-255")

    # Dividir por puntos
    octetos = rango_str.split(".")

    if len(octetos) != 4:
        return None

    # Procesar cada octeto
    rangos_octetos = []

    for octeto in octetos:
        if "-" in octeto:
            # Es un rango: "1-10"
            partes = octeto.split("-")
            if len(partes) != 2:
                return None

            try:
                inicio = int(partes[0])
                fin = int(partes[1])
            except ValueError:
                return None

            # Validar rango de octeto (0-255)
            if inicio < 0 or inicio > 255 or fin < 0 or fin > 255:
                return None

            if inicio > fin:
                return None

            rangos_octetos.append(range(inicio, fin + 1))
        else:
            # Es un nÃºmero fijo
            try:
                valor = int(octeto)
            except ValueError:
                return None

            if valor < 0 or valor > 255:
                return None

            rangos_octetos.append([valor])

    # Generar todas las combinaciones
    lista_ips = []
    for combinacion in itertools.product(*rangos_octetos):
        ip_str = ".".join(map(str, combinacion))
        # Validar que sea una IP vÃ¡lida
        try:
            ipaddress.ip_address(ip_str)
            lista_ips.append(ip_str)
        except ValueError:
            continue

    return lista_ips if lista_ips else None


class PortValidator:
    @staticmethod
    def validate(ports_str: str):
        """
        Valida que una cadena de puertos sea válida para Nmap y devuelve la lista expandida.

        Reglas de validación:
        - Puertos en rango 1-65535
        - Puertos y rangos en orden ascendente
        - Rangos válidos (inicio < fin)
        - No solapamiento de rangos
        - Formato: "80", "80,443", "1-1000", "80,443-8080,9000"

        Args:
            ports_str (str): String con especificación de puertos

        Returns:
            tuple: (bool, list, str) - (es_válido, lista_puertos, mensaje)
        """
        Port = _get_port()
        if not ports_str or not isinstance(ports_str, str):
            return False, [], "El parÃ¡metro debe ser una cadena no vacÃ­a"

        ports_str = ports_str.strip()

        if not ports_str:
            return False, [], "La cadena de puertos está vací­a"

        segmentos = ports_str.split(",")
        ultimo_puerto = 0
        lista_puertos = []  # Lista expandida de todos los puertos

        for i, segmento in enumerate(segmentos):
            segmento = segmento.strip()

            if not segmento:
                return False, [], f"Segmento vací­o encontrado en la posición {i+1}"

            if "-" in segmento:
                partes = segmento.split("-")

                # Rango desde 1: "-1000"
                if segmento.startswith("-"):
                    if len(partes) != 2 or partes[0] != "":
                        return False, [], f"Formato de rango incorrecto: '{segmento}'"

                    try:
                        fin = int(partes[1])
                    except ValueError:
                        return False, [], f"Puerto de fin no vÃ¡lido en rango: '{segmento}'"

                    if fin < 1 or fin > 65535:
                        return False, [], f"Puerto de fin fuera de rango (1-65535): {fin}"

                    inicio = 1

                # Rango hasta 65535: "1000-"
                elif segmento.endswith("-"):
                    if len(partes) != 2 or partes[1] != "":
                        return False, [], f"Formato de rango incorrecto: '{segmento}'"

                    try:
                        inicio = int(partes[0])
                    except ValueError:
                        return (
                            False,
                            [],
                            f"Puerto de inicio no vÃ¡lido en rango: '{segmento}'",
                        )

                    if inicio < 1 or inicio > 65535:
                        return (
                            False,
                            [],
                            f"Puerto de inicio fuera de rango (1-65535): {inicio}",
                        )

                    fin = 65535

                # Rango normal: "80-443"
                else:
                    if len(partes) != 2:
                        return (
                            False,
                            [],
                            f"Formato de rango incorrecto (demasiados guiones): '{segmento}'",
                        )

                    try:
                        inicio = int(partes[0])
                        fin = int(partes[1])
                    except ValueError:
                        return False, [], f"Puertos no numÃ©ricos en rango: '{segmento}'"

                    if inicio < 1 or inicio > 65535:
                        return (
                            False,
                            [],
                            f"Puerto de inicio fuera de rango (1-65535): {inicio}",
                        )

                    if fin < 1 or fin > 65535:
                        return False, [], f"Puerto de fin fuera de rango (1-65535): {fin}"

                    if inicio >= fin:
                        return (
                            False,
                            [],
                            f"Rango invÃ¡lido: el inicio ({inicio}) debe ser menor que el fin ({fin})",
                        )

                if inicio <= ultimo_puerto:
                    return (
                        False,
                        [],
                        f"Los puertos no estÃ¡n en orden ascendente: {inicio} aparece despuÃ©s de {ultimo_puerto}",
                    )

                # Expandir el rango y aÃ±adir a la lista
                lista_puertos.extend(range(inicio, fin + 1))
                ultimo_puerto = fin

            else:
                # Puerto individual
                try:
                    puerto = int(segmento)
                except ValueError:
                    return False, [], f"Puerto no numÃ©rico: '{segmento}'"

                if puerto < 1 or puerto > 65535:
                    return False, [], f"Puerto fuera de rango (1-65535): {puerto}"

                if puerto <= ultimo_puerto:
                    return (
                        False,
                        [],
                        f"Los puertos no estÃ¡n en orden ascendente: {puerto} aparece despuÃ©s de {ultimo_puerto}",
                    )

                # AÃ±adir puerto individual a la lista
                lista_puertos.append(puerto)
                ultimo_puerto = puerto

        return (
            True,
            lista_puertos,
            f"EspecificaciÃ³n vÃ¡lida con {len(lista_puertos)} puertos",
        )


class IPValidator:
    MAX_HOSTS_TO_EXPAND = 256

    @staticmethod
    def validate(ips_str: str) -> tuple[bool, List[str], str]:
        """
        Valida que una cadena de IPs sea válida para Nmap y devuelve la lista expandida.

        Formatos soportados:
        - IP individual: "192.168.1.1"
        - CIDR: "192.168.1.0/24"
        - Rangos por octeto: "192.168.1.1-10" o "192.168.1-2.1-10"
        - Lista separada por comas: "192.168.1.1,192.168.1.5"
        - Wildcards: "192.168.1.*" (equivalente a 192.168.1.0-255)

        Args:
            ips_str (str): String con especificación de IPs

        Returns:
            tuple: (bool, list, str) - (es_válido, lista_ips, mensaje)
        """

        if not ips_str or not isinstance(ips_str, str):
            return False, [], "El parámetro debe ser una cadena no vacía"

        ips_str = ips_str.strip()

        if not ips_str:
            return False, [], "La cadena de IPs está vacía"

        segmentos = [s.strip() for s in ips_str.split(",")]
        lista_ips = []
        for segmento in segmentos:
            if not segmento:
                return False, [], "Segmento vacío encontrado"

            if "/" in segmento:
                try:
                    red = ipaddress.ip_network(segmento, strict=False)
                    num_hosts = red.num_addresses - 2 if red.num_addresses > 2 else red.num_addresses
                    
                    if num_hosts > IPValidator.MAX_HOSTS_TO_EXPAND:
                        lista_ips.append(segmento)
                    else:
                        lista_ips.extend([str(ip) for ip in red.hosts()])
                        if not lista_ips or red.prefixlen >= 31:
                            lista_ips.extend([str(ip) for ip in red])
                except ValueError as e:
                    return False, [], f"Notación CIDR inválida '{segmento}': {str(e)}"

            elif "-" in segmento:
                try:
                    ips_expandidas = _expand_octal(segmento)
                    if ips_expandidas is None:
                        return False, [], f"Formato de rango inválido: '{segmento}'"
                    if len(ips_expandidas) > IPValidator.MAX_HOSTS_TO_EXPAND:
                        lista_ips.append(segmento)
                    else:
                        lista_ips.extend(ips_expandidas)
                except Exception as e:
                    return False, [], f"Error al procesar rango '{segmento}': {str(e)}"

            else:
                try:
                    ip = ipaddress.ip_address(segmento)
                    lista_ips.append(str(ip))
                except ValueError:
                    return False, [], f"Dirección IP inválida: '{segmento}'"

        if not lista_ips:
            return False, [], "No se generaron IPs válidas"

        lista_ips_unicas = list(dict.fromkeys(lista_ips))

        return (
            True,
            lista_ips_unicas,
            f"Especificación válida con {len(lista_ips_unicas)} IPs",
        )