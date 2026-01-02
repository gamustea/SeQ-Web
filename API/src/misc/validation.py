
import ipaddress
import itertools

from typing import List

from src.core.model import Port



def expandir_rango_octetos(rango_str):
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
    def validate(ports_str: str) -> tuple[bool, List[Port], str]:
        """
        Valida que una cadena de puertos sea vÃ¡lida para Nmap y devuelve la lista expandida.

        Reglas de validaciÃ³n:
        - Puertos en rango 1-65535
        - Puertos y rangos en orden ascendente
        - Rangos vÃ¡lidos (inicio < fin)
        - No solapamiento de rangos
        - Formato: "80", "80,443", "1-1000", "80,443-8080,9000"

        Args:
            ports_str (str): String con especificaciÃ³n de puertos

        Returns:
            tuple: (bool, list, str) - (es_vÃ¡lido, lista_puertos, mensaje)
        """

        if not ports_str or not isinstance(ports_str, str):
            return False, [], "El parÃ¡metro debe ser una cadena no vacÃ­a"

        ports_str = ports_str.strip()

        if not ports_str:
            return False, [], "La cadena de puertos estÃ¡ vacÃ­a"

        segmentos = ports_str.split(",")
        ultimo_puerto = 0
        lista_puertos = []  # Lista expandida de todos los puertos

        for i, segmento in enumerate(segmentos):
            segmento = segmento.strip()

            if not segmento:
                return False, [], f"Segmento vacÃ­o encontrado en la posiciÃ³n {i+1}"

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
    @staticmethod
    def validate(ips_str: str) -> tuple[bool, List[str], str]:
        """
        Valida que una cadena de IPs sea vÃ¡lida para Nmap y devuelve la lista expandida.

        Formatos soportados:
        - IP individual: "192.168.1.1"
        - CIDR: "192.168.1.0/24"
        - Rangos por octeto: "192.168.1.1-10" o "192.168.1-2.1-10"
        - Lista separada por comas: "192.168.1.1,192.168.1.5"
        - Wildcards: "192.168.1.*" (equivalente a 192.168.1.0-255)

        Args:
            ips_str (str): String con especificaciÃ³n de IPs

        Returns:
            tuple: (bool, list, str) - (es_vÃ¡lido, lista_ips, mensaje)
        """

        if not ips_str or not isinstance(ips_str, str):
            return False, [], "El parÃ¡metro debe ser una cadena no vacÃ­a"

        ips_str = ips_str.strip()

        if not ips_str:
            return False, [], "La cadena de IPs estÃ¡ vacÃ­a"

        segmentos = [s.strip() for s in ips_str.split(",")]
        lista_ips = []
        for segmento in segmentos:
            if not segmento:
                return False, [], "Segmento vacÃ­o encontrado"

            if "/" in segmento:
                try:
                    red = ipaddress.ip_network(segmento, strict=False)
                    # Expandir la red a todas las IPs
                    lista_ips.extend([str(ip) for ip in red.hosts()])
                    # Si es /32 o /31, hosts() puede estar vacÃ­o, incluir la IP de red
                    if not lista_ips or red.prefixlen >= 31:
                        lista_ips.extend([str(ip) for ip in red])
                except ValueError as e:
                    return False, [], f"NotaciÃ³n CIDR invÃ¡lida '{segmento}': {str(e)}"

            elif "-" in segmento:
                try:
                    ips_expandidas = expandir_rango_octetos(segmento)
                    if ips_expandidas is None:
                        return False, [], f"Formato de rango invÃ¡lido: '{segmento}'"
                    lista_ips.extend(ips_expandidas)
                except Exception as e:
                    return False, [], f"Error al procesar rango '{segmento}': {str(e)}"

            else:
                try:
                    ip = ipaddress.ip_address(segmento)
                    lista_ips.append(str(ip))
                except ValueError:
                    return False, [], f"DirecciÃ³n IP invÃ¡lida: '{segmento}'"

        if not lista_ips:
            return False, [], "No se generaron IPs vÃ¡lidas"

        # Eliminar duplicados manteniendo el orden
        lista_ips_unicas = list(dict.fromkeys(lista_ips))

        return (
            True,
            lista_ips_unicas,
            f"EspecificaciÃ³n vÃ¡lida con {len(lista_ips_unicas)} IPs",
        )