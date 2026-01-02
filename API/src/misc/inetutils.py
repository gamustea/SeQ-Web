
import socket
import ipaddress
import dns.resolver

from typing import Optional, Tuple


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
    
def normalize_target(user_input: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Normaliza el target del usuario a IP + hostname.
    
    Args:
        user_input: Puede ser IP (8.8.8.8) o dominio (google.com)
    
    Returns:
        (ip, hostname): Tupla con IP y hostname. Si no se puede resolver, lanza excepción.
    """
    
    ip: Optional[str] = None
    hostname: Optional[str] = None
    try:
        # Intentar parsear como IP primero
        ip_obj = ipaddress.ip_address(user_input.strip())
        ip = str(ip_obj)
        
        # Es una IP: hacer reverse DNS para obtener hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            hostname = hostname
        except (socket.herror, socket.gaierror):
            # No tiene registro PTR, dejarlo None
            pass
            
    except ValueError:
        # No es IP válida, asumir que es hostname/dominio
        hostname = user_input.strip()
        
        # Resolver a IP
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            # No se puede resolver
            raise ValueError(f"No se pudo resolver '{user_input}': {e}")
    
    return ip, hostname