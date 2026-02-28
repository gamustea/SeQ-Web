
import socket
import ipaddress
import dns.resolver
from urllib.parse import urlparse


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
    Acepta IPs, dominios o URLs completas (http://, https://).
    
    Args:
        user_input: Puede ser IP (8.8.8.8), dominio (google.com) 
                   o URL completa (https://google.com/path)
    
    Returns:
        (ip, hostname): Tupla con IP y hostname. Si no se puede resolver, lanza excepción.
    """
    
    cleaned_input = user_input.strip()
    
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
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            pass
            
    except ValueError:
        hostname = cleaned_input

        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            raise ValueError(f"No se pudo resolver '{user_input}': {e}")
    
    return ip, hostname
