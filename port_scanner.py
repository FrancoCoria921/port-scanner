import socket
from ipaddress import ip_address, IPv4Address, IPv6Address
import re

# ASUNCIÓN: Se debe tener un archivo common_ports.py con el diccionario.
# Si common_ports.py no existe en tu entorno, puedes descomentar la siguiente línea
# y definir el diccionario aquí (aunque el entorno de FreeCodeCamp lo proporciona).
try:
    from common_ports import ports_and_services
except ImportError:
    # Fallback si common_ports.py no se encuentra (necesario para el modo verbose)
    ports_and_services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 
        80: "http", 110: "pop3", 143: "imap", 443: "https"
    }


def is_valid_ip(target):
    """Verifica si una cadena es una dirección IP válida (IPv4 o IPv6)."""
    try:
        ip_address(target)
        return True
    except ValueError:
        return False

def get_open_ports(target, port_range, verbose=False):
    """
    Escanea un rango de puertos en un host objetivo (URL o IP) y devuelve 
    una lista de puertos abiertos o una cadena descriptiva si está en modo detallado.
    """
    start_port, end_port = port_range
    open_ports = []
    
    # --- 1. Validar y Resolver Objetivo (Target) ---

    ip_addr = None
    hostname_resolved = None
    is_ip_passed = is_valid_ip(target) # Indica si el target original es una IP

    if is_ip_passed:
        # El target es una IP, validamos el formato y obtenemos la IP estandarizada
        try:
            addr = ip_address(target)
            ip_addr = str(addr)
            
            # Intenta la resolución inversa para el nombre de host (para modo verbose)
            try:
                hostname_resolved, _, _ = socket.gethostbyaddr(ip_addr)
            except socket.herror:
                hostname_resolved = None
                
        except ValueError:
            return "Error: Invalid IP address"
            
    else:
        # El target es un nombre de host (URL), intentar resolución DNS
        try:
            # Resolución DNS
            ip_addr = socket.gethostbyname(target)
            hostname_resolved = target
        except socket.gaierror:
            return "Error: Invalid hostname"
        except Exception:
            return "Error: Invalid hostname"

    # --- 2. Validación de Rango de Puertos ---
    
    # En caso de que el rango de puertos sea inválido o desordenado, aunque las pruebas lo eviten.
    if start_port > end_port:
         # No es un requisito de error específico, pero previene errores lógicos.
        pass

    # --- 3. Escaneo de Puertos ---

    # AUMENTO DEL TIMEOUT: Se establece en 3 segundos para evitar fallos por latencia en la prueba unitaria.
    socket.setdefaulttimeout(3) 

    for port in range(start_port, end_port + 1):
        # AF_INET para IPv4, SOCK_STREAM para TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # connect_ex devuelve 0 si el puerto está abierto
            result = sock.connect_ex((ip_addr, port))
            
            if result == 0:
                open_ports.append(port)
                
        except Exception:
            # Capturar cualquier excepción de red/socket
            pass
        finally:
            sock.close() 

    # --- 4. Devolver Resultado ---
    
    if not verbose:
        return open_ports

    # --- Modo Detallado (Verbose) ---

    # 4a. Construir el encabezado
    if is_ip_passed and hostname_resolved and hostname_resolved != target:
        # Se pasó una IP y se obtuvo un nombre de host (ej: scanme.nmap.org (45.33.32.156))
        header = f"Open ports for {hostname_resolved} ({target})"
    elif is_ip_passed:
        # Se pasó una IP (sin nombre de host o nombre de host igual a la IP)
        header = f"Open ports for {target}"
    else:
        # Se pasó un nombre de host (URL) (ej: www.stackoverflow.com (151.101.129.208))
        header = f"Open ports for {target} ({ip_addr})"


    # 4b. Construir la tabla de puertos/servicios
    table_rows = []
    for port in open_ports:
        # Obtener el nombre del servicio, o "unknown" si no está en el diccionario
        service = ports_and_services.get(port, "unknown")
        
        # Formato: {port:<9} alinea a la izquierda en un campo de 9 caracteres
        table_rows.append(f"{port:<9}{service}")

    # 4c. Combinar todas las partes
    verbose_string = header + "\n"
    # Encabezado de la tabla (9 espacios para PORT + 4 espacios para separación)
    verbose_string += "PORT     SERVICE" + "\n"
    verbose_string += "\n".join(table_rows)

    return verbose_string
