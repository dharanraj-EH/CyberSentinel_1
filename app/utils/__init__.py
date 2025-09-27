"""
Utility functions for CyberSentinel.
"""
import os
import sys
import platform
import subprocess
import socket
import ipaddress
import re
from typing import Union, List, Dict, Any, Optional, Tuple
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cybersentinel.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def is_valid_ip(address: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    if not domain or len(domain) > 253:
        return False
    
    # Check each label
    labels = domain.split('.')
    if len(labels) < 2:  # At least domain.tld
        return False
    
    for label in labels:
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', label):
            return False
    
    return True

def is_valid_port(port: Union[int, str]) -> bool:
    """Check if a port number is valid."""
    try:
        port = int(port)
        return 0 < port <= 65535
    except (ValueError, TypeError):
        return False

def is_valid_port_range(port_range: str) -> bool:
    """Check if a port range string is valid (e.g., '80', '1-1024')."""
    if not port_range:
        return False
    
    # Single port
    if port_range.isdigit():
        return is_valid_port(int(port_range))
    
    # Port range
    if '-' in port_range:
        start, _, end = port_range.partition('-')
        if not (start.isdigit() and end.isdigit()):
            return False
        return is_valid_port(int(start)) and is_valid_port(int(end)) and int(start) <= int(end)
    
    return False

def parse_ports(port_spec: str) -> List[int]:
    """Parse a port specification string into a list of port numbers."""
    if not port_spec:
        return []
    
    ports = set()
    
    # Handle comma-separated values
    for part in port_spec.split(','):
        part = part.strip()
        if not part:
            continue
            
        # Handle ranges
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    logger.warning(f"Port out of range: {part}")
                    continue
                ports.update(range(min(start, end), max(start, end) + 1))
            except (ValueError, IndexError):
                logger.warning(f"Invalid port range: {part}")
        # Handle single port
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    logger.warning(f"Port out of range: {port}")
            except ValueError:
                logger.warning(f"Invalid port: {part}")
    
    return sorted(ports)

def is_ip_in_subnet(ip: str, subnet: str) -> bool:
    """Check if an IP address is within a subnet."""
    try:
        ip_addr = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(subnet, strict=False)
        return ip_addr in network
    except (ValueError, ipaddress.AddressValueError):
        return False

def is_host_reachable(host: str, port: int = None, timeout: float = 2.0) -> bool:
    """Check if a host is reachable (ICMP ping or TCP port check)."""
    try:
        # Try TCP port check if port is specified
        if port is not None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        
        # Otherwise try ICMP ping
        if platform.system().lower() == 'windows':
            command = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), host]
        else:
            command = ['ping', '-c', '1', '-W', str(timeout), host]
        
        # Suppress output
        with open(os.devnull, 'w') as devnull:
            return subprocess.call(
                command,
                stdout=devnull,
                stderr=devnull
            ) == 0
    except (socket.gaierror, socket.timeout, subprocess.SubprocessError):
        return False

def get_os_friendly_name() -> str:
    """Get a user-friendly name for the current operating system."""
    system = platform.system().lower()
    
    if system == 'windows':
        return f"Windows {platform.release()}"
    elif system == 'linux':
        try:
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        return line.split('=', 1)[1].strip('"\n')
        except (IOError, IndexError):
            pass
        return "Linux"
    elif system == 'darwin':
        return f"macOS {platform.mac_ver()[0]}"
    else:
        return system.capitalize()

def get_app_data_dir() -> Path:
    """Get the application data directory for the current platform."""
    system = platform.system().lower()
    
    if system == 'windows':
        base_dir = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming'))
    elif system == 'darwin':  # macOS
        base_dir = Path.home() / 'Library' / 'Application Support'
    else:  # Linux and others
        base_dir = Path.home() / '.local' / 'share'
    
    app_dir = base_dir / 'cybersentinel'
    app_dir.mkdir(parents=True, exist_ok=True)
    
    return app_dir

def get_temp_dir() -> Path:
    """Get the temporary directory for the application."""
    temp_dir = get_app_data_dir() / 'temp'
    temp_dir.mkdir(exist_ok=True)
    return temp_dir

def get_logs_dir() -> Path:
    """Get the logs directory."""
    logs_dir = get_app_data_dir() / 'logs'
    logs_dir.mkdir(exist_ok=True)
    return logs_dir

def get_scan_results_dir() -> Path:
    """Get the directory for storing scan results."""
    results_dir = get_app_data_dir() / 'scans'
    results_dir.mkdir(exist_ok=True)
    return results_dir


def get_reports_dir() -> Path:
    """Get the directory for storing generated reports."""
    reports_dir = get_app_data_dir() / 'reports'
    reports_dir.mkdir(exist_ok=True)
    return reports_dir

def get_plugin_dir() -> Path:
    """Get the directory for plugins."""
    plugin_dir = get_app_data_dir() / 'plugins'
    plugin_dir.mkdir(exist_ok=True)
    return plugin_dir

def get_config_path() -> Path:
    """Get the path to the configuration file."""
    return get_app_data_dir() / 'config.json'

def get_resource_path(relative_path: str) -> str:
    """Get the absolute path to a resource file."""
    # For development
    base_path = Path(__file__).parent.parent / 'resources'
    
    # For PyInstaller bundle
    if not base_path.exists():
        base_path = Path(sys._MEIPASS) / 'resources'  # type: ignore
    
    resource_path = base_path / relative_path
    
    if not resource_path.exists():
        logger.warning(f"Resource not found: {resource_path}")
    
    return str(resource_path)

def get_icon_path(icon_name: str) -> str:
    """Get the path to an icon file."""
    return get_resource_path(f"icons/{icon_name}.png")

def get_asset_path(asset_name: str) -> str:
    """Get the path to an asset file."""
    return get_resource_path(f"assets/{asset_name}")

def get_template_path(template_name: str) -> str:
    """Get the path to a template file."""
    return get_resource_path(f"templates/{template_name}")

def ensure_directories() -> None:
    """Ensure all required directories exist."""
    get_app_data_dir()
    get_temp_dir()
    get_logs_dir()
    get_scan_results_dir()
    get_reports_dir()
    get_plugin_dir()

def parse_nmap_output(xml_output: str) -> Dict[str, Any]:
    """Parse Nmap XML output into a structured format."""
    # This is a simplified version - in a real app, you'd want to use a proper XML parser
    # like xml.etree.ElementTree or python-nmap's built-in parser
    import xml.etree.ElementTree as ET
    
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        logger.error(f"Failed to parse Nmap XML: {e}")
        return {}
    
    result = {
        'nmap': {},
        'scan_info': {},
        'hosts': []
    }
    
    # Parse Nmap version and command
    nmap_info = root.find('nmaprun')
    if nmap_info is not None:
        result['nmap']['version'] = nmap_info.get('version', '')
        result['nmap']['args'] = nmap_info.get('args', '')
    
    # Parse scan info
    for info in root.findall('scaninfo'):
        result['scan_info'][info.get('protocol', 'tcp')] = {
            'type': info.get('type', ''),
            'services': info.get('services', '')
        }
    
    # Parse hosts
    for host in root.findall('host'):
        host_data = {
            'status': {},
            'addresses': [],
            'hostnames': [],
            'ports': []
        }
        
        # Host status
        status = host.find('status')
        if status is not None:
            host_data['status'] = {
                'state': status.get('state', 'unknown'),
                'reason': status.get('reason', '')
            }
        
        # Addresses
        for addr in host.findall('address'):
            host_data['addresses'].append({
                'type': addr.get('addrtype', ''),
                'address': addr.get('addr', '')
            })
        
        # Hostnames
        for hname in host.findall('hostnames/hostname'):
            host_data['hostnames'].append({
                'name': hname.get('name', ''),
                'type': hname.get('type', '')
            })
        
        # Ports
        for port in host.findall('ports/port'):
            port_data = {
                'port': int(port.get('portid', 0)),
                'protocol': port.get('protocol', 'tcp'),
                'state': {},
                'service': {}
            }
            
            # Port state
            state = port.find('state')
            if state is not None:
                port_data['state'] = {
                    'state': state.get('state', ''),
                    'reason': state.get('reason', '')
                }
            
            # Service info
            service = port.find('service')
            if service is not None:
                port_data['service'] = {
                    'name': service.get('name', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'extrainfo': service.get('extrainfo', '')
                }
            
            host_data['ports'].append(port_data)
        
        result['hosts'].append(host_data)
    
    return result

def is_admin() -> bool:
    """Check if the current user has administrative privileges."""
    if platform.system().lower() == 'windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.getuid() == 0

def run_as_admin() -> bool:
    """Relaunch the script with administrative privileges."""
    if is_admin():
        return True
    
    if platform.system().lower() == 'windows':
        try:
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(
                None, 'runas', sys.executable, ' '.join(sys.argv), None, 1
            )
            return True
        except Exception as e:
            logger.error(f"Failed to elevate privileges: {e}")
            return False
    else:
        try:
            os.execvp('sudo', ['sudo'] + sys.argv)
            return True
        except Exception as e:
            logger.error(f"Failed to elevate privileges: {e}")
            return False

def human_readable_size(size: int, decimal_places: int = 2) -> str:
    """Convert a size in bytes to a human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            break
        size /= 1024.0
    
    return f"{size:.{decimal_places}f} {unit}"

def human_readable_time(seconds: float) -> str:
    """Convert seconds to a human-readable time format."""
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours:02d}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes:02d}m")
    
    parts.append(f"{seconds:02d}s")
    return " ".join(parts)

def validate_url(url: str) -> bool:
    """Check if a string is a valid URL."""
    from urllib.parse import urlparse
    
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def get_public_ip() -> Optional[str]:
    """Get the public IP address of the current machine."""
    try:
        import requests
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        response.raise_for_status()
        return response.json().get('ip')
    except Exception as e:
        logger.warning(f"Failed to get public IP: {e}")
        return None

def get_local_ip() -> Optional[str]:
    """Get the local IP address of the current machine."""
    try:
        # Create a socket connection to a public DNS server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logger.warning(f"Failed to get local IP: {e}")
        return None
