

import socket
import concurrent.futures
import ipaddress
import time
from typing import Dict, List, Optional, Tuple, Union
import logging

logger = logging.getLogger(__name__)

class SocketScanner:
    """A pure Python socket-based port scanner."""
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        """Initialize the socket scanner.
        
        Args:
            timeout: Socket connection timeout in seconds.
            max_workers: Maximum number of concurrent workers for scanning.
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.default_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080
        ]
    
    def scan(
        self,
        target: str,
        ports: Optional[Union[List[int], str, int]] = None,
        scan_type: str = 'tcp'
    ) -> Dict:
        """Perform a port scan on the target.
        
        Args:
            target: Target host or IP address to scan.
            ports: Ports to scan. Can be a list of ports, a single port, or a range
                  in the format 'start-end'. If None, scans common ports.
            scan_type: Type of scan ('tcp' or 'udp'). Note: UDP scanning is less reliable.
            
        Returns:
            Dict containing the scan results.
        """
        start_time = time.time()
        results = {
            'target': target,
            'scan_type': scan_type.upper(),
            'ports': [],
            'start_time': start_time,
            'end_time': None,
            'elapsed': None,
            'status': 'completed'
        }
        
        try:
            # Resolve the target to an IP address
            try:
                ipaddress.ip_address(target)
                ip = target
                hostname = self._reverse_lookup(ip) or ip
            except ValueError:
                # Not a valid IP, try to resolve hostname
                try:
                    ip = socket.gethostbyname(target)
                    hostname = target
                except socket.gaierror:
                    raise ValueError(f"Could not resolve hostname: {target}")
            
            results['ip'] = ip
            results['hostname'] = hostname
            
            # Parse ports
            port_list = self._parse_ports(ports) if ports is not None else self.default_ports
            
            # Perform the scan
            open_ports = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Create a future for each port scan
                future_to_port = {
                    executor.submit(
                        self._check_port,
                        ip,
                        port,
                        scan_type
                    ): port for port in port_list
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open, service = future.result()
                        port_result = {
                            'port': port,
                            'protocol': scan_type.lower(),
                            'state': 'open' if is_open else 'closed',
                            'service': service or 'unknown'
                        }
                        if is_open:
                            open_ports.append(port_result)
                        results['ports'].append(port_result)
                    except Exception as e:
                        logger.error(f"Error scanning port {port}: {e}")
                        results['ports'].append({
                            'port': port,
                            'protocol': scan_type.lower(),
                            'state': 'error',
                            'error': str(e)
                        })
            
            # Sort results by port number
            results['ports'].sort(key=lambda x: x['port'])
            
            # Calculate statistics
            end_time = time.time()
            results['end_time'] = end_time
            results['elapsed'] = end_time - start_time
            results['open_ports'] = len(open_ports)
            results['total_ports'] = len(port_list)
            
            return results
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            logger.error(f"Scan failed: {e}", exc_info=True)
            return results
    
    def _parse_ports(self, ports: Union[List[int], str, int]) -> List[int]:
        """Parse the ports parameter into a list of port numbers.
        
        Args:
            ports: Ports to scan. Can be a list, a single port, or a range.
            
        Returns:
            List of port numbers.
            
        Raises:
            ValueError: If the ports parameter is invalid.
        """
        if isinstance(ports, int):
            return [ports]
        elif isinstance(ports, str):
            # Handle port ranges (e.g., '1-1024')
            if '-' in ports:
                try:
                    start, end = map(int, ports.split('-'))
                    if not (0 < start <= 65535 and 0 < end <= 65535):
                        raise ValueError("Port numbers must be between 1 and 65535")
                    return list(range(min(start, end), max(start, end) + 1))
                except (ValueError, IndexError):
                    raise ValueError("Invalid port range format. Use 'start-end'")
            # Handle comma-separated ports (e.g., '80,443,8080')
            elif ',' in ports:
                try:
                    port_list = [int(p.strip()) for p in ports.split(',')]
                    if not all(0 < p <= 65535 for p in port_list):
                        raise ValueError("Port numbers must be between 1 and 65535")
                    return port_list
                except ValueError:
                    raise ValueError("Invalid port list. Use comma-separated port numbers")
            # Single port as string
            else:
                try:
                    port = int(ports)
                    if not (0 < port <= 65535):
                        raise ValueError("Port number must be between 1 and 65535")
                    return [port]
                except ValueError:
                    raise ValueError("Invalid port number")
        elif isinstance(ports, list) and all(isinstance(p, int) for p in ports):
            if not all(0 < p <= 65535 for p in ports):
                raise ValueError("Port numbers must be between 1 and 65535")
            return ports
        else:
            raise ValueError(
                "Ports must be an integer, a list of integers, or a string in the format 'start-end'"
            )
    
    def _check_port(
        self,
        ip: str,
        port: int,
        scan_type: str = 'tcp'
    ) -> Tuple[bool, Optional[str]]:
        """Check if a port is open and try to determine the service.
        
        Args:
            ip: Target IP address.
            port: Port to check.
            scan_type: Type of scan ('tcp' or 'udp').
            
        Returns:
            Tuple of (is_open, service_name)
        """
        sock = None
        try:
            if scan_type.lower() == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                is_open = result == 0
                service = self._guess_service(port) if is_open else None
                return is_open, service
            else:
                # UDP scanning is less reliable
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(b'\x00', (ip, port))
                sock.recvfrom(1024)
                return True, self._guess_service(port)
        except socket.timeout:
            return False, None
        except (socket.gaierror, socket.error) as e:
            logger.debug(f"Error checking port {port}: {e}")
            return False, None
        finally:
            if sock:
                sock.close()
    
    def _guess_service(self, port: int) -> str:
        """Guess the service name based on the port number.
        
        Args:
            port: Port number.
            
        Returns:
            Service name if known, otherwise 'unknown'.
        """
        common_services = {
            20: 'ftp-data',
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            67: 'dhcps',
            68: 'dhcpc',
            69: 'tftp',
            80: 'http',
            110: 'pop3',
            111: 'rpcbind',
            135: 'msrpc',
            137: 'netbios-ns',
            138: 'netbios-dgm',
            139: 'netbios-ssn',
            143: 'imap',
            161: 'snmp',
            162: 'snmptrap',
            389: 'ldap',
            443: 'https',
            445: 'microsoft-ds',
            465: 'smtps',
            514: 'syslog',
            515: 'printer',
            587: 'submission',
            631: 'ipp',
            636: 'ldaps',
            993: 'imaps',
            995: 'pop3s',
            1080: 'socks',
            1433: 'ms-sql-s',
            1434: 'ms-sql-m',
            1521: 'oracle',
            1723: 'pptp',
            2049: 'nfs',
            2082: 'cpanel',
            2083: 'cpanel-ssl',
            2086: 'cpanel',
            2087: 'cpanel-ssl',
            2095: 'cpanel',
            2096: 'cpanel-ssl',
            2181: 'zookeeper',
            2375: 'docker',
            2376: 'docker-ssl',
            3000: 'http',
            3306: 'mysql',
            3389: 'ms-wbt-server',
            3690: 'svn',
            4369: 'epmd',
            5000: 'upnp',
            5432: 'postgresql',
            5601: 'kibana',
            5672: 'amqp',
            5900: 'vnc',
            6379: 'redis',
            7001: 'weblogic',
            7002: 'weblogic',
            8000: 'http-alt',
            8008: 'http-alt',
            8009: 'ajp13',
            8080: 'http-proxy',
            8081: 'http-alt',
            8088: 'http-alt',
            8089: 'http-alt',
            8090: 'http-alt',
            8091: 'http-alt',
            8095: 'http-alt',
            8140: 'puppet',
            8200: 'http-alt',
            8443: 'https-alt',
            8500: 'http-alt',
            8600: 'http-alt',
            8649: 'gmond',
            8888: 'http-alt',
            9000: 'http-alt',
            9001: 'http-alt',
            9002: 'http-alt',
            9042: 'cassandra',
            9090: 'http-alt',
            9092: 'kafka',
            9100: 'jetdirect',
            9200: 'elasticsearch',
            9300: 'elasticsearch',
            9418: 'git',
            9999: 'http-alt',
            10000: 'http-alt',
            11211: 'memcached',
            15672: 'http-alt',
            27017: 'mongod',
            27018: 'mongod',
            27019: 'mongod',
            28017: 'mongod',
            50000: 'db2',
            50030: 'hadoop',
            50060: 'hadoop',
            50070: 'hadoop',
            50075: 'hadoop',
            50090: 'hadoop',
            60010: 'hbase',
            60030: 'hbase',
            60070: 'hbase',
        }
        return common_services.get(port, 'unknown')
    
    def _reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform a reverse DNS lookup.
        
        Args:
            ip: IP address to look up.
            
        Returns:
            Hostname if found, None otherwise.
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None

# Example usage
if __name__ == "__main__":
    import json
    import argparse
    
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Simple port scanner')
    parser.add_argument('target', help='Target host or IP address')
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='Ports to scan (e.g., 80,443 or 1-1024)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                        help='Connection timeout in seconds')
    parser.add_argument('-w', '--workers', type=int, default=100,
                        help='Maximum number of concurrent workers')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create a scanner instance
    scanner = SocketScanner(
        timeout=args.timeout,
        max_workers=args.workers
    )
    
    # Run the scan
    try:
        print(f"Scanning {args.target} on ports {args.ports}...")
        results = scanner.scan(args.target, args.ports)
        
        # Print results
        print("\nScan Results:")
        print(f"Target: {results.get('hostname', '')} ({results.get('ip', '')})")
        print(f"Status: {results.get('status', 'unknown')}")
        print(f"Scanned {results.get('total_ports', 0)} ports in {results.get('elapsed', 0):.2f} seconds")
        print(f"Found {results.get('open_ports', 0)} open ports\n")
        
        if 'ports' in results and results['ports']:
            print("PORT     STATE    SERVICE")
            print("----     -----    -------")
            for port in results['ports']:
                if port.get('state') == 'open':
                    print(f"{port.get('port')}/tcp  {port.get('state'):<8} {port.get('service', 'unknown')}")
        
        # Save full results to a JSON file
        output_file = f'scan_{args.target.replace(".", "_")}.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nFull results saved to {output_file}")
        
    except KeyboardInterrupt:
        print("\nScan aborted by user")
    except Exception as e:
        print(f"Error: {e}")
