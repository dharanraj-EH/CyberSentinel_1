"""
Nmap wrapper for CyberSentinel.

This module provides a Python interface to the Nmap security scanner.
It requires the Nmap binary to be installed on the system.
"""

import logging
import subprocess
import shlex
from typing import Dict, List, Optional, Union, Callable
from pathlib import Path
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class NmapScanner:
    """A wrapper around the Nmap security scanner."""
    
    def __init__(self, nmap_path: str = 'nmap'):
        """Initialize the Nmap scanner.
        
        Args:
            nmap_path: Path to the Nmap executable. Defaults to 'nmap'.
        """
        self.nmap_path = nmap_path
        self._check_nmap_installed()
    
    def _check_nmap_installed(self) -> bool:
        """Check if Nmap is installed and accessible.
        
        Returns:
            bool: True if Nmap is installed, False otherwise.
        """
        try:
            result = subprocess.run(
                [self.nmap_path, '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            version_line = result.stdout.split('\n')[0]
            logger.info(f"Found Nmap: {version_line}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("Nmap not found. Using socket scanner as fallback.")
            return False
    
    def scan(
        self,
        target: str,
        ports: Optional[Union[str, List[int]]] = None,
        arguments: str = '-sV -sS -T4',
        output_xml: Optional[str] = None,
        *,
        on_output: Optional[Callable[[str], None]] = None,
        stream: bool = False,
    ) -> Dict:
        """Perform an Nmap scan.
        
        Args:
            target: Target host or network range to scan.
            ports: Ports to scan. Can be a range (e.g., '1-1024'), a list of ports,
                  or a single port. If None, scans top 1000 ports.
            arguments: Additional Nmap arguments.
            output_xml: If provided, saves the XML output to this file.
            
        Returns:
            Dict containing the scan results.
            
        Raises:
            RuntimeError: If the Nmap command fails.
        """
        if not self._check_nmap_installed():
            raise RuntimeError("Nmap is not installed or not in PATH")
        
        # Build the command
        cmd = [self.nmap_path]
        
        # Add ports if specified
        if ports:
            if isinstance(ports, list):
                ports_str = ','.join(map(str, ports))
            else:
                ports_str = str(ports)
            cmd.extend(['-p', ports_str])
        
        # Add output file if specified
        if output_xml:
            cmd.extend(['-oX', output_xml])
        
        # Add additional arguments
        if arguments:
            cmd.extend(shlex.split(arguments))
        
        # Add target
        cmd.append(target)
        
        logger.info(f"Running Nmap command: {' '.join(cmd)}")
        
        try:
            if stream and on_output is not None:
                # Stream output line-by-line
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # merge stderr into stdout
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                )
                collected: List[str] = []
                assert proc.stdout is not None
                for line in proc.stdout:
                    line = line.rstrip('\n')
                    collected.append(line)
                    try:
                        on_output(line)
                    except Exception:
                        # Never break streaming due to UI callback errors
                        logger.debug("on_output callback raised, ignoring", exc_info=True)
                proc.wait()
                returncode = proc.returncode or 0
                stdout_text = "\n".join(collected)

                if output_xml and Path(output_xml).exists():
                    parsed = self._parse_nmap_xml(output_xml)
                    # Attach the executed command for UI display
                    parsed['command'] = ' '.join(cmd)
                    return parsed
                else:
                    return {
                        'command': ' '.join(cmd),
                        'stdout': stdout_text,
                        'stderr': '',
                        'returncode': returncode,
                    }
            else:
                # Run and wait
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                
                # Parse the output
                if output_xml and Path(output_xml).exists():
                    parsed = self._parse_nmap_xml(output_xml)
                    # Attach the executed command for UI display
                    parsed['command'] = ' '.join(cmd)
                    return parsed
                else:
                    return {
                        'command': ' '.join(cmd),
                        'stdout': result.stdout,
                        'stderr': result.stderr,
                        'returncode': result.returncode
                    }
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap scan failed: {e.stderr}")
            raise RuntimeError(f"Nmap scan failed: {e.stderr}")
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict:
        """Parse Nmap XML output file.
        
        Args:
            xml_file: Path to the Nmap XML output file.
            
        Returns:
            Dict containing the parsed scan results.
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            result = {
                'scan_info': {},
                'hosts': [],
                'summary': {}
            }
            
            # Parse scan information
            scan_info = root.find('scaninfo')
            if scan_info is not None:
                result['scan_info'] = {
                    'type': scan_info.get('type', ''),
                    'protocol': scan_info.get('protocol', ''),
                    'num_services': int(scan_info.get('numservices', 0)),
                    'services': scan_info.get('services', '')
                }
            
            # Parse hosts
            for host in root.findall('host'):
                host_data = {
                    'status': {},
                    'addresses': [],
                    'hostnames': [],
                    'ports': [],
                    'os': {},
                    'uptime': {},
                    'tcpsequence': {},
                    'ipidsequence': {},
                    'tcptssequence': {},
                    'times': {},
                    'trace': {}
                }
                
                # Host status
                status = host.find('status')
                if status is not None:
                    host_data['status'] = {
                        'state': status.get('state', 'unknown'),
                        'reason': status.get('reason', '')
                    }
                
                # Host addresses
                for address in host.findall('address'):
                    host_data['addresses'].append({
                        'addr': address.get('addr', ''),
                        'addrtype': address.get('addrtype', ''),
                        'vendor': address.get('vendor', '')
                    })
                
                # Hostnames
                for hostname in host.findall('hostnames/hostname'):
                    host_data['hostnames'].append({
                        'name': hostname.get('name', ''),
                        'type': hostname.get('type', '')
                    })
                
                # Ports
                for port in host.findall('ports/port'):
                    port_data = {
                        'port': int(port.get('portid', 0)),
                        'protocol': port.get('protocol', ''),
                        'state': {},
                        'service': {}
                    }
                    
                    # Port state
                    state = port.find('state')
                    if state is not None:
                        port_data['state'] = {
                            'state': state.get('state', ''),
                            'reason': state.get('reason', ''),
                            'reason_ttl': int(state.get('reason_ttl', 0))
                        }
                    
                    # Service information
                    service = port.find('service')
                    if service is not None:
                        port_data['service'] = {
                            'name': service.get('name', ''),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', ''),
                            'ostype': service.get('ostype', ''),
                            'method': service.get('method', ''),
                            'conf': int(service.get('conf', 0)),
                            'cpe': service.get('cpe', '')
                        }
                    
                    host_data['ports'].append(port_data)
                
                # OS information
                os = host.find('os')
                if os is not None:
                    os_matches = []
                    for osmatch in os.findall('osmatch'):
                        os_matches.append({
                            'name': osmatch.get('name', ''),
                            'accuracy': int(osmatch.get('accuracy', 0)),
                            'line': int(osmatch.get('line', 0)),
                            'osclass': [{
                                'type': osclass.get('type', ''),
                                'vendor': osclass.get('vendor', ''),
                                'osfamily': osclass.get('osfamily', ''),
                                'osgen': osclass.get('osgen', ''),
                                'accuracy': int(osclass.get('accuracy', 0)),
                                'cpe': [cpe.text for cpe in osclass.findall('cpe')]
                            } for osclass in osmatch.findall('osclass')]
                        })
                    host_data['os'] = {'os_matches': os_matches}

                # Uptime
                uptime = host.find('uptime')
                if uptime is not None:
                    host_data['uptime'] = {
                        'seconds': int(uptime.get('seconds', 0) or 0),
                        'lastboot': uptime.get('lastboot', '')
                    }

                # Sequences
                tcpseq = host.find('tcpsequence')
                if tcpseq is not None:
                    host_data['tcpsequence'] = {k: v for k, v in tcpseq.attrib.items()}
                ipidseq = host.find('ipidsequence')
                if ipidseq is not None:
                    host_data['ipidsequence'] = {k: v for k, v in ipidseq.attrib.items()}
                tcptsseq = host.find('tcptssequence')
                if tcptsseq is not None:
                    host_data['tcptssequence'] = {k: v for k, v in tcptsseq.attrib.items()}

                # Times
                times = host.find('times')
                if times is not None:
                    host_data['times'] = {k: v for k, v in times.attrib.items()}

                # Traceroute (topology)
                trace = host.find('trace')
                if trace is not None:
                    hops = []
                    for hop in trace.findall('hop'):
                        hops.append({k: v for k, v in hop.attrib.items()})
                    host_data['trace'] = {
                        'proto': trace.get('proto', ''),
                        'port': trace.get('port', ''),
                        'hops': hops,
                    }
                
                result['hosts'].append(host_data)
            
            # Parse run statistics
            run_stats = root.find('runstats/finished')
            if run_stats is not None:
                result['summary'] = {
                    'time': int(run_stats.get('time', 0)),
                    'timestr': run_stats.get('timestr', ''),
                    'elapsed': float(run_stats.get('elapsed', 0)),
                    'summary': run_stats.get('summary', ''),
                    'exit': run_stats.get('exit', '')
                }
            
            return result
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML output: {e}")
            raise RuntimeError(f"Failed to parse Nmap XML output: {e}")

# Example usage
if __name__ == "__main__":
    import json
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create an Nmap scanner instance
    scanner = NmapScanner()
    
    # Run a scan
    try:
        results = scanner.scan(
            target="scanme.nmap.org",
            ports="22,80,443",
            arguments="-sS -T4 -A -v"
        )
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"Error: {e}")
