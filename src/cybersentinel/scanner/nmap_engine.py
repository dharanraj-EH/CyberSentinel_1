"""
Nmap wrapper for CyberSentinel.

This module provides a Python interface to the Nmap security scanner.
It requires the Nmap binary to be installed on the system.
"""

import logging
import subprocess
import shlex
import threading
import ipaddress
import re
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
        self._process = None
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
    
    def cancel(self):
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def scan(self, target, ports=None, arguments='-sV -sT -T3', output_xml=None,
             *, on_output=None, stream=False, cancel_event=None, timeout=180):
        if not target or target.startswith('-') or any(char.isspace() for char in target):
            raise ValueError('Use one hostname, IP address or network range.')
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', target):
                raise ValueError('Invalid assessment target')
        if not self._check_nmap_installed():
            raise RuntimeError('Nmap is not installed. Select the TCP Connect engine or install Nmap.')
        cmd = [self.nmap_path]
        if ports:
            ports = ','.join(map(str, ports)) if isinstance(ports, list) else str(ports)
            if not re.fullmatch(r'[0-9,-]+', ports):
                raise ValueError('Invalid port selection')
            cmd.extend(['-p', ports])
        if output_xml:
            cmd.extend(['-oX', output_xml])
        tokens = shlex.split(arguments)
        allowed_flags = {'-sT', '-sS', '-sV', '-sU', '-O', '-A', '-v', '-Pn', '-n', '-F'}
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in allowed_flags or re.fullmatch(r'-T[0-5]', token):
                index += 1
            elif token == '--host-timeout' and index + 1 < len(tokens) and re.fullmatch(r'\d+[smh]?', tokens[index+1]):
                index += 2
            else:
                raise ValueError('Unsupported Nmap option. Arbitrary scripts and file-output options are disabled.')
        cmd.extend(tokens)
        cmd.append(target)
        cancel_event = cancel_event or threading.Event()
        timed_out = threading.Event()
        stop_monitor = threading.Event()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self._process = proc
        def deadline():
            timed_out.set()
            self.cancel()
        timer = threading.Timer(timeout, deadline)
        def watch():
            while not stop_monitor.wait(.1):
                if cancel_event.is_set():
                    self.cancel()
                    return
        monitor = threading.Thread(target=watch, daemon=True)
        timer.start()
        monitor.start()
        collected = []
        try:
            for line in proc.stdout:
                collected.append(line.rstrip())
                if stream and on_output:
                    on_output(line.rstrip())
            proc.wait(timeout=5)
            if cancel_event.is_set():
                raise RuntimeError('Assessment cancelled')
            if timed_out.is_set():
                raise RuntimeError('Nmap assessment exceeded the time limit')
            if proc.returncode:
                raise RuntimeError('Nmap failed: ' + '\n'.join(collected[-10:]))
            if output_xml:
                result = self._parse_nmap_xml(output_xml)
                if result.get('summary', {}).get('exit') == 'error':
                    raise RuntimeError('Nmap reported an incomplete assessment')
            else:
                result = {'stdout': '\n'.join(collected), 'stderr': '', 'returncode': 0}
            result['command'] = ' '.join(cmd)
            return result
        finally:
            stop_monitor.set()
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            proc.stdout.close()
            self._process = None

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
                            'cpe': [item.text for item in service.findall('cpe') if item.text]
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
