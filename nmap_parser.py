import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import os

@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None
    product: Optional[str] = None
    scripts: List[Dict[str, Any]] = None

@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str]
    status: str
    os_info: Optional[Dict[str, Any]]
    ports: List[PortInfo]
    scan_time: datetime
    scan_type: str

class NmapParser:
    def __init__(self, xml_file_path: str):
        """Initialize parser with path to nmap XML file."""
        self.xml_file_path = xml_file_path
        self.tree = ET.parse(xml_file_path)
        self.root = self.tree.getroot()
        
    def _extract_os_info(self, host: ET.Element) -> Optional[Dict[str, Any]]:
        """Extract operating system information."""
        os_info = {}
        os_match = host.find('.//osmatch')
        if os_match is not None:
            os_info['name'] = os_match.get('name', '')
            os_info['accuracy'] = os_match.get('accuracy', '')
            os_info['line'] = os_match.get('line', '')
        return os_info if os_info else None

    def _extract_ports(self, host: ET.Element) -> List[PortInfo]:
        """Extract port information."""
        ports = []
        for port in host.findall('.//port'):
            port_info = PortInfo(
                port=int(port.get('portid', 0)),
                protocol=port.get('protocol', ''),
                state=port.find('state').get('state', '') if port.find('state') is not None else 'unknown',
                service=port.find('service').get('name', '') if port.find('service') is not None else 'unknown',
                version=port.find('service').get('version', '') if port.find('service') is not None else None,
                product=port.find('service').get('product', '') if port.find('service') is not None else None,
                scripts=[]
            )
            
            # Extract script output
            for script in port.findall('script'):
                script_info = {
                    'id': script.get('id', ''),
                    'output': script.get('output', ''),
                    'elements': []
                }
                for elem in script.findall('elem'):
                    script_info['elements'].append({
                        'key': elem.get('key', ''),
                        'value': elem.text
                    })
                port_info.scripts.append(script_info)
            
            ports.append(port_info)
        return ports

    def parse(self) -> List[HostInfo]:
        """Parse the nmap XML file and return structured data."""
        hosts = []
        scan_type = os.path.basename(self.xml_file_path).split('_')[1]  # Extract scan type from filename
        
        for host in self.root.findall('host'):
            # Extract basic host information
            ip = host.find('address').get('addr', '') if host.find('address') is not None else ''
            hostname = host.find('hostnames/hostname').get('name', '') if host.find('hostnames/hostname') is not None else None
            status = host.find('status').get('state', '') if host.find('status') is not None else 'unknown'
            
            # Create HostInfo object
            host_info = HostInfo(
                ip=ip,
                hostname=hostname,
                status=status,
                os_info=self._extract_os_info(host),
                ports=self._extract_ports(host),
                scan_time=datetime.fromtimestamp(int(self.root.get('start', 0))),
                scan_type=scan_type
            )
            hosts.append(host_info)
        
        return hosts

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the scan results."""
        hosts = self.parse()
        summary = {
            'scan_type': hosts[0].scan_type if hosts else None,
            'scan_time': hosts[0].scan_time if hosts else None,
            'total_hosts': len(hosts),
            'up_hosts': sum(1 for h in hosts if h.status == 'up'),
            'total_ports': sum(len(h.ports) for h in hosts),
            'open_ports': sum(1 for h in hosts for p in h.ports if p.state == 'open'),
            'services': {},
            'os_distribution': {}
        }
        
        # Count services
        for host in hosts:
            for port in host.ports:
                if port.service:
                    summary['services'][port.service] = summary['services'].get(port.service, 0) + 1
            
            if host.os_info and host.os_info.get('name'):
                os_name = host.os_info['name']
                summary['os_distribution'][os_name] = summary['os_distribution'].get(os_name, 0) + 1
        
        return summary

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Extract vulnerability information from script output."""
        vulnerabilities = []
        for host in self.parse():
            for port in host.ports:
                for script in port.scripts:
                    if 'vuln' in script['id'].lower():
                        vuln_info = {
                            'host': host.ip,
                            'port': port.port,
                            'service': port.service,
                            'vulnerability': script['id'],
                            'details': script['output'],
                            'elements': script['elements']
                        }
                        vulnerabilities.append(vuln_info)
        return vulnerabilities

    def get_llm_friendly_summary(self) -> str:
        """Generate a human-readable summary suitable for LLM consumption."""
        summary = self.get_summary()
        hosts = self.parse()
        
        report = f"""Nmap Scan Summary
-----------------
Scan Type: {summary['scan_type']}
Scan Time: {summary['scan_time']}
Total Hosts Scanned: {summary['total_hosts']}
Hosts Up: {summary['up_hosts']}

Port Statistics:
- Total Ports Found: {summary['total_ports']}
- Open Ports: {summary['open_ports']}

Top Services:
"""
        # Add top 5 services
        sorted_services = sorted(summary['services'].items(), key=lambda x: x[1], reverse=True)
        for service, count in sorted_services[:5]:
            report += f"- {service}: {count} instances\n"
        
        report += "\nOperating Systems Detected:\n"
        for os_name, count in summary['os_distribution'].items():
            report += f"- {os_name}: {count} hosts\n"
        
        # Add vulnerability summary
        vulns = self.get_vulnerabilities()
        if vulns:
            report += "\nVulnerabilities Found:\n"
            for vuln in vulns:
                report += f"- {vuln['vulnerability']} on {vuln['host']}:{vuln['port']} ({vuln['service']})\n"
        
        return report

# Example usage
if __name__ == "__main__":
    # Example of how to use the parser
    parser = NmapParser("nmap_outputs/example_scan.xml")
    
    # Get structured data
    hosts = parser.parse()
    
    # Get summary statistics
    summary = parser.get_summary()
    
    # Get vulnerability information
    vulnerabilities = parser.get_vulnerabilities()
    
    # Get LLM-friendly summary
    llm_summary = parser.get_llm_friendly_summary()
    print(llm_summary) 