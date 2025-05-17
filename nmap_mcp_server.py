from fastmcp import FastMCP
import subprocess
import os
import shortuuid
from typing import Optional, List, Dict, Any
from nmap_parser import NmapParser
import mysql.connector
from datetime import datetime
import json
from dotenv import load_dotenv
import requests
import logging
import re

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nmap_mcp_server')

# Create FastMCP server instance with increased timeouts
logger.debug("Initializing FastMCP server...")
app = FastMCP("nmap_mcp_server", function_timeout=3600)  # 60-minute function timeout

# Setup directory for nmap outputs
current_dir = os.getcwd()
output_dir = os.path.join(current_dir, "nmap_outputs")
os.makedirs(output_dir, exist_ok=True)
logger.debug(f"Output directory set to: {output_dir}")

# Load environment variables
load_dotenv()
logger.debug("Environment variables loaded")

# MySQL configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': os.getenv('LOCALHOST'),
    'password': os.getenv('MYSQLPASSWORD'),
    'database': 'nmap_scans'
}
logger.debug("Database configuration loaded")

# DeepSeek API configuration
DEEPSEEK_API_KEY = os.getenv('DEEPSEEK_API_KEY')
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
logger.debug("DeepSeek API configuration loaded")

def get_db_connection():
    """Create and return a MySQL database connection"""
    return mysql.connector.connect(**DB_CONFIG)

def init_db():
    """Initialize the MySQL database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create database if it doesn't exist
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
    cursor.execute(f"USE {DB_CONFIG['database']}")
    
    # Create scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target VARCHAR(255) NOT NULL,
            scan_type VARCHAR(50) NOT NULL,
            scan_time DATETIME NOT NULL,
            output_file VARCHAR(255) NOT NULL,
            parsed_data JSON,
            analysis JSON,
            UNIQUE KEY unique_scan (target, scan_type, scan_time)
        )
    ''')
    
    conn.commit()
    cursor.close()
    conn.close()

# Initialize database
init_db()

def generate_output_path(target: str, scan_type: str) -> str:
    """Generate a unique output path for scan results."""
    # Clean target to be filesystem safe by removing protocol prefixes and illegal characters
    clean_target = target.replace("http://", "").replace("https://", "")
    # Replace any illegal characters with underscores
    clean_target = re.sub(r'[\\/*?:"<>|]', "_", clean_target)
    filename = f"{clean_target}_{scan_type}_{shortuuid.uuid()[:8]}"
    return os.path.join(output_dir, f"{filename}.xml")

def run_nmap_scan(cmd: str, output_file: str, target: str, scan_type: str) -> Dict[str, Any]:
    """Execute nmap command using Docker and return parsed results."""
    try:
        # Convert the output path to a Docker volume path
        docker_output_path = f"/out/{os.path.basename(output_file)}"
        
        # Determine appropriate timeout based on scan type
        # More intensive scans need more time
        scan_timeout = {
            'basic': 300,     # 5 minutes
            'stealth': 600,   # 10 minutes
            'service': 900,   # 15 minutes
            'os': 900,        # 15 minutes
            'vuln': 1800,     # 30 minutes
            'aggressive': 3600,  # 60 minutes
            'custom': 1800    # 30 minutes
        }.get(scan_type, 900)  # Default 15 minutes
        
        logger.debug(f"Using timeout of {scan_timeout} seconds for {scan_type} scan")
        
        # Build the Docker command
        docker_cmd = [
            "docker", "run", "--rm",
            "--network=host",  # Use host networking to improve performance
            "--timeout", str(scan_timeout),
            "-v", f"{output_dir}:/out",
            "nmap",
            *cmd.split(),  # Split the nmap command into arguments
            "-oX", docker_output_path
        ]
        
        print(f"\n[DEBUG] Running Docker command: {' '.join(docker_cmd)}")
        
        # Run the Docker command with a timeout
        try:
            result = subprocess.run(
                docker_cmd, 
                capture_output=True, 
                text=True, 
                timeout=scan_timeout + 60  # Add 60 seconds buffer to Docker timeout
            )
            print(f"[DEBUG] Command return code: {result.returncode}")
            print(f"[DEBUG] Command stdout: {result.stdout[:200]}...")
            print(f"[DEBUG] Command stderr: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(f"[DEBUG] Command timed out after {scan_timeout + 60} seconds")
            return {
                "status": "error",
                "message": f"Scan timed out after {scan_timeout} seconds. Try with fewer targets or a simpler scan type."
            }
        
        # Check if command was successful
        if result.returncode == 0:
            # Check if output file exists
            print(f"[DEBUG] Checking if output file exists: {output_file}")
            if not os.path.exists(output_file):
                print(f"[DEBUG] Output file not found!")
                return {
                    "status": "error",
                    "message": f"Scan completed but output file {output_file} was not created"
                }
            
            try:
                print("[DEBUG] Attempting to parse XML file...")
                # Parse the XML output
                parser = NmapParser(output_file)
                parsed_data = parser.parse()
                print(f"[DEBUG] Successfully parsed {len(parsed_data)} hosts")
                
                summary = parser.get_summary()
                # Convert datetime in summary to ISO format string
                if 'scan_time' in summary and isinstance(summary['scan_time'], datetime):
                    summary['scan_time'] = summary['scan_time'].isoformat()
                print(f"[DEBUG] Generated summary: {summary}")
                
                # Extract vulnerabilities with more detailed information
                vulnerabilities = []
                logger.debug("Starting vulnerability extraction from scan results")
                
                for host in parsed_data:
                    logger.debug(f"Processing host: {host.ip}")
                    for port in host.ports:
                        logger.debug(f"Processing port: {port.port}/{port.protocol}")
                        if hasattr(port, 'scripts'):
                            logger.debug(f"Found {len(port.scripts)} scripts for port {port.port}")
                            for script in port.scripts:
                                logger.debug(f"Processing script: {script.id}")
                                # Check if this is a vulnerability script
                                if any(keyword in script.id.lower() for keyword in ['vuln', 'cve', 'exploit']):
                                    logger.debug(f"Found vulnerability script: {script.id}")
                                    
                                    # Extract CVE number if present
                                    cve_match = re.search(r'CVE-\d{4}-\d{4,}', script.id)
                                    cve = cve_match.group(0) if cve_match else None
                                    logger.debug(f"Extracted CVE: {cve}")
                                    
                                    # Determine severity based on script name and output
                                    severity = 'Medium'
                                    if any(keyword in script.id.lower() for keyword in ['critical', 'high']):
                                        severity = 'High'
                                    elif any(keyword in script.id.lower() for keyword in ['low', 'info']):
                                        severity = 'Low'
                                    logger.debug(f"Determined severity: {severity}")
                                    
                                    # Get description from script output
                                    description = script.output if hasattr(script, 'output') else ''
                                    logger.debug(f"Script output length: {len(description)}")
                                    logger.debug(f"Script output preview: {description[:200]}...")
                                    
                                    # Format the vulnerability name
                                    vuln_name = script.id
                                    if cve:
                                        vuln_name = f"{script.id} ({cve})"
                                    logger.debug(f"Formatted vulnerability name: {vuln_name}")
                                    
                                    # Create vulnerability info
                                    vuln_info = {
                                        'name': vuln_name,
                                        'severity': severity,
                                        'description': description,
                                        'port': f"{port.port}/{port.protocol}",
                                        'service': port.service if hasattr(port, 'service') else 'Unknown',
                                        'cve': cve,
                                        'host': host.ip
                                    }
                                    logger.debug(f"Created vulnerability info: {json.dumps(vuln_info, indent=2)}")
                                    
                                    # Add solution if available in script output
                                    if 'solution' in description.lower():
                                        solution_match = re.search(r'solution:?\s*(.*?)(?:\n|$)', description, re.IGNORECASE)
                                        if solution_match:
                                            vuln_info['solution'] = solution_match.group(1).strip()
                                            logger.debug(f"Found solution: {vuln_info['solution']}")
                                    
                                    # Add references if available
                                    if 'references' in description.lower():
                                        refs_match = re.search(r'references:?\s*(.*?)(?:\n\n|$)', description, re.IGNORECASE | re.DOTALL)
                                        if refs_match:
                                            refs = refs_match.group(1).strip().split('\n')
                                            vuln_info['references'] = [ref.strip() for ref in refs if ref.strip()]
                                            logger.debug(f"Found references: {vuln_info['references']}")
                                    
                                    # Add state if available
                                    if 'state' in description.lower():
                                        state_match = re.search(r'state:?\s*(.*?)(?:\n|$)', description, re.IGNORECASE)
                                        if state_match:
                                            vuln_info['state'] = state_match.group(1).strip()
                                            logger.debug(f"Found state: {vuln_info['state']}")
                                    
                                    vulnerabilities.append(vuln_info)
                                    logger.debug(f"Added vulnerability to list. Total vulnerabilities: {len(vulnerabilities)}")
                
                logger.debug(f"Finished vulnerability extraction. Found {len(vulnerabilities)} vulnerabilities")
                logger.debug(f"Vulnerabilities: {json.dumps(vulnerabilities, indent=2)}")
                
                llm_summary = parser.get_llm_friendly_summary()
                print("[DEBUG] Generated LLM summary")
                
                # Store scan results in database
                conn = get_db_connection()
                cursor = conn.cursor()
                current_time = datetime.now()
                payload = {
                    'summary': summary,
                    'vulnerabilities': vulnerabilities,
                    'llm_summary': llm_summary,
                    'raw_data': parsed_data,
                    'scan_time': current_time.isoformat()
                }
                payload_json = json.dumps(payload, default=str)
                cursor.execute('''
                    INSERT INTO scans (target, scan_type, scan_time, output_file, parsed_data)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (target, scan_type, current_time, output_file, payload_json))
                conn.commit()
                cursor.close()
                conn.close()
                
                return {
                    "status": "success",
                    "summary": summary,
                    "vulnerabilities": vulnerabilities,
                    "llm_summary": llm_summary,
                    "raw_data": parsed_data
                }
            except Exception as parse_error:
                print(f"[DEBUG] Error during parsing: {str(parse_error)}")
                return {
                    "status": "error",
                    "message": f"Error parsing scan results: {str(parse_error)}"
                }
        else:
            print(f"[DEBUG] Command failed with return code {result.returncode}")
            return {
                "status": "error",
                "message": f"Scan failed: {result.stderr}"
            }
    except Exception as e:
        print(f"[DEBUG] Unexpected error: {str(e)}")
        return {
            "status": "error",
            "message": f"Error during scan: {str(e)}"
        }

def analyze_with_deepseek(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze scan results using DeepSeek v3"""
    try:
        if not DEEPSEEK_API_KEY:
            return {
                "status": "error",
                "message": "DeepSeek API key not configured. Please set DEEPSEEK_API_KEY in your .env file."
            }
            
        # Prepare the prompt for DeepSeek with clear formatting instructions
        prompt = f"""Analyze this network scan data and provide a detailed security assessment in markdown format.
    
Include the following sections:
    
## Security Risk Assessment
- Overall Risk Level: [High/Medium/Low]
- Key Findings:
  - [Finding 1]
  - [Finding 2]
  - ...
    
## Critical Vulnerabilities
- **[Vulnerability Name]**
  - Severity: [High/Medium/Low]
  - Description: [Brief description]
    
## Recommended Actions
1. **[Action Title]**
   - [Specific step]
   - [Specific step]
    
## Technical Details
### Host Information
- Target: [Host/IP]
- OS: [OS details]
    
### Open Ports and Services
| Port | Service | Status | Notes |
|------|---------|--------|-------|
| [Port] | [Service] | [Status] | [Notes] |
    
## Next Steps
- [Next step recommendation]
- [Next step recommendation]

Use detailed markdown formatting for better readability.
Make sure to include all relevant information from the scan data.

Scan Data:
{json.dumps(scan_data, indent=2)}
"""
        
        # Call DeepSeek API
        headers = {
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "system", 
                    "content": """You are a cybersecurity expert analyzing network scan results. 
                    Provide clear, actionable insights in well-formatted markdown.
                    Focus on practical security implications and solutions.
                    Make the output structured and easy to read."""
                },
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        response = requests.post(DEEPSEEK_API_URL, headers=headers, json=data)
        response.raise_for_status()
        
        # Extract the analysis
        analysis = response.json()['choices'][0]['message']['content']
        
        return {
            "status": "success",
            "analysis": analysis,
            "raw_response": response.json()
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"DeepSeek API request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"DeepSeek analysis failed: {str(e)}"
        }

@app.tool(
    name="analyze_scan",
    description="""Analyze scan results using DeepSeek v3 AI.
    This tool provides detailed security analysis and recommendations based on scan results.
    Returns AI-generated insights about vulnerabilities, risks, and recommended actions.
    """
)
def analyze_scan(target: str, scan_type: str) -> Dict[str, Any]:
    """Analyze scan results using DeepSeek v3"""
    try:
        # Get the latest scan results
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT parsed_data, analysis 
            FROM scans 
            WHERE target = %s AND scan_type = %s
            ORDER BY scan_time DESC
            LIMIT 1
        ''', (target, scan_type))
        result = cursor.fetchone()
        
        if not result:
            return {'error': 'No scan found for this target and type'}
        
        # Parse the stored data
        scan_data = json.loads(result['parsed_data'])
        
        # Check if we already have an analysis
        if result['analysis']:
            stored_analysis = json.loads(result['analysis'])
            return {
                "target": target,
                "scan_type": scan_type,
                "scan_data": scan_data,
                "ai_analysis": stored_analysis
            }
        
        # Get DeepSeek analysis
        analysis = analyze_with_deepseek(scan_data)
        
        if analysis.get('status') == 'error':
            return {'error': analysis['message']}
        
        # Save the analysis in the database
        cursor.execute('''
            UPDATE scans 
            SET analysis = %s 
            WHERE target = %s AND scan_type = %s 
            ORDER BY scan_time DESC 
            LIMIT 1
        ''', (json.dumps(analysis), target, scan_type))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return {
            "target": target,
            "scan_type": scan_type,
            "scan_data": scan_data,
            "ai_analysis": analysis
        }
    except Exception as e:
        return {'error': str(e)}

@app.tool(
    name="basic_scan",
    description="""Perform a basic network scan on a target host.
    This is a simple scan that identifies open ports and basic service information.
    Use this for quick reconnaissance of a target system.
    Returns structured data including port information, services, and summary statistics.
    """
)
def basic_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "basic")
    cmd = f"-T4 -sV {target}"  # Added -T4 for faster timing
    return run_nmap_scan(cmd, output_file, target, "basic")

@app.tool(
    name="aggressive_scan",
    description="""Perform an aggressive scan with OS detection, version detection, script scanning, and traceroute.
    This scan is more intrusive and provides detailed information about the target.
    Use this when you need comprehensive information about a target system.
    Returns detailed data including OS information, service versions, and vulnerability details.
    """
)
def aggressive_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "aggressive")
    cmd = f"-T4 -A -p- -sV --version-intensity 9 -O --script=all -v --reason --packet-trace {target}"  # -T4 already present
    return run_nmap_scan(cmd, output_file, target, "aggressive")

@app.tool(
    name="stealth_scan",
    description="""Perform a stealth scan using SYN scanning technique.
    This scan is less likely to be detected by intrusion detection systems.
    Use this when you need to scan without being detected.
    Returns port and service information while maintaining stealth.
    """
)
def stealth_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "stealth")
    cmd = f"-T4 -sS -sV {target}"  # Added -T4 for faster timing
    return run_nmap_scan(cmd, output_file, target, "stealth")

@app.tool(
    name="vulnerability_scan",
    description="""Perform a vulnerability scan using nmap's built-in scripts.
    This scan focuses on identifying potential security vulnerabilities.
    Use this when you need to assess the security posture of a target.
    Returns detailed vulnerability information and risk assessment.
    """
)
def vulnerability_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "vuln")
    cmd = f"-T4 -sV --script vuln {target}"  # Added -T4 for faster timing
    return run_nmap_scan(cmd, output_file, target, "vuln")

@app.tool(
    name="custom_scan",
    description="""Perform a custom scan with specified options.
    This allows for flexible scanning configurations based on specific needs.
    Use this when you need a tailored scanning approach.
    Returns structured data based on the custom scan configuration.
    """
)
def custom_scan(
    target: str,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    timing: Optional[int] = None,
    verbose: bool = False
) -> Dict[str, Any]:
    output_file = generate_output_path(target, "custom")
    
    # Build command with optional parameters
    cmd_parts = ["-T4"]  # Always add -T4 for faster timing
    if ports:
        cmd_parts.append(f"-p{ports}")
    if scripts:
        cmd_parts.append(f"--script={scripts}")
    if timing:
        cmd_parts.append(f"-T{timing}")  # User timing will override -T4 if specified
    if verbose:
        cmd_parts.append("-v")
    
    cmd_parts.append(target)
    cmd = " ".join(cmd_parts)
    return run_nmap_scan(cmd, output_file, target, "custom")

@app.tool(
    name="service_scan",
    description="""Perform a detailed service version detection scan.
    This scan focuses on identifying running services and their versions.
    Use this when you need detailed information about running services.
    Returns comprehensive service information and version details.
    """
)
def service_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "service")
    cmd = f"-T4 -sV --version-intensity 9 {target}"  # Added -T4 for faster timing
    return run_nmap_scan(cmd, output_file, target, "service")

@app.tool(
    name="os_detection_scan",
    description="""Perform an operating system detection scan.
    This scan attempts to identify the target's operating system.
    Use this when you need to determine the OS of the target system.
    Returns detailed OS information and detection confidence levels.
    """
)
def os_detection_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "os")
    cmd = f"-T4 -O --osscan-guess {target}"  # Added -T4 for faster timing
    return run_nmap_scan(cmd, output_file, target, "os")

@app.tool(
    name="get_scan_history",
    description="Get the history of all scans"
)
def get_scan_history() -> List[Dict[str, Any]]:
    """Retrieve scan history from database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT target, scan_type, scan_time, output_file, parsed_data 
            FROM scans 
            ORDER BY scan_time DESC
        ''')
        scans = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return [
            {
                'target': scan['target'],
                'scan_type': scan['scan_type'],
                'scan_time': scan['scan_time'].isoformat(),
                'output_file': scan['output_file'],
                'summary': json.loads(scan['parsed_data'])['summary']
            }
            for scan in scans
        ]
    except Exception as e:
        return [{'error': str(e)}]

@app.tool(
    name="get_scan_details",
    description="Get detailed information about a specific scan"
)
def get_scan_details(target: str, scan_type: str, scan_time: str) -> Dict[str, Any]:
    """Retrieve detailed scan information from database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT parsed_data, output_file 
            FROM scans 
            WHERE target = %s AND scan_type = %s AND scan_time = %s
        ''', (target, scan_type, scan_time))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            return {
                'parsed_data': json.loads(result['parsed_data']),
                'output_file': result['output_file']
            }
        return {'error': 'Scan not found'}
    except Exception as e:
        return {'error': str(e)}

@app.resource("resource://scan/{target}/{scan_type}")
def get_scan_resource(target: str, scan_type: str) -> Dict[str, Any]:
    """Get the latest scan results for a specific target and scan type"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT parsed_data, scan_time, output_file
            FROM scans 
            WHERE target = %s AND scan_type = %s
            ORDER BY scan_time DESC
            LIMIT 1
        ''', (target, scan_type))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            return {
                'target': target,
                'scan_type': scan_type,
                'scan_time': result['scan_time'].isoformat(),
                'output_file': result['output_file'],
                'data': json.loads(result['parsed_data'])
            }
        return {'error': 'No scan found for this target and type'}
    except Exception as e:
        return {'error': str(e)}

@app.resource("resource://scan/{target}/history")
def get_target_history(target: str) -> List[Dict[str, Any]]:
    """Get scan history for a specific target"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT scan_type, scan_time, parsed_data
            FROM scans 
            WHERE target = %s
            ORDER BY scan_time DESC
        ''', (target,))
        scans = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return [
            {
                'scan_type': scan['scan_type'],
                'scan_time': scan['scan_time'].isoformat(),
                'summary': json.loads(scan['parsed_data'])['summary']
            }
            for scan in scans
        ]
    except Exception as e:
        return [{'error': str(e)}]

@app.resource("resource://debug/scan/{target}/{scan_type}")
def get_scan_debug_info(target: str, scan_type: str) -> Dict[str, Any]:
    """Get detailed debugging information for a scan"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT parsed_data, scan_time, output_file
            FROM scans 
            WHERE target = %s AND scan_type = %s
            ORDER BY scan_time DESC
            LIMIT 1
        ''', (target, scan_type))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            parsed_data = json.loads(result['parsed_data'])
            return {
                'target': target,
                'scan_type': scan_type,
                'scan_time': result['scan_time'].isoformat(),
                'output_file': result['output_file'],
                'summary': parsed_data['summary'],
                'vulnerabilities': parsed_data['vulnerabilities'],
                'llm_summary': parsed_data['llm_summary'],
                'raw_data': parsed_data['raw_data'],
                'debug_info': {
                    'total_hosts': len(parsed_data['raw_data']),
                    'open_ports': sum(1 for host in parsed_data['raw_data'] 
                                    for port in host.ports if port.state == 'open'),
                    'vulnerability_count': len(parsed_data['vulnerabilities']),
                    'services_found': len(set(port.service for host in parsed_data['raw_data'] 
                                            for port in host.ports if port.service))
                }
            }
        return {'error': 'No scan found for this target and type'}
    except Exception as e:
        return {'error': str(e)}

@app.resource("resource://stats/overview")
def get_scan_stats() -> Dict[str, Any]:
    """Get overall statistics about all scans"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get total scans
        cursor.execute('SELECT COUNT(*) as total FROM scans')
        total_scans = cursor.fetchone()['total']
        
        # Get scans by type
        cursor.execute('''
            SELECT scan_type, COUNT(*) as count
            FROM scans
            GROUP BY scan_type
        ''')
        scans_by_type = {row['scan_type']: row['count'] for row in cursor.fetchall()}
        
        # Get most scanned targets
        cursor.execute('''
            SELECT target, COUNT(*) as count
            FROM scans
            GROUP BY target
            ORDER BY count DESC
            LIMIT 5
        ''')
        top_targets = [{'target': row['target'], 'count': row['count']} 
                      for row in cursor.fetchall()]
        
        # Get vulnerability statistics
        cursor.execute('''
            SELECT 
                JSON_EXTRACT(parsed_data, '$.vulnerabilities') as vulns
            FROM scans
            WHERE parsed_data IS NOT NULL
        ''')
        vulnerabilities = []
        for row in cursor.fetchall():
            if row['vulns']:
                try:
                    vulns = json.loads(row['vulns'])
                    if isinstance(vulns, list):
                        for vuln in vulns:
                            vuln_type = vuln.get('type', 'Unknown')
                            found = False
                            for v in vulnerabilities:
                                if v['type'] == vuln_type:
                                    v['count'] += 1
                                    found = True
                                    break
                            if not found:
                                vulnerabilities.append({
                                    'type': vuln_type,
                                    'count': 1
                                })
                except json.JSONDecodeError:
                    continue
        
        # Get scan activity over time (last 7 days)
        cursor.execute('''
            SELECT 
                DATE(scan_time) as date,
                COUNT(*) as count
            FROM scans
            WHERE scan_time >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(scan_time)
            ORDER BY date
        ''')
        activity = [{'date': row['date'].strftime('%Y-%m-%d'), 'count': row['count']} 
                   for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return {
            'total_scans': total_scans,
            'scans_by_type': scans_by_type,
            'top_targets': top_targets,
            'vulnerabilities': vulnerabilities,
            'activity': activity,
            'last_updated': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting scan stats: {str(e)}")
        return {'error': str(e)}

if __name__ == "__main__":
    app.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=4200,
        path="/nmap",
        request_timeout=3600  # 60 minutes max request timeout
    )