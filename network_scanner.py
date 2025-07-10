import ipaddress
import os
import subprocess
import re
import time
from progress_manager import ProgressManager
from error_handler import ErrorHandler
from utils import get_creation_flags, is_valid_ip, parse_ip_range

class NetworkScanner:
    def __init__(self, nmap_path, log_function):
        self.nmap_path = nmap_path
        self.log = log_function
        self.error_handler = ErrorHandler(log_function)
    
    def scan_network(self, target, port, service, auto_brute=False):
        try:
            # Parse target specification
            targets = self.parse_targets(target)
            if not targets:
                self.log("Warning", "No valid targets to scan")
                return []
            
            total_targets = len(targets)
            progress = ProgressManager(total_targets)
            
            scan_results = []
            for target_spec in targets:
                # Handle CIDR ranges
                if '/' in target_spec:
                    scan_results += self.scan_cidr(target_spec, port, service, progress)
                else:
                    scan_results += self.scan_single(target_spec, port, service, progress)
            
            return scan_results
        except Exception as e:
            self.error_handler.handle(e, "Network scanning")
            return []
    
    def parse_targets(self, target):
        """Parse target into list of network specifications"""
        # If it's a file
        if os.path.isfile(target):
            try:
                with open(target, 'r') as f:
                    return [line.strip() for line in f.readlines() if line.strip()]
            except Exception as e:
                self.log("Error", f"Cannot read target file: {str(e)}")
                return []
        
        # If it's a comma-separated list
        if ',' in target:
            return [t.strip() for t in target.split(',') if t.strip()]
        
        # Single target
        return [target]
    
    def scan_cidr(self, cidr, port, service, progress):
        """Scan CIDR range by splitting into /24 subnets"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # For large networks, split into smaller /24 subnets
            if network.prefixlen < 24 and network.num_addresses > 256:
                subnets = list(network.subnets(new_prefix=24))
                self.log("Info", f"Splitting {cidr} into {len(subnets)} /24 subnets")
                
                results = []
                for subnet in subnets:
                    results += self.scan_single(str(subnet), port, service, progress)
                return results
            else:
                return self.scan_single(cidr, port, service, progress)
        except Exception as e:
            self.error_handler.handle(e, f"Scanning CIDR {cidr}")
            return []
    
    def scan_single(self, target, port, service, progress):
        """Scan a single target or subnet"""
        try:
            self.log("Info", f"Scanning: {target}")
            
            # Build Nmap command
            cmd = [self.nmap_path, "-n", "-p", port, "--open", target]
            
            # Service-specific scripts
            if service == "SSH":
                cmd.extend(["--script", "ssh2-enum-algos,ssh-auth-methods"])
            elif service == "RDP":
                cmd.extend(["--script", "rdp-enum-encryption"])
            elif service == "HTTP" or service == "HTTPS":
                cmd.extend(["--script", "http-title"])
            
            # Execute Nmap with timeout
            creation_flags = get_creation_flags()
            timeout = 300 if '/' in target else 120  # Longer timeout for subnets
            
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=timeout,
                    creationflags=creation_flags
                )
                stdout = result.stdout
                stderr = result.stderr
            except subprocess.TimeoutExpired:
                self.log("Warning", f"Scan timeout for {target}")
                return []
            except Exception as e:
                self.log("Error", f"Error executing nmap: {str(e)}")
                return []
            
            if stderr:
                self.log("Warning", f"Nmap stderr: {stderr.strip()}")
            
            return self.parse_nmap_output(stdout, target, service, progress)
        except Exception as e:
            self.error_handler.handle(e, f"Scanning target {target}")
            return []
    
    def parse_nmap_output(self, output, target, service, progress):
        """Parse Nmap output to extract results"""
        if not output:
            self.log("Warning", f"No output from Nmap for {target}")
            return []
            
        blocks = re.split(r"Nmap scan report for ", output)
        results = []
        service_counts = {service: 0}
        
        for block in blocks[1:]:
            lines = block.splitlines()
            if not lines:
                continue
                
            ip_line = lines[0].strip()
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", ip_line)
            if not ip_match:
                continue
                
            ip = ip_match.group(1)
            for line in lines:
                # Find open ports
                m = re.search(r"(\d+)/tcp\s+open", line)
                if m:
                    port_found = m.group(1)
                    results.append((ip, port_found, service))
                    service_counts[service] += 1
        
        # Update progress
        progress.target_completed(target, len(results), service_counts)
        self.log("Info", f"{target}: Found {len(results)} open {service} services")
        
        return results