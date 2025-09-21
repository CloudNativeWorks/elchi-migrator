import json
import os
import re

class DNSResolver:
    def __init__(self, dns_zones_dir='config/dns-zones', dns_mapping_file='config/dns_mapping.json'):
        self.dns_zones_dir = dns_zones_dir
        self.dns_mapping_file = dns_mapping_file
        self.dns_mapping = self._load_or_build_dns_mapping()
    
    def _load_or_build_dns_mapping(self):
        """Load DNS mapping from JSON file or build from zone files"""
        # Try to load existing mapping first
        try:
            if os.path.exists(self.dns_mapping_file):
                with open(self.dns_mapping_file, 'r') as f:
                    mapping = json.load(f)
                    if mapping:  # If mapping exists and not empty, use it
                        return mapping
        except Exception as e:
            print(f"Error loading DNS mapping: {e}")
        
        # If no mapping file or empty, build from zone files
        return self._build_dns_mapping_from_zones()
    
    def _build_dns_mapping_from_zones(self):
        """Build DNS mapping by parsing zone files"""
        dns_mapping = {}
        
        if not os.path.exists(self.dns_zones_dir):
            return dns_mapping
        
        try:
            for filename in os.listdir(self.dns_zones_dir):
                # Skip README files
                if filename.lower() == 'readme.md' or filename.lower() == 'readme.txt':
                    continue
                    
                # Accept various DNS zone file extensions
                valid_extensions = ('.zone', '.txt', '.conf')
                if filename.endswith(valid_extensions) or filename.startswith('db-') or '.' not in filename:
                    file_path = os.path.join(self.dns_zones_dir, filename)
                    if os.path.isfile(file_path):
                        self._parse_zone_file(file_path, dns_mapping)
            
            # Save the built mapping
            self._save_dns_mapping(dns_mapping)
            
        except Exception as e:
            print(f"Error building DNS mapping from zones: {e}")
        
        return dns_mapping
    
    def _parse_zone_file(self, file_path, dns_mapping):
        """Parse a single zone file and extract IP to domain mappings"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Extract domain from $ORIGIN directive
            domain = None
            origin_pattern = r'^\$ORIGIN\s+([^\s;]+)'
            
            for line in content.split('\n'):
                match = re.match(origin_pattern, line, re.IGNORECASE)
                if match:
                    domain = match.group(1)
                    # Remove trailing dot if present
                    if domain.endswith('.'):
                        domain = domain[:-1]
                    break
            
            # Fallback to filename if no $ORIGIN found
            if not domain:
                filename = os.path.basename(file_path)
                if filename.startswith('db-'):
                    domain = filename[3:]  # Remove 'db-' prefix
                else:
                    domain = filename
                
                # Remove common DNS zone file extensions from domain name
                for ext in ['.zone', '.txt', '.conf']:
                    if domain.endswith(ext):
                        domain = domain[:-len(ext)]
                        break
            
            # Parse A records: domain_or_subdomain IN A ip_address
            a_record_pattern = r'^([^\s;]+)\s+(?:\d+\s+)?IN\s+A\s+([0-9.]+)'
            
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith(';'):
                    continue
                
                match = re.match(a_record_pattern, line, re.IGNORECASE)
                if match:
                    subdomain, ip = match.groups()
                    
                    # Build full domain name
                    if subdomain == '@' or subdomain == domain:
                        full_domain = domain
                    else:
                        full_domain = f"{subdomain}.{domain}"
                    
                    # Add to mapping
                    if ip not in dns_mapping:
                        dns_mapping[ip] = []
                    if full_domain not in dns_mapping[ip]:
                        dns_mapping[ip].append(full_domain)
                        
        except Exception as e:
            print(f"Error parsing zone file {file_path}: {e}")
    
    def _save_dns_mapping(self, dns_mapping):
        """Save DNS mapping to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.dns_mapping_file), exist_ok=True)
            with open(self.dns_mapping_file, 'w') as f:
                json.dump(dns_mapping, f, indent=2, sort_keys=True)
        except Exception as e:
            print(f"Error saving DNS mapping: {e}")
    
    def get_domains_for_ip(self, ip):
        """Get domain names for an IP address"""
        return self.dns_mapping.get(ip, [])
    
    def has_domains(self, ip):
        """Check if IP has associated domains"""
        return ip in self.dns_mapping and len(self.dns_mapping[ip]) > 0
    
    def get_primary_domain(self, ip):
        """Get the first/primary domain for an IP"""
        domains = self.get_domains_for_ip(ip)
        return domains[0] if domains else None
    
    def reload_mapping(self):
        """Reload DNS mapping from file"""
        self.dns_mapping = self._load_or_build_dns_mapping()
    
    def reload_zones(self):
        """Reload DNS zones from uploaded files"""
        self.dns_mapping = self._build_dns_mapping_from_zones()
    
    def force_rebuild(self):
        """Force rebuild DNS mapping and clear cache"""
        # Remove existing mapping file
        if os.path.exists(self.dns_mapping_file):
            os.remove(self.dns_mapping_file)
        # Rebuild from zones
        self.dns_mapping = self._build_dns_mapping_from_zones()
    
    def load_dns_zones(self):
        """Load DNS zones from files (alias for reload_zones for compatibility)"""
        self.reload_zones()

# Global instance
dns_resolver = DNSResolver()