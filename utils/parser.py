import json
import re
import ipaddress
import os

class NetScalerConfigParser:
    def __init__(self):
        self.virtual_servers = []
        self.ip_filter_config = self._load_ip_filter_config()
    
    def _load_ip_filter_config(self):
        """Load IP filtering configuration from JSON file"""
        try:
            from app.routes import get_settings_file
            config_path = get_settings_file()
        except ImportError:
            config_path = 'config/settings.json'
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                # Return default config if file doesn't exist
                return {
                    "filters": {
                        "exclude_ips": ["0.0.0.0"],
                        "exclude_ip_ranges": ["10.70.", "192.168.10.", "192.168.211"],
                        "include_private_only": True,
                        "custom_rules": {"exclude_patterns": []}
                    }
                }
        except Exception as e:
            print(f"Error loading IP filter config: {e}")
            # Return default config on error
            return {
                "filters": {
                    "exclude_ips": ["0.0.0.0"],
                    "exclude_ip_ranges": ["10.70.", "192.168.10.", "192.168.211"],
                    "include_private_only": True,
                    "custom_rules": {"exclude_patterns": []}
                }
            }
    
    def is_private_ip(self, ip):
        """Check if IP should be included based on filter configuration"""
        try:
            filters = self.ip_filter_config.get("filters", {})
            
            # Check exclude_ips
            exclude_ips = filters.get("exclude_ips", [])
            if ip in exclude_ips:
                return False
            
            # Check exclude_ip_ranges
            exclude_ranges = filters.get("exclude_ip_ranges", [])
            for range_prefix in exclude_ranges:
                if ip.startswith(range_prefix):
                    return False
            
            # Check custom exclude patterns
            custom_rules = filters.get("custom_rules", {})
            exclude_patterns = custom_rules.get("exclude_patterns", [])
            for pattern in exclude_patterns:
                if re.match(pattern, ip):
                    return False
            
            # Check IP filter type
            ip_filter_type = filters.get("ip_filter_type", "private")
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_filter_type == "private":
                return ip_obj.is_private
            elif ip_filter_type == "public":
                return not ip_obj.is_private
            else:  # "all"
                return True
                
        except Exception as e:
            print(f"Error checking IP {ip}: {e}")
            return False
    
    def parse_config(self, config_text):
        """Parse NetScaler config and extract virtual servers"""
        self.virtual_servers = []
        
        # Parse lb vserver configurations
        lb_vserver_pattern = r'add\s+lb\s+vserver\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)'
        cs_vserver_pattern = r'add\s+cs\s+vserver\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)'
        
        # Parse LB virtual servers
        for match in re.finditer(lb_vserver_pattern, config_text):
            name, protocol, ip, port = match.groups()
            if self.is_private_ip(ip):
                vserver = {
                    'name': name,
                    'type': 'LB',
                    'protocol': protocol,
                    'ip': ip,
                    'port': port,
                    'services': [],
                    'policies': []
                }
                self.virtual_servers.append(vserver)
        
        # Parse CS virtual servers
        for match in re.finditer(cs_vserver_pattern, config_text):
            name, protocol, ip, port = match.groups()
            if self.is_private_ip(ip):
                vserver = {
                    'name': name,
                    'type': 'CS',
                    'protocol': protocol,
                    'ip': ip,
                    'port': port,
                    'services': [],
                    'policies': []
                }
                self.virtual_servers.append(vserver)
        
        # Parse service bindings
        service_binding_pattern = r'bind\s+(?:lb|cs)\s+vserver\s+(\S+)\s+(\S+)'
        for match in re.finditer(service_binding_pattern, config_text):
            vserver_name, service_name = match.groups()
            for vserver in self.virtual_servers:
                if vserver['name'] == vserver_name:
                    vserver['services'].append(service_name)
        
        # Parse policy bindings
        policy_binding_pattern = r'bind\s+(?:lb|cs)\s+vserver\s+(\S+)\s+-policyName\s+(\S+)'
        for match in re.finditer(policy_binding_pattern, config_text):
            vserver_name, policy_name = match.groups()
            for vserver in self.virtual_servers:
                if vserver['name'] == vserver_name:
                    vserver['policies'].append(policy_name)
        
        return self.virtual_servers
    
    def to_json(self):
        """Convert parsed data to JSON"""
        return json.dumps(self.virtual_servers, indent=2)