import requests
import json
import os
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from utils.stats_tracker import VServerStatsTracker
from utils.dns_resolver import dns_resolver
from utils.cluster_resolver import get_cluster_resolver

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NetScalerClient:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.base_url = self._build_base_url(host)
        self.session = requests.Session()
        self.session.verify = False  # Always skip SSL verification
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        self.auth_token = None
        self.stats_tracker = VServerStatsTracker()
    
    def _build_base_url(self, host):
        """Build base URL from user input, handling various formats"""
        # If host already contains protocol, parse it
        if '://' in host:
            parsed = urlparse(host)
            scheme = parsed.scheme
            hostname = parsed.hostname
            port = parsed.port
            
            # Build base URL
            if port:
                base = f"{scheme}://{hostname}:{port}"
            else:
                base = f"{scheme}://{hostname}"
        else:
            # No protocol specified, assume HTTPS (NetScaler default)
            if ':' in host:
                # Has port
                base = f"https://{host}"
            else:
                # No port, just hostname/IP
                base = f"https://{host}"
        
        return f"{base}/nitro/v1"
    
    def login(self):
        """Login to NetScaler and get session token"""
        login_payload = {
            "login": {
                "username": self.username,
                "password": self.password
            }
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/config/login",
                json=login_payload
            )
            response.raise_for_status()
            
            # Get session ID from response
            if 'sessionid' in response.json():
                self.auth_token = response.json()['sessionid']
                self.session.headers.update({
                    'Cookie': f'NITRO_AUTH_TOKEN={self.auth_token}'
                })
            return True
        except Exception as e:
            print(f"Login failed: {e}")
            return False
    
    def logout(self):
        """Logout from NetScaler"""
        try:
            response = self.session.post(
                f"{self.base_url}/config/logout",
                json={"logout": {}}
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Logout failed: {e}")
    
    def get_lb_vservers(self):
        """Get all LB virtual servers"""
        try:
            response = self.session.get(f"{self.base_url}/config/lbvserver")
            response.raise_for_status()
            return response.json().get('lbvserver', [])
        except Exception as e:
            print(f"Failed to get LB vservers: {e}")
            return []
    
    def get_cs_vservers(self):
        """Get all CS virtual servers"""
        try:
            response = self.session.get(f"{self.base_url}/config/csvserver")
            response.raise_for_status()
            return response.json().get('csvserver', [])
        except Exception as e:
            print(f"Failed to get CS vservers: {e}")
            return []
    
    def get_running_config(self):
        """Get running configuration"""
        try:
            response = self.session.get(f"{self.base_url}/config/nsrunningconfig")
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Failed to get running config: {e}")
            return ""
    
    def get_all_vservers(self):
        """Get all virtual servers and filter private IPs"""
        from utils.parser import NetScalerConfigParser
        
        all_vservers = []
        parser = NetScalerConfigParser()
        
        # Get LB vservers
        lb_vservers = self.get_lb_vservers()
        for vserver in lb_vservers:
            # NetScaler API uses 'ipv46' field for IP address
            ip = vserver.get('ipv46', vserver.get('ip', ''))
            if parser.is_private_ip(ip):
                all_vservers.append({
                    'name': vserver.get('name', ''),
                    'type': 'LB',
                    'protocol': vserver.get('servicetype', ''),
                    'ip': ip,
                    'port': vserver.get('port', ''),
                    'state': vserver.get('curstate', ''),
                    'health': vserver.get('health', 'N/A')
                })
        
        # Get CS vservers
        cs_vservers = self.get_cs_vservers()
        for vserver in cs_vservers:
            # NetScaler API uses 'ipv46' field for IP address
            ip = vserver.get('ipv46', vserver.get('ip', ''))
            if parser.is_private_ip(ip):
                all_vservers.append({
                    'name': vserver.get('name', ''),
                    'type': 'CS',
                    'protocol': vserver.get('servicetype', ''),
                    'ip': ip,
                    'port': vserver.get('port', ''),
                    'state': vserver.get('curstate', ''),
                    'health': 'N/A'
                })
        return all_vservers
    
    def get_lb_vservers_filtered(self, from_cache=True):
        """Get only LB virtual servers with private IPs and request stats"""
        if from_cache:
            return self._load_lb_vservers_from_cache()
        
        from utils.parser import NetScalerConfigParser
        
        filtered_vservers = []
        parser = NetScalerConfigParser()
        
        lb_vservers = self.get_lb_vservers()
        for vserver in lb_vservers:
            ip = vserver.get('ipv46', vserver.get('ip', ''))
            if parser.is_private_ip(ip):
                vserver_name = vserver.get('name', '')
                
                # Get cached total stats only (no live API call)
                vserver_stats = self.stats_tracker.stats.get(vserver_name, {})
                total_requests = vserver_stats.get('total_requests', 0)
                
                # Get domains for this IP
                domains = dns_resolver.get_domains_for_ip(ip)
                
                filtered_vservers.append({
                    'name': vserver_name,
                    'type': 'LB',
                    'protocol': vserver.get('servicetype', ''),
                    'ip': ip,
                    'port': vserver.get('port', ''),
                    'state': vserver.get('curstate', ''),
                    'health': vserver.get('health', 'N/A'),
                    'total_requests': total_requests,
                    'domains': domains
                })
        
        # Save to cache when fetching from NetScaler
        self._save_lb_vservers_to_cache(filtered_vservers)
        
        return filtered_vservers
    
    def get_cs_vservers_filtered(self, from_cache=True):
        """Get only CS virtual servers with private IPs and request stats"""
        if from_cache:
            return self._load_cs_vservers_from_cache()
        
        from utils.parser import NetScalerConfigParser
        
        filtered_vservers = []
        parser = NetScalerConfigParser()
        
        cs_vservers = self.get_cs_vservers()
        for vserver in cs_vservers:
            ip = vserver.get('ipv46', vserver.get('ip', ''))
            if parser.is_private_ip(ip):
                vserver_name = vserver.get('name', '')
                
                # Get cached total stats only (no live API call)
                vserver_stats = self.stats_tracker.stats.get(vserver_name, {})
                total_requests = vserver_stats.get('total_requests', 0)
                
                # Get domains for this IP
                domains = dns_resolver.get_domains_for_ip(ip)
                
                filtered_vservers.append({
                    'name': vserver_name,
                    'type': 'CS',
                    'protocol': vserver.get('servicetype', ''),
                    'ip': ip,
                    'port': vserver.get('port', ''),
                    'state': vserver.get('curstate', ''),
                    'health': 'N/A',
                    'total_requests': total_requests,
                    'domains': domains
                })
        
        # Save to cache when fetching from NetScaler
        self._save_cs_vservers_to_cache(filtered_vservers)
        
        return filtered_vservers
    
    def get_vserver_details(self, vserver_name):
        """Get detailed information about a specific virtual server"""
        details = {
            'name': vserver_name,
            'bindings': [],
            'services': [],
            'servicegroups': []
        }
        
        try:
            # Check if it's LB or CS vserver
            vserver_type = None
            vserver_info = None
            
            # Try LB vserver first
            try:
                response = self.session.get(f"{self.base_url}/config/lbvserver/{vserver_name}")
                response.raise_for_status()
                vserver_info = response.json().get('lbvserver', [{}])[0]
                vserver_type = 'LB'
            except:
                pass
            
            # If not LB, try CS vserver
            if not vserver_type:
                try:
                    response = self.session.get(f"{self.base_url}/config/csvserver/{vserver_name}")
                    response.raise_for_status()
                    vserver_info = response.json().get('csvserver', [{}])[0]
                    vserver_type = 'CS'
                except:
                    pass
            
            if vserver_info:
                details['info'] = vserver_info
                details['type'] = vserver_type
                
                # Check for redirect URL in vserver configuration
                redirect_url = vserver_info.get('redirecturl', '') or vserver_info.get('redirect_url', '')
                if redirect_url:
                    details['redirect_url'] = redirect_url
                    print(f"DEBUG: Found redirect URL for {vserver_name}: {redirect_url}")
                
                # For CS vserver, get default LB vserver if exists
                if vserver_type == 'CS':
                    default_lb = vserver_info.get('lbvserver', '')
                    if default_lb:
                        details['default_lbvserver'] = default_lb
                
                # Get SSL certificate binding if it's HTTPS/SSL
                if vserver_info.get('servicetype', '').upper() in ['HTTPS', 'SSL', 'SSL_BRIDGE']:
                    try:
                        ssl_response = self.session.get(f"{self.base_url}/config/sslvserver_sslcertkey_binding/{vserver_name}")
                        ssl_response.raise_for_status()
                        ssl_bindings = ssl_response.json().get('sslvserver_sslcertkey_binding', [])
                        details['ssl_certificates'] = []
                        
                        for ssl_binding in ssl_bindings:
                            cert_name = ssl_binding.get('certkeyname', '')
                            if cert_name:
                                # Get certificate details
                                try:
                                    cert_response = self.session.get(f"{self.base_url}/config/sslcertkey/{cert_name}")
                                    cert_response.raise_for_status()
                                    cert_info = cert_response.json().get('sslcertkey', [{}])[0]
                                    details['ssl_certificates'].append({
                                        'name': cert_name,
                                        'certfile': cert_info.get('cert', ''),
                                        'keyfile': cert_info.get('key', ''),
                                        'expirydate': cert_info.get('daystoexpiration', 'N/A'),
                                        'issuer': cert_info.get('issuer', 'N/A'),
                                        'subject': cert_info.get('subject', 'N/A')
                                    })
                                except:
                                    details['ssl_certificates'].append({
                                        'name': cert_name,
                                        'certfile': 'N/A',
                                        'keyfile': 'N/A',
                                        'expirydate': 'N/A',
                                        'issuer': 'N/A',
                                        'subject': 'N/A'
                                    })
                    except:
                        pass
                
                # Get bindings
                if vserver_type == 'LB':
                    # Get service bindings
                    try:
                        response = self.session.get(f"{self.base_url}/config/lbvserver_service_binding/{vserver_name}")
                        response.raise_for_status()
                        service_bindings = response.json().get('lbvserver_service_binding', [])
                        for binding in service_bindings:
                            service_name = binding.get('servicename', '')
                            if service_name:
                                # Get service details
                                try:
                                    svc_response = self.session.get(f"{self.base_url}/config/service/{service_name}")
                                    svc_response.raise_for_status()
                                    service_info = svc_response.json().get('service', [{}])[0]
                                    details['services'].append({
                                        'name': service_name,
                                        'ip': service_info.get('ipaddress', service_info.get('ip', '')),
                                        'port': service_info.get('port', ''),
                                        'state': service_info.get('svrstate', ''),
                                        'type': service_info.get('servicetype', ''),
                                        'weight': binding.get('weight', '')
                                    })
                                except:
                                    details['services'].append({
                                        'name': service_name,
                                        'ip': 'N/A',
                                        'port': 'N/A',
                                        'state': 'N/A',
                                        'type': 'N/A',
                                        'weight': binding.get('weight', '')
                                    })
                    except:
                        pass
                    
                    # Get servicegroup bindings
                    try:
                        response = self.session.get(f"{self.base_url}/config/lbvserver_servicegroup_binding/{vserver_name}")
                        response.raise_for_status()
                        sg_bindings = response.json().get('lbvserver_servicegroup_binding', [])
                        for binding in sg_bindings:
                            sg_name = binding.get('servicegroupname', '')
                            if sg_name:
                                # Get servicegroup members
                                try:
                                    sg_response = self.session.get(f"{self.base_url}/config/servicegroup_servicegroupmember_binding/{sg_name}")
                                    sg_response.raise_for_status()
                                    members = sg_response.json().get('servicegroup_servicegroupmember_binding', [])
                                    sg_details = {
                                        'name': sg_name,
                                        'members': []
                                    }
                                    for member in members:
                                        sg_details['members'].append({
                                            'name': member.get('servername', ''),
                                            'ip': member.get('ip', ''),
                                            'port': member.get('port', ''),
                                            'state': member.get('svrstate', ''),
                                            'weight': member.get('weight', '')
                                        })
                                    details['servicegroups'].append(sg_details)
                                except:
                                    details['servicegroups'].append({
                                        'name': sg_name,
                                        'members': []
                                    })
                    except:
                        pass
                
                elif vserver_type == 'CS':
                    # Get CS policies and LB vserver bindings
                    try:
                        response = self.session.get(f"{self.base_url}/config/csvserver_lbvserver_binding/{vserver_name}")
                        response.raise_for_status()
                        lb_bindings = response.json().get('csvserver_lbvserver_binding', [])
                        details['bindings'] = lb_bindings
                    except:
                        pass
                    
                    # Get CS policy bindings (rules)
                    try:
                        response = self.session.get(f"{self.base_url}/config/csvserver_cspolicy_binding/{vserver_name}")
                        response.raise_for_status()
                        policy_bindings = response.json().get('csvserver_cspolicy_binding', [])
                        details['policies'] = []
                        
                        for binding in policy_bindings:
                            policy_name = binding.get('policyname', '')
                            if policy_name:
                                # Get policy details
                                try:
                                    policy_response = self.session.get(f"{self.base_url}/config/cspolicy/{policy_name}")
                                    policy_response.raise_for_status()
                                    policy_info = policy_response.json().get('cspolicy', [{}])[0]
                                    details['policies'].append({
                                        'policyname': policy_name,
                                        'rule': policy_info.get('rule', ''),
                                        'targetlbvserver': binding.get('targetlbvserver', ''),
                                        'priority': binding.get('priority', ''),
                                        'bindpoint': binding.get('bindpoint', ''),
                                        'invoke': binding.get('invoke', ''),
                                        'labeltype': binding.get('labeltype', '')
                                    })
                                except:
                                    details['policies'].append({
                                        'policyname': policy_name,
                                        'rule': 'N/A',
                                        'targetlbvserver': binding.get('targetlbvserver', ''),
                                        'priority': binding.get('priority', ''),
                                        'bindpoint': binding.get('bindpoint', ''),
                                        'invoke': binding.get('invoke', ''),
                                        'labeltype': binding.get('labeltype', '')
                                    })
                    except:
                        pass
        
        except Exception as e:
            print(f"Failed to get vserver details: {e}")
        
        # Add cluster information for service IPs
        self._add_cluster_info(details)
        
        # Add domain information for vserver IP
        self._add_domain_info(details)
        
        # Add related vservers (same IP, different protocol/port)
        self._add_related_vservers(details)
        
        return details
    
    def _add_cluster_info(self, details):
        """Add cluster information for service IPs"""
        all_service_ips = set()
        
        # Collect all service IPs
        for service in details.get('services', []):
            ip = service.get('ip', '')
            if ip and ip != 'N/A':
                all_service_ips.add(ip)
        
        # Collect servicegroup member IPs
        for sg in details.get('servicegroups', []):
            for member in sg.get('members', []):
                ip = member.get('ip', '')
                if ip and ip != 'N/A':
                    all_service_ips.add(ip)
        
        # Get cluster information for all service IPs
        if all_service_ips:
            # print(f"DEBUG: Looking up clusters for IPs: {all_service_ips}")
            clusters_info = get_cluster_resolver(use_cache_only=True).get_clusters_for_service_ips(list(all_service_ips))
            # print(f"DEBUG: Cluster lookup result: {clusters_info}")
            if clusters_info:
                # Extract unique cluster names and create cluster matches
                cluster_names = set()
                cluster_matches = []
                
                for ip, clusters in clusters_info.items():
                    for cluster in clusters:
                        cluster_name = cluster['cluster_name']
                        cluster_names.add(cluster_name)
                        
                        # Find or create cluster match entry
                        cluster_match = None
                        for match in cluster_matches:
                            if match['cluster_name'] == cluster_name:
                                cluster_match = match
                                break
                        
                        if not cluster_match:
                            cluster_match = {
                                'cluster_name': cluster_name,
                                'ips': []
                            }
                            cluster_matches.append(cluster_match)
                        
                        # Add IP if not already in the list
                        if ip not in cluster_match['ips']:
                            cluster_match['ips'].append(ip)
                
                details['clusters'] = {
                    'cluster_names': list(cluster_names),
                    'ip_mappings': clusters_info
                }
                details['cluster_matches'] = cluster_matches
                # Debug output only in development
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Created cluster_matches: {cluster_matches}")
    
    def _add_domain_info(self, details):
        """Add domain information for vserver IP"""
        vserver_info = details.get('info', {})
        
        # Get vserver IP address
        vserver_ip = vserver_info.get('ipv46') or vserver_info.get('ip', '')
        
        if vserver_ip:
            # Get domains for this IP
            domains = dns_resolver.get_domains_for_ip(vserver_ip)
            if domains:
                details['domains'] = domains
    
    def _add_related_vservers(self, details):
        """Add related vservers with same IP but different protocol/port"""
        vserver_info = details.get('info', {})
        current_vserver_name = details.get('name', '')
        
        # Get current vserver IP address
        vserver_ip = vserver_info.get('ipv46') or vserver_info.get('ip', '')
        current_protocol = vserver_info.get('servicetype', '')
        current_port = vserver_info.get('port', '')
        
        print(f"DEBUG: _add_related_vservers starting for {current_vserver_name}")
        print(f"DEBUG: Vserver IP: {vserver_ip}")
        
        if not vserver_ip or vserver_ip == '0.0.0.0':
            print(f"DEBUG: No valid IP for {current_vserver_name}, skipping")
            return
        
        related_vservers = []
        
        try:
            # Use cached vservers from JSON files for better performance
            print(f"DEBUG: Loading cached vservers for IP comparison...")
            related_vservers_data = []
            
            # Load from cs_vservers.json
            if os.path.exists('config/cs_vservers.json'):
                with open('config/cs_vservers.json', 'r') as f:
                    cs_vservers = json.load(f)
                    for vs in cs_vservers:
                        if vs.get('ip') == vserver_ip:
                            related_vservers_data.append({
                                'name': vs.get('name'),
                                'servicetype': vs.get('protocol'),
                                'port': vs.get('port'),
                                'curstate': vs.get('state'),
                                'type': 'CS'
                            })
            
            # Load from lb_vservers.json  
            if os.path.exists('config/lb_vservers.json'):
                with open('config/lb_vservers.json', 'r') as f:
                    lb_vservers = json.load(f)
                    for vs in lb_vservers:
                        if vs.get('ip') == vserver_ip:
                            related_vservers_data.append({
                                'name': vs.get('name'),
                                'servicetype': vs.get('protocol'),
                                'port': vs.get('port'),
                                'curstate': vs.get('state'),
                                'type': 'LB'
                            })
            
            print(f"DEBUG: Found {len(related_vservers_data)} vservers with IP {vserver_ip} in cache files")
            
            for vserver in related_vservers_data:
                vs_name = vserver.get('name', '')
                vs_protocol = vserver.get('servicetype', '')  # NetScaler API uses 'servicetype'
                vs_port = vserver.get('port', '')
                vs_type = vserver.get('type', '')  # Will be set by our method
                vs_state = vserver.get('curstate', '')  # NetScaler API uses 'curstate'
                
                print(f"DEBUG: Checking vserver {vs_name} - Protocol: {vs_protocol}, Port: {vs_port}, Type: {vs_type}")
                
                # Skip if it's the same vserver
                if vs_name != current_vserver_name:
                    # Check if it's a meaningful related vserver (different protocol or port)
                    if (vs_protocol != current_protocol or vs_port != current_port):
                        print(f"DEBUG: Adding related vserver: {vs_name}")
                        # Get domains for this IP
                        domains = dns_resolver.get_domains_for_ip(vserver_ip)
                        
                        related_vservers.append({
                            'name': vs_name,
                            'type': vs_type,
                            'protocol': vs_protocol,
                            'port': vs_port,
                            'state': vs_state,
                            'domains': domains or []
                        })
                    else:
                        print(f"DEBUG: Skipping {vs_name} - same protocol/port")
                else:
                    print(f"DEBUG: Skipping {vs_name} - same vserver")
            
            if related_vservers:
                details['related_vservers'] = related_vservers
                print(f"DEBUG: Added {len(related_vservers)} related vservers to details")
            else:
                print(f"DEBUG: No related vservers found for {current_vserver_name}")
                
        except Exception as e:
            print(f"DEBUG: Error finding related vservers: {e}")
            import traceback
            traceback.print_exc()
    
    def _get_vservers_by_ip(self, ip_address):
        """Get all vservers with a specific IP address using NetScaler filter"""
        all_vservers = []
        
        try:
            # Get LB vservers with specific IP
            lb_response = self.session.get(f"{self.base_url}/config/lbvserver", 
                                         params={'filter': f'ipv46:{ip_address}'})
            if lb_response.status_code == 200:
                lb_vservers = lb_response.json().get('lbvserver', [])
                for vserver in lb_vservers:
                    vserver['type'] = 'LB'  # Add type info
                    all_vservers.append(vserver)
            
            # Get CS vservers with specific IP  
            cs_response = self.session.get(f"{self.base_url}/config/csvserver",
                                         params={'filter': f'ipv46:{ip_address}'})
            if cs_response.status_code == 200:
                cs_vservers = cs_response.json().get('csvserver', [])
                for vserver in cs_vservers:
                    vserver['type'] = 'CS'  # Add type info
                    all_vservers.append(vserver)
                    
        except Exception as e:
            print(f"DEBUG: Error in _get_vservers_by_ip: {e}")
        
        return all_vservers
    
    def _get_vserver_requests(self, vserver_name):
        """Get current request count for a virtual server"""
        try:
            # Try LB vserver stats first
            response = self.session.get(f"{self.base_url}/stat/lbvserver/{vserver_name}")
            if response.status_code == 200:
                stats = response.json().get('lbvserver', [{}])[0]
                return int(stats.get('totalrequests', 0))
            
            # Try CS vserver stats
            response = self.session.get(f"{self.base_url}/stat/csvserver/{vserver_name}")
            if response.status_code == 200:
                stats = response.json().get('csvserver', [{}])[0]
                return int(stats.get('totalrequests', 0))
                
        except Exception as e:
            print(f"Failed to get requests for {vserver_name}: {e}")
        
        return 0
    
    def _load_lb_vservers_from_cache(self):
        """Load LB vservers from cached JSON file"""
        try:
            if os.path.exists('config/lb_vservers.json'):
                with open('config/lb_vservers.json', 'r') as f:
                    lb_data = json.load(f)
                
                # Update with latest stats and domains
                for vserver in lb_data:
                    vserver_name = vserver.get('name', '')
                    
                    # Update stats
                    vserver_stats = self.stats_tracker.stats.get(vserver_name, {})
                    vserver['total_requests'] = vserver_stats.get('total_requests', 0)
                    
                    # Update domains
                    ip = vserver.get('ip', '')
                    if ip:
                        vserver['domains'] = dns_resolver.get_domains_for_ip(ip)
                
                return lb_data
        except Exception as e:
            print(f"Error loading LB vservers from cache: {e}")
        
        return []
    
    def _load_cs_vservers_from_cache(self):
        """Load CS vservers from cached JSON file"""
        try:
            if os.path.exists('config/cs_vservers.json'):
                with open('config/cs_vservers.json', 'r') as f:
                    cs_data = json.load(f)
                
                # Update with latest stats and domains
                for vserver in cs_data:
                    vserver_name = vserver.get('name', '')
                    
                    # Update stats
                    vserver_stats = self.stats_tracker.stats.get(vserver_name, {})
                    vserver['total_requests'] = vserver_stats.get('total_requests', 0)
                    
                    # Update domains
                    ip = vserver.get('ip', '')
                    if ip:
                        vserver['domains'] = dns_resolver.get_domains_for_ip(ip)
                
                return cs_data
        except Exception as e:
            print(f"Error loading CS vservers from cache: {e}")
        
        return []
    
    def _save_lb_vservers_to_cache(self, vservers):
        """Save LB vservers to cache file"""
        try:
            os.makedirs('config', exist_ok=True)
            with open('config/lb_vservers.json', 'w') as f:
                json.dump(vservers, f, indent=2)
            print(f"DEBUG: Saved {len(vservers)} LB vservers to cache")
        except Exception as e:
            print(f"Error saving LB vservers to cache: {e}")
    
    def _save_cs_vservers_to_cache(self, vservers):
        """Save CS vservers to cache file"""
        try:
            os.makedirs('config', exist_ok=True)
            with open('config/cs_vservers.json', 'w') as f:
                json.dump(vservers, f, indent=2)
            print(f"DEBUG: Saved {len(vservers)} CS vservers to cache")
        except Exception as e:
            print(f"Error saving CS vservers to cache: {e}")