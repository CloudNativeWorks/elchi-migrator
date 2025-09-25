"""
ELCHI Template Generation Service
================================

This module handles all ELCHI template generation logic, including:
- Endpoint templates
- Cluster templates  
- Listener templates
- Route templates
- Virtual Host templates
- HCM (HTTP Connection Manager) templates
- TCP templates
"""

import base64
import string
import random
import json
import os
import re
from utils.name_utils import clean_name, normalize_name_hcm


# Template configuration by protocol
PROTOCOL_TEMPLATE_MAP = {
    'TCP': {
        'templates': ['endpoint', 'cluster', 'tcp', 'listener'],
        'description': 'TCP protocol templates'
    },
    'HTTP': {
        'templates': ['endpoint', 'cluster', 'vhost', 'route', 'hcm', 'listener'],
        'description': 'HTTP protocol templates'
    },
    'HTTPS': {
        'templates': ['endpoint', 'cluster', 'vhost', 'route', 'hcm', 'listener'],
        'description': 'HTTPS protocol templates'
    },
    'SSL': {
        'templates': ['endpoint', 'cluster', 'vhost', 'route', 'hcm', 'listener'],
        'description': 'SSL protocol templates'
    },
    'SSL_BRIDGE': {
        'templates': ['endpoint', 'cluster', 'vhost', 'route', 'hcm', 'listener'],
        'description': 'SSL Bridge protocol templates'
    }
}


def generate_stdout_access_log_base64(version="v1.35.3"):
    """Generate base64 encoded stdout access log data with specified version"""
    try:
        # Load the stdout access log template
        with open('bodies/stdout_access_log.json', 'r') as f:
            template = f.read()
        
        # Replace version placeholder
        data_json = template.replace('{{version}}', version)
        
        # Convert to base64
        data_bytes = data_json.encode('utf-8')
        base64_data = base64.b64encode(data_bytes).decode('utf-8')
        
        return base64_data
    except Exception as e:
        print(f"Error generating stdout access log: {e}")
        # Fallback to hardcoded config
        config = {
            "@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
            "format": "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" \"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\"\n"
        }
        json_str = json.dumps(config)
        return base64.b64encode(json_str.encode()).decode()


def generate_upstream_tls_context_base64(version="v1.35.3"):
    """Generate base64 encoded upstream TLS context data with specified version"""
    try:
        # Load the upstream TLS context template
        with open('bodies/upstream_tls_context.json', 'r') as f:
            template = f.read()
        
        # Replace version placeholder
        data_json = template.replace('{{version}}', version)
        
        # Convert to base64
        data_bytes = data_json.encode('utf-8')
        base64_data = base64.b64encode(data_bytes).decode('utf-8')
        
        return base64_data
    except Exception as e:
        print(f"Error generating upstream TLS context: {e}")
        # Fallback to hardcoded config
        config = {
            "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
            "sni": "www.example.com"
        }
        json_str = json.dumps(config)
        return base64.b64encode(json_str.encode()).decode()


def generate_random_id(length=6):
    """Generate random alphanumeric ID"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def check_service_ips_in_kubernetes(analysis_result):
    """Check if any service IPs exist in Kubernetes clusters"""
    try:
        from utils.cluster_resolver import get_cluster_resolver
        resolver = get_cluster_resolver(use_cache_only=True)
        
        # Collect all service IPs from analysis result
        all_service_ips = set()
        
        # Get IPs from service details
        for service in analysis_result.get('services', []):
            ip = service.get('ip', '')
            if ip and ip != 'N/A':
                all_service_ips.add(ip)
        
        # Get IPs from servicegroup members
        for sg in analysis_result.get('servicegroups', []):
            for member in sg.get('members', []):
                ip = member.get('ip', '')
                if ip and ip != 'N/A':
                    all_service_ips.add(ip)
        
        # Check if any IP exists in Kubernetes clusters
        for ip in all_service_ips:
            cluster_names = resolver.get_cluster_names_for_ip(ip)
            if cluster_names:
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Found service IP {ip} in Kubernetes cluster(s): {cluster_names}")
                return True
        
        if all_service_ips:
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: No service IPs {list(all_service_ips)} found in Kubernetes - using static endpoint")
        else:
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: No service IPs found - using static endpoint")
        
        return False
        
    except Exception as e:
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Error checking service IPs in Kubernetes: {e}")
        return False


def is_target_vserver_redirect(target_lb, target_vserver_details):
    """Check if target vserver is configured for redirect based on NetScaler configuration"""
    
    # No target vserver = direct redirect policy
    if not target_lb or target_lb == 'N/A':
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: No target LB vserver - direct redirect policy")
        return True, None
    
    # Check target vserver details
    if target_lb in target_vserver_details:
        vserver_details = target_vserver_details[target_lb]
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Checking target vserver '{target_lb}' for redirect configuration")
        
        # Check if vserver has services or service groups
        services = vserver_details.get('services', [])
        service_groups = vserver_details.get('servicegroups', [])  # Fixed typo: servicegroups not service_groups
        
        # Check for redirect URL in vserver configuration
        redirect_url = vserver_details.get('redirect_url', '') or vserver_details.get('redirecturl', '')
        
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Target vserver '{target_lb}' - services: {len(services)}, servicegroups: {len(service_groups)}, redirect_url: {redirect_url}")
        
        # If vserver has redirect URL, it's definitely a redirect vserver
        if redirect_url:
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Target vserver '{target_lb}' has redirect URL '{redirect_url}' - redirect detected")
            return True, redirect_url
        
        # If no services AND no servicegroups, likely redirect vserver
        if not services and not service_groups:
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Target vserver '{target_lb}' has no services/servicegroups - likely redirect")
            return True, None
        
        # Has services or servicegroups, normal backend vserver
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Target vserver '{target_lb}' has services/servicegroups - normal backend")
        return False, None
    else:
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Target vserver '{target_lb}' not found in details - assuming normal backend")
        return False, None


def parse_cs_policy_rule(rule):
    """Parse CS policy rule to extract hostname and path conditions"""
    if not rule or rule == 'N/A':
        return {'domains': [], 'paths': [], 'path_match_type': 'prefix', 'case_sensitive': True}
    
    domains = []
    paths = []
    path_match_type = 'prefix'  # default to prefix
    case_sensitive = True  # default to case sensitive
    
    # Check for IGNORECASE in the rule
    if 'SET_TEXT_MODE(IGNORECASE)' in rule.upper() or 'IGNORECASE' in rule.upper():
        case_sensitive = False
    
    # Extract hostname conditions (HTTP.REQ.HOSTNAME.EQ("example.com"))
    import re
    hostname_patterns = [
        r'HTTP\.REQ\.HOSTNAME\.EQ\(["\']([^"\']+)["\']\)',
        r'HTTP\.REQ\.HOSTNAME\.CONTAINS\(["\']([^"\']+)["\']\)',
        r'HTTP\.REQ\.HOSTNAME\s*==\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in hostname_patterns:
        matches = re.findall(pattern, rule, re.IGNORECASE)
        domains.extend(matches)
    
    # Extract path conditions with type detection
    # STARTSWITH patterns
    startswith_patterns = [
        r'HTTP\.REQ\.URL\.STARTSWITH\(["\']([^"\']+)["\']\)',
        r'HTTP\.REQ\.URL\.SET_TEXT_MODE\([^)]*\)\.STARTSWITH\(["\']([^"\']+)["\']\)',
        r'HTTP\.REQ\.URL\.PATH\.STARTSWITH\(["\']([^"\']+)["\']\)'
    ]
    
    for pattern in startswith_patterns:
        matches = re.findall(pattern, rule, re.IGNORECASE)
        if matches:
            paths.extend(matches)
            path_match_type = 'prefix'
    
    # EXACT match patterns
    exact_patterns = [
        r'HTTP\.REQ\.URL\.PATH\.EQ\(["\']([^"\']+)["\']\)',
        r'HTTP\.REQ\.URL\.EQ\(["\']([^"\']+)["\']\)',
        r'HTTP\.REQ\.URL\s*==\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in exact_patterns:
        matches = re.findall(pattern, rule, re.IGNORECASE)
        if matches:
            paths.extend(matches)
            path_match_type = 'exact'
    
    # CONTAINS patterns
    contains_patterns = [
        r'HTTP\.REQ\.URL\.PATH\.CONTAINS\(["\']([^"\']+)["\']\)',
        r'HTTP\.REQ\.URL\.CONTAINS\(["\']([^"\']+)["\']\)'
    ]
    
    for pattern in contains_patterns:
        matches = re.findall(pattern, rule, re.IGNORECASE)
        if matches:
            paths.extend(matches)
            path_match_type = 'regex'  # Will need to convert to regex
    
    return {'domains': domains, 'paths': paths, 'path_match_type': path_match_type, 'case_sensitive': case_sensitive}


def generate_cs_virtual_hosts_new(analysis_result, template_clustername, template_port, text_replace_from=None, text_replace_to=''):
    """Generate virtual hosts array for CS vserver - New domain-grouped implementation"""
    virtual_hosts = []
    cs_policies = analysis_result.get('cs_policies', [])
    default_lbvserver = analysis_result.get('default_lbvserver', '')
    target_vserver_details = analysis_result.get('target_vserver_details', {})
    vserver_name = analysis_result.get('vserver_name', 'unknown')
    
    # Sort CS policies by priority (NetScaler priority order)
    sorted_cs_policies = sorted(cs_policies, key=lambda p: int(p.get('priority', 999999)))
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Sorted {len(cs_policies)} CS policies by priority")
    
    # Get unique clusters to find correct port for each target
    unique_clusters = get_cs_unique_clusters_and_endpoints(analysis_result, text_replace_from, text_replace_to)
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Available clusters: {list(unique_clusters.keys())}")
    
    # Group policies by domain
    domain_policies = {}
    for policy in sorted_cs_policies:
        rule_info = parse_cs_policy_rule(policy.get('rule', ''))
        
        # Extract domain from rule
        domains = rule_info['domains'] if rule_info['domains'] else ['*']
        for domain in domains:
            if domain not in domain_policies:
                domain_policies[domain] = []
            # Avoid adding the same policy multiple times for the same domain
            if policy not in domain_policies[domain]:
                domain_policies[domain].append(policy)
            else:
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Skipping duplicate policy '{policy.get('policyname', '')}' for domain '{domain}'")
    
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Grouped policies into {len(domain_policies)} domains: {list(domain_policies.keys())}")
    
    # Generate one virtual host per domain
    used_vhost_names = set()
    for domain, policies in domain_policies.items():
        base_name = clean_name(domain, text_replace_from, text_replace_to)
        vhost_name = f"{base_name}_vhost"
        
        # Handle duplicate vhost names (especially for wildcard domains)
        if vhost_name in used_vhost_names:
            counter = 1
            while f"{base_name}_{counter:02d}_vhost" in used_vhost_names:
                counter += 1
            vhost_name = f"{base_name}_{counter:02d}_vhost"
        
        used_vhost_names.add(vhost_name)
        routes = []
        
        # Process each policy in priority order to create routes
        for policy in policies:
            policy_routes = create_routes_for_policy(policy, unique_clusters, target_vserver_details, template_clustername, template_port, text_replace_from, text_replace_to)
            # Add routes but avoid duplicates
            add_routes_without_duplicates(routes, policy_routes)
        
        # Add default route for default LB vserver only for wildcard domains
        # Default LB handles requests that don't match any specific policy
        if default_lbvserver and domain == '*':
            # Find cluster for default LB vserver
            default_cluster_name = None
            for cluster_name, cluster_info in unique_clusters.items():
                if default_lbvserver in cluster_info.get('target_lbs', [cluster_info.get('target_lb', '')]):
                    default_cluster_name = cluster_name
                    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                        print(f"DEBUG: Found default cluster {cluster_name} for default LB {default_lbvserver}")
                    break
            
            # Add default route with lowest priority (at the end)
            if default_cluster_name:
                default_route = {
                    "name": f"default_route_{clean_name(vserver_name, text_replace_from, text_replace_to)}",
                    "match": {"prefix": "/"},
                    "route": {"cluster": default_cluster_name}
                }
                # Use duplicate check for default route too
                add_routes_without_duplicates(routes, [default_route])
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Added default route for wildcard domain -> cluster {default_cluster_name}")

        # Create virtual host for this domain
        virtual_host = {
            "name": vhost_name,
            "domains": [domain],
            "routes": routes
        }
        virtual_hosts.append(virtual_host)
    
    # Ensure default LB vserver has a virtual host if no policies created one
    if default_lbvserver and not any(vhost for vhost in virtual_hosts if '*' in vhost.get('domains', [])):
        # Find cluster for default LB vserver
        default_cluster_name = None
        for cluster_name, cluster_info in unique_clusters.items():
            if default_lbvserver in cluster_info.get('target_lbs', [cluster_info.get('target_lb', '')]):
                default_cluster_name = cluster_name
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Found default cluster {cluster_name} for default LB {default_lbvserver}")
                break
        
        # Create a default virtual host for the default LB vserver
        if default_cluster_name:
            default_vhost = {
                "name": f"{clean_name(vserver_name, text_replace_from, text_replace_to)}_default_vhost",
                "domains": ["*"],
                "routes": [{
                    "name": f"default_route_{clean_name(vserver_name, text_replace_from, text_replace_to)}",
                    "match": {"prefix": "/"},
                    "route": {"cluster": default_cluster_name}
                }]
            }
            virtual_hosts.append(default_vhost)
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Created default virtual host for default LB -> cluster {default_cluster_name}")
    
    return virtual_hosts


def add_routes_without_duplicates(existing_routes, new_routes):
    """Add routes to existing list but avoid duplicates based on match and cluster"""
    for new_route in new_routes:
        # Check if this route already exists
        is_duplicate = False
        new_match = new_route.get('match', {})
        new_cluster = new_route.get('route', {}).get('cluster', '')
        
        for existing_route in existing_routes:
            existing_match = existing_route.get('match', {})
            existing_cluster = existing_route.get('route', {}).get('cluster', '')
            
            # Compare match and cluster
            if new_match == existing_match and new_cluster == existing_cluster:
                is_duplicate = True
                print(f"DEBUG: Skipping duplicate route - match: {new_match}, cluster: {new_cluster}")
                break
        
        if not is_duplicate:
            existing_routes.append(new_route)
            print(f"DEBUG: Added route - match: {new_match}, cluster: {new_cluster}")


def create_routes_for_policy(policy, unique_clusters, target_vserver_details, template_clustername, template_port, text_replace_from=None, text_replace_to=''):
    """Create routes for a single CS policy"""
    routes = []
    policy_name = policy.get('policyname', 'unknown_policy')
    rule = policy.get('rule', '')
    target_lb = policy.get('targetlbvserver', '')
    
    # Parse the policy rule
    rule_info = parse_cs_policy_rule(rule)
    
    # Check if this is a redirect policy
    is_redirect_policy, redirect_url = is_target_vserver_redirect(target_lb, target_vserver_details)
    
    # Find the correct cluster name based on target_lb
    policy_cluster_name = None
    if not is_redirect_policy:
        for cluster_name, cluster_info in unique_clusters.items():
            # Check if this target_lb is in the cluster's target_lbs list
            if target_lb in cluster_info.get('target_lbs', [cluster_info.get('target_lb', '')]):
                policy_cluster_name = cluster_name
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Found cluster {cluster_name} for target {target_lb}")
                break
        
        if not policy_cluster_name:
            policy_cluster_name = f"{template_clustername}_{template_port}"
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Using fallback cluster {policy_cluster_name} for target {target_lb}")
    
    # Create routes based on paths in the rule
    case_sensitive = rule_info.get('case_sensitive', True)
    if rule_info['paths']:
        path_match_type = rule_info.get('path_match_type', 'prefix')
        for path in rule_info['paths']:
            route = create_single_route(policy_name, path, path_match_type, is_redirect_policy, redirect_url, policy_cluster_name, case_sensitive, text_replace_from, text_replace_to)
            routes.append(route)
    else:
        # Default route for root path
        route = create_single_route(policy_name, "/", "prefix", is_redirect_policy, redirect_url, policy_cluster_name, case_sensitive, text_replace_from, text_replace_to)
        routes.append(route)
    
    return routes


def create_single_route(policy_name, path, match_type, is_redirect, redirect_url, cluster_name, case_sensitive=True, text_replace_from=None, text_replace_to=''):
    """Create a single route object"""
    import re
    import urllib.parse
    
    # Create route name
    path_suffix = path.replace('/', '_').replace('*', 'wildcard').replace('.', '_')
    route_name = f"{clean_name(policy_name, text_replace_from, text_replace_to)}_{path_suffix}" if path != "/" else f"{clean_name(policy_name, text_replace_from, text_replace_to)}_default"
    
    # Create match object
    if match_type == 'exact':
        match_obj = {"path": path}
    elif match_type == 'regex':
        match_obj = {"safe_regex": {"regex": f".*{re.escape(path)}.*"}}
    else:  # prefix (default)
        match_obj = {"prefix": path}
    
    # Add case_sensitive setting if false (default is true in Envoy)
    if not case_sensitive:
        match_obj["case_sensitive"] = False
    
    # Create route action
    if is_redirect:
        if redirect_url:
            parsed = urllib.parse.urlparse(redirect_url)
            redirect_config = {"response_code": "MOVED_PERMANENTLY"}
            
            if parsed.scheme:
                redirect_config["scheme_redirect"] = parsed.scheme
            if parsed.netloc:
                redirect_config["host_redirect"] = parsed.netloc
            if parsed.path and parsed.path != "/":
                redirect_config["path_redirect"] = parsed.path
            
            action = {"redirect": redirect_config}
        else:
            action = {"redirect": {"scheme_redirect": "https", "response_code": "MOVED_PERMANENTLY"}}
    else:
        action = {"route": {"cluster": cluster_name}}
    
    return {
        "name": route_name,
        "match": match_obj,
        **action
    }


# Keep the old function as backup and use the new one
def generate_cs_virtual_hosts(analysis_result, template_clustername, template_port, text_replace_from=None, text_replace_to=''):
    """Generate virtual hosts array for CS vserver based on policies"""
    return generate_cs_virtual_hosts_new(analysis_result, template_clustername, template_port, text_replace_from, text_replace_to)


def get_cs_unique_clusters_and_endpoints(analysis_result, text_replace_from=None, text_replace_to=''):
    """Get unique cluster names based on backend IP:port signatures to avoid duplicates"""
    unique_clusters = {}  # signature -> cluster_info
    cs_policies = analysis_result.get('cs_policies', [])
    default_lbvserver = analysis_result.get('default_lbvserver', '')
    target_vserver_details = analysis_result.get('target_vserver_details', {})
    default_lbvserver_details = analysis_result.get('default_lbvserver_details', {})
    cluster_matches = analysis_result.get('cluster_matches', [])
    
    # Sort CS policies by priority
    sorted_cs_policies = sorted(cs_policies, key=lambda p: int(p.get('priority', 999999)))
    
    # Collect all unique backend signatures
    backend_signatures = {}  # signature -> [target_lbs]
    
    # Process each policy's target to collect signatures
    for policy in sorted_cs_policies:
        target_lb = policy.get('targetlbvserver', '')
        if target_lb and target_lb != 'N/A':
            signature = get_backend_signature(target_lb, target_vserver_details)
            if signature:
                if signature not in backend_signatures:
                    backend_signatures[signature] = []
                if target_lb not in backend_signatures[signature]:
                    backend_signatures[signature].append(target_lb)
    
    # Process default LB vserver
    if default_lbvserver:
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Processing default LB vserver: {default_lbvserver}")
            print(f"DEBUG: default_lbvserver_details: {default_lbvserver_details}")
        signature = get_backend_signature(default_lbvserver, default_lbvserver_details)
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Default LB signature: {signature}")
        if signature:
            if signature not in backend_signatures:
                backend_signatures[signature] = []
            if default_lbvserver not in backend_signatures[signature]:
                backend_signatures[signature].append(default_lbvserver)
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Added default LB {default_lbvserver} to signature {signature}")
    
    # Generate unique clusters based on signatures
    for signature, target_lbs in backend_signatures.items():
        # Use first target_lb for generating cluster info
        primary_target = target_lbs[0]
        details_dict = target_vserver_details if primary_target in target_vserver_details else default_lbvserver_details
        
        cluster_info = generate_cluster_info_for_signature(signature, primary_target, details_dict, cluster_matches, text_replace_from, text_replace_to)
        if cluster_info:
            cluster_info['target_lbs'] = target_lbs  # Track all target LBs using this cluster
            unique_clusters[cluster_info['cluster_name']] = cluster_info
    
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Generated {len(unique_clusters)} unique clusters from {len(backend_signatures)} signatures")
    for cluster_name, info in unique_clusters.items():
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Cluster {cluster_name} -> IPs: {info['ips']}, Port: {info['port']}, Targets: {info['target_lbs']}")
    
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: unique_clusters.keys() = {list(unique_clusters.keys())}")
    
    return unique_clusters


def get_backend_signature(target_lb, vserver_details_dict):
    """Generate a unique signature for backend services to identify duplicates"""
    # For regular target LBs, vserver_details_dict is a dict of {lb_name: details}
    # For default LB, vserver_details_dict might be the details directly
    if isinstance(vserver_details_dict, dict) and target_lb in vserver_details_dict:
        details = vserver_details_dict[target_lb]
    elif isinstance(vserver_details_dict, dict) and 'services' in vserver_details_dict:
        # This is default_lbvserver_details passed directly
        details = vserver_details_dict
    else:
        return None
    services = details.get('services', [])
    servicegroups = details.get('servicegroups', [])
    
    # Collect all IP:port combinations and service names
    ip_port_set = set()
    service_names = []
    
    # Process services
    for service in services:
        service_ip = service.get('ip', '')
        service_port = service.get('port', '')
        service_name = service.get('name', '')
        if service_ip and service_port and service_port != 'N/A':
            ip_port_set.add((service_ip, int(service_port)))
            if service_name:
                service_names.append(service_name)
    
    # Process service groups
    for sg in servicegroups:
        sg_name = sg.get('name', 'unknown_sg')
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Processing servicegroup '{sg_name}' with {len(sg.get('members', []))} members")
        for member in sg.get('members', []):
            member_ip = member.get('ip', '')
            member_port = member.get('port', '')
            member_name = member.get('name', '')
            print(f"DEBUG: ServiceGroup member: ip={member_ip}, port={member_port}, name='{member_name}', full_member={member}")
            if member_ip and member_port and member_port != 'N/A':
                ip_port_set.add((member_ip, int(member_port)))
                if member_name and member_name != member_ip:
                    # Use member name if it's not an IP address
                    service_names.append(member_name)
                else:
                    # If no member name or member name is IP, use servicegroup name
                    print(f"DEBUG: Member name is IP '{member_name}', using servicegroup name '{sg_name}'")
                    service_names.append(sg_name)
    
    if not ip_port_set:
        return None
    
    # Create a signature that includes both IP:port and service names info
    # Sort everything for consistent hashing
    sorted_ip_ports = tuple(sorted(ip_port_set))
    sorted_service_names = tuple(sorted(service_names))
    
    # Create hashable signature as tuple
    signature = (sorted_ip_ports, sorted_service_names)
    return signature


def check_service_states_for_ips(target_vserver_details, target_ips, target_lb):
    """Check if any service for the given IPs has UP state"""
    if isinstance(target_vserver_details, dict) and target_lb in target_vserver_details:
        details = target_vserver_details[target_lb]
    elif isinstance(target_vserver_details, dict) and 'services' in target_vserver_details:
        details = target_vserver_details
    else:
        return True  # Default to True if no details available
    
    services = details.get('services', [])
    servicegroups = details.get('servicegroups', [])
    
    # Check services
    for service in services:
        service_ip = service.get('ip', '')
        service_state = service.get('state', '').upper()
        if service_ip in target_ips and service_state == 'UP':
            return True
    
    # Check servicegroup members  
    for sg in servicegroups:
        for member in sg.get('members', []):
            member_ip = member.get('ip', '')
            member_state = member.get('state', '').upper()
            if member_ip in target_ips and member_state == 'UP':
                return True
    
    return False


def get_ip_state_map(target_vserver_details, target_lb):
    """Create a map of IP addresses to their states"""
    ip_state_map = {}
    
    if isinstance(target_vserver_details, dict) and target_lb in target_vserver_details:
        details = target_vserver_details[target_lb]
    elif isinstance(target_vserver_details, dict) and 'services' in target_vserver_details:
        details = target_vserver_details
    else:
        return ip_state_map
    
    services = details.get('services', [])
    servicegroups = details.get('servicegroups', [])
    
    # Map services IP states
    for service in services:
        service_ip = service.get('ip', '')
        service_state = service.get('state', '').upper()
        if service_ip:
            ip_state_map[service_ip] = service_state
            print(f"DEBUG: Service IP {service_ip} has state {service_state}")
    
    # Map servicegroup member states
    for sg in servicegroups:
        for member in sg.get('members', []):
            member_ip = member.get('ip', '')
            member_state = member.get('state', '').upper()
            if member_ip:
                ip_state_map[member_ip] = member_state
                print(f"DEBUG: ServiceGroup member IP {member_ip} has state {member_state}")
    
    return ip_state_map


def check_ip_has_up_state(cluster_info, target_ip):
    """Check if a specific IP has UP state in services"""
    # Use IP state map if available
    ip_state_map = cluster_info.get('ip_state_map', {})
    
    if target_ip in ip_state_map:
        state = ip_state_map.get(target_ip, 'UNKNOWN')
        return state == 'UP'
    
    # Fallback to general UP state
    return cluster_info.get('has_up_services', True)


def generate_cluster_info_for_signature(signature, target_lb, target_vserver_details, cluster_matches=None, text_replace_from=None, text_replace_to=''):
    """Generate cluster information based on backend signature"""
    if not signature:
        return None
    
    # Extract IPs, ports and service names from signature tuple
    ip_ports, service_names = signature
    
    all_ips = {ip for ip, port in ip_ports}
    ports = {port for ip, port in ip_ports}
    
    # Check service states for UP/DOWN filtering
    has_up_services = check_service_states_for_ips(target_vserver_details, all_ips, target_lb)
    
    # Get IP state map for individual IP state checks
    ip_state_map = get_ip_state_map(target_vserver_details, target_lb)
    
    # Generate hash for uniqueness (sorted for consistency)
    import hashlib
    signature_str = str(signature)  # Already contains sorted tuples
    signature_hash = hashlib.md5(signature_str.encode()).hexdigest()[:8]
    
    # Find common prefix from service names
    raw_common_name = find_common_service_prefix(service_names)
    common_name = clean_name(raw_common_name, text_replace_from, text_replace_to) if raw_common_name else None
    
    # Check if this is a Kubernetes cluster using cluster_matches data
    is_k8s_cluster = False
    k8s_cluster_name = None
    
    if cluster_matches:
        # Check if any of our IPs are in Kubernetes clusters
        for ip in all_ips:
            for cluster_match in cluster_matches:
                cluster_name_match = cluster_match.get('cluster_name', '')
                cluster_ips = cluster_match.get('ips', [])
                
                if ip in cluster_ips and cluster_name_match:
                    is_k8s_cluster = True
                    k8s_cluster_name = cluster_name_match
                    print(f"DEBUG: Found IP {ip} in Kubernetes cluster '{cluster_name_match}'")
                    break
            if is_k8s_cluster:
                break
    
    # Generate cluster name based on content and k8s detection
    if is_k8s_cluster and k8s_cluster_name:
        # For Kubernetes clusters, use simple <clustername>_<port> format without hash or backend prefix
        primary_port = sorted(ports)[0] if ports else 80
        clean_k8s_name = clean_name(k8s_cluster_name, text_replace_from, text_replace_to)
        cluster_name = f"{clean_k8s_name}_{primary_port}"
        print(f"DEBUG: Detected K8s cluster, using simplified naming: '{cluster_name}'")
    elif len(ip_ports) == 1:
        # Single IP:port
        ip, port = ip_ports[0]
        if common_name:
            cluster_name = f"backend_{common_name}_{port}"
        else:
            cluster_name = f"backend_{ip.replace('.', '_')}_{port}"
    else:
        # Multiple IP:port combinations
        if common_name:
            # Use common service name prefix
            if len(ports) == 1:
                port = list(ports)[0]
                cluster_name = f"backend_{common_name}_{port}_{signature_hash}"
            else:
                primary_port = sorted(ports)[0]
                cluster_name = f"backend_{common_name}_{primary_port}_{signature_hash}"
        else:
            # No common service names, use backend + hash
            cluster_name = f"backend_{signature_hash}"
    
    print(f"DEBUG: generate_cluster_info_for_signature generated cluster_name: '{cluster_name}' for target_lb: '{target_lb}', is_k8s: {is_k8s_cluster}")
    
    # Use the most common port
    most_common_port = sorted(ports)[0] if ports else 80
    
    return {
        'cluster_name': cluster_name,
        'ips': list(all_ips),
        'target_lb': target_lb,  # Primary target LB
        'port': most_common_port,
        'ip_port_combinations': list(ip_ports),
        'signature': signature,
        'service_names': list(service_names),
        'common_name': common_name,
        'has_up_services': has_up_services,  # Track if any services are UP
        'ip_state_map': ip_state_map  # Map of IP -> state for individual checks
    }


def find_common_service_prefix(service_names):
    """Find common prefix from service names"""
    if not service_names:
        return None
    
    if len(service_names) == 1:
        # Single service, use cleaned name
        single_service = service_names[0].rstrip('-')  # Only remove trailing dashes, keep underscores
        print(f"DEBUG: find_common_service_prefix - single service: '{service_names[0]}' -> '{single_service}'")
        return single_service
    
    # Find longest common prefix
    import os
    common_prefix = os.path.commonprefix(service_names)
    
    # Clean and validate prefix
    if len(common_prefix) >= 3:  # Minimum meaningful prefix length
        # Remove trailing separators and clean
        common_prefix = common_prefix.rstrip('-').rstrip('0123456789').rstrip('-')  # Only remove dashes, keep underscores
        print(f"DEBUG: find_common_service_prefix - common_prefix after cleaning: '{common_prefix}'")
        if len(common_prefix) >= 3:
            return common_prefix  # clean_name function doesn't exist, return directly
    
    # If no meaningful common prefix, try first service name without numbers
    first_service = service_names[0]
    # Remove numbers and clean
    import re
    clean_first = re.sub(r'-?\d+$', '', first_service)  # Remove trailing numbers
    # Also remove any trailing dashes only, keep underscores
    clean_first = clean_first.rstrip('-')
    print(f"DEBUG: find_common_service_prefix - first_service: '{first_service}' -> clean_first: '{clean_first}'")
    if len(clean_first) >= 3:
        return clean_first  # clean_name function doesn't exist, return directly
    
    return None


def generate_cluster_info_for_target(target_lb, target_vserver_details, text_replace_from=None, text_replace_to=''):
    """Generate cluster information for a target LB vserver with IP:port based naming"""
    if target_lb not in target_vserver_details:
        return None
    
    details = target_vserver_details[target_lb]
    services = details.get('services', [])
    servicegroups = details.get('servicegroups', [])
    
    # Collect all IP:port combinations
    ip_port_combinations = set()
    
    # Process services
    for service in services:
        service_ip = service.get('ip', '')
        service_port = service.get('port', '')
        if service_ip and service_port and service_port != 'N/A':
            ip_port_combinations.add((service_ip, int(service_port)))
    
    # Process service groups
    for sg in servicegroups:
        for member in sg.get('members', []):
            member_ip = member.get('ip', '')
            member_port = member.get('port', '')
            if member_ip and member_port and member_port != 'N/A':
                ip_port_combinations.add((member_ip, int(member_port)))
    
    if not ip_port_combinations:
        return None
    
    # Collect all IPs and ports first
    all_ips = {ip for ip, port in ip_port_combinations}
    ports = {port for ip, port in ip_port_combinations}
    
    # Determine cluster naming strategy
    if len(ip_port_combinations) == 1:
        # Single IP:port - use IP-based naming
        ip, port = list(ip_port_combinations)[0]
        cluster_name = f"{clean_name(target_lb, text_replace_from, text_replace_to)}_{ip.replace('.', '_')}_{port}"
    else:
        # Multiple IP:port combinations
        # Check if all have same port
        if len(ports) == 1:
            # Same port for all IPs - use LB name with port
            port = list(ports)[0]
            cluster_name = f"{clean_name(target_lb, text_replace_from, text_replace_to)}_{port}"
        else:
            # Different ports - this is complex, use LB name with first port as fallback
            port = sorted(ports)[0]
            cluster_name = f"{clean_name(target_lb, text_replace_from, text_replace_to)}_{port}"
    
    # Use the most common port or first port
    most_common_port = sorted(ports)[0] if ports else 80
    
    return {
        'cluster_name': cluster_name,
        'ips': list(all_ips),  # Convert set to list for JSON serialization
        'target_lb': target_lb,
        'port': most_common_port,
        'ip_port_combinations': list(ip_port_combinations)  # Convert set to list
    }


def generate_listener_ids(vserver_name, text_replace_from=None, text_replace_to=''):
    """Generate listener, filter chain, and filter IDs based on vserver name"""
    base_name = clean_name(vserver_name, text_replace_from, text_replace_to)
    
    # Generate random components
    listener_suffix = generate_random_id(6)
    fc_suffix = generate_random_id(6) 
    filter_suffix = generate_random_id(6)
    
    # Build hierarchical IDs
    listener_id = f"{base_name}{listener_suffix}"
    filter_chain_id = f"{listener_id}-fc{fc_suffix}"
    filter_id = f"{filter_chain_id}-filter{filter_suffix}"
    
    return {
        'listener': listener_id,
        'filter_chain': filter_chain_id,
        'filter': filter_id
    }


def generate_hcm_filter_config_base64(filter_name, version="v1.35.3"):
    """Generate base64 encoded HCM filter config data"""
    try:
        with open('bodies/hcm_filter_config.json', 'r') as f:
            template = f.read()
        
        data_json = template.replace('{{filter_name}}', filter_name).replace('{{version}}', version)
        return base64.b64encode(data_json.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"Error generating HCM filter config: {e}")
        fallback = {"name": filter_name, "type": "network_filter", "version": version}
        return base64.b64encode(json.dumps(fallback).encode('utf-8')).decode('utf-8')


def generate_tcp_filter_config_base64(filter_name, version="v1.35.3"):
    """Generate base64 encoded TCP filter config data"""
    try:
        with open('bodies/tcp_filter_config.json', 'r') as f:
            template = f.read()
        
        data_json = template.replace('{{filter_name}}', filter_name).replace('{{version}}', version)
        return base64.b64encode(data_json.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"Error generating TCP filter config: {e}")
        fallback = {"name": filter_name, "type": "network_filter", "version": version}
        return base64.b64encode(json.dumps(fallback).encode('utf-8')).decode('utf-8')


def generate_downstream_tls_config_base64(version="v1.35.3", tls_context=None):
    """Generate base64 encoded downstream TLS config data"""
    try:
        if tls_context:
            # Use selected TLS context from ELCHI API
            return base64.b64encode(json.dumps(tls_context).encode('utf-8')).decode('utf-8')
        else:
            # Use default template
            with open('bodies/downstream_tls_config.json', 'r') as f:
                template = f.read()
            
            data_json = template.replace('{{version}}', version)
            return base64.b64encode(data_json.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"Error generating downstream TLS config: {e}")
        fallback = {"name": "downstream-tls-context", "type": "tls", "version": version}
        return base64.b64encode(json.dumps(fallback).encode('utf-8')).decode('utf-8')


def generate_listeners_array(vserver_name, vserver_port, vserver_protocol, listener_type, version, tls_context=None, hcm_name=None, tcp_name=None, text_replace_from=None, text_replace_to=''):
    """Generate listeners array based on protocol and listener type"""
    listeners = []
    
    # Generate HCM name if not provided
    if not hcm_name:
        hcm_name = clean_name(vserver_name, text_replace_from, text_replace_to) + '_hcm'
        
    # Generate TCP name if not provided
    if not tcp_name:
        tcp_name = clean_name(vserver_name, text_replace_from, text_replace_to) + '_tcp'
    
    # Determine ports and filters based on vserver protocol and listener options
    if vserver_protocol.upper() == 'TCP':
        # TCP protocol: single listener with TCP filter
        ids = generate_listener_ids(vserver_name, text_replace_from, text_replace_to)
        
        listener = {
            "name": ids['listener'],
            "address": {
                "socket_address": {
                    "protocol": "TCP",
                    "address": "0.0.0.0",
                    "port_value": int(vserver_port) if vserver_port != 'N/A' else 8080
                }
            },
            "filter_chains": [{
                "filters": [{
                    "name": ids['filter'],
                    "typed_config": {
                        "type_url": "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
                        "value": generate_tcp_filter_config_base64(tcp_name, version)
                    }
                }],
                "name": ids['filter_chain']
            }],
            "transparent": True
        }
        listeners.append(listener)
        
    else:
        # HTTP/HTTPS protocols: determine listeners based on listener_type
        http_port = int(vserver_port) if vserver_port != 'N/A' else 80
        https_port = 443
        
        # Auto mode: use vserver port for appropriate protocol
        if listener_type == 'auto':
            if vserver_protocol.upper() in ['HTTPS', 'SSL', 'SSL_BRIDGE']:
                listener_type = 'https'
                https_port = http_port
            else:
                listener_type = 'http'
        
        # Generate HTTP listener
        if listener_type in ['http', 'both']:
            port = http_port if listener_type == 'http' else 80
            ids = generate_listener_ids(vserver_name, text_replace_from, text_replace_to)
            
            listener = {
                "name": ids['listener'],
                "address": {
                    "socket_address": {
                        "protocol": "TCP",
                        "address": "0.0.0.0",
                        "port_value": port
                    }
                },
                "filter_chains": [{
                    "filters": [{
                        "name": ids['filter'],
                        "typed_config": {
                            "type_url": "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                            "value": generate_hcm_filter_config_base64(hcm_name, version)
                        }
                    }],
                    "name": ids['filter_chain']
                }],
                "transparent": True
            }
            listeners.append(listener)
        
        # Generate HTTPS listener
        if listener_type in ['https', 'both']:
            port = https_port if listener_type == 'https' else 443
            ids = generate_listener_ids(vserver_name, text_replace_from, text_replace_to)
            
            listener = {
                "name": ids['listener'],
                "address": {
                    "socket_address": {
                        "protocol": "TCP",
                        "address": "0.0.0.0",
                        "port_value": port
                    }
                },
                "filter_chains": [{
                    "filters": [{
                        "name": ids['filter'],
                        "typed_config": {
                            "type_url": "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                            "value": generate_hcm_filter_config_base64(hcm_name, version)
                        }
                    }],
                    "transport_socket": {
                        "name": "envoy.transport_sockets.tls",
                        "typed_config": {
                            "type_url": "envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                            "value": generate_downstream_tls_config_base64(version, tls_context)
                        }
                    },
                    "name": ids['filter_chain']
                }],
                "transparent": True
            }
            listeners.append(listener)
    
    return listeners






def generate_elchi_templates(analysis_result, options):
    """Generate ELCHI templates based on analysis result and options"""
    try:
        from flask import session
        import os
        
        vserver_name = analysis_result.get('vserver_name', '')
        vserver_type = analysis_result.get('vserver_type', 'LB')
        vserver_protocol = analysis_result.get('vserver_protocol', 'HTTP')
        vserver_port = analysis_result.get('vserver_port', '80')
        vserver_ip = analysis_result.get('vserver_ip', '')
        
        # Extract options
        version = options.get('version', 'v1.35.3')
        cluster_ssl = options.get('cluster_ssl', False)
        listener_type = options.get('listener_type', 'auto')
        address_type = options.get('address_type', 'InternalIP')
        text_replace_from = options.get('text_replace_from', '').strip()
        text_replace_to = options.get('text_replace_to', '')
        tls_context = options.get('tls_context')
        
        # Check if this is a CS vserver
        is_cs_vserver = vserver_type.upper() == 'CS'
        
        # Determine which templates to generate based on protocol
        protocol_config = PROTOCOL_TEMPLATE_MAP.get(vserver_protocol.upper(), PROTOCOL_TEMPLATE_MAP['HTTP'])
        templates_to_generate = protocol_config['templates']
        
        # Check if service IPs exist in Kubernetes clusters to determine endpoint template
        has_cluster_match = check_service_ips_in_kubernetes(analysis_result)
        
        # Template file paths - use CS-specific templates for CS vservers
        template_files = {
            'cluster': 'bodies/cluster.j2',
            'vhost': 'bodies/cs_virtual_host.j2' if is_cs_vserver else 'bodies/virtual_host.j2',
            'route': 'bodies/route.j2',
            'hcm': 'bodies/hcm.j2',
            'tcp': 'bodies/tcp.j2',
            'listener': 'bodies/listener.j2',
            'endpoint': 'bodies/endpoint.j2' if has_cluster_match else 'bodies/endpoint_static.j2'
        }
        
        # Load only required templates
        loaded_templates = {}
        
        # For CS vservers, we'll generate endpoint and cluster as additional templates
        # Keep them in templates_to_generate for tracking but skip loading standard templates
        
        for template_name in templates_to_generate:
            # Skip loading endpoint and cluster templates for CS vservers (will be generated as additional)
            if is_cs_vserver and template_name in ['endpoint', 'cluster']:
                continue
                
            try:
                template_path = template_files[template_name]
                with open(template_path, 'r') as f:
                    loaded_templates[template_name] = f.read()
            except Exception as e:
                return {'error': f'Failed to load {template_name} template: {e}'}, 500
        
        # Get hcm_config from analysis result (exactly like routes_old.py)
        hcm_config = analysis_result['hcm_config']
        
        # Determine what to use for template filling (exactly like routes_old.py)
        template_name = ""
        template_clustername = ""
        template_port = None
        
        if hcm_config['clustername_port']:
            # Use clustername_port
            template_name = hcm_config['clustername_port']
            template_clustername = hcm_config['clustername_port'].rsplit('_', 1)[0]
            template_port = int(hcm_config['clustername_port'].rsplit('_', 1)[1])
        elif hcm_config['cluster_name']:
            # Use cluster_name
            template_name = hcm_config['cluster_name']
            template_clustername = hcm_config['cluster_name'].rsplit('_', 1)[0]
            template_port = int(hcm_config['cluster_name'].rsplit('_', 1)[1])
        else:
            # Use vserver name
            template_name = clean_name(vserver_name, text_replace_from, text_replace_to)
            template_clustername = clean_name(vserver_name, text_replace_from, text_replace_to)
            template_port = int(hcm_config['ip_port'][0].split(':')[1]) if hcm_config['ip_port'] else 80
        
        # Get project from session  
        project = session.get('elchi_project', 'default-project')
        
        # Generate names with clean_name function
        vhost_name = clean_name(vserver_name, text_replace_from, text_replace_to) + '_vhost'
        route_name = clean_name(vserver_name, text_replace_from, text_replace_to) + '_route'
        hcm_name = clean_name(vserver_name, text_replace_from, text_replace_to) + '_hcm'
        tcp_name = clean_name(vserver_name, text_replace_from, text_replace_to) + '_tcp'
        listener_name = clean_name(vserver_name, text_replace_from, text_replace_to)
        
        # Generate SSL transport socket if enabled
        ssl_transport_socket = ""
        if cluster_ssl:
            ssl_transport_socket = f',\n            "transport_socket": {{\n                "name": "envoy.transport_sockets.tls",\n                "typed_config": {{\n                    "type_url": "envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",\n                    "value": "{generate_upstream_tls_context_base64(version)}"\n                }}\n            }}'
        
        # Template variables
        template_vars = {
            'clustername_port': template_name,
            'project': project,
            'vhost_name': vhost_name,
            'route_name': route_name,
            'hcm_name': hcm_name,
            'tcp_name': tcp_name,
            'listener_name': listener_name,
            'cluster_name': template_name,
            'route_config_name': route_name,
            'stat_prefix': clean_name(vserver_name, text_replace_from, text_replace_to),
            'version': version,
            'address_type': address_type,
            'stdout_access_log_base64': generate_stdout_access_log_base64(version),
            'ssl_transport_socket': ssl_transport_socket
        }
        
        # Fill templates dynamically
        filled_templates = {}
        for template_name_key in templates_to_generate:
            # Skip endpoint and cluster for CS (will be generated as additional)
            if is_cs_vserver and template_name_key in ['endpoint', 'cluster']:
                continue
                
            template_content = loaded_templates.get(template_name_key)
            if not template_content:
                continue
                
            # Apply variable replacements
            for var_name, var_value in template_vars.items():
                template_content = template_content.replace(f'{{{{{var_name}}}}}', str(var_value))
            
            filled_templates[template_name_key] = template_content
        
        # Special handling for endpoint template (only for non-CS vservers)
        if 'endpoint' in filled_templates and not is_cs_vserver:
            if has_cluster_match:
                # Dynamic discovery template - need K8s cluster name for elchi_discovery
                k8s_cluster_name = template_clustername  # fallback to service name
                
                # Find the actual K8s cluster name from service IPs
                service_ips = [ip_port.split(':')[0] for ip_port in hcm_config.get('ip_port', [])]
                if service_ips:
                    try:
                        from utils.cluster_resolver import get_cluster_resolver
                        resolver = get_cluster_resolver(use_cache_only=True)
                        
                        # Find the first IP that has a cluster match
                        for ip in service_ips:
                            cluster_names = resolver.get_cluster_names_for_ip(ip)
                            if cluster_names:
                                k8s_cluster_name = cluster_names[0]  # Use first cluster name
                                print(f"DEBUG: Found K8s cluster '{k8s_cluster_name}' for service IP {ip}")
                                break
                    except Exception as e:
                        print(f"DEBUG: Could not resolve K8s cluster for IPs {service_ips}: {e}")
                
                # Replace clustername with K8s cluster name and port
                filled_templates['endpoint'] = filled_templates['endpoint'].replace('{{clustername}}', k8s_cluster_name)
                filled_templates['endpoint'] = filled_templates['endpoint'].replace('{{port}}', str(template_port))
            else:
                # Static endpoint template - generate IP:port endpoints JSON
                ip_ports = hcm_config.get('ip_port', [])
                endpoints_json_parts = []
                
                for ip_port in ip_ports:
                    ip, port = ip_port.split(':')
                    endpoint_json = {
                        "endpoint": {
                            "address": {
                                "socket_address": {
                                    "protocol": "TCP",
                                    "address": ip,
                                    "port_value": int(port)
                                }
                            }
                        }
                    }
                    # Format with proper indentation for template
                    endpoint_str = json.dumps(endpoint_json, indent=4)
                    # Add proper indentation to match template structure (24 spaces)
                    indented_endpoint = '\n'.join('                        ' + line if line.strip() else line 
                                                 for line in endpoint_str.split('\n'))
                    endpoints_json_parts.append(indented_endpoint.strip())
                
                # Join with commas and newlines
                ip_port_endpoints = ',\n                        '.join(endpoints_json_parts)
                filled_templates['endpoint'] = filled_templates['endpoint'].replace('{{ip_port_endpoints}}', ip_port_endpoints)
        
        # Special handling for CS virtual_host template
        if 'vhost' in filled_templates and is_cs_vserver:
            # Generate virtual hosts array for CS vserver
            virtual_hosts_array = generate_cs_virtual_hosts(analysis_result, template_clustername, template_port, text_replace_from, text_replace_to)
            print(f"DEBUG: Generated {len(virtual_hosts_array)} virtual hosts for CS vserver")
            
            if not virtual_hosts_array:
                print("WARNING: No virtual hosts generated for CS vserver - this will cause JSON error")
                # Create a default virtual host to prevent empty array
                virtual_hosts_array = [{
                    "name": f"{clean_name(analysis_result.get('vserver_name', 'default'), text_replace_from, text_replace_to)}_default",
                    "domains": ["*"],
                    "routes": [{
                        "name": "default_route",
                        "match": {"prefix": "/"},
                        "route": {"cluster": template_name}
                    }]
                }]
            
            # Convert virtual hosts array to JSON string WITHOUT the outer array brackets
            # Because the template already has [ ... ] around {{virtual_hosts_array}}
            if virtual_hosts_array:
                # Convert each virtual host object to JSON separately
                vhost_json_parts = []
                for vhost in virtual_hosts_array:
                    vhost_json = json.dumps(vhost, indent=12)
                    # Add proper indentation
                    indented = '\n'.join('            ' + line if line.strip() else line 
                                       for line in vhost_json.split('\n'))
                    vhost_json_parts.append(indented.strip())
                
                # Join with commas (no array brackets)
                virtual_hosts_content = ',\n            '.join(vhost_json_parts)
            else:
                virtual_hosts_content = ""
            
            print(f"DEBUG: Virtual hosts content to be inserted (first 500 chars):\n{virtual_hosts_content[:500]}")
            filled_templates['vhost'] = filled_templates['vhost'].replace('{{virtual_hosts_array}}', virtual_hosts_content)
            
            # Validate final VHOST template JSON
            try:
                parsed_vhost = json.loads(filled_templates['vhost'])
                print("DEBUG: VHOST template JSON is valid")
                print(f"DEBUG: VHOST template has keys: {list(parsed_vhost.keys())}")
                if 'resource' in parsed_vhost and 'resource' in parsed_vhost['resource']:
                    print(f"DEBUG: VHOST template has {len(parsed_vhost['resource']['resource'])} virtual hosts")
            except Exception as e:
                print(f"ERROR: VHOST template JSON is invalid: {e}")
                print(f"First 500 chars of VHOST template:\n{filled_templates['vhost'][:500]}")

        # Special handling for listener template
        if 'listener' in filled_templates:
            # Extract vserver port (exactly like routes_old.py)
            vserver_port = template_port if template_port else (int(hcm_config['ip_port'][0].split(':')[1]) if hcm_config['ip_port'] else 80)
            
            # Generate listeners array based on vserver protocol and listener type
            listeners_array = generate_listeners_array(vserver_name, vserver_port, vserver_protocol, listener_type, version, tls_context, hcm_name, tcp_name, text_replace_from, text_replace_to)
            
            # Convert listeners array to JSON string and replace in template
            listeners_json = json.dumps(listeners_array, indent=4)
            filled_templates['listener'] = filled_templates['listener'].replace('{{listeners_array}}', listeners_json)
        
        # Build response exactly like routes_old.py
        response = {
            'template_type': 'dynamic' if has_cluster_match else 'static',
            'protocol': vserver_protocol,
            'vserver_type': vserver_type,
            'templates_generated': templates_to_generate,
            'options': {
                'version': version,
                'cluster_ssl': cluster_ssl,
                'listener_type': listener_type,
                'address_type': address_type,
                'text_replace_from': text_replace_from,
                'text_replace_to': text_replace_to,
                'tls_context': tls_context.get('name') if tls_context else None
            },
            'template_values': {
                'clustername_port': template_name,
                'clustername': template_clustername,
                'port': template_port,
                'vhost_name': vhost_name,
                'route_name': route_name,
                'hcm_name': hcm_name,
                'tcp_name': tcp_name,
                'has_cluster_match': has_cluster_match
            }
        }
        
        # For CS vservers, generate multiple cluster and endpoint templates
        if is_cs_vserver:
            unique_clusters = get_cs_unique_clusters_and_endpoints(analysis_result, text_replace_from, text_replace_to)
            print(f"DEBUG: CS Unique clusters found: {list(unique_clusters.keys())}")
            response['cs_unique_clusters'] = unique_clusters
            response['cs_policies'] = analysis_result.get('cs_policies', [])
            response['default_lbvserver'] = analysis_result.get('default_lbvserver', '')
            
            # Generate additional cluster and endpoint templates for each unique cluster
            additional_templates = {}
            
            # Load cluster and endpoint templates for CS
            try:
                with open('bodies/cluster.j2', 'r') as f:
                    cluster_template_base = f.read()
            except Exception as e:
                print(f"Error loading cluster template: {e}")
                cluster_template_base = None
                
            for cluster_name_with_port, cluster_info in unique_clusters.items():
                cluster_port = cluster_info.get('port', template_port or 80)
                cluster_ips = cluster_info.get('ips', [])
                
                # cluster_name_with_port already includes the port (e.g., "api_vserver_5050")
                # Extract the base name for comparison
                cluster_base_name = cluster_name_with_port.rsplit('_', 1)[0] if '_' in cluster_name_with_port else cluster_name_with_port
                
                print(f"DEBUG: Processing CS cluster: {cluster_name_with_port}")
                print(f"DEBUG: cluster_info = {cluster_info}")
                print(f"DEBUG: Will create template key: cluster_template_{cluster_name_with_port}")
                
                # Generate cluster template for this target
                if cluster_template_base:
                    cluster_template_vars = template_vars.copy()
                    cluster_template_vars['cluster_name'] = cluster_name_with_port
                    cluster_template_vars['clustername_port'] = cluster_name_with_port
                    print(f"DEBUG: Generating cluster template with name: {cluster_name_with_port}")
                    
                    cluster_template_content = cluster_template_base
                    for var_name, var_value in cluster_template_vars.items():
                        cluster_template_content = cluster_template_content.replace(f'{{{{{var_name}}}}}', str(var_value))
                    
                    # Use full name with port for template key to ensure uniqueness
                    additional_templates[f'cluster_template_{cluster_name_with_port}'] = cluster_template_content
                
                # Generate endpoint template for this target
                endpoint_template_vars = template_vars.copy()
                endpoint_template_vars['clustername_port'] = cluster_name_with_port
                endpoint_template_vars['port'] = cluster_port
                
                # For elchi_discovery, we need the actual Kubernetes cluster name, not the service name
                # Find the K8s cluster name from the service IPs
                k8s_cluster_name = cluster_base_name  # fallback to service name
                if cluster_ips:
                    # Get cluster resolver to find K8s cluster from IPs
                    try:
                        from utils.cluster_resolver import get_cluster_resolver
                        resolver = get_cluster_resolver(use_cache_only=True)
                        
                        # Find the first IP that has a cluster match
                        for ip in cluster_ips:
                            cluster_names = resolver.get_cluster_names_for_ip(ip)
                            if cluster_names:
                                k8s_cluster_name = cluster_names[0]  # Use first cluster name
                                print(f"DEBUG: Found K8s cluster '{k8s_cluster_name}' for service IP {ip}")
                                break
                    except Exception as e:
                        print(f"DEBUG: Could not resolve K8s cluster for IPs {cluster_ips}: {e}")
                
                endpoint_template_vars['clustername'] = k8s_cluster_name
                
                # Separate Kubernetes and non-Kubernetes IPs
                k8s_ips = set()
                non_k8s_ips = set()
                
                if cluster_ips:
                    try:
                        from utils.cluster_resolver import get_cluster_resolver
                        resolver = get_cluster_resolver(use_cache_only=True)
                        
                        # Check each IP individually
                        for ip in cluster_ips:
                            cluster_names = resolver.get_cluster_names_for_ip(ip)
                            if cluster_names:
                                k8s_ips.add(ip)
                                print(f"DEBUG: IP {ip} found in Kubernetes cluster")
                            else:
                                non_k8s_ips.add(ip)
                                print(f"DEBUG: IP {ip} NOT found in Kubernetes, adding to non-K8s set")
                    except Exception as e:
                        print(f"DEBUG: Error checking K8s for cluster '{cluster_name_with_port}': {e}")
                        # If error, add all IPs as non-K8s (assume UP state)
                        non_k8s_ips = cluster_ips
                
                # Determine template type based on what we have
                has_k8s_ips = len(k8s_ips) > 0
                has_non_k8s_ips = len(non_k8s_ips) > 0
                
                if has_k8s_ips and has_non_k8s_ips:
                    endpoint_template_file = 'bodies/endpoint_hybrid.j2'
                    print(f"DEBUG: Using hybrid endpoint - K8s IPs: {k8s_ips}, Non-K8s IPs: {non_k8s_ips}")
                elif has_k8s_ips:
                    endpoint_template_file = 'bodies/endpoint.j2'
                    print(f"DEBUG: Using dynamic endpoint - K8s IPs: {k8s_ips}")
                else:
                    endpoint_template_file = 'bodies/endpoint_static.j2'
                    print(f"DEBUG: Using static endpoint - Non-K8s IPs: {non_k8s_ips}")
                    
                cluster_has_k8s_match = has_k8s_ips
                
                try:
                    with open(endpoint_template_file, 'r') as f:
                        endpoint_template_content = f.read()
                    
                    # Apply variable replacements
                    for var_name, var_value in endpoint_template_vars.items():
                        endpoint_template_content = endpoint_template_content.replace(f'{{{{{var_name}}}}}', str(var_value))
                    
                    # Handle different endpoint template types
                    if endpoint_template_file == 'bodies/endpoint_hybrid.j2':
                        # Hybrid template: both elchi_discovery and static endpoints
                        # Generate elchi_discovery array
                        if has_k8s_ips:
                            elchi_discovery = [{
                                "cluster_name": k8s_cluster_name,
                                "protocol": "TCP", 
                                "port": cluster_port,
                                "address_type": "ipv4",
                                "roles": ["worker"]
                            }]
                        else:
                            elchi_discovery = []
                            
                        elchi_discovery_json = json.dumps(elchi_discovery, indent=8)
                        endpoint_template_content = endpoint_template_content.replace('{{elchi_discovery_array}}', elchi_discovery_json)
                        
                        # Generate static endpoints array for non-K8s IPs only
                        # Filter by UP state only in hybrid mode
                        if has_non_k8s_ips:
                            # Filter non-K8s IPs by UP state for hybrid endpoint
                            up_non_k8s_ips = []
                            for ip in non_k8s_ips:
                                if check_ip_has_up_state(cluster_info, ip):
                                    up_non_k8s_ips.append(ip)
                                    print(f"DEBUG: Non-K8s IP {ip} has UP state, adding to hybrid static endpoints")
                                else:
                                    print(f"DEBUG: Non-K8s IP {ip} has DOWN state, skipping in hybrid endpoint")
                            
                            ip_ports = [f"{ip}:{cluster_port}" for ip in up_non_k8s_ips]
                            endpoints_json_parts = []
                            
                            for ip_port in ip_ports:
                                ip, port = ip_port.split(':')
                                endpoint_json = {
                                    "endpoint": {
                                        "address": {
                                            "socket_address": {
                                                "protocol": "TCP",
                                                "address": ip,
                                                "port_value": int(port)
                                            }
                                        }
                                    }
                                }
                                endpoint_str = json.dumps(endpoint_json, indent=4)
                                indented_endpoint = '\n'.join('                        ' + line if line.strip() else line 
                                                             for line in endpoint_str.split('\n'))
                                endpoints_json_parts.append(indented_endpoint.strip())
                            
                            static_endpoints = ',\n                        '.join(endpoints_json_parts)
                        else:
                            static_endpoints = ""
                            
                        endpoint_template_content = endpoint_template_content.replace('{{static_endpoints_array}}', static_endpoints)
                        
                    elif not cluster_has_k8s_match and cluster_ips:
                        # Pure static endpoint template
                        ip_ports = [f"{ip}:{cluster_port}" for ip in cluster_ips]
                        endpoints_json_parts = []
                        
                        for ip_port in ip_ports:
                            ip, port = ip_port.split(':')
                            endpoint_json = {
                                "endpoint": {
                                    "address": {
                                        "socket_address": {
                                            "protocol": "TCP",
                                            "address": ip,
                                            "port_value": int(port)
                                        }
                                    }
                                }
                            }
                            endpoint_str = json.dumps(endpoint_json, indent=4)
                            indented_endpoint = '\n'.join('                        ' + line if line.strip() else line 
                                                         for line in endpoint_str.split('\n'))
                            endpoints_json_parts.append(indented_endpoint.strip())
                        
                        ip_port_endpoints = ',\n                        '.join(endpoints_json_parts)
                        endpoint_template_content = endpoint_template_content.replace('{{ip_port_endpoints}}', ip_port_endpoints)
                    
                    # Use full name with port for template key to ensure uniqueness
                    additional_templates[f'endpoint_template_{cluster_name_with_port}'] = endpoint_template_content
                    
                except Exception as e:
                    print(f"Error generating endpoint template for {cluster_name_with_port}: {e}")
            
            # Add additional templates to response
            response.update(additional_templates)
        
        # Add templates with proper naming (exactly like routes_old.py)
        template_key_mapping = {
            'endpoint': 'endpoint_template',
            'cluster': 'cluster_template',
            'vhost': 'vhost_template',
            'route': 'route_template',
            'hcm': 'hcm_template',
            'tcp': 'tcp_template',
            'listener': 'listener_template'
        }
        
        for template_name_key, template_content in filled_templates.items():
            response_key = template_key_mapping.get(template_name_key, f'{template_name_key}_template')
            response[response_key] = template_content
        
        return response, 200
        
    except Exception as e:
        print(f"Error generating templates: {e}")
        import traceback
        traceback.print_exc()
        return {'error': str(e)}, 500


# These functions are no longer needed since we use template files directly
# Template generation is now handled by the main function using Jinja2 template files