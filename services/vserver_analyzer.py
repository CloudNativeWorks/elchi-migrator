"""
VServer Analysis Service
========================

This module handles all vserver analysis logic, including:
- CS (Content Switching) vserver analysis
- LB (Load Balancing) vserver analysis  
- Cluster matching and discovery
- Service and ServiceGroup processing
"""

import os
from flask import session
from utils.netscaler_client import NetScalerClient
from utils.cluster_resolver import get_cluster_resolver
from utils.dns_resolver import dns_resolver
from utils.name_utils import clean_name, normalize_name_hcm, get_service_ip_ports








def analyze_cs_vserver(vserver_name, client, cluster_resolver):
    """Analyze CS (Content Switching) vserver"""
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Analyzing CS vserver: {vserver_name}")
    
    # Get vserver details from NetScaler
    details = client.get_vserver_details(vserver_name)
    if not details:
        raise ValueError(f"Could not get details for CS vserver: {vserver_name}")
    
    
    vserver_info = details.get('info', {})
    
    # Base analysis result
    analysis_result = {
        'vserver_name': vserver_name,
        'vserver_type': 'CS',
        'vserver_protocol': vserver_info.get('servicetype', ''),
        'vserver_ip': vserver_info.get('ipv46') or vserver_info.get('ip', ''),
        'vserver_port': vserver_info.get('port', ''),
        'domains': details.get('domains', []),
        'ssl_certificates': details.get('ssl_certificates', []),
        'cs_policies': details.get('policies', []),
        'default_lbvserver': details.get('default_lbvserver', ''),
        'related_vservers': details.get('related_vservers', []),
        'cluster_name': None,
        'clustername_port': None
    }
    
    # Get default LB vserver details if exists
    default_lbvserver_details = {}
    default_lbvserver = details.get('default_lbvserver', '')
    if default_lbvserver:
        try:
            default_details = client.get_vserver_details(default_lbvserver)
            if default_details:
                services = default_details.get('services', [])
                servicegroups = default_details.get('servicegroups', [])
                default_lbvserver_details = {
                    'services': services,
                    'servicegroups': servicegroups,
                    'services_count': len(services),
                    'servicegroups_count': len(servicegroups)
                }
        except Exception as e:
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Error getting default LB details: {e}")
    
    analysis_result['default_lbvserver_details'] = default_lbvserver_details
    
    # Collect target vserver details for each policy
    target_vservers = set()
    target_vserver_details = {}
    all_target_ips = set()  # Use set like routes_old.py
    all_services = []
    all_servicegroups = []
    
    for policy in details.get('policies', []):
        target_lb = policy.get('targetlbvserver', '')
        if target_lb and target_lb != 'N/A':
            target_vservers.add(target_lb)
            
            # Get target vserver details
            try:
                target_details = client.get_vserver_details(target_lb)
                if target_details:
                    services = target_details.get('services', [])
                    servicegroups = target_details.get('servicegroups', [])
                    
                    target_vserver_details[target_lb] = {
                        'services': services,
                        'servicegroups': servicegroups
                    }
                    
                    # Collect IPs for cluster analysis
                    for service in services:
                        service_ip = service.get('ip', '')
                        if service_ip:
                            all_target_ips.add(service_ip)  # Use add() for set
                            all_services.append({'ip': service_ip, 'name': f'target_service_{service_ip}'})
                    
                    for sg in servicegroups:
                        for member in sg.get('members', []):
                            member_ip = member.get('ip', '')
                            if member_ip:
                                all_target_ips.add(member_ip)  # Use add() for set
                        all_servicegroups.append(sg)
                        
            except Exception as e:
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Error getting target vserver {target_lb} details: {e}")
    
    # Run cluster analysis if we have target IPs (exactly like routes_old.py)
    if all_target_ips:
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Found target IPs for cluster analysis: {all_target_ips}")
        
        # Add target vserver services to details for cluster analysis
        all_services = details.get('services', [])  # Start with existing CS services
        all_servicegroups = details.get('servicegroups', [])  # Start with existing CS servicegroups
        
        # Create temporary service entries for target vserver IPs
        for ip in all_target_ips:
            all_services.append({'ip': ip, 'name': f'target_service_{ip}'})
        
        # Update details with all services
        details['services'] = all_services
        details['servicegroups'] = all_servicegroups
        
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Total services before cluster analysis: {len(all_services)}")
        
        # Optimize: Do cluster analysis in batch for all target IPs
        unique_ips = list(all_target_ips)  # Convert set to list for processing
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Running batch cluster analysis for {len(unique_ips)} unique target IPs")
        cluster_matches = []
        
        # Use cluster resolver directly for batch processing
        from utils.cluster_resolver import get_cluster_resolver
        cluster_resolver = get_cluster_resolver(use_cache_only=True)
        
        # Batch process all IPs at once for better performance
        for ip in unique_ips:
            clusters = cluster_resolver.get_clusters_for_ip(ip)
            if clusters:
                cluster_info = clusters[0]  # Take first match
                cluster_matches.append({
                    'ip': ip,
                    'cluster_name': cluster_info['cluster_name'],
                    'node_name': cluster_info.get('node_name', ''),
                    'ips': [ip]  # For compatibility
                })
        
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Found {len(cluster_matches)} cluster matches for CS target IPs")
        analysis_result['cluster_matches'] = cluster_matches
    else:
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print("DEBUG: No target IPs found for cluster analysis")
    
    analysis_result['target_vservers'] = list(target_vservers)
    analysis_result['target_vserver_details'] = target_vserver_details
    
    # Create HCM configuration for CS vserver (like routes_old.py)
    hcm_config = {
        "type": "cs",  # vserver_type.lower() would be 'cs'
        "name": normalize_name_hcm(vserver_name),
        "domains": details.get('domains', []),
        "vs_address": vserver_info.get('ipv46') or vserver_info.get('ip', ''),
        "clustername_port": analysis_result.get('clustername_port'),
        "cluster_name": analysis_result.get('cluster_name'),
        "ip_port": []  # CS doesn't have direct IP ports, but structure should match
    }
    
    analysis_result['hcm_config'] = hcm_config
    
    return analysis_result


def analyze_lb_vserver(vserver_name, client, cluster_resolver):
    """Analyze LB (Load Balancing) vserver"""
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Analyzing LB vserver: {vserver_name}")
    
    # Get vserver details from NetScaler
    details = client.get_vserver_details(vserver_name)
    if not details:
        raise ValueError(f"Could not get details for LB vserver: {vserver_name}")
    
    
    vserver_info = details.get('info', {})
    
    # Get service IP:ports
    services = details.get('services', [])
    servicegroups = details.get('servicegroups', [])
    ip_ports = get_service_ip_ports(services, servicegroups)
    
    # Check cluster matches
    cluster_matches = []
    clustername_port = None
    cluster_name = None
    
    # Pre-extract IPs for batch processing info
    service_ips = [ip_port.split(':')[0] for ip_port in ip_ports]
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Checking {len(service_ips)} IPs for cluster matches")
    
    for ip_port in ip_ports:
        ip = ip_port.split(':')[0]
        clusters = cluster_resolver.get_clusters_for_ip(ip)
        if clusters:
            cluster_info = clusters[0]  # Take first match
            cluster_matches.append({
                'ip_port': ip_port,
                'cluster_name': cluster_info['cluster_name'],
                'node_name': cluster_info.get('node_name', '')
            })
            
            # Set clustername_port for the first match
            if not clustername_port:
                port = ip_port.split(':')[1]
                clustername_port = f"{cluster_info['cluster_name']}_{port}"
    
    # Generate cluster_name if no cluster matches (exactly like routes_old.py)
    if not clustername_port and ip_ports:
        clean_name_for_cluster = clean_name(vserver_name)
        first_port = ip_ports[0].split(':')[1]
        cluster_name = f"{clean_name_for_cluster}_{first_port}"
        # NOTE: Do NOT set clustername_port here - this ensures endpoint_static template is used
    elif cluster_matches:
        # Extract cluster name from first match
        cluster_name = cluster_matches[0]['cluster_name']
    
    if not cluster_name:
        cluster_name = clean_name(vserver_name)
    
    # Create HCM configuration exactly like routes_old.py
    hcm_config = {
        "type": "lb",  # vserver_type.lower() would be 'lb'
        "name": normalize_name_hcm(vserver_name),
        "domains": details.get('domains', []),
        "vs_address": vserver_info.get('ipv46') or vserver_info.get('ip', ''),
        "clustername_port": clustername_port,
        "cluster_name": cluster_name,
        "ip_port": ip_ports
    }
    
    # Build analysis result exactly like routes_old.py
    analysis_result = {
        'vserver_name': vserver_name,
        'vserver_type': 'LB',
        'vserver_ip': vserver_info.get('ipv46') or vserver_info.get('ip', ''),
        'vserver_port': vserver_info.get('port', 'N/A'),
        'vserver_protocol': vserver_info.get('servicetype', 'N/A'),
        'domains': details.get('domains', []),
        'services': services,
        'servicegroups': servicegroups,
        'ip_ports': ip_ports,
        'cluster_matches': cluster_matches,
        'clustername_port': clustername_port,
        'cluster_name': cluster_name,
        'related_vservers': details.get('related_vservers', []),
        'hcm_config': hcm_config
    }
    
    return analysis_result


def analyze_vserver(vserver_type, vserver_name):
    """Main vserver analysis function"""
    try:
        # Check NetScaler session expiry
        from datetime import datetime
        if 'netscaler_expiry' in session:
            try:
                # Use strptime for compatibility with older Python versions
                expiry_time = datetime.strptime(session['netscaler_expiry'], '%Y-%m-%dT%H:%M:%S.%f')
                if datetime.now() >= expiry_time:
                    return {'error': 'NetScaler session expired. Please login again.'}, 401
            except Exception as e:
                print(f"DEBUG: Error parsing NetScaler expiry: {e}")
                pass
        
        # Initialize NetScaler client
        if 'netscaler_host' not in session or 'netscaler_username' not in session:
            return {'error': 'NetScaler credentials not found'}, 401
        
        client = NetScalerClient(
            session['netscaler_host'],
            session['netscaler_username'], 
            session['netscaler_password']
        )
        
        if not client.login():
            return {'error': 'Failed to login to NetScaler'}, 401
        
        # Get cluster resolver
        cluster_resolver = get_cluster_resolver(use_cache_only=True)
        
        try:
            if vserver_type.lower() == 'cs':
                analysis_result = analyze_cs_vserver(vserver_name, client, cluster_resolver)
            elif vserver_type.lower() == 'lb':
                analysis_result = analyze_lb_vserver(vserver_name, client, cluster_resolver)
            else:
                return {'error': f'Unsupported vserver type: {vserver_type}'}, 400
            
            return analysis_result, 200
            
        finally:
            client.logout()
            
    except Exception as e:
        print(f"Error analyzing vserver: {e}")
        import traceback
        traceback.print_exc()
        return {'error': str(e)}, 500