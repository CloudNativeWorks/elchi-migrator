"""
Flask Routes - Refactored Version
=================================

This module contains only the Flask routing logic.
All business logic has been moved to separate service modules:
- services/vserver_analyzer.py: VServer analysis logic
- services/template_generator.py: ELCHI template generation  
- services/elchi_service.py: ELCHI integration
- services/vserver_service.py: VServer listing and basic operations
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, send_from_directory

# Import service modules
from services.vserver_analyzer import analyze_vserver
from services.template_generator import generate_elchi_templates
from services.elchi_service import (
    elchi_login, elchi_logout, get_elchi_status, 
    get_elchi_clusters, get_tls_contexts, 
    send_templates_to_elchi, check_domain_in_dns
)
from services.vserver_service import (
    get_all_vservers, get_vserver_completion_suggestions,
    netscaler_login, netscaler_logout, get_netscaler_status
)

# Import utilities
from utils.dns_resolver import dns_resolver
import json
import os


def get_settings_file():
    """Get settings file based on LOCAL environment variable"""
    try:
        # Check if LOCAL=true in environment
        local_mode = os.environ.get('LOCAL', '').lower() == 'true'
        
        if local_mode:
            local_settings_file = 'config/settings_local.json'
            # Check if local settings file exists
            if os.path.exists(local_settings_file):
                return local_settings_file
            else:
                print(f"DEBUG: Local settings file {local_settings_file} not found, falling back to default")
                return 'config/settings.json'
        else:
            return 'config/settings.json'
    except Exception as e:
        print(f"DEBUG: Error reading LOCAL environment variable: {e}, using default settings")
        return 'config/settings.json'


def auto_mark_vserver_completed(vserver_type, vserver_name):
    """Auto-mark vserver as completed when successfully sent to ELCHI"""
    completion_file = 'config/vserver_completion.json'
    
    try:
        # Ensure config directory exists
        os.makedirs('config', exist_ok=True)
        
        # Load existing completion data
        completion_data = {'completed': {}}
        if os.path.exists(completion_file):
            try:
                with open(completion_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        completion_data = json.loads(content)
            except json.JSONDecodeError:
                # File is corrupted, start fresh
                completion_data = {'completed': {}}
        
        # Mark as completed
        key = f"{vserver_type}_{vserver_name}"
        completion_data['completed'][key] = True
        
        # Save to file
        with open(completion_file, 'w') as f:
            json.dump(completion_data, f, indent=2, sort_keys=True)
        
        print(f"DEBUG: Successfully auto-marked {key} as completed")
        
    except Exception as e:
        print(f"ERROR: Failed to auto-mark {vserver_type}_{vserver_name} as completed: {e}")

main = Blueprint('main', __name__)


# =============================================================================
# MAIN PAGES
# =============================================================================

@main.route('/')
def index():
    return render_template('index.html')


@main.route('/vservers')
def vservers():
    return render_template('vservers.html')


@main.route('/vserver/<vserver_name>')
def vserver_detail(vserver_name):
    """Display virtual server details"""
    return render_template('vserver_detail.html', vserver_name=vserver_name)


@main.route('/vserver-analysis/<vserver_type>/<vserver_name>')
def vserver_analysis_page(vserver_type, vserver_name):
    return render_template('vserver_detail.html', 
                         vserver_name=vserver_name, 
                         vserver_type=vserver_type)


@main.route('/settings')
def settings():
    return render_template('settings.html')


# =============================================================================
# AUTHENTICATION ROUTES
# =============================================================================

@main.route('/api/netscaler/login', methods=['POST'])
def api_netscaler_login():
    data = request.get_json()
    host = data.get('host', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not all([host, username, password]):
        return jsonify({'success': False, 'message': 'Missing credentials'}), 400
    
    result = netscaler_login(host, username, password)
    return jsonify(result)


@main.route('/api/netscaler/logout', methods=['POST'])
def api_netscaler_logout():
    result = netscaler_logout()
    return jsonify(result)


@main.route('/api/netscaler/status')
def api_netscaler_status():
    return jsonify(get_netscaler_status())


@main.route('/api/elchi/login', methods=['POST'])
def api_elchi_login():
    data = request.get_json()
    host = data.get('host', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not all([host, username, password]):
        return jsonify({'success': False, 'message': 'Missing credentials'}), 400
    
    result = elchi_login(host, username, password)
    return jsonify(result)


@main.route('/api/elchi/logout', methods=['POST'])
def api_elchi_logout():
    result = elchi_logout()
    return jsonify(result)


@main.route('/api/elchi/status')
def api_elchi_status():
    # Get version from request args, default to v1.35.3
    version = request.args.get('version', 'v1.35.3')
    return jsonify(get_elchi_status(version))


@main.route('/api/elchi/clusters')
def api_elchi_clusters():
    result, status_code = get_elchi_clusters()
    return jsonify(result), status_code


@main.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    return redirect(url_for('main.index'))


# =============================================================================
# VSERVER ROUTES
# =============================================================================

@main.route('/api/vservers')
def api_vservers():
    # Support both nocache (old) and from_cache (new) parameters for compatibility
    nocache = request.args.get('nocache', 'false').lower() == 'true'
    from_cache = request.args.get('from_cache', 'true').lower() == 'true'
    
    # If nocache is specified, use it (inverted logic)
    if 'nocache' in request.args:
        from_cache = not nocache
    
    result, status_code = get_all_vservers(from_cache=from_cache)
    return jsonify(result), status_code


@main.route('/api/vserver-completion', methods=['GET', 'POST'])
def api_vserver_completion():
    """Handle VServer completion status"""
    completion_file = 'config/vserver_completion.json'
    
    if request.method == 'GET':
        # Load completion status
        try:
            # Ensure config directory exists
            os.makedirs('config', exist_ok=True)
            
            if os.path.exists(completion_file):
                with open(completion_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        completion_data = json.loads(content)
                    else:
                        completion_data = {'completed': {}}
            else:
                completion_data = {'completed': {}}
            
            return jsonify(completion_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        # Save completion status
        try:
            data = request.get_json()
            vserver_name = data.get('vserver')
            vserver_type = data.get('type')
            completed = data.get('completed', True)
            
            if not all([vserver_name, vserver_type]):
                return jsonify({'error': 'Missing vserver name or type'}), 400
            
            # Ensure config directory exists
            os.makedirs('config', exist_ok=True)
            
            # Load existing completion data
            completion_data = {'completed': {}}
            if os.path.exists(completion_file):
                try:
                    with open(completion_file, 'r') as f:
                        content = f.read().strip()
                        if content:
                            completion_data = json.loads(content)
                except json.JSONDecodeError:
                    # File is corrupted, start fresh
                    completion_data = {'completed': {}}
            
            # Update completion status
            key = f"{vserver_type}_{vserver_name}"
            if completed:
                completion_data['completed'][key] = True
            else:
                completion_data['completed'].pop(key, None)
            
            # Save to file
            with open(completion_file, 'w') as f:
                json.dump(completion_data, f, indent=2, sort_keys=True)
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500


@main.route('/api/analyze-vserver/<vserver_type>/<vserver_name>')
def api_analyze_vserver(vserver_type, vserver_name):
    result, status_code = analyze_vserver(vserver_type, vserver_name)
    return jsonify(result), status_code


# =============================================================================
# TEMPLATE GENERATION ROUTES
# =============================================================================

@main.route('/api/generate-elchi-templates/<vserver_type>/<vserver_name>', methods=['GET', 'POST'])
def api_generate_elchi_templates(vserver_type, vserver_name):
    try:
        # Get analysis data first
        analysis_result, analysis_status = analyze_vserver(vserver_type, vserver_name)
        if analysis_status != 200:
            return jsonify(analysis_result), analysis_status
        
        # Get generation options (POST) or use defaults (GET)
        options = {}
        if request.method == 'POST':
            options = request.get_json() or {}
        
        # Generate templates
        result, status_code = generate_elchi_templates(analysis_result, options)
        return jsonify(result), status_code
        
    except Exception as e:
        print(f"Error in template generation route: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/get-tls-contexts')
def api_get_tls_contexts():
    version = request.args.get('version', 'v1.35.3')
    result, status_code = get_tls_contexts(version)
    return jsonify(result), status_code


@main.route('/api/send-templates-to-elchi', methods=['POST'])
def api_send_templates_to_elchi():
    print(f"DEBUG: /api/send-templates-to-elchi called")
    print(f"DEBUG: Session in route: {list(session.keys())}")
    print(f"DEBUG: Session ID: {id(session)}")
    
    data = request.get_json()
    templates = data.get('templates', {})
    version = data.get('version', 'v1.35.3')
    ignore_duplicate = data.get('ignore_duplicate', False)
    
    print(f"DEBUG: ignore_duplicate = {ignore_duplicate}")
    
    result, status_code = send_templates_to_elchi(templates, version, ignore_duplicate)
    
    # Auto-mark as completed if ELCHI submission was successful
    if status_code == 200 and result.get('success'):
        try:
            # Extract vserver info from request data
            vserver_name = data.get('vserver_name')
            vserver_type = data.get('vserver_type')
            
            if vserver_name and vserver_type:
                # Check if any template was successfully sent
                results = result.get('results', {})
                has_successful_template = any(
                    template_result.get('success', False) 
                    for template_result in results.values()
                )
                
                if has_successful_template:
                    print(f"DEBUG: Auto-marking {vserver_type}_{vserver_name} as completed")
                    auto_mark_vserver_completed(vserver_type, vserver_name)
                
        except Exception as e:
            print(f"DEBUG: Error auto-marking completion: {e}")
            # Don't fail the main request if auto-completion fails
    
    return jsonify(result), status_code


# =============================================================================
# DNS ROUTES
# =============================================================================

@main.route('/api/dns-check', methods=['POST'])
def api_check_domain_in_dns():
    data = request.get_json()
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Domain parameter required'}), 400
    
    result, status_code = check_domain_in_dns(domain)
    return jsonify(result), status_code


@main.route('/api/dns-files')
def api_get_dns_files():
    try:
        dns_files = []
        zones_dir = 'config/dns-zones'  # Fix directory name (dns-zones not dns_zones)
        
        if os.path.exists(zones_dir):
            for filename in os.listdir(zones_dir):
                # Skip README files
                if filename.lower() == 'readme.md' or filename.lower() == 'readme.txt':
                    continue
                    
                if filename.endswith('.txt') or filename.endswith('.zone'):  # Support both .txt and .zone files
                    file_path = os.path.join(zones_dir, filename)
                    file_stats = os.stat(file_path)
                    
                    dns_files.append({
                        'filename': filename,
                        'size': file_stats.st_size,
                        'modified': file_stats.st_mtime
                    })
        
        return jsonify({'files': dns_files})
        
    except Exception as e:
        print(f"Error getting DNS files: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/dns-files', methods=['POST'])
def api_upload_dns_files():
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        uploaded_files = []
        
        # Create zones directory
        zones_dir = 'config/dns-zones'  # Fix directory name
        os.makedirs(zones_dir, exist_ok=True)
        
        for file in files:
            if file.filename and (file.filename.endswith('.txt') or file.filename.endswith('.zone')):  # Accept both .txt and .zone files
                filename = file.filename
                file_path = os.path.join(zones_dir, filename)
                file.save(file_path)
                uploaded_files.append(filename)
        
        if uploaded_files:
            # Rebuild DNS mapping
            dns_resolver.load_dns_zones()
            
        return jsonify({
            'success': True, 
            'uploaded_files': uploaded_files,
            'message': f'Successfully uploaded {len(uploaded_files)} DNS zone files'
        })
        
    except Exception as e:
        print(f"Error uploading DNS files: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/dns-files/<filename>', methods=['DELETE'])
def api_delete_dns_file(filename):
    try:
        zones_dir = 'config/dns-zones'  # Fix directory name
        file_path = os.path.join(zones_dir, filename)
        
        if os.path.exists(file_path) and (filename.endswith('.txt') or filename.endswith('.zone')):  # Accept both extensions
            os.remove(file_path)
            
            # Rebuild DNS mapping
            dns_resolver.load_dns_zones()
            
            return jsonify({'success': True, 'message': f'Successfully deleted {filename}'})
        else:
            return jsonify({'error': 'File not found'}), 404
            
    except Exception as e:
        print(f"Error deleting DNS file: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/dns-rebuild', methods=['POST'])
def api_rebuild_dns_mapping():
    try:
        dns_resolver.load_dns_zones()
        total_mappings = sum(len(domains) for domains in dns_resolver.dns_mapping.values())
        
        return jsonify({
            'success': True,
            'message': f'DNS mapping rebuilt successfully. Total mappings: {total_mappings}'
        })
        
    except Exception as e:
        print(f"Error rebuilding DNS mapping: {e}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# KUBERNETES CLUSTERS ROUTES  
# =============================================================================

@main.route('/api/clusters/status')
def api_clusters_status():
    """Get the status of cached kubernetes clusters"""
    try:
        cache_file = 'config/clusters.json'
        
        if os.path.exists(cache_file):
            # Get file stats
            file_stat = os.stat(cache_file)
            
            # Load clusters to get counts
            with open(cache_file, 'r') as f:
                content = f.read().strip()
                if content:
                    clusters = json.loads(content)
                    
                    # Count IPs
                    ip_count = 0
                    for cluster in clusters:
                        nodes = cluster.get('nodes', [])
                        for node in nodes:
                            if node.get('addresses', {}).get('InternalIP'):
                                ip_count += 1
                    
                    return jsonify({
                        'has_cache': True,
                        'cluster_count': len(clusters),
                        'ip_count': ip_count,
                        'last_modified': file_stat.st_mtime,
                        'file_size': file_stat.st_size
                    })
                else:
                    return jsonify({
                        'has_cache': False,
                        'cluster_count': 0,
                        'ip_count': 0
                    })
        else:
            return jsonify({
                'has_cache': False,
                'cluster_count': 0,
                'ip_count': 0
            })
            
    except Exception as e:
        print(f"Error getting cluster status: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/clusters/sync', methods=['POST'])
def api_sync_clusters():
    """Sync clusters from ELCHI API and save to cache"""
    try:
        # Check if ELCHI session exists
        if 'elchi_token' not in session:
            return jsonify({'error': 'ELCHI session not found. Please login to ELCHI first.'}), 401
            
        # Initialize ELCHI client with session
        from elchi.elchi_client import ElchiClient
        
        client = ElchiClient()
        client.set_host(session['elchi_host'])
        # Use set_token method to properly set headers
        client.set_token(session['elchi_token'])
        client.base_project = session['elchi_project']
        client.user_id = session.get('elchi_user_id', '')
        
        # Get clusters from ELCHI
        clusters = client.get_clusters()
        
        if clusters:
            # Save to cache
            os.makedirs('config', exist_ok=True)
            cache_file = 'config/clusters.json'
            
            with open(cache_file, 'w') as f:
                json.dump(clusters, f, indent=2)
            
            # Count IPs
            ip_count = 0
            for cluster in clusters:
                nodes = cluster.get('nodes', [])
                for node in nodes:
                    if node.get('addresses', {}).get('InternalIP'):
                        ip_count += 1
            
            # Reload cluster resolver to use new data
            from utils.cluster_resolver import get_cluster_resolver
            resolver = get_cluster_resolver(use_cache_only=True)
            resolver.reload_clusters(clusters_data=clusters)
            
            return jsonify({
                'success': True,
                'message': f'Successfully synced {len(clusters)} clusters with {ip_count} IPs',
                'cluster_count': len(clusters),
                'ip_count': ip_count
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No clusters found in ELCHI',
                'cluster_count': 0,
                'ip_count': 0
            })
            
    except Exception as e:
        print(f"Error syncing clusters: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/clusters/clear', methods=['POST'])
def api_clear_clusters():
    """Clear the clusters cache"""
    try:
        cache_file = 'config/clusters.json'
        
        if os.path.exists(cache_file):
            os.remove(cache_file)
            
            # Clear the in-memory cache as well
            import utils.cluster_resolver as cr
            cr.cluster_resolver = None
            
            return jsonify({
                'success': True,
                'message': 'Clusters cache cleared successfully'
            })
        else:
            return jsonify({
                'success': True,
                'message': 'No cache to clear'
            })
            
    except Exception as e:
        print(f"Error clearing clusters cache: {e}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# VSERVER STATISTICS ROUTES  
# =============================================================================

@main.route('/api/vserver-stats/status')
def api_vserver_stats_status():
    """Get the status of cached vserver statistics"""
    try:
        cache_file = 'config/vserver_stats.json'
        
        if os.path.exists(cache_file):
            # Get file stats
            file_stat = os.stat(cache_file)
            
            # Load stats to get counts
            with open(cache_file, 'r') as f:
                content = f.read().strip()
                if content:
                    stats = json.loads(content)
                    
                    # Count total requests
                    total_requests = sum(stats.values()) if isinstance(stats, dict) else 0
                    
                    return jsonify({
                        'has_cache': True,
                        'vserver_count': len(stats),
                        'total_requests': total_requests,
                        'last_modified': file_stat.st_mtime,
                        'file_size': file_stat.st_size
                    })
                else:
                    return jsonify({
                        'has_cache': False,
                        'vserver_count': 0,
                        'total_requests': 0
                    })
        else:
            return jsonify({
                'has_cache': False,
                'vserver_count': 0,
                'total_requests': 0
            })
            
    except Exception as e:
        print(f"Error getting vserver stats status: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/vserver-stats/sync', methods=['POST'])
def api_sync_vserver_stats():
    """Sync vserver statistics from NetScaler and save to cache"""
    try:
        # Check if NetScaler session exists
        if 'netscaler_host' not in session or 'netscaler_username' not in session:
            return jsonify({'error': 'NetScaler session not found. Please login to NetScaler first.'}), 401
            
        # Initialize NetScaler client
        from utils.netscaler_client import NetScalerClient
        client = NetScalerClient(
            session['netscaler_host'],
            session['netscaler_username'], 
            session['netscaler_password']
        )
        
        if not client.login():
            return jsonify({'error': 'Failed to login to NetScaler'}), 401
        
        try:
            # Get all vserver statistics directly from NetScaler
            vserver_stats = {}
            
            # Import parser for IP filtering
            from utils.parser import NetScalerConfigParser
            parser = NetScalerConfigParser()
            
            # Get LB vservers list
            lb_vservers = client.get_lb_vservers()
            for vserver in lb_vservers:
                vserver_name = vserver.get('name', '')
                ip = vserver.get('ipv46', vserver.get('ip', ''))
                
                # Only process private IPs like the main list
                if vserver_name and parser.is_private_ip(ip):
                    # Get real stats from NetScaler for this vserver
                    try:
                        stats_response = client.session.get(f"{client.base_url}/stat/lbvserver/{vserver_name}")
                        stats_response.raise_for_status()
                        stats_data = stats_response.json().get('lbvserver', [{}])[0]
                        total_requests = int(stats_data.get('totalrequests', 0))
                        vserver_stats[vserver_name] = total_requests
                        print(f"DEBUG: LB {vserver_name} = {total_requests} requests")
                    except Exception as e:
                        print(f"Failed to get stats for LB {vserver_name}: {e}")
                        vserver_stats[vserver_name] = 0
            
            # Get CS vservers list
            cs_vservers = client.get_cs_vservers()
            for vserver in cs_vservers:
                vserver_name = vserver.get('name', '')
                ip = vserver.get('ipv46', vserver.get('ip', ''))
                
                # Only process private IPs like the main list
                if vserver_name and parser.is_private_ip(ip):
                    # Get real stats from NetScaler for this vserver
                    try:
                        stats_response = client.session.get(f"{client.base_url}/stat/csvserver/{vserver_name}")
                        stats_response.raise_for_status()
                        stats_data = stats_response.json().get('csvserver', [{}])[0]
                        total_requests = int(stats_data.get('totalrequests', 0))
                        vserver_stats[vserver_name] = total_requests
                        print(f"DEBUG: CS {vserver_name} = {total_requests} requests")
                    except Exception as e:
                        print(f"Failed to get stats for CS {vserver_name}: {e}")
                        vserver_stats[vserver_name] = 0
            
            # Save to cache
            os.makedirs('config', exist_ok=True)
            cache_file = 'config/vserver_stats.json'
            
            with open(cache_file, 'w') as f:
                json.dump(vserver_stats, f, indent=2)
            
            total_requests = sum(vserver_stats.values())
            
            print(f"DEBUG: Final stats summary: {len(vserver_stats)} vservers, {total_requests} total requests")
            
            return jsonify({
                'success': True,
                'message': f'Successfully synced statistics for {len(vserver_stats)} vservers with {total_requests:,} total requests',
                'vserver_count': len(vserver_stats),
                'total_requests': total_requests
            })
            
        finally:
            client.logout()
            
    except Exception as e:
        print(f"Error syncing vserver stats: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/vserver-stats/clear', methods=['POST'])
def api_clear_vserver_stats():
    """Clear the vserver statistics cache"""
    try:
        cache_file = 'config/vserver_stats.json'
        
        if os.path.exists(cache_file):
            os.remove(cache_file)
            
            return jsonify({
                'success': True,
                'message': 'VServer statistics cache cleared successfully'
            })
        else:
            return jsonify({
                'success': True,
                'message': 'No cache to clear'
            })
            
    except Exception as e:
        print(f"Error clearing vserver stats cache: {e}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# CONFIG FILE SERVING ROUTES  
# =============================================================================

@main.route('/config/<filename>')
def serve_config_file(filename):
    """Serve config files (like vserver_stats.json)"""
    try:
        import os
        # Use absolute path from project root
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_dir = os.path.join(project_root, 'config')
        return send_from_directory(config_dir, filename)
    except Exception as e:
        return jsonify({'error': 'File not found'}), 404


# =============================================================================
# SETTINGS ROUTES  
# =============================================================================

@main.route('/api/settings')
def api_get_settings():
    try:
        settings_file = get_settings_file()
        print(f"DEBUG: Using settings file: {settings_file}")
        
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
        else:
            settings = {
                'netscaler': {
                    'default_host': '',
                    'default_username': ''
                },
                'elchi': {
                    'default_host': '',
                    'default_project': ''
                },
                'ui': {
                    'theme': 'light',
                    'items_per_page': 50
                }
            }
        
        return jsonify(settings)
        
    except Exception as e:
        print(f"Error getting settings: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/api/settings', methods=['POST'])
def api_update_settings():
    try:
        settings = request.get_json()
        
        # Create config directory
        os.makedirs('config', exist_ok=True)
        
        # Save settings
        settings_file = get_settings_file()
        print(f"DEBUG: Saving to settings file: {settings_file}")
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        return jsonify({'success': True, 'message': 'Settings saved successfully'})
        
    except Exception as e:
        print(f"Error saving settings: {e}")
        return jsonify({'error': str(e)}), 500