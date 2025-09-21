"""
ELCHI Integration Service
========================

This module handles all ELCHI integration logic, including:
- ELCHI authentication
- Template submission to ELCHI
- TLS context management  
- Resource conflict checking
"""

from flask import session
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from elchi.elchi_client import ElchiClient
import json
import requests


# Template -> ELCHI API endpoint mapping
TEMPLATE_ELCHI_ENDPOINTS = {
    'endpoint': 'api/v3/xds/endpoints',
    'cluster': 'api/v3/xds/clusters', 
    'listener': 'api/v3/xds/listeners',
    'route': 'api/v3/xds/routes',
    'vhost': 'api/v3/xds/virtual_hosts',
    'tcp': 'api/v3/eo/filters/filters/envoy.filters.network.tcp_proxy',
    'hcm': 'api/v3/eo/filters/filters/envoy.filters.network.http_connection_manager'
}


def create_elchi_client():
    """Create and configure ELCHI client from session"""
    if 'elchi_token' not in session:
        return None
    
    try:
        from datetime import datetime, timedelta
        
        client = ElchiClient()
        client.set_host(session['elchi_host'])
        client.token = session['elchi_token']
        client.base_project = session['elchi_project']
        client.user_id = session['elchi_user_id']
        
        # Set Authorization header manually (since we're not calling login())
        client.session.headers.update({
            'Authorization': f'Bearer {client.token}'
        })
        
        # Set token expiry from session or default
        if 'elchi_token_expiry' in session:
            client.token_expiry = datetime.fromisoformat(session['elchi_token_expiry'])
        else:
            client.token_expiry = datetime.now() + timedelta(hours=24)
        
        return client
    except Exception as e:
        print(f"Error creating ELCHI client: {e}")
        return None


def elchi_login(host, username, password):
    """Login to ELCHI and store session data"""
    try:
        client = ElchiClient()
        client.set_host(host)
        
        if client.login(username, password):
            # Store ELCHI session data with permanent session and JWT expiry time
            session.permanent = True
            session['elchi_host'] = host
            session['elchi_username'] = username
            session['elchi_token'] = client.token
            session['elchi_project'] = client.base_project
            session['elchi_user_id'] = client.user_id
            session['elchi_projects'] = client.projects
            
            # Extract expiry from JWT token (manual decode)
            try:
                import base64
                import json
                from datetime import datetime
                
                # JWT format: header.payload.signature
                token_parts = client.token.split('.')
                if len(token_parts) >= 2:
                    # Decode payload (second part)
                    payload_b64 = token_parts[1]
                    # Add padding if needed
                    padding = len(payload_b64) % 4
                    if padding:
                        payload_b64 += '=' * (4 - padding)
                    
                    payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
                    payload = json.loads(payload_json)
                    
                    if 'exp' in payload:
                        expiry_timestamp = payload['exp']
                        expiry_datetime = datetime.fromtimestamp(expiry_timestamp)
                        session['elchi_token_expiry'] = expiry_datetime.isoformat()
                        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                            print(f"DEBUG: JWT token expires at: {expiry_datetime}")
                    else:
                        # Fallback if no exp claim
                        from datetime import timedelta
                        session['elchi_token_expiry'] = (datetime.now() + timedelta(hours=24)).isoformat()
                        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                            print(f"DEBUG: No exp claim, using 24h default")
                else:
                    raise ValueError("Invalid JWT format")
                    
            except Exception as e:
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Error parsing JWT token: {e}")
                # Fallback to 24 hours
                from datetime import datetime, timedelta
                session['elchi_token_expiry'] = (datetime.now() + timedelta(hours=24)).isoformat()
            
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: ELCHI login successful. Token: {client.token[:10]}...")
            return {'success': True}
        else:
            return {'success': False, 'message': 'Login failed'}
            
    except Exception as e:
        print(f"ELCHI login error: {e}")
        return {'success': False, 'message': str(e)}


def elchi_logout():
    """Logout from ELCHI and clear session data"""
    try:
        client = create_elchi_client()
        if client:
            client.logout()
        
        # Clear ELCHI session data
        elchi_keys = ['elchi_host', 'elchi_username', 'elchi_token', 'elchi_project', 'elchi_user_id', 'elchi_projects']
        for key in elchi_keys:
            session.pop(key, None)
        
        return {'success': True}
        
    except Exception as e:
        print(f"ELCHI logout error: {e}")
        return {'success': False, 'message': str(e)}


def get_elchi_status(version="v1.35.3"):
    """Get ELCHI authentication status based on token expiry"""
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Checking ELCHI status...")
    
    if 'elchi_token' not in session:
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: No elchi_token in session")
        return {'authenticated': False}
    
    # Check token expiry first (no API call needed)
    if 'elchi_token_expiry' in session:
        try:
            from datetime import datetime
            expiry_time = datetime.fromisoformat(session['elchi_token_expiry'])
            current_time = datetime.now()
            
            if current_time >= expiry_time:
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Token expired at {expiry_time}, current time: {current_time}")
                _clear_elchi_session()
                return {'authenticated': False}
            else:
                time_left = expiry_time - current_time
                if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                    print(f"DEBUG: Token valid for {time_left}")
        except Exception as e:
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Error parsing token expiry: {e}")
            # If we can't parse expiry, assume valid (fallback)
    else:
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: No token expiry stored, assuming valid")
    
    # Token is valid based on expiry time
    if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
        print(f"DEBUG: Authentication valid (token not expired)")
    return {
        'authenticated': True,
        'host': session.get('elchi_host', ''),
        'project': session.get('elchi_project', ''),
        'user_id': session.get('elchi_user_id', ''),
        'projects': session.get('elchi_projects', [])
    }


def _clear_elchi_session():
    """Clear ELCHI session data"""
    print(f"DEBUG: CLEARING ELCHI SESSION - Before: {list(session.keys())}")
    elchi_keys = ['elchi_host', 'elchi_username', 'elchi_token', 'elchi_project', 'elchi_user_id', 'elchi_projects']
    for key in elchi_keys:
        session.pop(key, None)
    print(f"DEBUG: CLEARING ELCHI SESSION - After: {list(session.keys())}")
    
    # Print stack trace to see who called this
    import traceback
    print("DEBUG: Session cleared from:")
    traceback.print_stack()


def get_elchi_clusters():
    """Get clusters from ELCHI"""
    try:
        client = create_elchi_client()
        if not client:
            return {'error': 'Not authenticated to ELCHI'}, 401
        
        clusters = client.get_clusters()
        if clusters is None:
            return {'error': 'Failed to fetch clusters from ELCHI'}, 500
        
        return {'clusters': clusters}, 200
        
    except Exception as e:
        print(f"Error fetching ELCHI clusters: {e}")
        return {'error': str(e)}, 500


def get_tls_contexts(version="v1.35.3"):
    """Get TLS contexts from ELCHI using ElchiClient"""
    try:
        print(f"DEBUG: get_tls_contexts - Session keys: {list(session.keys())}")
        print(f"DEBUG: get_tls_contexts - Token exists: {'elchi_token' in session}")
        if 'elchi_token' in session:
            print(f"DEBUG: get_tls_contexts - Token: {session['elchi_token'][:20]}...")
        
        client = create_elchi_client()
        if not client:
            print(f"DEBUG: get_tls_contexts - Client creation failed")
            return {'error': 'Not authenticated to ELCHI'}, 401
        
        print(f"DEBUG: get_tls_contexts - Client token: {client.token[:20] if client.token else 'None'}...")
        
        # Use ElchiClient's session for consistent headers and auth
        api_url = f"{client.host}/api/v3/custom/resource_list_search"
        params = {
            'collection': 'tls',
            'gtype': 'envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
            'version': version,
            'project': client.base_project,
            'search': ''
        }
        
        # Set authorization header using client's token
        headers = {'Authorization': f'Bearer {client.token}'}
        
        print(f"DEBUG: TLS Context API URL: {api_url}")
        print(f"DEBUG: TLS Context API Params: {params}")
        
        response = client.session.get(api_url, params=params, headers=headers, timeout=30)
        
        print(f"DEBUG: TLS Context API Response: Status={response.status_code}")
        print(f"DEBUG: TLS Context API Response Text: {response.text[:500]}...")
        
        if response.status_code == 200:
            tls_contexts = response.json()
            print(f"DEBUG: TLS Contexts received: {len(tls_contexts) if isinstance(tls_contexts, list) else 'Not a list'}")
            return {'tls_contexts': tls_contexts}, 200
        else:
            return {'error': f'Failed to fetch TLS contexts: {response.status_code}'}, response.status_code
            
    except Exception as e:
        print(f"Error fetching TLS contexts: {e}")
        return {'error': str(e)}, 500


def send_templates_to_elchi(templates_data, version="v1.35.3", ignore_duplicate=False):
    """Send templates to ELCHI"""
    try:
        print(f"DEBUG: send_templates_to_elchi - Session keys: {list(session.keys())}")
        print(f"DEBUG: send_templates_to_elchi - Token exists: {'elchi_token' in session}")
        if 'elchi_token' in session:
            print(f"DEBUG: send_templates_to_elchi - Token: {session['elchi_token'][:20]}...")
        
        client = create_elchi_client()
        if not client:
            print(f"DEBUG: send_templates_to_elchi - Client creation failed")
            return {'error': 'Not authenticated to ELCHI'}, 401
        
        print(f"DEBUG: send_templates_to_elchi - Client token: {client.token[:20] if client.token else 'None'}...")
        
        # Manual test - try direct XDS API call
        print(f"DEBUG: Testing direct XDS clusters API call...")
        test_url = f"{client.host}/api/v3/xds/clusters"
        test_params = {
            'limit': 1,
            'offset': 0,
            'project': client.base_project,
            'version': version
        }
        try:
            test_response = client.session.get(test_url, params=test_params)
            print(f"DEBUG: Direct XDS call - Status: {test_response.status_code}")
            print(f"DEBUG: Direct XDS call - Headers sent: {dict(client.session.headers)}")
            if test_response.status_code != 200:
                print(f"DEBUG: Direct XDS call - Response: {test_response.text[:200]}...")
        except Exception as e:
            print(f"DEBUG: Direct XDS call failed: {e}")
        
        # Check for existing resources first (unless ignore_duplicate is enabled)
        if not ignore_duplicate:
            print(f"DEBUG: Starting conflict check with project={client.base_project}, version={version}")
            print(f"DEBUG: Template keys received: {list(templates_data.keys())}")
            conflicts = client.check_all_resources_exist(templates_data, project=client.base_project, version=version)
            print(f"DEBUG: Conflict check result: {conflicts}")
            
            if conflicts:
                print(f"DEBUG: Conflicts found, returning 409")
                return {
                    'success': False,
                    'has_conflicts': True,
                    'conflicts': conflicts,
                    'error': 'Resource name conflicts detected'
                }, 409
        else:
            print(f"DEBUG: ignore_duplicate=True, skipping conflict check")
        
        # Send each template
        results = {}
        for template_key, template_content in templates_data.items():
            # Map template key to template type
            # Handle dynamic templates for CS vservers
            if template_key.startswith('cluster_template_'):
                template_type = 'cluster'
            elif template_key.startswith('endpoint_template_'):
                template_type = 'endpoint'
            else:
                # Regular templates: remove '_template' suffix
                template_type = template_key.replace('_template', '')
            
            try:
                # Handle both string and object formats
                if isinstance(template_content, str):
                    template_json = json.loads(template_content)
                else:
                    template_json = template_content
                
                print(f"DEBUG: Sending {template_key} template to {TEMPLATE_ELCHI_ENDPOINTS.get(template_type)}")
                print(f"DEBUG: Template data keys: {list(template_json.keys()) if isinstance(template_json, dict) else 'Not a dict'}")
                
                result = client.send_template(template_type, template_json, client.base_project, version)
                results[template_key] = result
                
                if not result.get('success'):
                    print(f"Failed to send {template_key}: {result}")
                    
            except json.JSONDecodeError as e:
                results[template_key] = {
                    'success': False,
                    'error': f'Invalid JSON in template: {str(e)}'
                }
            except Exception as e:
                results[template_key] = {
                    'success': False,
                    'error': str(e)
                }
        
        return {
            'success': True,
            'results': results,
            'has_conflicts': False
        }, 200
        
    except Exception as e:
        print(f"Error sending templates to ELCHI: {e}")
        import traceback
        traceback.print_exc()
        return {'error': str(e)}, 500


def check_domain_in_dns(domain):
    """Check if domain exists in DNS mapping"""
    try:
        from utils.dns_resolver import dns_resolver
        
        if not domain:
            return {'exists': False, 'error': 'No domain provided'}, 400
        
        # Check if domain exists in DNS mappings
        for ip, domains in dns_resolver.dns_mapping.items():
            if domain in domains:
                return {'exists': True, 'ip': ip}, 200
        
        return {'exists': False}, 200
        
    except Exception as e:
        print(f"Error checking domain in DNS: {e}")
        return {'error': str(e)}, 500