import requests
import json
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse

class ElchiClient:
    """Client for interacting with ELCHI API"""
    
    def __init__(self, host=None):
        """Initialize ELCHI client with host"""
        self.host = host
        self.session = requests.Session()
        self.session.verify = False  # For self-signed certificates
        self.session.headers.update({
            'Content-Type': 'application/json',
            'from-elchi': 'yes'
        })
        self.token = None
        self.refresh_token = None
        self.user_id = None
        self.base_project = None
        self.projects = []
        self.token_expiry = None
        
    def set_host(self, host):
        """Set the ELCHI host - accepts full URLs"""
        self.host = self._build_base_url(host)
    
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
            # No protocol specified, assume HTTPS
            if ':' in host:
                # Has port
                base = f"https://{host}"
            else:
                # No port, just hostname/IP
                base = f"https://{host}"
        
        return base.rstrip('/')
        
    def login(self, username, password):
        """Login to ELCHI and get auth token"""
        if not self.host:
            raise ValueError("Host not set. Call set_host() first")
            
        login_url = f"{self.host}/auth/login"
        login_payload = {
            "username": username,
            "password": password
        }
        
        try:
            response = self.session.post(login_url, json=login_payload)
            response.raise_for_status()
            
            data = response.json()
            
            # Store authentication details
            self.token = data.get('token')
            self.refresh_token = data.get('refresh_token')
            self.user_id = data.get('user_id')
            self.base_project = data.get('base_project')
            
            # Extract projects
            if 'projects' in data:
                self.projects = data.get('projects', [])
            
            # Parse token to get expiry (simple extraction, could be JWT decode)
            # For now, assume 24 hours validity
            self.token_expiry = datetime.now() + timedelta(hours=24)
            
            # Update session headers with auth token
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}',
                'from-elchi': 'yes'
            })
            
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"ELCHI login failed: {e}")
            return False
    
    def logout(self):
        """Logout from ELCHI"""
        # Clear session data
        self.token = None
        self.refresh_token = None
        self.user_id = None
        self.base_project = None
        self.projects = []
        self.token_expiry = None
        
        # Remove auth header
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']
    
    def set_token(self, token, expiry_hours=24):
        """Set authentication token and update session headers"""
        self.token = token
        self.token_expiry = datetime.now() + timedelta(hours=expiry_hours)
        
        # Update session headers with auth token
        self.session.headers.update({
            'Authorization': f'Bearer {self.token}',
            'from-elchi': 'yes'
        })
    
    def is_authenticated(self):
        """Check if client is authenticated"""
        if not self.token or not self.token_expiry:
            return False
        
        # Check if token is still valid
        return datetime.now() < self.token_expiry
    
    def get_clusters(self):
        """Get clusters from ELCHI discovery API"""
        if not self.is_authenticated():
            raise ValueError("Not authenticated. Please login first")
        
        clusters_url = f"{self.host}/api/discovery/clusters"
        
        try:
            # Add project query parameter if available
            params = {}
            if self.base_project:
                params['project'] = self.base_project
            
            # Debug: Print request details
            print(f"DEBUG: Getting clusters from {clusters_url} with params: {params}")
            print(f"DEBUG: Auth header present: {'Authorization' in self.session.headers}")
            
            response = self.session.get(clusters_url, params=params)
            response.raise_for_status()
            
            clusters_data = response.json()
            print(f"DEBUG: Got {len(clusters_data) if clusters_data else 0} clusters from ELCHI")
            return clusters_data
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to get clusters: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response status: {e.response.status_code}")
                print(f"Response body: {e.response.text}")
            return []
    
    def get_endpoints(self):
        """Get endpoints from ELCHI API"""
        if not self.is_authenticated():
            raise ValueError("Not authenticated. Please login first")
        
        endpoints_url = f"{self.host}/api/v3/xds/endpoints"
        
        try:
            # Add project query parameter if available
            params = {}
            if self.base_project:
                params['project'] = self.base_project
            
            response = self.session.get(endpoints_url, params=params)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to get endpoints: {e}")
            return None
    
    def create_cluster(self, cluster_data):
        """Create a new cluster in ELCHI"""
        if not self.is_authenticated():
            raise ValueError("Not authenticated. Please login first")
        
        clusters_url = f"{self.host}/api/v3/xds/clusters"
        
        # Ensure project is set in the data
        if self.base_project and 'general' in cluster_data:
            cluster_data['general']['project'] = self.base_project
        
        try:
            response = self.session.post(clusters_url, json=cluster_data)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to create cluster: {e}")
            return None
    
    def create_endpoint(self, endpoint_data):
        """Create a new endpoint in ELCHI"""
        if not self.is_authenticated():
            raise ValueError("Not authenticated. Please login first")
        
        endpoints_url = f"{self.host}/api/v3/xds/endpoints"
        
        # Ensure project is set in the data
        if self.base_project and 'general' in endpoint_data:
            endpoint_data['general']['project'] = self.base_project
        
        try:
            response = self.session.post(endpoints_url, json=endpoint_data)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to create endpoint: {e}")
            return None
    
    def update_cluster(self, cluster_id, cluster_data):
        """Update an existing cluster"""
        if not self.is_authenticated():
            raise ValueError("Not authenticated. Please login first")
        
        cluster_url = f"{self.host}/api/v3/xds/clusters/{cluster_id}"
        
        try:
            response = self.session.put(cluster_url, json=cluster_data)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to update cluster: {e}")
            return None
    
    def update_endpoint(self, endpoint_id, endpoint_data):
        """Update an existing endpoint"""
        if not self.is_authenticated():
            raise ValueError("Not authenticated. Please login first")
        
        endpoint_url = f"{self.host}/api/v3/xds/endpoints/{endpoint_id}"
        
        try:
            response = self.session.put(endpoint_url, json=endpoint_data)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to update endpoint: {e}")
            return None
    
    def delete_cluster(self, cluster_id):
        """Delete a cluster"""
        if not self.is_authenticated():
            raise ValueError("Not authenticated. Please login first")
        
        cluster_url = f"{self.host}/api/v3/xds/clusters/{cluster_id}"
        
        try:
            response = self.session.delete(cluster_url)
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to delete cluster: {e}")
            return False
    
    def delete_endpoint(self, endpoint_id):
        """Delete an endpoint"""
        if not self.is_authenticated():
            raise ValueError("Not authenticated. Please login first")
        
        endpoint_url = f"{self.host}/api/v3/xds/endpoints/{endpoint_id}"
        
        try:
            response = self.session.delete(endpoint_url)
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to delete endpoint: {e}")
            return False
    
    def send_template(self, template_type, template_data, project=None, version=None):
        """Send template to appropriate ELCHI endpoint"""
        if not self.is_authenticated():
            return {
                'success': False,
                'error': 'Authentication expired. Please login to ELCHI again.',
                'auth_required': True
            }
        
        # Template -> endpoint mapping
        endpoints = {
            'endpoint': 'api/v3/xds/endpoints',
            'cluster': 'api/v3/xds/clusters', 
            'listener': 'api/v3/xds/listeners',
            'route': 'api/v3/xds/routes',
            'vhost': 'api/v3/xds/virtual_hosts',
            'tcp': 'api/v3/eo/filters/filters/envoy.filters.network.tcp_proxy',
            'hcm': 'api/v3/eo/filters/filters/envoy.filters.network.http_connection_manager'
        }
        
        endpoint_path = endpoints.get(template_type)
        if not endpoint_path:
            raise ValueError(f"Unknown template type: {template_type}")
        
        url = f"{self.host}/{endpoint_path}"
        
        # Build params
        params = {}
        if project:
            params['project'] = project
        if version:
            params['version'] = version
            
        try:
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Sending {template_type} template to {url}")
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Params: {params}")
            if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
                print(f"DEBUG: Template data keys: {list(template_data.keys()) if isinstance(template_data, dict) else 'Not a dict'}")
            
            response = self.session.post(url, json=template_data, params=params)
            
            # Check status before raise_for_status() so we can capture response body on error
            if response.status_code >= 400:
                error_message = f"{response.status_code} {response.reason}"
                response_body = response.text if response.text else "No response body"
                
                return {
                    'success': False,
                    'error': error_message,
                    'status_code': response.status_code,
                    'response_text': response_body
                }
            
            response.raise_for_status()
            
            return {
                'success': True,
                'status_code': response.status_code,
                'response': response.json() if response.text else {'message': 'Success'}
            }
            
        except requests.exceptions.RequestException as e:
            # Check if it's an authentication error
            if hasattr(e, 'response') and e.response and e.response.status_code == 401:
                return {
                    'success': False,
                    'error': 'Authentication expired. Please login to ELCHI again.',
                    'auth_required': True,
                    'status_code': 401
                }
            
            error_message = str(e)
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            response_text = e.response.text if hasattr(e, 'response') and e.response else None
            
            # Include response body in error message for better debugging
            if response_text:
                error_message += f" | Response: {response_text[:500]}{'...' if len(response_text) > 500 else ''}"
            
            return {
                'success': False,
                'error': error_message,
                'status_code': status_code,
                'response_text': response_text
            }
    
    def check_resource_exists(self, template_type, resource_name, project=None, version=None):
        """Check if a resource with the given name already exists"""
        if not self.is_authenticated():
            return {'error': 'Not authenticated'}
        
        # Template -> check endpoint mapping
        check_endpoints = {
            'endpoint': 'api/v3/xds/endpoints',
            'cluster': 'api/v3/xds/clusters', 
            'listener': 'api/v3/xds/listeners',
            'route': 'api/v3/xds/routes',
            'vhost': 'api/v3/xds/virtual_hosts',
            'tcp': 'api/v3/eo/filters/filters/envoy.filters.network.tcp_proxy',
            'hcm': 'api/v3/eo/filters/filters/envoy.filters.network.http_connection_manager'
        }
        
        endpoint_path = check_endpoints.get(template_type)
        if not endpoint_path:
            return {'error': f'Unknown template type: {template_type}'}
        
        url = f"{self.host}/{endpoint_path}"
        
        # Build params for search
        params = {
            'limit': 1,
            'offset': 0,
            'name': resource_name
        }
        if project:
            params['project'] = project
        if version:
            params['version'] = version
            
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Check if any resources found
            if 'data' in data and 'data' in data['data']:
                resources = data['data']['data']
                return {
                    'exists': len(resources) > 0,
                    'count': len(resources),
                    'resources': resources
                }
            
            return {'exists': False, 'count': 0, 'resources': []}
            
        except requests.exceptions.RequestException as e:
            return {'error': f'Failed to check resource existence: {str(e)}'}
    
    def check_all_resources_exist(self, templates_data, project=None, version=None):
        """Check existence for all templates and return conflicts"""
        conflicts = []
        
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
                # Parse template to get name
                template_json = json.loads(template_content)
                resource_name = template_json.get('general', {}).get('name')
                
                if resource_name:
                    result = self.check_resource_exists(template_type, resource_name, project, version)
                    
                    if result.get('exists'):
                        conflicts.append({
                            'template_type': template_type,
                            'resource_name': resource_name,
                            'existing_resources': result.get('resources', [])
                        })
                    elif result.get('error'):
                        conflicts.append({
                            'template_type': template_type,
                            'resource_name': resource_name,
                            'error': result['error']
                        })
                        
            except (json.JSONDecodeError, KeyError) as e:
                conflicts.append({
                    'template_type': template_type,
                    'error': f'Failed to parse template: {str(e)}'
                })
        
        return conflicts