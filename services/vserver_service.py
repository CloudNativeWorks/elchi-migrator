"""
VServer Service
==============

This module handles vserver listing and basic operations, including:
- Getting all vservers (LB and CS)  
- Filtering and caching
- VServer completion suggestions
"""

from flask import session
from utils.netscaler_client import NetScalerClient
from utils.cluster_resolver import get_cluster_resolver
import json


def get_all_vservers(from_cache=True):
    """Get all vservers (LB and CS) from NetScaler"""
    try:
        # Check NetScaler session expiry
        from datetime import datetime
        if 'netscaler_expiry' in session:
            try:
                # Use strptime for compatibility with older Python versions
                expiry_time = datetime.strptime(session['netscaler_expiry'], '%Y-%m-%dT%H:%M:%S.%f')
                if datetime.now() >= expiry_time:
                    return {'error': 'NetScaler session expired. Please login again.'}, 401
            except:
                pass
        
        if 'netscaler_host' not in session:
            return {'error': 'NetScaler credentials not found'}, 401
        
        client = NetScalerClient(
            session['netscaler_host'],
            session['netscaler_username'], 
            session['netscaler_password']
        )
        
        if not client.login():
            return {'error': 'Failed to login to NetScaler'}, 401
        
        try:
            # Get filtered vservers
            lb_vservers = client.get_lb_vservers_filtered(from_cache=from_cache)
            cs_vservers = client.get_cs_vservers_filtered(from_cache=from_cache)
            
            # If not using cache, also refresh ELCHI clusters (exactly like routes_old.py)
            if not from_cache and 'elchi_token' in session:
                try:
                    print("DEBUG: Fetching ELCHI clusters during nocache refresh...")
                    from elchi.elchi_client import ElchiClient
                    from utils.cluster_resolver import ClusterResolver
                    from datetime import datetime, timedelta
                    
                    client_elchi = ElchiClient()
                    client_elchi.set_host(session['elchi_host'])
                    client_elchi.token = session['elchi_token']
                    client_elchi.base_project = session['elchi_project']
                    client_elchi.user_id = session['elchi_user_id']
                    
                    # Set token expiry to avoid authentication check failure
                    client_elchi.token_expiry = datetime.now() + timedelta(hours=24)
                    
                    print(f"DEBUG: ELCHI client setup - token: {client_elchi.token[:10]}..., authenticated: {client_elchi.is_authenticated()}")
                    
                    clusters_data = client_elchi.get_clusters()
                    if clusters_data:
                        # Save clusters to cache using ClusterResolver
                        cluster_resolver = ClusterResolver(clusters_data)
                        print(f"DEBUG: Cached {len(clusters_data)} clusters during refresh")
                    else:
                        print("DEBUG: No clusters data received from ELCHI")
                except Exception as e:
                    print(f"DEBUG: Error fetching ELCHI clusters during refresh: {e}")
            
            # Combine vservers exactly like routes_old.py
            vservers = lb_vservers + cs_vservers
            
            return {
                'success': True,
                'vservers': vservers,
                'count': len(vservers),
                'from_cache': from_cache
            }, 200
            
        finally:
            client.logout()
            
    except Exception as e:
        print(f"Error getting vservers: {e}")
        return {'error': str(e)}, 500


def get_vserver_completion_suggestions():
    """Get vserver names for autocomplete"""
    try:
        # Check NetScaler session expiry
        from datetime import datetime
        if 'netscaler_expiry' in session:
            try:
                # Use strptime for compatibility with older Python versions
                expiry_time = datetime.strptime(session['netscaler_expiry'], '%Y-%m-%dT%H:%M:%S.%f')
                if datetime.now() >= expiry_time:
                    return {'error': 'NetScaler session expired. Please login again.'}, 401
            except:
                pass
        
        if 'netscaler_host' not in session:
            return {'error': 'NetScaler credentials not found'}, 401
        
        client = NetScalerClient(
            session['netscaler_host'],
            session['netscaler_username'], 
            session['netscaler_password']
        )
        
        if not client.login():
            return {'error': 'Failed to login to NetScaler'}, 401
        
        try:
            # Get all vserver names
            lb_vservers = client.get_lb_vservers()
            cs_vservers = client.get_cs_vservers()
            
            suggestions = []
            
            # Add LB vservers
            for vserver in lb_vservers:
                name = vserver.get('name', '')
                if name:
                    suggestions.append({
                        'name': name,
                        'type': 'LB',
                        'protocol': vserver.get('servicetype', ''),
                        'ip': vserver.get('ipv46', vserver.get('ip', '')),
                        'port': vserver.get('port', ''),
                        'state': vserver.get('curstate', '')
                    })
            
            # Add CS vservers
            for vserver in cs_vservers:
                name = vserver.get('name', '')
                if name:
                    suggestions.append({
                        'name': name,
                        'type': 'CS',
                        'protocol': vserver.get('servicetype', ''),
                        'ip': vserver.get('ipv46', vserver.get('ip', '')),
                        'port': vserver.get('port', ''),
                        'state': vserver.get('curstate', '')
                    })
            
            return {'suggestions': suggestions}, 200
            
        finally:
            client.logout()
            
    except Exception as e:
        print(f"Error getting vserver suggestions: {e}")
        return {'error': str(e)}, 500


def netscaler_login(host, username, password):
    """Login to NetScaler and store session data"""
    try:
        from datetime import datetime, timedelta
        
        client = NetScalerClient(host, username, password)
        
        if client.login():
            # Store NetScaler session data with expiry time (1 hour)
            session['netscaler_host'] = host
            session['netscaler_username'] = username
            session['netscaler_password'] = password
            
            # Set session expiry to 1 hour from now
            expiry_time = datetime.now() + timedelta(hours=1)
            # Use strftime for compatibility with older Python versions
            session['netscaler_expiry'] = expiry_time.strftime('%Y-%m-%dT%H:%M:%S.%f')
            
            print(f"DEBUG: NetScaler session will expire at: {expiry_time}")
            
            client.logout()
            
            # Note: Cluster data is only refreshed from settings page, not automatically
            return {'success': True}
        else:
            return {'success': False, 'message': 'Login failed'}
            
    except Exception as e:
        print(f"NetScaler login error: {e}")
        return {'success': False, 'message': str(e)}


def netscaler_logout():
    """Logout from NetScaler and clear session data"""
    try:
        # Clear NetScaler session data including expiry
        netscaler_keys = ['netscaler_host', 'netscaler_username', 'netscaler_password', 'netscaler_expiry']
        for key in netscaler_keys:
            session.pop(key, None)
        
        return {'success': True}
        
    except Exception as e:
        print(f"NetScaler logout error: {e}")
        return {'success': False, 'message': str(e)}


def get_netscaler_status():
    """Get NetScaler authentication status with expiry check"""
    if 'netscaler_host' not in session or 'netscaler_username' not in session:
        return {'authenticated': False}
    
    # Check if session has expired
    if 'netscaler_expiry' in session:
        try:
            from datetime import datetime
            expiry_time = datetime.fromisoformat(session['netscaler_expiry'])
            current_time = datetime.now()
            
            if current_time >= expiry_time:
                print(f"DEBUG: NetScaler session expired at {expiry_time}, current time: {current_time}")
                # Clear expired session
                netscaler_keys = ['netscaler_host', 'netscaler_username', 'netscaler_password', 'netscaler_expiry']
                for key in netscaler_keys:
                    session.pop(key, None)
                return {'authenticated': False, 'expired': True}
            else:
                time_left = expiry_time - current_time
                print(f"DEBUG: NetScaler session valid for {time_left}")
        except Exception as e:
            print(f"DEBUG: Error parsing NetScaler expiry: {e}")
            # If we can't parse expiry, assume valid (fallback)
    else:
        print(f"DEBUG: No NetScaler expiry stored, assuming valid")
    
    return {
        'authenticated': True,
        'host': session['netscaler_host'],
        'username': session['netscaler_username']
    }