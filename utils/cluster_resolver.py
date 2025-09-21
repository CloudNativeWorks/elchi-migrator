import json
import os
from flask import session

class ClusterResolver:
    def __init__(self, clusters_data=None, use_cache_only=False):
        self.cache_file = 'config/clusters.json'
        if clusters_data:
            self.clusters = clusters_data
            # Save provided data to cache
            self._save_clusters_to_cache(clusters_data)
        elif use_cache_only:
            self.clusters = self._load_clusters_from_cache()
        else:
            self.clusters = self._load_clusters_from_cache_or_api()
        self.ip_to_cluster = self._build_ip_mapping()
    
    def _load_clusters_from_cache_or_api(self, from_cache=True):
        """Load clusters from cache only - API calls only triggered from settings"""
        # Always try to load from cache first
        cached_clusters = self._load_clusters_from_cache()
        if cached_clusters:
            return cached_clusters
        
        # Return empty if no clusters available in cache
        # API calls should only be triggered from settings page
        return []
    
    def _load_clusters_from_cache(self):
        """Load clusters from JSON cache file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
        except Exception as e:
            print(f"Error loading clusters from cache: {e}")
        return []
    
    def _save_clusters_to_cache(self, clusters):
        """Save clusters to JSON cache file"""
        try:
            print(f"DEBUG: Saving {len(clusters)} clusters to {self.cache_file}")
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(clusters, f, indent=2)
            print(f"DEBUG: Successfully saved clusters to {self.cache_file}")
        except Exception as e:
            print(f"Error saving clusters to cache: {e}")
    
    def _build_ip_mapping(self):
        """Build IP to cluster mapping"""
        ip_mapping = {}
        # Only print debug in development mode
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Building IP mapping from {len(self.clusters)} clusters")
        
        for cluster in self.clusters:
            cluster_name = cluster.get('cluster_name', '')
            nodes = cluster.get('nodes', [])
            
            for node in nodes:
                addresses = node.get('addresses', {})
                internal_ip = addresses.get('InternalIP', '')
                
                if internal_ip:
                    if internal_ip not in ip_mapping:
                        ip_mapping[internal_ip] = []
                    
                    ip_mapping[internal_ip].append({
                        'cluster_name': cluster_name,
                        'node_name': node.get('name', ''),
                        'node_status': node.get('status', ''),
                        'node_roles': node.get('roles', [])
                    })
        
        # Only print debug in development mode
        if os.environ.get('FLASK_DEBUG', '').lower() == 'true':
            print(f"DEBUG: Built IP mapping with {len(ip_mapping)} IPs")
        return ip_mapping
    
    def get_clusters_for_ip(self, ip):
        """Get cluster information for an IP address"""
        return self.ip_to_cluster.get(ip, [])
    
    def has_clusters(self, ip):
        """Check if IP has associated clusters"""
        return ip in self.ip_to_cluster and len(self.ip_to_cluster[ip]) > 0
    
    def get_cluster_names_for_ip(self, ip):
        """Get only cluster names for an IP"""
        clusters = self.get_clusters_for_ip(ip)
        return list(set([cluster['cluster_name'] for cluster in clusters]))
    
    def get_clusters_for_service_ips(self, service_ips):
        """Get clusters for a list of service IPs (optimized batch lookup)"""
        result = {}
        for ip in service_ips:
            if ip in self.ip_to_cluster:  # Direct dict lookup is faster
                result[ip] = self.ip_to_cluster[ip]
        return result
    
    def get_cluster_summary_for_ips(self, service_ips):
        """Get a summary of cluster matches for multiple IPs (optimized for UI display)"""
        matched_ips = []
        unmatched_ips = []
        cluster_matches = []
        
        for ip in service_ips:
            if ip in self.ip_to_cluster:
                clusters = self.ip_to_cluster[ip]
                matched_ips.append(ip)
                for cluster in clusters:
                    cluster_matches.append({
                        'ip': ip,
                        'cluster_name': cluster['cluster_name'],
                        'node_name': cluster.get('node_name', ''),
                        'ips': [ip]  # For compatibility with existing code
                    })
            else:
                unmatched_ips.append(ip)
        
        return {
            'matched_ips': matched_ips,
            'unmatched_ips': unmatched_ips,
            'cluster_matches': cluster_matches,
            'total_ips': len(service_ips),
            'matched_count': len(matched_ips)
        }
    
    def reload_clusters(self, clusters_data=None, from_cache=True):
        """Reload clusters from ELCHI API or cache"""
        if clusters_data:
            self.clusters = clusters_data
            # Save provided data to cache
            self._save_clusters_to_cache(clusters_data)
        else:
            self.clusters = self._load_clusters_from_cache_or_api(from_cache=from_cache)
        self.ip_to_cluster = self._build_ip_mapping()

# Global instance - will be initialized when needed
cluster_resolver = None

def get_cluster_resolver(use_cache_only=False):
    """Get cluster resolver instance, create if needed"""
    global cluster_resolver
    if cluster_resolver is None:
        cluster_resolver = ClusterResolver(use_cache_only=use_cache_only)
    return cluster_resolver