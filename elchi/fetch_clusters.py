#!/usr/bin/env python3
"""
Fetch clusters from ELCHI API dynamically and save to clusters.json
"""

import json
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elchi.elchi_client import ElchiClient

def fetch_clusters(host, username, password):
    """Fetch clusters from ELCHI API"""
    
    # Initialize ELCHI client
    client = ElchiClient()
    client.set_host(host)
    
    # Login to ELCHI
    if not client.login(username, password):
        print("❌ Failed to login to ELCHI")
        return None
    
    print("✅ Successfully logged in to ELCHI")
    print(f"   Project: {client.base_project}")
    print(f"   User ID: {client.user_id}")
    
    # Fetch clusters
    print("📥 Fetching clusters from ELCHI...")
    clusters = client.get_clusters()
    
    if clusters:
        print(f"✅ Fetched {len(clusters)} clusters")
        
        # Save to file
        output_file = 'clusters.json'
        with open(output_file, 'w') as f:
            json.dump(clusters, f, indent=2)
        
        print(f"💾 Saved clusters to {output_file}")
        
        # Parse and extract cluster information
        cluster_info = []
        for cluster in clusters:
            if 'general' in cluster and 'name' in cluster['general']:
                cluster_name = cluster['general']['name']
                cluster_type = cluster['general'].get('type', 'unknown')
                cluster_info.append({
                    'name': cluster_name,
                    'type': cluster_type,
                    'project': cluster['general'].get('project', ''),
                    'version': cluster['general'].get('version', '')
                })
        
        # Display summary
        print("\n📊 Cluster Summary:")
        for info in cluster_info[:10]:  # Show first 10
            print(f"   • {info['name']} (Type: {info['type']})")
        
        if len(cluster_info) > 10:
            print(f"   ... and {len(cluster_info) - 10} more clusters")
        
        return clusters
    else:
        print("❌ Failed to fetch clusters")
        return None

def main():
    """Main function to run the script"""
    
    # Get credentials from user or environment
    print("🔄 ELCHI Cluster Fetcher")
    print("=" * 50)
    
    # You can modify this to get from command line args or config
    host = input("Enter ELCHI host (e.g., elchi.example.com): ").strip()
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    
    if not all([host, username, password]):
        print("❌ All fields are required")
        sys.exit(1)
    
    # Fetch clusters
    clusters = fetch_clusters(host, username, password)
    
    if clusters:
        print("\n✅ Successfully fetched and saved clusters")
        sys.exit(0)
    else:
        print("\n❌ Failed to fetch clusters")
        sys.exit(1)

if __name__ == '__main__':
    main()