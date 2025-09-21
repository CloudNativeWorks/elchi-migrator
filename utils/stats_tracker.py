import json
import os
from datetime import datetime

class VServerStatsTracker:
    def __init__(self, stats_file='vserver_stats.json'):
        self.stats_file = stats_file
        self.stats = self._load_stats()
    
    def _load_stats(self):
        """Load stats from file (read-only mode)"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def reload_stats(self):
        """Reload stats from file"""
        self.stats = self._load_stats()
    
    def update_vserver_stats(self, vserver_name, current_requests):
        """DEPRECATED: Use update_stats.py script instead"""
        print("Warning: update_vserver_stats is deprecated. Use update_stats.py script instead.")
        return self.get_total_requests(vserver_name)
    
    def get_total_requests(self, vserver_name):
        """Get total accumulated requests for a virtual server"""
        return self.stats.get(vserver_name, {}).get('total_requests', 0)
    
    def get_all_stats(self):
        """Get all stats"""
        return self.stats
    
    def reset_stats(self, vserver_name=None):
        """DEPRECATED: Manual stats management disabled"""
        print("Warning: reset_stats is deprecated. Manage stats via update_stats.py script.")