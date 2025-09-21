#!/usr/bin/env python3
"""
DEPRECATED: Background Stats Updater
This module is deprecated. Use Flask web interface instead.
"""

print("WARNING: background_stats.py is deprecated!")
print("Use Flask web interface with nocache parameter instead")
exit(1)

class BackgroundStatsUpdater:
    def __init__(self):
        self.running = False
        self.thread = None
        self.stats_tracker = VServerStatsTracker()
    
    def update_stats(self):
        """Update stats for all virtual servers"""
        if not NetScalerConfig.is_configured():
            print("DEBUG: NetScaler config not found in .env file")
            return
        
        config = NetScalerConfig.get_config()
        
        try:
            client = NetScalerClient(
                config['host'],
                config['username'],
                config['password']
            )
            
            if not client.login():
                print("Failed to login to NetScaler for stats update")
                return
            
            print(f"Starting stats update at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Get filtered LB vservers and update stats (only private IPs)
            from utils.parser import NetScalerConfigParser
            parser = NetScalerConfigParser()
            
            lb_vservers = client.get_lb_vservers()
            for vserver in lb_vservers:
                vserver_name = vserver.get('name', '')
                ip = vserver.get('ipv46', vserver.get('ip', ''))
                
                # Only update stats for private IPs (exclude 0.0.0.0, 10.70.x.x, public IPs)
                if vserver_name and parser.is_private_ip(ip):
                    try:
                        current_requests = client._get_vserver_requests(vserver_name)
                        total_requests = self.stats_tracker.update_vserver_stats(vserver_name, current_requests)
                        print(f"Updated LB {vserver_name} ({ip}): total={total_requests}")
                    except Exception as e:
                        print(f"Failed to update LB {vserver_name}: {e}")
            
            # Get filtered CS vservers and update stats (only private IPs)
            cs_vservers = client.get_cs_vservers()
            for vserver in cs_vservers:
                vserver_name = vserver.get('name', '')
                ip = vserver.get('ipv46', vserver.get('ip', ''))
                
                # Only update stats for private IPs (exclude 0.0.0.0, 10.70.x.x, public IPs)
                if vserver_name and parser.is_private_ip(ip):
                    try:
                        current_requests = client._get_vserver_requests(vserver_name)
                        total_requests = self.stats_tracker.update_vserver_stats(vserver_name, current_requests)
                        print(f"Updated CS {vserver_name} ({ip}): total={total_requests}")
                    except Exception as e:
                        print(f"Failed to update CS {vserver_name}: {e}")
            
            client.logout()
            print(f"Stats update completed at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            
        except Exception as e:
            print(f"Error updating stats: {e}")
    
    def run_scheduler(self):
        """Run the scheduler in background thread"""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def start(self):
        """DEPRECATED: Start the background stats updater"""
        print("❌ Background stats updater is DISABLED")
        print("📋 Use 'python3 update_stats.py' to update statistics manually")
        return
        print("Running initial stats update...")
        threading.Thread(target=self.update_stats, daemon=True).start()
        
        # Start scheduler in background thread
        self.thread = threading.Thread(target=self.run_scheduler, daemon=True)
        self.thread.start()
        
        print("Background stats updater started (5 minute intervals)")
    
    def stop(self):
        """Stop the background stats updater"""
        self.running = False
        schedule.clear()
        if self.thread:
            self.thread.join(timeout=5)
        print("Background stats updater stopped")

# Global instance
background_updater = BackgroundStatsUpdater()