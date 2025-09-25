"""
Name Utilities
==============

Shared utility functions for name cleaning and normalization across the application.
This module contains the exact logic from routes_old.py to ensure consistency.
"""

import re
import os
import json


def clean_name(name, text_replace_from=None, text_replace_to=''):
    """Clean name by removing unwanted suffixes and making ELCHI-compatible"""
    if not name:
        return name
    
    # Handle wildcard domains specially
    if name == '*':
        return 'star'
    
    # Apply text replacement if provided (from UI input)
    if text_replace_from:
        text_replace_from = text_replace_from.strip()
        if text_replace_from:
            # Split by comma and replace each text
            replace_items = [item.strip() for item in text_replace_from.split(',') if item.strip()]
            for item in replace_items:
                name = name.replace(item, text_replace_to)
    
    # Remove _cs, _CS, _lb, _LB suffixes
    name = re.sub(r'_(cs|CS|lb|LB)_', '_', name)  # Replace _cs_ or _lb_ with _
    name = re.sub(r'_(cs|CS|lb|LB)$', '', name)   # Remove _cs or _lb at the end
    
    # Remove port numbers like _80, _443, _8080, etc
    name = re.sub(r'_\d+_', '_', name)  # Replace _80_ with _ in the middle  
    name = re.sub(r'_\d+$', '', name)   # Remove _80, _443 etc at the end
    
    # Remove _Null, _null, null suffixes
    null_suffixes = ['_Null', '_null', '_NULL', 'Null', 'null', 'NULL']
    for null_suffix in null_suffixes:
        if name.endswith(null_suffix):
            name = name[:-len(null_suffix)]
    
    # Load known suffixes from config
    try:
        from app.routes import get_settings_file
        config_path = get_settings_file()
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
            known_suffixes = config.get('known_suffixes', [])
        else:
            # Default known suffixes
            known_suffixes = []
    except Exception:
        # Fallback to default
        known_suffixes = []
    
    # Replace known suffixes in the middle of the name with _ (routes_old.py logic)
    for suffix in known_suffixes:
        # Replace suffix followed by _ with just _
        name = name.replace(suffix + '_', '_')
        # Also handle cases where suffix appears at the end
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    
    # ELCHI validation: only letters, numbers, underscore (_) and hyphen (-) are allowed
    # Replace dots and other invalid characters with underscore
    name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    
    # Remove consecutive underscores
    name = re.sub(r'_+', '_', name)
    
    # Remove leading/trailing underscores
    name = name.strip('_')
    
    return name


def normalize_name_hcm(name):
    """Normalize name by replacing specific suffixes with _hcm (routes_old.py logic)"""
    # First clean unwanted suffixes
    name = clean_name(name)
    
    suffixes_to_replace = []
    
    # Check if name ends with any of the suffixes
    for suffix in suffixes_to_replace:
        if name.endswith(suffix):
            return name[:-len(suffix)] + '_hcm'
    
    # If no suffix found, add _hcm to the end
    return name + '_hcm'


def get_service_ip_ports(services, servicegroups):
    """Extract IP:port combinations from services and servicegroups"""
    ip_ports = []
    
    # Process direct services
    for service in services:
        service_ip = service.get('ip', '')
        service_port = service.get('port', '')
        if service_ip and service_port:
            ip_ports.append(f"{service_ip}:{service_port}")
    
    # Process service groups
    for sg in servicegroups:
        for member in sg.get('members', []):
            member_ip = member.get('ip', '')
            member_port = member.get('port', '')
            if member_ip and member_port:
                ip_ports.append(f"{member_ip}:{member_port}")
    
    return list(set(ip_ports))  # Remove duplicates