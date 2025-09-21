# ELCHI Migrator

A web-based migration tool that automatically converts NetScaler configurations to ELCHI Envoy Gateway.

## 🚀 Features

- **NetScaler Integration**: Automatic discovery and analysis of CS and LB vServers
- **ELCHI Integration**: Direct submission of Envoy configurations to ELCHI API
- **DNS Management**: Load CoreDNS zone files and automatic domain-IP mapping recognition
- **Cluster Discovery**: Automatic cluster name discovery from service IPs
- **Web Interface**: User-friendly Flask-based web interface
- **Template Generation**: Listener, Route, Cluster, Endpoint, HCM, and TCP proxy configurations

## 📋 Requirements

- Python 3.8+
- NetScaler access credentials
- ELCHI API access
- CoreDNS zone files (optional)

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/elchi-migrator.git
cd elchi-migrator
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```


## 🚀 Getting Started

Start the application:
```bash
python run.py
```

Access the web interface: `http://localhost:5001`

## 📖 Usage Guide

### 1. NetScaler Connection

1. Click **NetScaler Login** button on the homepage
2. Enter NetScaler IP/hostname, username, and password
3. Click **Login** button

### 2. ELCHI Connection

1. Click **ELCHI Login** button on the homepage
2. Enter ELCHI URL, username, and password
3. Click **Login** button

### 3. Loading DNS Zone Files

1. Navigate to **Settings** page
2. Upload CoreDNS zone files in `.txt` or `.zone` format in the **DNS Zones** section (no other file types accepted)
3. Files are automatically processed and domain-IP mappings are created

### 4. Viewing VServer List

1. Navigate to **VServers** page
2. View your CS and LB vServers
3. Use **Refresh Data** to fetch current data from NetScaler
4. Use filtering and search features

### 5. VServer Analysis and Migration

1. Select a vServer from the list
2. Click **Analyze** button
3. Review analysis results:
   - Domain mappings
   - Cluster information
   - Service/ServiceGroup details
   - CS Policies (for CS vServers)
4. Click **Generate Templates** to create ELCHI configurations
5. Review and edit templates
6. Click **Send to ELCHI** to submit configurations to ELCHI

### 6. Progress Tracking

- Completed vServers are automatically marked
- Track with **Completed** badge
- View statistics on **Settings** page

## 🔧 Configuration

### DNS Zone File Format

Zone files should be in the following format:
```
$ORIGIN example.com.
domain1.example.com. IN A 10.1.1.1
domain2.example.com. IN A 10.1.1.2
*.subdomain.example.com. IN A 10.1.1.3
```

## 📊 Feature Details

### Supported VServer Types
- **CS (Content Switching)**: L7 routing rules
- **LB (Load Balancing)**: L4/L7 load balancing

### Generated ELCHI Configurations
- **Listener**: Inbound traffic listeners
- **Route**: URL-based routing rules
- **Cluster**: Upstream cluster definitions
- **Endpoint**: Backend endpoint definitions
- **HCM**: HTTP Connection Manager filters
- **TCP Proxy**: TCP-level proxy configurations

### Automatic Features
- SSL certificate detection and TLS context creation
- Wildcard domain support
- Service discovery and cluster mapping
- Policy-based routing analysis
