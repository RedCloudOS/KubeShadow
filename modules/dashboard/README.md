# KubeShadow Dashboard

A real-time web dashboard for monitoring and visualizing KubeShadow command executions, results, and security findings.

## 🎯 Overview

The KubeShadow Dashboard provides:
- **Real-time monitoring** of command execution
- **Result visualization** with charts and graphs
- **Export functionality** for CSV and PDF reports
- **Historical data** tracking
- **Interactive interface** for exploration
- **WebSocket support** for live updates

## 🚀 Quick Start

### Starting the Dashboard

```bash
# Start dashboard on default port (8080)
./kubeshadow dashboard

# Start on custom port
./kubeshadow dashboard --port 9090

# Run in background
./kubeshadow dashboard --background
```

### Accessing the Dashboard

Once started, the dashboard will display access URLs:

```
🎯 Dashboard starting on http://localhost:8080

═══════════════════════════════════════════════════════════
🌐 DASHBOARD ACCESSIBLE FROM ANYWHERE
═══════════════════════════════════════════════════════════
🌍 VM PUBLIC IP: http://YOUR_VM_PUBLIC_IP:8080
   ↳ This is your VM's public IP - accessible from anywhere on the internet
   ↳ Share this URL to allow remote access to the dashboard

📡 LOCAL NETWORK IPs:
   • http://10.0.0.1:8080
   • http://192.168.1.100:8080

💻 LOCAL ACCESS: http://localhost:8080
═══════════════════════════════════════════════════════════
```

## 🔥 Important: Firewall Configuration

### ⚠️ Cloud Provider Firewall Rules

**To allow remote access to the dashboard, you MUST open port 8080 in your cloud provider's firewall/security group rules:**

#### AWS (EC2 Security Groups)
```bash
# Add inbound rule to security group
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 8080 \
  --cidr 0.0.0.0/0

# Or via AWS Console:
# EC2 → Security Groups → Select your group → Inbound Rules → Add Rule
# Type: Custom TCP, Port: 8080, Source: 0.0.0.0/0 (or specific IP)
```

#### GCP (Firewall Rules)
```bash
# Create firewall rule
gcloud compute firewall-rules create allow-dashboard \
  --allow tcp:8080 \
  --source-ranges 0.0.0.0/0 \
  --description "Allow KubeShadow Dashboard access"

# Or via GCP Console:
# VPC Network → Firewall → Create Firewall Rule
# Direction: Ingress, Action: Allow, Protocol: TCP, Port: 8080
```

#### Azure (Network Security Group)
```bash
# Add inbound security rule
az network nsg rule create \
  --resource-group myResourceGroup \
  --nsg-name myNSG \
  --name allow-dashboard \
  --priority 1000 \
  --protocol Tcp \
  --destination-port-ranges 8080 \
  --access Allow

# Or via Azure Portal:
# Network Security Groups → Select NSG → Inbound security rules → Add
# Service: Custom, Protocol: TCP, Port: 8080, Action: Allow
```

### 🔒 Security Best Practices

- **For Production**: Restrict access to specific IP addresses instead of `0.0.0.0/0`
- **Use VPN**: Consider accessing via VPN for better security
- **HTTPS**: For production use, consider adding a reverse proxy with SSL/TLS
- **Authentication**: The dashboard currently has no authentication - add a reverse proxy with auth for production

## 📊 Features

### Real-Time Monitoring
- Live command execution tracking
- WebSocket-based updates
- Progress indicators
- Status notifications

### Data Visualization
- Command result charts
- Attack map visualization
- Graph builder for relationships
- Timeline views

### Export Capabilities
- CSV export for data analysis
- PDF reports for documentation
- Historical data access
- Filtered exports

### Integration
- Auto-detects running dashboard
- Publishes results automatically
- Works with all KubeShadow modules
- Command history tracking

## 🔧 Usage Examples

### Running Commands with Dashboard

```bash
# Dashboard auto-detects and publishes results
./kubeshadow recon --dashboard

# Explicitly enable dashboard
./kubeshadow lab create --provider gcp --dashboard

# Multiple commands with dashboard
./kubeshadow recon --dashboard
./kubeshadow rbac-escalate --dashboard
./kubeshadow data-exfil --presigned-url "URL" --dashboard
```

### Background Mode

```bash
# Start dashboard in background
./kubeshadow dashboard --background

# Stop background dashboard
./kubeshadow dashboard stop
```

### Custom Port

```bash
# Use custom port
./kubeshadow dashboard --port 9090

# Access at http://YOUR_IP:9090
```

## 🌐 Remote Access

### Accessing from Different Networks

1. **Local Network**: Use the local network IP shown in startup
2. **Internet**: Use the VM public IP shown in startup
3. **SSH Tunnel**: For secure access without opening firewall
   ```bash
   ssh -L 8080:localhost:8080 user@vm-ip
   # Then access http://localhost:8080 locally
   ```

### Troubleshooting Remote Access

**Dashboard not accessible remotely?**
1. ✅ Check firewall rules are configured (see above)
2. ✅ Verify dashboard shows "VM PUBLIC IP" in startup
3. ✅ Ensure port 8080 is not blocked by local firewall
4. ✅ Check cloud provider security group/NSG rules
5. ✅ Verify VM has a public IP address assigned

**Port already in use?**
```bash
# Use different port
./kubeshadow dashboard --port 8081
```

## 📡 API Endpoints

The dashboard exposes several API endpoints:

- `GET /api/results` - Get all command results
- `GET /api/stats` - Get dashboard statistics
- `POST /api/publish` - Publish command result
- `GET /api/export/csv` - Export results as CSV
- `GET /api/export/pdf` - Export results as PDF
- `WS /ws` - WebSocket for real-time updates
- `WS /ws/enhanced` - Enhanced WebSocket endpoint

## 🛠️ Configuration

### Environment Variables

- `KUBESHADOW_DASHBOARD_PORT` - Default port (default: 8080)
- `KUBESHADOW_DASHBOARD_HOST` - Bind address (default: 0.0.0.0)

### Storage

- **SQLite Database**: Persistent storage (requires CGO_ENABLED=1)
- **In-Memory Mode**: Fallback when CGO is disabled
- **Database Location**: `kubeshadow.db` in current directory

## 🔍 Troubleshooting

### Dashboard Won't Start

```bash
# Check if port is in use
netstat -tulpn | grep 8080

# Try different port
./kubeshadow dashboard --port 8081
```

### Can't Access Remotely

1. Verify firewall rules (see Firewall Configuration above)
2. Check VM has public IP
3. Verify security group allows port 8080
4. Test with curl: `curl http://VM_PUBLIC_IP:8080/api/stats`

### Storage Warnings

If you see CGO warnings, the dashboard will use in-memory mode:
- Data is lost on restart
- For persistence, rebuild with `CGO_ENABLED=1`

## 📝 Notes

- The dashboard listens on `0.0.0.0:8080` by default (all interfaces)
- Public IP is automatically detected when dashboard starts
- No authentication is required - add reverse proxy for production
- Dashboard works with all KubeShadow modules automatically
- Background mode allows dashboard to run while executing other commands

## 🔗 Related Documentation

- [Main README](../README.md)
- [Lab Module README](../lab/README.md)
- [Exploitation Module README](../exploitation/README.md)

