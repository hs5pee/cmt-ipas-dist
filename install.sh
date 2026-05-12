#!/bin/bash
# CMT-IPAS Linux Online Installer (install.sh)
# Usage: curl -sSL https://cmt-sys.com/install.sh | sudo bash

URL="https://cmt-sys.com/CMT-IPAS-Release.zip"
INSTALL_DIR="/opt/cmt-ipas"

echo "--- CMT-IPAS Linux Online Installer ---"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (sudo)"
  exit 1
fi

# 2. Check for unzip (required for zip files)
if ! command -v unzip &> /dev/null; then
    echo "unzip could not be found, installing..."
    apt-get update && apt-get install -y unzip || yum install -y unzip
fi

# 3. Download and Extract
mkdir -p $INSTALL_DIR
echo "Downloading CMT-IPAS from cmt-sys.com..."
TEMP_ZIP="/tmp/cmt-ipas.zip"
curl -L $URL -o $TEMP_ZIP

echo "Extracting to $INSTALL_DIR..."
unzip -o $TEMP_ZIP -d $INSTALL_DIR
rm $TEMP_ZIP

# Ensure binary is executable
chmod +x $INSTALL_DIR/cmt-ipas

# 4. Create Systemd Service
echo "Creating systemd service..."
cat <<EOF > /etc/systemd/system/cmt-ipas.service
[Unit]
Description=CMT-IPAS Industrial Audio Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/cmt-ipas
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# 5. Start Service
systemctl daemon-reload
systemctl enable cmt-ipas
systemctl start cmt-ipas

echo "Successfully installed and started CMT-IPAS service."
echo "Check status with: systemctl status cmt-ipas"
