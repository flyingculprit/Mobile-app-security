#!/bin/bash

# Update package lists
echo "Updating package lists..."
sudo apt-get update

# Install Java (required for apktool)
echo "Installing Java..."
sudo apt-get install -y default-jre

# Install apktool
echo "Installing apktool..."
APKTOOL_VERSION="2.7.0"  # Change this to the desired version
APKTOOL_JAR="apktool_${APKTOOL_VERSION}.jar"
APKTOOL_INSTALL_DIR="/usr/local/bin"

# Download apktool and the wrapper script
wget "https://github.com/iBotPeaches/Apktool/releases/download/${APKTOOL_VERSION}/${APKTOOL_JAR}" -O "/tmp/${APKTOOL_JAR}"
wget "https://github.com/iBotPeaches/Apktool/releases/download/${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.tar.bz2" -O "/tmp/apktool_${APKTOOL_VERSION}.tar.bz2"

# Install apktool
sudo mkdir -p "${APKTOOL_INSTALL_DIR}"
sudo mv "/tmp/${APKTOOL_JAR}" "${APKTOOL_INSTALL_DIR}/apktool.jar"
sudo chmod +x "${APKTOOL_INSTALL_DIR}/apktool.jar"
sudo ln -s "${APKTOOL_INSTALL_DIR}/apktool.jar" "/usr/local/bin/apktool"

# Create a symlink for apktool
echo "Creating symlink for apktool..."
sudo ln -s "${APKTOOL_INSTALL_DIR}/apktool.jar" "/usr/local/bin/apktool"

# Install Python dependencies
echo "Installing Python dependencies..."
pip install flask

# Confirm installation
echo "Verifying installations..."
java -version
apktool --version
python3 -m pip show flask

echo "Setup complete!"


# Install Python packages
echo "Installing Python packages..."
pip install -r requirements.txt

echo "Setup complete!"
