#!/bin/bash

# Update package list and install necessary tools
echo "Updating package list and installing required tools..."
sudo apt-get update

# Install Java
echo "Installing Java..."
sudo apt-get install -y openjdk-11-jre  # Adjust the Java version if needed

# Install apktool
echo "Installing apktool..."
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.7.0/apktool_2.7.0.jar -O /usr/local/bin/apktool.jar
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.7.0/apktool -O /usr/local/bin/apktool
chmod +x /usr/local/bin/apktool
sudo ln -s /usr/local/bin/apktool /usr/local/bin/apktool

# Install Python packages
echo "Installing Python packages..."
pip install -r requirements.txt

echo "Setup complete!"
