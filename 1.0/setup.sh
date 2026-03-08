#!/bin/bash

# Update package lists
echo "Updating package lists..."
sudo apt-get update

# Install Java (required for apktool)
echo "Installing Java..."
sudo apt-get install -y default-jre

# Install apktool
echo "Installing apktool..."
sudo apt-get install -y apktool

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Run the extract_features.py script
echo "Running extract_features.py..."
python3 extract_features.py

echo "Setup complete."
