#!/bin/bash

# Create and activate virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate the virtual environment
if [ "$OSTYPE" == "msys" ] || [ "$OSTYPE" == "win32" ]; then
    # Windows (Git Bash)
    source venv/Scripts/activate
else
    # Unix-like
    source venv/bin/activate
fi

# Upgrade pip
pip install --upgrade pip

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

# Check for nmap
if ! command -v nmap &> /dev/null; then
    echo "WARNING: nmap is not installed or not in PATH."
    echo "Nmap is required for port scanning functionality."
    echo "Please install nmap using one of the following commands:"
    echo "  Debian/Ubuntu: sudo apt-get install nmap"
    echo "  RHEL/CentOS:  sudo yum install nmap"
    echo "  macOS:        brew install nmap"
    echo "  Windows:      Download from https://nmap.org/download.html"
    echo -e "\nYou can still use the socket-based scanner, but it has limited functionality.\n"
    read -p "Press Enter to continue or Ctrl+C to cancel..."
fi

# Run the application
echo -e "\nStarting CyberSentinel...\n"
python -m cybersentinel.gui_main
