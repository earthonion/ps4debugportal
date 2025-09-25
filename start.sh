#!/bin/bash

# PS4 Memory Debugger Startup Script

# Activate the virtual environment
echo "🔧 Activating virtual environment..."
source ../../.venv/bin/activate

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "⚠️  WARNING: Not running as root!"
    echo "The debugger features require root access."
    echo ""
    echo "For full functionality, run:"
    echo "  sudo bash start.sh"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Start the application
echo "🚀 Starting PS4 Memory Debugger..."
python app.py