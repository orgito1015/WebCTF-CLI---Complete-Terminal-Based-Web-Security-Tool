#!/bin/bash

# WebCTF CLI Quick Start Script
# This script sets up the tool and runs a quick demo

echo "🔒 WebCTF CLI - Quick Start"
echo "=========================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

echo "✓ Node.js detected: $(node --version)"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
npm install --silent

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Make CLI executable
chmod +x webctf-cli.js
chmod +x examples.js

echo ""
echo "✓ WebCTF CLI is ready!"
echo ""
echo "Quick Start Guide:"
echo "=================="
echo ""
echo "1. Start the interactive CLI:"
echo "   node webctf-cli.js"
echo ""
echo "2. Run example scenarios:"
echo "   node examples.js"
echo ""
echo "3. Quick commands to try:"
echo "   webctf> go https://example.com"
echo "   webctf> requests"
echo "   webctf> cookies"
echo "   webctf> storage"
echo "   webctf> js document.title"
echo "   webctf> help"
echo ""
echo "For full documentation, see README.md"
echo ""

# Offer to run a quick demo
read -p "Would you like to run a quick demo? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Running quick demo..."
    echo ""
    node examples.js
fi

echo ""
echo "Happy hacking! 🚀"
echo ""
