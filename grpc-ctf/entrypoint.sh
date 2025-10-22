#!/bin/bash
set -e

# Generate random hex suffix
SUFFIX=$(tr -dc 'a-f0-9' < /dev/urandom | head -c 10)

# Rename flag file
mv /flag.txt /flag_${SUFFIX}.txt

echo "Flag file created: /flag_${SUFFIX}.txt"
echo "Starting application..."

# Start application (use exec so signals work correctly)
exec python app.py
