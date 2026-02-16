#!/bin/bash
# Run Entropy server locally in development mode

export ENTROPY_ENVIRONMENT=development
export ENTROPY_LOG_LEVEL=DEBUG

# Activate venv if exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

echo "🔥 Starting Entropy Firewall..."
python -m entropy.cli.main server --reload --port 8000
