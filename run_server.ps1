# Run Entropy server locally in development mode

$env:ENTROPY_ENVIRONMENT = "development"
$env:ENTROPY_LOG_LEVEL = "DEBUG"

Write-Host "🔥 Starting Entropy Firewall..." -ForegroundColor Cyan
python -m entropy.cli.main server --reload --port 8000
