# PowerShell script to start the API server

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "MALWARE DETECTION API SERVER" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if uvicorn is installed
Write-Host "Checking if uvicorn is installed..." -ForegroundColor Yellow
$uvicornCheck = uvicorn --version 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ uvicorn is not installed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Installing uvicorn..." -ForegroundColor Yellow
    pip install uvicorn[standard]
    Write-Host ""
}

Write-Host "✓ Starting API server..." -ForegroundColor Green
Write-Host ""
Write-Host "Server will be available at:" -ForegroundColor Cyan
Write-Host "  • API: http://localhost:8000" -ForegroundColor White
Write-Host "  • Interactive Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host "  • ReDoc: http://localhost:8000/redoc" -ForegroundColor White
Write-Host ""
Write-Host "Press CTRL+C to stop the server" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Start the server
uvicorn app_email_scanner:app --reload --host 0.0.0.0 --port 8000
