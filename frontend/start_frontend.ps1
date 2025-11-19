# PowerShell script to start the React frontend

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "MALWARE DETECTION - REACT FRONTEND" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if node_modules exists
if (-not (Test-Path "node_modules")) {
    Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
    Write-Host ""
    npm install
    Write-Host ""
}

Write-Host "✓ Starting React development server..." -ForegroundColor Green
Write-Host ""
Write-Host "Frontend will be available at:" -ForegroundColor Cyan
Write-Host "  • http://localhost:3000" -ForegroundColor White
Write-Host ""
Write-Host "Make sure the API backend is running at http://localhost:8000" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press CTRL+C to stop the server" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Start the dev server
npm run dev
