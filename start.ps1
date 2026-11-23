# Culkibo Orchestrator v1.0.0 — Quick Launcher
$Host.UI.RawUI.WindowTitle = "Culkibo v1.0.0 Orchestrator"
Write-Host "========================================================" -ForegroundColor Yellow
Write-Host "  ⚡ CULKIBO ORCHESTRATOR v1.0.0 — AI-ERA CLOUD PLATFORM  " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Yellow
Write-Host "  The Forge (desarrollo) y The Citadel (produccion)      " -ForegroundColor Gray
Write-Host "  Cloudflare DNS-01 Wildcard SSL & Native MCP Server    " -ForegroundColor Gray
Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray

$root = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Check if web/dist exists, if not build it
if (-not (Test-Path "$root\web\dist")) {
    Write-Host "[*] Building web dashboard assets..." -ForegroundColor Yellow
    npm --prefix "$root\web" run build
}

Write-Host "[*] Starting Culkibo Daemon..." -ForegroundColor Green
node "$root\bin\culkibo.js" start --port 3030
