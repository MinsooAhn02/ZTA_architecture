# ZTA Port-Forward Launcher
# Opens Keycloak, Kiali, Grafana each in a separate PowerShell window

Write-Host ">>> Starting port-forwards in separate windows..." -ForegroundColor Cyan

# Kill existing port-forwards
Get-Process -Name "kubectl" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*port-forward*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue

Start-Process powershell -ArgumentList "-NoExit", "-Command",
    "Write-Host '[Keycloak] localhost:8080' -ForegroundColor Yellow; kubectl port-forward svc/keycloak 8080:8080" `
    -WindowStyle Normal

Start-Sleep -Seconds 1

Start-Process powershell -ArgumentList "-NoExit", "-Command",
    "Write-Host '[Kiali] localhost:20001' -ForegroundColor Green; kubectl port-forward svc/kiali -n istio-system 20001:20001" `
    -WindowStyle Normal

Start-Sleep -Seconds 1

Start-Process powershell -ArgumentList "-NoExit", "-Command",
    "Write-Host '[Grafana] localhost:3000' -ForegroundColor Magenta; kubectl port-forward svc/grafana -n istio-system 3000:3000" `
    -WindowStyle Normal

Write-Host ""
Write-Host "  Keycloak : http://localhost:8080" -ForegroundColor Yellow
Write-Host "  Kiali    : http://localhost:20001" -ForegroundColor Green
Write-Host "  Grafana  : http://localhost:3000" -ForegroundColor Magenta
Write-Host ""
Write-Host "각 창을 닫으면 해당 port-forward가 종료됩니다." -ForegroundColor Gray
