Write-Host "Running Selo cryptographic accounting skill verification..." -ForegroundColor Cyan
cargo test --workspace
if ($LASTEXITCODE -ne 0) {
Write-Host "Selo skill test failed." -ForegroundColor Red
exit $LASTEXITCODE
}
Write-Host "Selo skill test completed successfully." -ForegroundColor Green