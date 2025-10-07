# KubeShadow Quick Build Script for Windows
# Bypasses CGO issues and builds reliably

Write-Host "🔨 Building KubeShadow..." -ForegroundColor Green
Write-Host "📦 Checking dependencies... (10%)" -ForegroundColor Yellow
go mod tidy

Write-Host "🧹 Cleaning previous builds... (20%)" -ForegroundColor Yellow
go clean -cache

Write-Host "🔧 Building without CGO (fast and reliable)... (30%)" -ForegroundColor Yellow
Write-Host "⏳ Compiling Go modules... (40%)" -ForegroundColor Yellow

# Build without CGO to avoid compilation issues
$env:CGO_ENABLED = "0"
go build -ldflags="-s -w" -o kubeshadow.exe .

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Build successful! (100%)" -ForegroundColor Green
    Write-Host "🔧 Making executable... (90%)" -ForegroundColor Yellow
    Write-Host "🎉 KubeShadow built successfully! (100%)" -ForegroundColor Green
    Write-Host "💡 Run './kubeshadow.exe help' to get started" -ForegroundColor Cyan
} else {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}
