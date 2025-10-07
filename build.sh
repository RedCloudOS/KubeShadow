#!/bin/bash

# KubeShadow Quick Build Script
# Bypasses CGO issues and builds reliably

echo "🔨 Building KubeShadow..."
echo "📦 Checking dependencies... (10%)"
go mod tidy

echo "🧹 Cleaning previous builds... (20%)"
go clean -cache

echo "🔧 Building without CGO (fast and reliable)... (30%)"
echo "⏳ Compiling Go modules... (40%)"

# Build without CGO to avoid compilation issues
CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .

if [ $? -eq 0 ]; then
    echo "✅ Build successful! (100%)"
    echo "🔧 Making executable... (90%)"
    chmod +x kubeshadow
    echo "🎉 KubeShadow built successfully! (100%)"
    echo "💡 Run './kubeshadow help' to get started"
else
    echo "❌ Build failed!"
    exit 1
fi
