#!/bin/bash
# Setup script for KubeShadow (already in directory)

echo "=== Installing Go 1.24.3 (Required by KubeShadow) ==="
wget https://go.dev/dl/go1.24.3.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export GOBIN=$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

echo "=== Building KubeShadow ==="
go mod tidy
go build -o kubeshadow .
chmod +x kubeshadow

echo "=== Version Check ==="
go version
./kubeshadow --version

echo "Setup complete!" 