#!/bin/bash

# KubeShadow Lab Cleanup Script
# This script removes all lab resources

echo "🧹 Cleaning up KubeShadow Lab Environment..."

# Remove persistent volumes
echo "💾 Removing persistent volumes..."
kubectl delete -f 08-persistent-volumes.yaml --ignore-not-found=true

# Remove network policies
echo "🛡️ Removing network policies..."
kubectl delete -f 07-network-policies.yaml --ignore-not-found=true

# Remove configmaps
echo "⚙️ Removing configmaps..."
kubectl delete -f 06-configmaps.yaml --ignore-not-found=true

# Remove secrets
echo "🔑 Removing secrets..."
kubectl delete -f 05-secrets.yaml --ignore-not-found=true

# Remove services
echo "🌐 Removing services..."
kubectl delete -f 04-services.yaml --ignore-not-found=true

# Remove pods
echo "🚀 Removing pods..."
kubectl delete -f 03-pods.yaml --ignore-not-found=true

# Remove RBAC
echo "🔐 Removing RBAC configurations..."
kubectl delete -f 02-rbac.yaml --ignore-not-found=true

# Remove namespaces
echo "📁 Removing namespaces..."
kubectl delete -f 01-namespace.yaml --ignore-not-found=true

echo ""
echo "✅ Lab environment cleanup complete!"
echo "All KubeShadow lab resources have been removed."
