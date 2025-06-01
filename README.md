# KubeShadow

KubeShadow is a powerful Kubernetes security testing and exploitation toolkit designed for red team operations and security assessments. It provides a comprehensive suite of modules for testing cluster security, identifying misconfigurations, and validating security controls.

## Features

### Core Capabilities
- **Modular Architecture**: Extensible plugin system for custom functionality
- **Multiple Attack Vectors**: Support for various exploitation techniques
- **Comprehensive Reconnaissance**: Detailed cluster and cloud environment analysis
- **Stealth Operations**: Low-visibility testing capabilities
- **Cloud Integration**: Multi-cloud provider support (AWS, GCP, Azure)
- **Robust Error Handling**: Comprehensive error management and reporting
- **Detailed Logging**: Configurable logging with level filtering

### Module Categories

#### 1. Cluster Exploitation (`modules/cluster_exploit/`)
- **ETCD Injection**: Direct pod injection via etcd
- **Kubelet Exploitation**: Kubelet API exploitation and hijacking
- **Sidecar Injection**: Pod sidecar container injection
- **RBAC Escalation**: RBAC privilege escalation and permission analysis
- **Namespace Pivot**: Cross-namespace access and privilege movement

#### 2. Cloud Exploitation (`modules/multi_cloud/`)
- **Metadata Hijacking**: Cloud metadata service exploitation
- **Cloud Privilege Escalation**: Cloud IAM privilege escalation
- **Assume Role Abuse**: Cloud role assumption and token abuse
- **Cloud Elevator**: Automated cloud privilege escalation paths

#### 3. Reconnaissance (`modules/recon/`)
- **Cluster Reconnaissance**: Comprehensive Kubernetes cluster information gathering
  - RBAC analysis
  - Network policy enumeration
  - Service account discovery
  - Pod security context analysis
  - Node information gathering

#### 4. Stealth Operations (`modules/stealth/`)
- **Audit Bypass**: Audit policy bypass testing and analysis
- **DNS Cache Poisoning**: DNS cache poisoning and spoofing attacks
- **Cleanup Operations**: Evidence removal and operation cleanup
  - Log sanitization
  - Resource cleanup
  - Operation trace removal
  - Evidence elimination

## Installation

```bash
go get github.com/ashifly/KubeShadow
```

## Quick Start

1. Basic reconnaissance:
```bash
kubeshadow recon --kubeconfig ~/.kube/config
```

2. View available commands:
```bash
kubeshadow --help
```

## Common Usage Patterns

### 1. Initial Reconnaissance
```bash
# Full cluster and cloud recon
kubeshadow recon

# Only Kubernetes recon
kubeshadow recon --k8s-only

# Only cloud recon
kubeshadow recon --cloud-only
```

### 2. Privilege Escalation
```bash
# RBAC escalation
kubeshadow rbac-escalate --kubeconfig ~/.kube/config

# Cloud privilege escalation
kubeshadow cloud-elevator
```

### 3. Pod Manipulation
```bash
# Sidecar injection
kubeshadow sidecarinject --mode api --pod target-pod --namespace default

# ETCD injection
kubeshadow etcdinject --endpoint https://etcd:2379 --cert cert.pem --key key.pem --ca ca.pem
```

## Security Considerations

1. **Legal and Ethical Use**
   - Only use on systems you own or have explicit permission to test
   - Follow responsible disclosure practices
   - Document all testing activities

2. **Safe Testing Practices**
   - Use in isolated test environments
   - Avoid production systems
   - Implement proper logging and monitoring
   - Clean up after testing

3. **Required Permissions**
   - Cluster admin or equivalent for full functionality
   - Service account with appropriate RBAC
   - Cloud provider credentials for cloud modules

## Project Structure

```
KubeShadow/
├── modules/                 # Core exploitation modules
│   ├── cluster_exploit/    # Cluster exploitation tools
│   ├── multi_cloud/        # Cloud provider exploitation
│   ├── recon/             # Reconnaissance tools
│   └── stealth/           # Stealth operation tools
├── pkg/                    # Supporting packages
│   ├── banner/            # CLI banner utilities
│   ├── config/            # Configuration management
│   ├── errors/            # Error handling
│   ├── etcd/              # ETCD client utilities
│   ├── k8s/               # Kubernetes client utilities
│   ├── kubelet/           # Kubelet API utilities
│   ├── logger/            # Logging utilities
│   ├── modules/           # Module interfaces
│   ├── plugins/           # Plugin system
│   ├── recon/             # Reconnaissance utilities
│   ├── registry/          # Module registry
│   ├── testutil/          # Testing utilities
│   ├── types/             # Common types
│   └── utils/             # General utilities
├── docs/                  # Documentation
├── examples/              # Usage examples
└── resources/            # Resource files
```

## Documentation

Detailed documentation is available in the `docs/` directory:
- [Architecture Overview](docs/architecture.md)
- [Module Documentation](docs/modules/)
- [Troubleshooting Guide](docs/troubleshooting.md)
- [Contributing Guide](CONTRIBUTING.md)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes.