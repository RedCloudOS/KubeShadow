# KubeShadow

KubeShadow is a powerful Kubernetes shadow pod management system designed for testing and development environments. It provides a flexible framework for managing shadow pods with different injection strategies.

## Features

- **Modular Architecture**: Extensible plugin system for custom functionality
- **Multiple Injection Modes**: Support for API and etcd-based pod management
- **Configuration Management**: Flexible and validated configuration system
- **Comprehensive Logging**: Configurable logging with level filtering
- **Plugin System**: Extend functionality with custom plugins
- **Metrics Collection**: Built-in metrics plugin for monitoring
- **Error Handling**: Robust error management and reporting

## Installation

```bash
go get github.com/ashifly/KubeShadow
```

## Quick Start

1. Create a configuration file:
```yaml
log_level: info
modules:
  sidecar:
    enabled: true
    config:
      image: test-image:latest
```

2. Run KubeShadow:
```bash
kubeshadow --config config.yaml
```

## Plugin System

KubeShadow provides a powerful plugin system that allows you to extend its functionality. Plugins can be used for:

- Metrics collection
- Custom monitoring
- Additional injection strategies
- Resource management
- Custom validations

### Creating a Plugin

1. Implement the `Plugin` interface:
```go
type Plugin interface {
    Name() string
    Version() string
    Initialize(ctx context.Context) error
    Execute(ctx context.Context) error
    Cleanup(ctx context.Context) error
    GetStatus() *PluginStatus
}
```

2. Register your plugin:
```go
registry := NewPluginRegistry()
plugin := NewMyPlugin()
registry.RegisterPlugin(plugin)
```

### Available Plugins

- **Metrics Plugin**: Collects and reports system metrics
- **Sidecar Plugin**: Manages shadow pod injection
- More plugins coming soon!

## Configuration

KubeShadow uses a YAML configuration file with the following structure:

```yaml
log_level: info
modules:
  sidecar:
    enabled: true
    config:
      image: test-image:latest
  metrics:
    enabled: true
    config:
      interval: 30s
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Roadmap

- [ ] Additional plugin types
- [ ] Enhanced monitoring
- [ ] Advanced security features
- [ ] Performance optimizations
- [ ] More documentation
- [ ] Community examples