# PQCValidator.jl

A Julia package for validating Post-Quantum Cryptography (PQC) implementations in TLS 1.3 connections. This tool provides comprehensive testing capabilities for both external endpoints and laboratory environments.

## Features

- **Dual Mode Operation**: Support for both external endpoint testing and offline laboratory validation
- **TLS 1.3 Handshake Verification**: Complete validation of PQC-enabled TLS 1.3 connections
- **Key Exchange Analysis**: Verification of hybrid key exchange mechanisms (classical + post-quantum)
- **Trace Consistency Checking**: Analysis of TLS key logs for cryptographic consistency
- **Configurable Testing**: Flexible configuration through TOML files and command-line arguments

## Quick Start

```bash
$ bash run.sh
```

## Installation

### Prerequisites

- Julia 1.6 or later
- OpenSSL (for external mode)
- liboqs library (for laboratory mode, optional)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd PQCValidator.jl
```

2. Install Julia dependencies:
```bash
julia --project=. -e "using Pkg; Pkg.instantiate()"
```

3. For laboratory mode, ensure liboqs is installed on your system.

## Usage

### Command Line Interface

```bash
julia bin/pqc-validate.jl [OPTIONS]
```

#### Options

- `--mode <external|lab>`: Operation mode (default: external)
- `--host <hostname>`: Target hostname for external mode
- `--port <port>`: Target port number
- `--sni <servername>`: Server Name Indication
- `--group <group>`: Force specific named group
- `--keylog <path>`: Path to TLS key log file (default: keylog.txt)
- `--hash <algorithm>`: Hash algorithm for validation
- `--acceptable <groups>`: Comma-separated list of acceptable groups

### External Mode

Test a live TLS endpoint:

```bash
julia bin/pqc-validate.jl --mode external --host example.com --port 443
```

### Laboratory Mode

Run offline validation with synthetic data:

```bash
julia bin/pqc-validate.jl --mode lab
```

## Configuration

The tool uses `config.toml` for default settings. You can override any configuration value using command-line arguments or environment variables.

## Current Status

### ✅ Implemented Features
- Basic PQC validation logic
- Support for both External and Lab modes
- TLS 1.3 handshake verification functionality
- Configuration loading system
- JSON output for audit trails

### ❌ Known Issues
- Dependencies need to be properly configured
- Limited test coverage
- Documentation needs improvement

## Development Roadmap

### 🚧 High Priority - Core Functionality

#### 1. Dependency Resolution
- [x] **Sodium.jl dependency**: Already added to Project.toml
- [x] **SHA.jl dependency**: Already added to Project.toml
- [ ] **liboqs system dependency check**: Add installation verification for `OQS.jl:3`

#### 2. Error Handling Improvements
- [ ] **OpenSSL command robustness**: Enhance error handling in `TLSProbe.jl:14-18` with detailed diagnostics
- [ ] **liboqs library call validation**: Implement return value checking for `OQS.jl:10,13,16` ccall operations
- [ ] **File operation error handling**: Improve exception handling in `TraceConsistency.jl:20` after isfile() checks

#### 3. Configuration Integration
- [ ] **config.toml implementation**: Currently exists but not used in `bin/pqc-validate.jl`
- [ ] **Command-line vs config priority**: Define precedence rules for configuration sources

### 🔧 Feature Enhancements

#### 4. Testing Implementation
- [ ] **Unit tests**: Add test files for each module
- [ ] **Integration tests**: Implement external/lab mode operation verification
- [ ] **CI/CD pipeline**: Set up automated testing infrastructure

#### 5. Documentation
- [ ] **Comprehensive README**: Add installation procedures and feature descriptions
- [ ] **Module docstrings**: Document all public functions and types
- [ ] **Usage guides**: Create examples and configuration guides

#### 6. Code Quality Improvements
- [ ] **Type safety in HKDFHelpers.jl**: Improve type checking in `hkdf_expand_label:29-33` string operations
- [ ] **TraceConsistency.jl parsing**: Enhance `parse_keylog:22-27` for malformed input handling
- [ ] **Constants consolidation**: Centralize scattered constant values across modules

### 📦 Performance & Security

#### 7. Security Enhancements
- [ ] **Memory clearing**: Implement secure deletion of private keys and shared secrets
- [ ] **Input validation**: Strengthen validation for external inputs (hostnames, ports, etc.)
- [ ] **Log filtering**: Filter sensitive information from log outputs

#### 8. Performance Optimization
- [ ] **Memory allocation optimization**: Especially in `HKDFHelpers.jl` iterative processes
- [ ] **Parallel processing**: Consider concurrent execution for multiple endpoint validation

### 🎯 Release Preparation

#### 9. Release Management
- [ ] **Versioning strategy**: Define semantic versioning approach
- [ ] **Package publishing**: Prepare for Julia General registry submission
- [ ] **License and copyright**: Complete legal information setup

#### 10. Operations & Maintenance
- [ ] **Logging system**: Implement detailed execution and debug logging
- [ ] **Configuration validation**: Add startup-time configuration value checking
- [ ] **Help system**: Implement usage and help display functionality

## Architecture

The package consists of several key modules:

- **PQCValidator.jl**: Core validation logic and data structures
- **TLSProbe.jl**: External endpoint testing via OpenSSL
- **LabHarness.jl**: Laboratory mode testing with synthetic data
- **TraceConsistency.jl**: TLS key log analysis and validation
- **HKDFHelpers.jl**: HKDF (HMAC-based Key Derivation Function) utilities
- **OQS.jl**: Interface to liboqs library for post-quantum algorithms
- **ConfigLoader.jl**: Configuration file and argument parsing

## Output

The tool generates:

1. **Console output**: Human-readable validation results table
2. **audit.json**: Machine-readable JSON artifact with detailed results
3. **Exit codes**: 0 for pass, 1 for fail, 2 for errors

## Contributing

Contributions are welcome! Please focus on:

1. Resolving dependency issues
2. Improving error handling and robustness
3. Adding comprehensive tests
4. Enhancing documentation

## License

[License information to be added]

## Support

For issues and questions, please use the project's issue tracker.