# Open Problem Toolkit

A comprehensive Julia toolkit for learning and implementing modern cryptographic systems. This educational platform helps university students understand and work with cutting-edge encryption techniques that protect our digital world.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Julia 1.10+](https://img.shields.io/badge/julia-1.10+-blue.svg)](https://julialang.org)

## 🚀 Overview

The Open Problem Toolkit provides specialized packages for modern cryptographic research and development:

- **🔐 HomomorphicCryptography.jl** - Perform computations on encrypted data without decrypting it first, enabling privacy-preserving cloud computing
- **🛡️ PQCValidator.jl** - Validate cryptographic systems against quantum computer attacks using post-quantum algorithms
- **🔍 ZKPValidator.jl** - Prove you know something without revealing the information itself (e.g., prove you're over 18 without showing your birth date)
- **🔒 LibOQS.jl** - Access quantum-safe cryptographic algorithms through Julia bindings to the Open Quantum Safe library
- **🧮 LatticeBasedCryptography.jl** - Learn lattice-based cryptography through interactive tools and visualizations

## 🎯 Use Cases

### Privacy-Preserving Healthcare
Use **HomomorphicCryptography.jl** to analyze encrypted patient data in the cloud without exposing sensitive medical information.

### Quantum-Safe Communications
Deploy **PQCValidator.jl** and **LibOQS.jl** to ensure your TLS connections remain secure even against future quantum computers.

### Anonymous Credentials
Build systems with **ZKPValidator.jl** that verify user attributes (age, membership, credentials) without revealing personal information.

### Cryptography Education
Use **LatticeBasedCryptography.jl** interactive notebooks to teach students the mathematical foundations of modern post-quantum cryptography.

### Research & Development
Experiment with cutting-edge cryptographic protocols in a well-structured, documented environment with all packages.

## 🏃 Quick Start

### Prerequisites
- Julia 1.10 or later ([download here](https://julialang.org/downloads/))
- Git

### Your First Example

Get started with lattice-based cryptography in under 5 minutes:

```bash
# Clone and navigate
git clone https://github.com/Kiara-Dev-Team/open-problem-toolkit.git
cd open-problem-toolkit/LatticeBasedCryptography.jl

# Install dependencies
julia --project=. -e "using Pkg; Pkg.instantiate()"

# Launch interactive notebook
julia --project=. playground/pluto/lattice_demo.jl
```

This opens an interactive Pluto notebook where you can experiment with lattice reduction algorithms, see encryption in action, and visualize the mathematical structures that make post-quantum cryptography possible.

## 📦 Package Structure

```
open-problem-toolkit/
├── HomomorphicCryptography.jl/       # Homomorphic encryption library
├── PQCValidator.jl/                  # Post-quantum crypto validator
├── ZKPValidator.jl/                  # Zero-knowledge proof validator
├── LibOQS.jl/                       # Open Quantum Safe Julia bindings
├── LatticeBasedCryptography.jl/      # Lattice cryptography educational toolkit
│   ├── playground/
│   │   └── pluto/                    # Interactive Pluto notebooks
│   └── src/                          # Core implementations
├── CONTRIBUTING.md                   # Contribution guidelines
└── LICENSE                           # MIT License
```

## 🛠️ Installation

### Option 1: Quick Install Script (Recommended)

```bash
git clone https://github.com/Kiara-Dev-Team/open-problem-toolkit.git
cd open-problem-toolkit
julia install_all.jl
```

### Option 2: Individual Package Installation

Install only the packages you need:

```bash
# HomomorphicCryptography.jl
cd HomomorphicCryptography.jl
julia --project=. -e "using Pkg; Pkg.instantiate()"

# PQCValidator.jl
cd ../PQCValidator.jl
julia --project=. -e "using Pkg; Pkg.instantiate()"

# ZKPValidator.jl
cd ../ZKPValidator.jl
julia --project=. -e "using Pkg; Pkg.instantiate()"

# LibOQS.jl
cd ../LibOQS.jl
julia --project=. -e "using Pkg; Pkg.instantiate()"

# LatticeBasedCryptography.jl
cd ../LatticeBasedCryptography.jl
julia --project=. -e "using Pkg; Pkg.instantiate()"
```

## 🧪 Testing

Each package includes comprehensive test suites:

```bash
# Test all packages
julia test_all.jl

# Or test individually
cd HomomorphicCryptography.jl && julia --project=. test/runtests.jl
cd ../PQCValidator.jl && julia --project=. test/runtests.jl
cd ../ZKPValidator.jl && julia --project=. test/runtests.jl
cd ../LibOQS.jl && julia --project=. test/runtests.jl
cd ../LatticeBasedCryptography.jl && julia --project=. test/runtests.jl
```

## 📊 Project Status

| Package | Status | Standards Compliance | Purpose |
|---------|--------|----------------------|---------|
| HomomorphicCryptography.jl | 🧪 Experimental | ISO/IEC 18033-6:2019 (homomorphic encryption standard) | Privacy-preserving computation |
| PQCValidator.jl | 🧪 Experimental | TLS 1.3 with NIST PQC algorithms | Post-quantum security validation |
| ZKPValidator.jl | 🧪 Experimental | Draft ZKP standards (IETF, academic protocols) | Zero-knowledge proof research |
| LibOQS.jl | 🧪 Experimental | NIST PQC Standards (Kyber, Dilithium, SPHINCS+) | Quantum-safe cryptographic algorithms |
| LatticeBasedCryptography.jl | 🚀 Active Development | Educational best practices | Interactive lattice cryptography learning |

**Status Legend:**
- 🧪 **Experimental** = Research-ready, not production-ready
- 🚀 **Active Development** = Under active improvement, stable for educational use

## 🤝 Contributing

We welcome contributions to all packages! See our [Contributing Guide](CONTRIBUTING.md) for detailed information.

### Quick Contribution Areas
- **Algorithm implementations** - New cryptographic schemes and protocols
- **Performance optimizations** - Hardware acceleration, algorithmic improvements
- **Standards compliance** - Implementation of emerging cryptographic standards
- **Documentation** - Examples, tutorials, and API documentation
- **Testing** - Additional test cases and validation scenarios
- **Interactive notebooks** - New educational demonstrations

### Getting Started with Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`julia test_all.jl`)
5. Submit a pull request

## 📚 Documentation

Detailed documentation is available for each package:
- [HomomorphicCryptography.jl Documentation](HomomorphicCryptography.jl/README.md)
- [PQCValidator.jl Documentation](PQCValidator.jl/README.md)
- [ZKPValidator.jl Documentation](ZKPValidator.jl/README.md)
- [LibOQS.jl Documentation](LibOQS.jl/README.md)
- [LatticeBasedCryptography.jl Documentation](LatticeBasedCryptography.jl/README.md)

## 🐛 Troubleshooting

### Common Issues

**Julia version mismatch**
```bash
# Check your Julia version
julia --version
# Should be 1.10 or higher
```

**Package installation fails**
```bash
# Clear package cache and retry
julia -e 'using Pkg; Pkg.gc(); Pkg.instantiate()'
```

**LibOQS.jl native library errors**
```bash
# Ensure system dependencies are installed
# On Ubuntu/Debian:
sudo apt-get install cmake gcc g++ libssl-dev
```

**Pluto notebook won't launch**
```bash
# Install Pluto separately if needed
julia -e 'using Pkg; Pkg.add("Pluto"); using Pluto; Pluto.run()'
```

Still having issues? [Open an issue](https://github.com/Kiara-Dev-Team/open-problem-toolkit/issues) or ask in our [Discussions](https://github.com/Kiara-Dev-Team/open-problem-toolkit/discussions).

## 💬 Community & Support

- **💡 Questions & Discussions**: [GitHub Discussions](https://github.com/Kiara-Dev-Team/open-problem-toolkit/discussions)
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/Kiara-Dev-Team/open-problem-toolkit/issues)
- **📧 Email**: open-problem-toolkit@kiara.dev
- **💬 Discord**: [Join our community](https://discord.gg/kiara-crypto)

## 📈 Recent Updates

### 🆕 September 2025 - LatticeBasedCryptography.jl Package

We've added a comprehensive educational toolkit for lattice-based cryptography, featuring:

#### **🔐 Complete Lattice-Based Encryption/Decryption System**
- **Key generation algorithms** - Implementation of lattice-based key pair generation using Learning With Errors (LWE) and NTRU techniques
- **Encryption/decryption functions** - Core cryptographic operations that transform plaintext to ciphertext using lattice mathematical structures

#### **🔄 Interactive Lattice Reduction Algorithms**
- **LLL (Lenstra-Lenstra-Lovász) algorithm** - The foundational lattice reduction technique with step-by-step visualization
- **BKZ (Block Korkine-Zolotarev) variants** - Advanced reduction algorithms with interactive parameter tuning

#### **🎓 Educational Demonstrations of LWE/Ring-LWE**
- **Learning With Errors problem setup** - Interactive examples showing how LWE instances are constructed and why they're hard to solve
- **Ring-LWE polynomial arithmetic** - Demonstrations of polynomial ring operations and their cryptographic applications
 
#### **🔒 Cryptographic Protocol Implementations**
- **Key exchange protocols** - Implementation of lattice-based key agreement schemes with interactive parameter selection
- **Digital signature schemes** - Code for lattice-based signatures like Dilithium and FALCON with verification demos
 
### 🛠️ Technical Implementation Details
- **585 lines of new Pluto notebook code** added for interactive demonstrations
- Full step-by-step walkthroughs of cryptographic operations
- Visual representations of lattice structures and reduction processes

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Kiara Development Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

**⚠️ Security Notice**: These tools are intended for research and educational purposes. For production use, ensure proper security review and follow current best practices for cryptographic implementations. Do not use experimental cryptographic implementations in production systems without thorough security auditing.

---

**🌟 Star us on GitHub!** If you find this toolkit useful, please consider giving us a star. It helps others discover this educational resource.
