**Open Problem Toolkit**
A comprehensive Julia toolkit for learning and implementing modern cryptographic systems. This educational platform helps university students understand and work with cutting-edge encryption techniques that protect our digital world.

## 🚀 Overview

The Open Problem Toolkit provides specialized packages for modern cryptographic research and development:

- **🔐 HomomorphicCryptography.jl** - Standards-compliant homomorphic encryption implementations
- **🛡️ PQCValidator.jl** - Post-quantum cryptography validation for TLS 1.3
- **🔍 ZKPValidator.jl** - Zero-knowledge proof protocol validation framework
- **🔒 LibOQS.jl** - Julia bindings for the Open Quantum Safe library
- **🧮 LatticeBasedCryptography.jl** - Interactive lattice-based cryptography educational toolkit

## 📦 Package Structure

```
open-problem-toolkit/
├── HomomorphicCryptography.jl/       # Homomorphic encryption library
├── PQCValidator.jl/                  # Post-quantum crypto validator
├── ZKPValidator.jl/                  # Zero-knowledge proof validator
├── LibOQS.jl/                       # Open Quantum Safe Julia bindings
└── LatticeBasedCryptography.jl/      # Lattice cryptography educational toolkit
    ├── playground/
    │   └── pluto/                    # Interactive Pluto notebooks
    └── src/                          # Core implementations
```

## 🛠️ Installation

### Prerequisites
- Julia 1.10 or later
- Git

### Installation Steps

1. **Clone the repository:**
```bash
git clone https://github.com/Kiara-Dev-Team/open-problem-toolkit.git
cd open-problem-toolkit
```

2. **Install individual packages:**

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
# Test HomomorphicCryptography.jl (parallel execution)
cd HomomorphicCryptography.jl
julia --project=. test/runtests.jl

# Test PQCValidator.jl
cd ../PQCValidator.jl
julia --project=. test/runtests.jl

# Test ZKPValidator.jl
cd ../ZKPValidator.jl
julia --project=. test/runtests.jl

# Test LibOQS.jl
cd ../LibOQS.jl
julia --project=. test/runtests.jl

# Test LatticeBasedCryptography.jl
cd ../LatticeBasedCryptography.jl
julia --project=. test/runtests.jl
```

## 📊 Project Status

| Package | Status | Compliance | Use Case |
|---------|--------|------------|----------|
| HomomorphicCryptography.jl | 🧪 Experimental | ISO/IEC 18033-6:2019 | Privacy-preserving computation |
| PQCValidator.jl | 🧪 Experimental | TLS 1.3 PQC | Post-quantum security validation |
| ZKPValidator.jl | 🧪 Experimental | Draft standards | Zero-knowledge proof research |
| LibOQS.jl | 🧪 Experimental | NIST PQC Standards | Quantum-safe cryptographic algorithms |
| LatticeBasedCryptography.jl | 🚀 Active Development | Educational Standards | Interactive lattice cryptography learning |

## 🎯 Use Cases

## 🤝 Contributing

We welcome contributions to all packages! Please see individual package documentation for specific contribution guidelines.

### Areas for Contribution
- **Algorithm implementations** - New cryptographic schemes
- **Performance optimizations** - Hardware acceleration, algorithmic improvements
- **Standards compliance** - Implementation of emerging standards
- **Documentation** - Examples, tutorials, and API documentation
- **Testing** - Additional test cases and validation scenarios

## 📚 Documentation

Detailed documentation is available in each package:
- [HomomorphicCryptography.jl README](HomomorphicCryptography.jl/README.md)
- [PQCValidator.jl README](PQCValidator.jl/README.md)
- [ZKPValidator.jl README](ZKPValidator.jl/README.md)
- [LibOQS.jl README](LibOQS.jl/README.md)
- [LatticeBasedCryptography.jl README](LatticeBasedCryptography.jl/README.md)

---

**⚠️ Security Notice**: These tools are intended for research and educational purposes. For production use, ensure proper security review and follow current best practices for cryptographic implementations.

---

## 📈 Recent Updates (September 21, 2025)

### 🆕 New: LatticeBasedCryptography.jl Package

We've added a comprehensive educational toolkit for lattice-based cryptography, featuring:

#### **🔐 Complete Lattice-Based Encryption/Decryption System**
   • **Key generation algorithms** - Implementation of lattice-based key pair generation using techniques like LWE or NTRU
   • **Encryption/decryption functions** - Core cryptographic operations that transform plaintext to ciphertext using lattice mathematical structures

#### **🔄 Interactive Lattice Reduction Algorithms**
   • **LLL (Lenstra-Lenstra-Lovász) algorithm implementation** - The foundational lattice reduction technique with step-by-step visualization
   • **BKZ (Block Korkine-Zolotarev) variants** - More advanced reduction algorithms with interactive parameter tuning

#### **🎓 Educational Demonstrations of LWE/Ring-LWE**
   • **Learning With Errors problem setup** - Interactive examples showing how LWE instances are constructed and why they're hard to solve
   • **Ring-LWE polynomial arithmetic** - Demonstrations of polynomial ring operations and their cryptographic applications
 
#### **🔒 Cryptographic Protocol Implementations**
   • **Key exchange protocols** - Implementation of lattice-based key agreement schemes with interactive parameter selection
   • **Digital signature schemes** - Code for lattice-based signatures like Dilithium or FALCON with verification demos
 
### 🛠️ Technical Implementation Details
- **585 lines of new Pluto notebook code** added for interactive demonstrations

