# LibOQS.jl

Julia bindings for the [Open Quantum Safe](https://openquantumsafe.org/) (OQS) library, providing access to quantum-safe cryptographic algorithms standardized by NIST and other leading cryptographic research organizations.

## Overview

LibOQS.jl brings post-quantum cryptography to Julia by wrapping the comprehensive OQS library. This package enables Julia developers to experiment with and implement quantum-resistant cryptographic protocols in their applications.

### Supported Algorithm Categories

- **Key Encapsulation Mechanisms (KEMs)** - Quantum-safe key exchange
- **Digital Signature Schemes** - Quantum-resistant authentication

## ⚠️ Security Notice

**This library is experimental and intended for research and prototyping.** 

- Post-quantum algorithms are still evolving
- Implementation may contain timing side-channels
- Not recommended for production use without security audit
- Consider hybrid approaches combining classical and post-quantum crypto

## 📄 License

LibOQS.jl is released under the MIT License. See [LICENSE](LICENSE) for details.

The underlying OQS library has its own licensing terms - see the [OQS repository](https://github.com/open-quantum-safe/liboqs) for details.