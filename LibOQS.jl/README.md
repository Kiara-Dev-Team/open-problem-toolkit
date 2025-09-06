# LibOQS.jl

Julia bindings for the [Open Quantum Safe](https://openquantumsafe.org/) (OQS) library, providing access to quantum-safe cryptographic algorithms standardized by NIST and other leading cryptographic research organizations.

## Overview

LibOQS.jl brings post-quantum cryptography to Julia by wrapping the comprehensive OQS library. This package enables Julia developers to experiment with and implement quantum-resistant cryptographic protocols in their applications.

### Supported Algorithm Categories

- **Key Encapsulation Mechanisms (KEMs)** - Quantum-safe key exchange
- **Digital Signature Schemes** - Quantum-resistant authentication
- **Hash-based Signatures** - Stateful and stateless post-quantum signatures

## 🚀 Quick Start

### Installation

```julia
using Pkg
Pkg.add("LibOQS")
```

### Basic Usage

```julia
using LibOQS

# List available KEM algorithms
kems = OQS.supported_kems()
println("Available KEMs: ", kems)

# List available signature algorithms  
sigs = OQS.supported_sigs()
println("Available Signatures: ", sigs)

# Example: Kyber KEM
kem = OQS.KEM("Kyber512")
public_key, secret_key = OQS.keypair(kem)

# Encapsulation
ciphertext, shared_secret = OQS.encaps(kem, public_key)

# Decapsulation
recovered_secret = OQS.decaps(kem, secret_key, ciphertext)

@assert shared_secret == recovered_secret
println("KEM operation successful!")

# Example: Dilithium Signature
sig_alg = OQS.Signature("Dilithium2")
public_key, secret_key = OQS.keypair(sig_alg)

message = b"Hello, quantum-safe world!"
signature = OQS.sign(sig_alg, message, secret_key)

is_valid = OQS.verify(sig_alg, message, signature, public_key)
println("Signature valid: ", is_valid)
```

## 📚 Supported Algorithms

### NIST Standardized Algorithms

#### Key Encapsulation Mechanisms
- **Kyber** (`Kyber512`, `Kyber768`, `Kyber1024`) - NIST ML-KEM standard
- **Classic McEliece** - Code-based cryptography

#### Digital Signatures
- **Dilithium** (`Dilithium2`, `Dilithium3`, `Dilithium5`) - NIST ML-DSA standard  
- **Falcon** (`Falcon-512`, `Falcon-1024`) - NTRU lattice-based signatures
- **SPHINCS+** - Hash-based signatures

### Experimental Algorithms

Additional algorithms available for research purposes:
- **BIKE**, **HQC** - Alternative code-based KEMs
- **Rainbow**, **GeMSS** - Multivariate signatures
- **XMSS**, **LMS** - Stateful hash-based signatures

## 🛠️ API Reference

### Core Functions

#### KEM Operations
```julia
# Initialize KEM
kem = OQS.KEM(algorithm_name::String)

# Generate keypair
public_key, secret_key = OQS.keypair(kem)

# Encapsulation
ciphertext, shared_secret = OQS.encaps(kem, public_key)

# Decapsulation  
shared_secret = OQS.decaps(kem, secret_key, ciphertext)
```

#### Signature Operations
```julia
# Initialize signature scheme
sig = OQS.Signature(algorithm_name::String)

# Generate keypair
public_key, secret_key = OQS.keypair(sig)

# Sign message
signature = OQS.sign(sig, message, secret_key)

# Verify signature
is_valid = OQS.verify(sig, message, signature, public_key)
```

#### Utility Functions
```julia
# List supported algorithms
OQS.supported_kems()    # Available KEM algorithms
OQS.supported_sigs()    # Available signature algorithms

# Algorithm information
OQS.kem_details(algorithm_name)
OQS.sig_details(algorithm_name)
```

## 🧪 Examples

### TLS Integration Example

```julia
using LibOQS

function quantum_safe_handshake()
    # Client generates Kyber keypair
    client_kem = OQS.KEM("Kyber768")
    client_public, client_secret = OQS.keypair(client_kem)
    
    # Server receives client public key and encapsulates
    server_kem = OQS.KEM("Kyber768")
    ciphertext, server_shared_secret = OQS.encaps(server_kem, client_public)
    
    # Client decapsulates to recover shared secret
    client_shared_secret = OQS.decaps(client_kem, client_secret, ciphertext)
    
    return client_shared_secret == server_shared_secret
end

println("Quantum-safe handshake: ", quantum_safe_handshake())
```

### Hybrid Cryptography Example

```julia
using LibOQS, Crypto  # Hypothetical classical crypto library

function hybrid_encrypt(message, recipient_classical_key, recipient_pq_key)
    # Classical component (ECDH)
    classical_shared = ECDH.derive_shared(recipient_classical_key)
    
    # Post-quantum component (Kyber)
    pq_kem = OQS.KEM("Kyber1024") 
    pq_ciphertext, pq_shared = OQS.encaps(pq_kem, recipient_pq_key)
    
    # Combine secrets
    combined_key = hash(classical_shared * pq_shared)
    
    # Encrypt message
    encrypted = AES.encrypt(message, combined_key)
    
    return (encrypted, pq_ciphertext)
end
```

## ⚡ Performance Considerations

### Algorithm Selection Guide

| Use Case | Recommended KEM | Recommended Signature |
|----------|----------------|----------------------|
| High throughput | Kyber512 | Dilithium2 |
| Balanced security | Kyber768 | Dilithium3 |
| Maximum security | Kyber1024 | Dilithium5 |
| Minimal signatures | Kyber768 | Falcon-512 |
| Long-term security | Classic McEliece | SPHINCS+ |

### Benchmarking

```julia
using BenchmarkTools, LibOQS

function benchmark_kem(algorithm)
    kem = OQS.KEM(algorithm)
    
    # Benchmark key generation
    keygen_time = @benchmark OQS.keypair($kem)
    
    pk, sk = OQS.keypair(kem)
    
    # Benchmark encapsulation
    encaps_time = @benchmark OQS.encaps($kem, $pk)
    
    ct, ss = OQS.encaps(kem, pk)
    
    # Benchmark decapsulation  
    decaps_time = @benchmark OQS.decaps($kem, $sk, $ct)
    
    return (keygen_time, encaps_time, decaps_time)
end

# Compare Kyber variants
for variant in ["Kyber512", "Kyber768", "Kyber1024"]
    times = benchmark_kem(variant)
    println("$variant performance: ", times)
end
```

## 🔧 Building and Dependencies

### System Requirements

- Julia 1.6+
- CMake 3.5+
- C compiler (GCC, Clang, or MSVC)

### Manual Build

```bash
# Clone repository with OQS submodule
git clone --recurse-submodules https://github.com/your-org/LibOQS.jl.git
cd LibOQS.jl

# Build OQS library
mkdir build && cd build
cmake .. -DOQS_BUILD_ONLY_LIB=ON
make -j$(nproc)

# Install Julia package
julia --project=. -e "using Pkg; Pkg.instantiate()"
```

### Docker Usage

```dockerfile
FROM julia:1.9

RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY . /LibOQS.jl
WORKDIR /LibOQS.jl

RUN julia --project=. -e "using Pkg; Pkg.instantiate()"
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
julia --project=. test/runtests.jl
```

Test specific algorithm categories:

```julia
# Test only KEMs
julia --project=. -e "using Pkg; Pkg.test(test_args=[\"kem\"])"

# Test only signatures  
julia --project=. -e "using Pkg; Pkg.test(test_args=[\"sig\"])"

# Performance tests
julia --project=. -e "using Pkg; Pkg.test(test_args=[\"perf\"])"
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/your-org/LibOQS.jl.git
cd LibOQS.jl
julia --project=. -e "using Pkg; Pkg.develop(path=\".\")"
```

### Areas for Contribution

- **Algorithm bindings** - Support for new OQS algorithms
- **Performance optimization** - Assembly optimizations, SIMD usage
- **Platform support** - Windows, macOS, embedded systems  
- **Integration examples** - Real-world usage patterns
- **Documentation** - Tutorials, algorithm guides

## 📊 Algorithm Status

| Algorithm | NIST Status | Security Level | Key Size | Signature Size |
|-----------|-------------|----------------|----------|----------------|
| Kyber512 | Standardized | 1 | 800B | - |
| Kyber768 | Standardized | 3 | 1184B | - |  
| Kyber1024 | Standardized | 5 | 1568B | - |
| Dilithium2 | Standardized | 2 | 1312B | 2420B |
| Dilithium3 | Standardized | 3 | 1952B | 3293B |
| Dilithium5 | Standardized | 5 | 2592B | 4595B |
| Falcon-512 | Standardized | 1 | 897B | 690B |
| Falcon-1024 | Standardized | 5 | 1793B | 1330B |

## 📖 Resources

- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [LibOQS Documentation](https://github.com/open-quantum-safe/liboqs)
- [Algorithm Specifications](https://openquantumsafe.org/applications/)

## ⚠️ Security Notice

**This library is experimental and intended for research and prototyping.** 

- Post-quantum algorithms are still evolving
- Implementation may contain timing side-channels
- Not recommended for production use without security audit
- Consider hybrid approaches combining classical and post-quantum crypto

## 📄 License

LibOQS.jl is released under the MIT License. See [LICENSE](LICENSE) for details.

The underlying OQS library has its own licensing terms - see the [OQS repository](https://github.com/open-quantum-safe/liboqs) for details.