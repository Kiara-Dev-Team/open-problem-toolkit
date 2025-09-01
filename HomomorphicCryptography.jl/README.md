# HomomorphicCryptography.jl

[![Build Status](https://github.com/username/HomomorphicCryptography.jl/workflows/CI/badge.svg)](https://github.com/username/HomomorphicCryptography.jl/actions)
[![Coverage](https://codecov.io/gh/username/HomomorphicCryptography.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/username/HomomorphicCryptography.jl)

A comprehensive Julia library for homomorphic encryption with standards compliance.

## Features

### ✅ Implemented Schemes

- **Paillier Cryptosystem** - ISO/IEC 18033-6:2019 compliant
  - Additive homomorphic encryption
  - 128/192/256-bit security levels
  - Secure key generation, encryption, decryption
  - Homomorphic addition and scalar multiplication

- **ElGamal Cryptosystem (Exponential variant)** - ISO/IEC 18033-6:2019 compliant
  - Additive homomorphic encryption (in exponent)
  - 128/192/256-bit security levels
  - Suitable for small plaintext values
  - Fast homomorphic operations

- **BFV (Brakerski/Fan-Vercauteren)** - Somewhat homomorphic (integer arithmetic) ✅
  - RLWE-based lattice cryptography
  - Polynomial ring arithmetic with NTT optimization
  - Addition and multiplication operations
  - 128/192/256-bit security levels

### 🧪 Experimental Schemes (Prototypes)

- **BGV (Brakerski-Gentry-Vaikuntanathan)** - Modulus switching, level management (prototype)
- **TFHE (Fast FHE over Torus)** - Boolean gates, LWE-based core (prototype)

### 🔄 Planned Schemes

- **CKKS (Cheon-Kim-Kim-Song)** - FHE for real/complex numbers

### 📋 Standards Compliance

- **ISO/IEC 18033-6:2019** - Homomorphic encryption mechanisms ✅
- **ISO/IEC DIS 28033-1** - FHE general principles (planned)
- **IEEE 2410-2021** - Biometric privacy (applicable)
- **HomomorphicEncryption.org** security standard ✅

### 🚀 Advanced Features

- **Parallel Testing Infrastructure** - ReTestItems.jl with configurable workers ✅
- **Comprehensive Benchmarking** - Performance analysis across security levels ✅
- **Serialization & Key Management** - Secure key export/import ✅
- **Standards Validation** - Automated compliance testing ✅
- **Real-world Examples** - Voting, salary analysis, and more ✅
- **Lattice-based Foundations** - Polynomial rings, NTT, discrete sampling ✅

## Installation

```julia
using Pkg
Pkg.add("HomomorphicCryptography")
```

Or for development:

```julia
using Pkg
Pkg.develop("HomomorphicCryptography")
```

## Quick Start

### Basic Paillier Usage

```julia
using HomomorphicCryptography

# Create scheme and security parameters
scheme = PaillierScheme()
params = PaillierParameters(SECURITY_128)  # 128-bit security

# Generate key pair
keypair = keygen(scheme, params)
pk, sk = keypair.public_key, keypair.private_key

# Encrypt some numbers
a, b = 100, 200
c_a = encrypt(pk, a)
c_b = encrypt(pk, b)

# Perform homomorphic addition
c_sum = add_encrypted(c_a, c_b)

# Decrypt the result
result = decrypt_to_int(sk, c_sum)
println("$a + $b = $result")  # Output: 100 + 200 = 300
```

### Advanced Operations

```julia
# Scalar multiplication
c_value = encrypt(pk, 25)
c_multiplied = multiply_plain(c_value, 4)
result = decrypt_to_int(sk, c_multiplied)  # 100

# Adding plaintext to ciphertext
c_encrypted = encrypt(pk, 500)
p_addition = PaillierPlaintext(75)
c_result = add_plain(c_encrypted, p_addition)
result = decrypt_to_int(sk, c_result)  # 575

# Complex computation: 3*x + 2*y + z
x, y, z = 10, 20, 5
c_x = encrypt(pk, x)
c_y = encrypt(pk, y)
c_z = encrypt(pk, z)

c_result = add_encrypted(
    add_encrypted(multiply_plain(c_x, 3), multiply_plain(c_y, 2)),
    c_z
)
result = decrypt_to_int(sk, c_result)  # 75
```

### BFV Somewhat Homomorphic Encryption (SHE)

```julia
using HomomorphicCryptography

# Create BFV scheme and parameters
scheme = BFVScheme()
params = LatticeParameters(SECURITY_128; plaintext_modulus=65537)

# Generate keys
keypair = keygen(scheme, params)
pk, sk = keypair.public_key, keypair.private_key

# Encrypt integer vectors (coeff-wise)
pt1 = [1, 2, 3, 4, 5]
pt2 = [10, 20, 30, 40, 50]

ct1 = encrypt(pk, pt1)
ct2 = encrypt(pk, pt2)

# Homomorphic addition
sum_ct = add_encrypted(ct1, ct2)
sum_pt = decrypt(sk, sum_ct)
sum_vals = bfv_decode(sum_pt)  # [11, 22, 33, 44, 55]

# Homomorphic multiplication with relinearization
eval_key = generate_evaluation_key(sk)
mult_ct = multiply_encrypted(ct1, ct2, eval_key)
mult_pt = decrypt(sk, mult_ct)
mult_vals = bfv_decode(mult_pt)

# Mixed operation: (a + b) * 2 (scalar multiply)
mixed_ct = multiply_plain(sum_ct, 2)
mixed_pt = decrypt(sk, mixed_ct)
mixed_vals = bfv_decode(mixed_pt)
```

## Standards Validation

### ISO/IEC 18033-6:2019 Compliance

```julia
# Validate implementation compliance
is_compliant = validate_iso18033_6_compliance(scheme, params)
println("ISO/IEC 18033-6 compliant: $is_compliant")

# Generate detailed compliance report
report = ISO18033_6_Validation.generate_compliance_report(scheme, params)
println(report)
```

## Security Levels

The library supports multiple security levels following international standards:

```julia
# 128-bit security (minimum recommended)
params_128 = PaillierParameters(SECURITY_128)  # 2048-bit keys

# 192-bit security (recommended for sensitive data)
params_192 = PaillierParameters(SECURITY_192)  # 3072-bit keys

# 256-bit security (high-security applications)
params_256 = PaillierParameters(SECURITY_256)  # 4096-bit keys
```

## Scheme Properties

```julia
scheme = PaillierScheme()

# Check scheme capabilities
println("Supports addition: $(supports_addition(scheme))")        # true
println("Supports multiplication: $(supports_multiplication(scheme))")  # false
println("Is fully homomorphic: $(is_fully_homomorphic(scheme))")  # false
```

## Performance

### Paillier Cryptosystem (PHE)
Typical performance on modern hardware:

| Operation | 2048-bit | 3072-bit | 4096-bit |
|-----------|----------|----------|----------|
| Key Generation | ~100ms | ~300ms | ~800ms |
| Encryption | ~5ms | ~15ms | ~30ms |
| Decryption | ~5ms | ~15ms | ~30ms |
| Homomorphic Add | ~1ms | ~2ms | ~5ms |
| Scalar Multiply | ~10ms | ~30ms | ~60ms |

### BFV Cryptosystem (SHE, prototype)
Performance for polynomial degree n=1024:

| Operation | 128-bit | 192-bit | 256-bit |
|-----------|---------|---------|---------|
| Key Generation | ~50ms | ~100ms | ~200ms |
| Encryption | ~2ms | ~5ms | ~10ms |
| Decryption | ~1ms | ~3ms | ~6ms |
| Homomorphic Add | ~0.1ms | ~0.2ms | ~0.5ms |
| Homomorphic Mult | ~5ms | ~15ms | ~30ms |

*Note: BFV supports SIMD-style batching; results and APIs may evolve.*

## Documentation

For detailed documentation, examples, and API reference:

```julia
julia> using HomomorphicCryptography
julia> ?PaillierScheme  # Get help for any function/type
julia> available_schemes()  # List all available schemes
julia> scheme_info("Paillier")  # Get detailed scheme information
julia> security_recommendations()  # Get security guidelines
```

## Examples

The `examples/` directory contains comprehensive usage examples:

- `paillier_basic_usage.jl` - Basic Paillier operations and ISO compliance
- `comprehensive_demo.jl` - End-to-end demo (Paillier/ElGamal, serialization, benchmarks)

## Testing

### Parallel Test Execution with ReTestItems.jl

The library uses ReTestItems.jl for fast, parallel test execution:

```bash
julia --project=. test/runtests.jl
```

Features:
- **Parallel Execution**: Automatic worker detection (CPU_THREADS ÷ 2)
- **Test Categories**: Tagged tests (`:fast`, `:slow`, `:phe`, `:fhe`, `:multiplication`)
- **Timeout Control**: Per-test timeouts (30-300s based on complexity)
- **Memory Management**: 80% memory threshold with monitoring
- **Resource Tracking**: Execution time and allocation statistics

### Test Structure

- **31 Test Items** split across multiple categories:
  - Core Tests: 3 items (fast execution)
  - Paillier Tests: 9 items (PHE validation)
  - ElGamal Tests: 5 items (split by value sizes)
  - BFV Tests: 9 items (FHE with lattice operations)
  - Serialization & Error Handling: 5 items

### Running Specific Test Categories

```bash
# Run only fast tests
julia --project=. -e "using ReTestItems; runtests(testitem_filter=ti->:fast in ti.tags)"

# Run FHE tests only
julia --project=. -e "using ReTestItems; runtests(testitem_filter=ti->:fhe in ti.tags)"

# Run with custom worker count
julia --project=. -e "using ReTestItems; runtests(nworkers=4)"
```

## Development Roadmap

### Phase 1: Foundation ✅
- [x] Core abstractions and interfaces
- [x] Security parameter framework
- [x] Number theory utilities
- [x] ISO/IEC 18033-6 compliant Paillier implementation
- [x] ElGamal exponential variant implementation
- [x] Standards validation, serialization, and testing setup

### Phase 2: Performance Optimizations ✅
- [x] SIMD/threading, memory pooling, and profiling
- [x] Advanced benchmarking (scalability, memory, threading)

### Phase 3: Lattice Foundations ✅
- [x] Polynomial ring arithmetic (`PolyZqN`), NTT, sampling
- [x] RLWE utilities and lattice parameter framework

### Phase 4: BFV Scheme ✅
- [x] BFV core (add/mul), parameter validation, relinearization (prototype)
- [x] Noise helpers and basic batching utilities

### Phase 5: Advanced FHE Schemes 🔄 (In Progress)
- [x] BGV core + modulus switching (prototype)
- [x] TFHE boolean gates + LWE core (prototype)
- [ ] CKKS minimal prototype
- [ ] Bootstrapping research track (BFV/CKKS)

### Phase 6: Advanced Features (Planned)
- [ ] Hardware acceleration (GPU)
- [ ] Multi-key and threshold HE
- [ ] ISO/IEC DIS 28033-1 alignment

**Overall Progress: ~65%**

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution
- Additional homomorphic encryption schemes
- Performance optimizations
- Hardware acceleration
- Documentation improvements
- Example applications

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Citation

If you use HomomorphicCryptography.jl in your research, please cite:

```bibtex
@software{HomomorphicCryptographyJl,
  title = {HomomorphicCryptography.jl: A Standards-Compliant Julia Library for Homomorphic Encryption},
  author = {Satoshi Terasaki},
  year = {2024},
  url = {https://github.com/username/HomomorphicCryptography.jl}
}
```

## Acknowledgments

- ISO/IEC 18033-6:2019 standard for homomorphic encryption mechanisms
- HomomorphicEncryption.org for security standards and best practices
- NIST Post-Quantum Cryptography project for lattice-based foundations
- The Julia community for excellent cryptographic libraries and tools

## Security Notice

This library is intended for research and educational purposes. For production use:

1. Ensure you understand the security assumptions of each scheme
2. Use appropriate security parameters for your threat model
3. Follow current best practices for key management
4. Regularly update to the latest version for security fixes

For security-critical applications, consider professional cryptographic review.
