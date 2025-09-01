# HomomorphicCryptography.jl
# A comprehensive Julia library for homomorphic encryption
# Supporting multiple schemes with standards compliance

module HomomorphicCryptography

# Core abstractions
include("core/schemes.jl")
include("core/parameters.jl")

# Utilities
include("utils/number_theory.jl")

# Lattice utilities (needed for BFV)
include("lattice/polynomial.jl")
include("lattice/sampling.jl")
include("lattice/ntt.jl")
include("lattice/rlwe.jl")

# Partially homomorphic schemes
include("partially_homomorphic/paillier.jl")
include("partially_homomorphic/elgamal.jl")

# Phase 3 Performance optimizations (load after scheme definitions)
include("performance/optimization.jl")
include("performance/optimized_paillier.jl")
include("performance/polynomial_math.jl")
include("performance/advanced_benchmarks.jl")

# Fully homomorphic schemes
include("fhe/bfv.jl")
include("fhe/bgv.jl")
# include("fhe/ckks.jl")  # Temporarily disabled - will be reimplemented
include("fhe/tfhe.jl")

# Serialization (after schemes are defined)
include("utils/serialization.jl")

# Standards validation
include("standards/iso18033_6.jl")

# Benchmarking
include("benchmarks/performance.jl")

# Re-export core types and functions
export HomomorphicScheme,
    PartiallyHomomorphicScheme, SomewhatHomomorphicScheme, FullyHomomorphicScheme
export PublicKey, PrivateKey, KeyPair, Plaintext, Ciphertext, SecurityParameters
export SecurityLevel, SECURITY_128, SECURITY_192, SECURITY_256
export StandardSecurityParameters,
    PaillierParameters, LatticeParameters, CKKSParameters, TFHEParameters

# Re-export scheme operations
export keygen,
    encrypt, decrypt, add_encrypted, multiply_encrypted, add_plain, multiply_plain
export scheme_name,
    is_fully_homomorphic,
    is_somewhat_homomorphic,
    supports_addition,
    supports_multiplication

# Re-export Paillier implementation
export PaillierScheme,
    PaillierPublicKey, PaillierPrivateKey, PaillierPlaintext, PaillierCiphertext
export decrypt_to_int, validate_iso18033_6_compliance

# Re-export ElGamal implementation
export ElGamalScheme,
    ElGamalPublicKey,
    ElGamalPrivateKey,
    ElGamalPlaintext,
    ElGamalCiphertext,
    ElGamalParameters
export validate_elgamal_iso18033_6

# Re-export standards validation
export ISO18033_6_Validation

# Utility functions
export validate_parameters, get_recommended_parameters

# Module utility functions
export greet, available_schemes, scheme_info, security_recommendations

# Benchmarking functions
export benchmark_paillier,
    benchmark_elgamal,
    compare_schemes,
    security_level_analysis,
    run_comprehensive_benchmarks,
    BenchmarkResults

# Serialization functions
export SerializationFormat, BINARY_FORMAT, BASE64_FORMAT, JSON_FORMAT
export serialize, save_to_file, load_from_file, secure_delete_file
export export_keypair, import_keypair

# Lattice polynomial utilities for BFV
export PolyZqN, zero_poly, one_poly, poly_add, poly_sub, poly_mul, scalar_mul
export centered_mod, random_uniform_poly, from_coeffs_mod_q
export poly_mul_ntt
export to_centered_coeffs, linf_norm, l2_norm, coeff_stats
export discrete_gaussian, gaussian_poly, LatticeParameters

# Sampling functions
export centered_binomial_distribution, binomial_poly
export ternary_poly, hamming_weight_poly

# NTT functions
export is_ntt_compatible, try_find_primitive_root_2n, ntt!, intt!

# Performance optimization utilities
export OptimizationLevel, OPT_NONE, OPT_BASIC, OPT_AGGRESSIVE
export MemoryPool, get_pooled_bigint, return_pooled_bigint!, reset_pool!
export batch_modular_exponentiation, batch_modular_multiplication
export blocked_matrix_multiply, prefetch_memory
export constant_time_compare, secure_zero!
export ThreadSafeCounter, increment!, get_value
export PerformanceMetrics, record_operation!, get_stats
export GLOBAL_MEMORY_POOL

# Optimized Paillier operations
export OptimizedPaillierOperations
export batch_encrypt, batch_decrypt, batch_add_encrypted, batch_multiply_plain
export optimized_homomorphic_sum, memory_efficient_encrypt

# Polynomial mathematics
export Polynomial, degree, evaluate
export schoolbook_multiply, karatsuba_multiply, fft_multiply
export number_theoretic_transform_multiply, number_theoretic_transform
export mod_inverse, benchmark_polynomial_multiplication
export polynomial_add, polynomial_subtract, pad_polynomial, shift_polynomial
export fft, ifft

# Advanced benchmarking types
export ScalabilityResults, MemoryProfileResults
export benchmark_scalability, profile_memory_usage

# BFV implementation
export BFVScheme, BFVPublicKey, BFVPrivateKey, BFVPlaintext, BFVCiphertext, BFVEvaluationKey
export bfv_encode, bfv_decode, validate_bfv_parameters
export generate_evaluation_key, relinearize, digit_decompose
export bfv_noise_poly, bfv_noise_linf
export NoiseAnalysis, analyze_noise, estimate_multiplication_depth
export noise_growth_after_addition, noise_growth_after_multiplication, print_noise_analysis

# BFV Batching/SIMD operations
export BatchEncoder, can_batch, batch_encode, batch_decode
export simd_add, simd_multiply, simd_add_constant, simd_multiply_constant
export find_primitive_2n_root

# BGV implementation
export BGVScheme, BGVParameters, BGVPublicKey, BGVPrivateKey, BGVPlaintext, BGVCiphertext
export generate_modulus_chain, bgv_encode, bgv_decode
export modulus_switch, relinearize_bgv, bgv_noise_budget, suggest_modulus_switch

# CKKS implementation
export CKKSScheme, CKKSParameters, CKKSPublicKey, CKKSPrivateKey, CKKSPlaintext, CKKSCiphertext
export encode_complex, encode_real, decode_complex, decode_real
export rescale, conjugate, rotate_slots, check_precision, suggest_rescale

# RLWE helpers
export RLWEParams, RLWEPublicKey, RLWESecretKey
export sample_rlwe_instance, rlwe_keygen, rlwe_encrypt, rlwe_decrypt

"""
    greet()

A simple greeting function (placeholder from original template).
"""
greet() =
    print("Welcome to HomomorphicCryptography.jl - Secure computation on encrypted data!")

"""
    available_schemes() -> Vector{String}

List all available homomorphic encryption schemes in this library.
"""
function available_schemes()
    return [
        "PaillierScheme - Partially homomorphic (additive), ISO/IEC 18033-6 compliant",
        "ElGamalScheme - Partially homomorphic (additive), ISO/IEC 18033-6 compliant",
        "BFVScheme - Somewhat homomorphic (addition + limited multiplication), lattice-based RLWE",
        "BGVScheme - Somewhat homomorphic with modulus switching, lattice-based RLWE",
        "CKKSScheme - Approximate arithmetic on real/complex numbers with rescaling",
    ]
end

"""
    scheme_info(scheme_name::String) -> String

Get detailed information about a specific scheme.
"""
function scheme_info(scheme_name::String)
    if scheme_name == "Paillier" || scheme_name == "PaillierScheme"
        return """
        Paillier Cryptosystem
        ====================
        Type: Partially Homomorphic Encryption (PHE)
        Operations: Additive homomorphism
        Standard: ISO/IEC 18033-6:2019 compliant
        Security: Based on composite residuosity assumption
        Use cases: E-voting, secure aggregation, privacy-preserving statistics

        Key sizes: 2048, 3072, 4096 bits
        Security levels: 128, 192, 256 bits
        """
    elseif scheme_name == "ElGamal" || scheme_name == "ElGamalScheme"
        return """
        ElGamal Cryptosystem (Exponential variant)
        =========================================
        Type: Partially Homomorphic Encryption (PHE)
        Operations: Additive homomorphism (in exponent)
        Standard: ISO/IEC 18033-6:2019 compliant
        Security: Based on discrete logarithm assumption
        Use cases: E-voting, secure auctions, small message encryption

        Key sizes: 2048, 3072, 4096 bits
        Security levels: 128, 192, 256 bits
        Limitation: Practical only for small plaintext values due to discrete log
        """
    elseif scheme_name == "BFV" || scheme_name == "BFVScheme"
        return """
        BFV (Brakerski/Fan-Vercauteren) Cryptosystem
        ============================================
        Type: Fully Homomorphic Encryption (FHE)
        Operations: Addition and multiplication (unlimited depth with bootstrapping)
        Standard: Lattice-based, RLWE security
        Security: Based on Ring Learning With Errors assumption
        Use cases: Private computation, secure cloud computing, encrypted databases

        Ring dimensions: 1024, 2048, 4096, 8192
        Security levels: 128, 192, 256 bits
        Features: Batching (SIMD), noise management, parameter optimization
        """
    else
        return "Unknown scheme: $scheme_name"
    end
end

"""
    security_recommendations() -> String

Get current security recommendations for homomorphic encryption.
"""
function security_recommendations()
    return """
    Security Recommendations for Homomorphic Encryption
    ===================================================

    1. Minimum Security Levels:
       - 128-bit security: Minimum for most applications
       - 192-bit security: Recommended for sensitive data
       - 256-bit security: High-security applications

    2. Key Sizes (Paillier):
       - 128-bit security: 2048-bit keys minimum
       - 192-bit security: 3072-bit keys minimum
       - 256-bit security: 4096-bit keys minimum

    3. Random Number Generation:
       - Use cryptographically secure random number generators
       - Ensure sufficient entropy for key generation

    4. Implementation Security:
       - Clear sensitive data from memory after use
       - Validate all inputs and parameters
       - Use constant-time operations where possible

    Based on:
    - ISO/IEC 18033-6:2019
    - HomomorphicEncryption.org security standard
    - NIST recommendations
    """
end

end # module HomomorphicCryptography
