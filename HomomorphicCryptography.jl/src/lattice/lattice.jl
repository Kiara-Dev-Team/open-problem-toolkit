# Lattice-Based Cryptography Module
# Main module for lattice-based homomorphic encryption foundations

# Include all lattice components
include("polynomial_ring.jl")
include("ntt.jl")
include("gaussian.jl")
include("rlwe.jl")

# Re-export all important types and functions
using .HomomorphicCryptography

# Polynomial Ring exports
export PolynomialRing, degree, modulus
export zero_polynomial, one_polynomial, random_polynomial
export norm_infinity, norm_2_squared
export to_centered_form, from_centered_form
export LATTICE_PARAMS, create_polynomial_ring

# NTT exports
export NTTParameters, get_ntt_parameters
export ntt_forward!, ntt_inverse!, ntt_multiply, ntt_multiply!
export find_primitive_root, ispowerof2

# Gaussian sampling exports
export DiscreteGaussianSampler, CenteredBinomialSampler
export UniformSampler, TernarySampler
export sample, sample_vector, sample_polynomial
export estimate_sigma, chi_squared_test

# RLWE exports
export RLWEParameters, RLWESample, RLWESecretKey, RLWEPublicKey, RLWECiphertext
export RelinearizationKey
export generate_secret_key, generate_rlwe_sample, generate_public_key
export generate_relinearization_key
export rlwe_encrypt, rlwe_decrypt, rlwe_add, rlwe_sub, rlwe_multiply_plain
export noise_budget, is_valid_ciphertext
export RLWE_PARAMETER_SETS, create_rlwe_parameters

"""
    LatticeFoundation

Module containing all lattice-based cryptographic foundations.
Provides polynomial rings, NTT, Gaussian sampling, and RLWE primitives.
"""
module LatticeFoundation
# This module serves as a namespace for lattice operations
# All functionality is re-exported at the top level
end

"""
    test_lattice_foundations() -> Bool

Basic test to verify lattice foundations are working correctly.
"""
function test_lattice_foundations()
    try
        println("🧪 Testing Lattice Foundations...")

        # Test polynomial ring
        println("  Testing PolynomialRing...")
        PolyType = create_polynomial_ring(:BFV_128)
        p1 = zero_polynomial(PolyType)
        p2 = one_polynomial(PolyType)
        p3 = p1 + p2
        @assert p3 == p2
        println("  ✅ PolynomialRing basic operations work")

        # Test Gaussian sampling
        println("  Testing Gaussian sampling...")
        sampler = DiscreteGaussianSampler(3.2)
        samples = sample_vector(sampler, 100)
        estimated_sigma = estimate_sigma(samples)
        @assert 2.0 < estimated_sigma < 5.0  # Reasonable range
        println("  ✅ Gaussian sampling works (σ ≈ $(round(estimated_sigma, digits=2)))")

        # Test RLWE
        println("  Testing RLWE...")
        params = create_rlwe_parameters(:conservative_128)
        sk = generate_secret_key(params)
        pk = generate_public_key(sk, params)

        # Test encryption/decryption
        message = zero_polynomial(params.polynomial_ring)
        ciphertext = rlwe_encrypt(message, pk, params)
        decrypted = rlwe_decrypt(ciphertext, sk)
        @assert is_valid_ciphertext(ciphertext, sk, message, 0.1)
        println("  ✅ RLWE encryption/decryption works")

        # Test homomorphic addition
        c1 = rlwe_encrypt(message, pk, params)
        c2 = rlwe_encrypt(message, pk, params)
        c_sum = rlwe_add(c1, c2)
        expected_sum = message + message
        @assert is_valid_ciphertext(c_sum, sk, expected_sum, 0.1)
        println("  ✅ RLWE homomorphic addition works")

        println("🎉 All lattice foundation tests passed!")
        return true

    catch e
        println("❌ Lattice foundation test failed: $e")
        return false
    end
end
