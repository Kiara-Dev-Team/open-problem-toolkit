# Security parameters and parameter generation for homomorphic encryption schemes

using Random

# SecurityParameters is defined in core/schemes.jl
# This file contains concrete implementations of SecurityParameters

"""
    StandardSecurityParameters

Standard security parameters following community recommendations.
"""
struct StandardSecurityParameters <: SecurityParameters
    security_level::SecurityLevel
    key_size::Int

    function StandardSecurityParameters(level::SecurityLevel)
        key_size = security_level_to_key_size(level)
        new(level, key_size)
    end
end

"""
    security_level_to_key_size(level::SecurityLevel) -> Int

Convert security level to recommended key size in bits.
"""
function security_level_to_key_size(level::SecurityLevel)
    if level == SECURITY_128
        return 2048  # For RSA/Paillier-like schemes
    elseif level == SECURITY_192
        return 3072
    elseif level == SECURITY_256
        return 4096
    else
        error("Unsupported security level: $level")
    end
end

"""
    PaillierParameters <: SecurityParameters

Security parameters specific to Paillier cryptosystem.
Follows ISO/IEC 18033-6:2019 recommendations.
"""
struct PaillierParameters <: SecurityParameters
    security_level::SecurityLevel
    key_size::Int  # Size of n = p*q in bits
    p_size::Int    # Size of prime p in bits
    q_size::Int    # Size of prime q in bits

    function PaillierParameters(level::SecurityLevel = SECURITY_128)
        key_size = security_level_to_key_size(level)
        # For Paillier, we need two primes of equal size
        prime_size = key_size ÷ 2
        new(level, key_size, prime_size, prime_size)
    end
end

"""
    LatticeParameters <: SecurityParameters

Security parameters for lattice-based schemes (BFV, BGV, CKKS, TFHE).
Based on HomomorphicEncryption.org security standard.
"""
struct LatticeParameters <: SecurityParameters
    security_level::SecurityLevel
    ring_dimension::Int       # n - polynomial ring dimension
    ciphertext_modulus::BigInt # q - ciphertext modulus
    plaintext_modulus::Int    # t - plaintext modulus (for BFV/BGV)
    noise_distribution::Symbol # :gaussian or :uniform
    noise_parameter::Float64   # σ for Gaussian, bound for uniform

    function LatticeParameters(
        level::SecurityLevel = SECURITY_128;
        plaintext_modulus::Int = 1024,
        noise_distribution::Symbol = :gaussian,
    )
        ring_dim, cipher_mod, noise_param = lattice_params_for_security_level(level)
        new(level, ring_dim, cipher_mod, plaintext_modulus, noise_distribution, noise_param)
    end
end

"""
    lattice_params_for_security_level(level::SecurityLevel) -> Tuple{Int, BigInt, Float64}

Get recommended lattice parameters for a given security level.
Based on HomomorphicEncryption.org security standard.
"""
function lattice_params_for_security_level(level::SecurityLevel)
    if level == SECURITY_128
        # Conservative parameters for 128-bit security
        ring_dimension = 4096
        ciphertext_modulus = BigInt(2)^109  # ~109-bit modulus
        noise_parameter = 3.2  # Gaussian parameter σ
        return (ring_dimension, ciphertext_modulus, noise_parameter)
    elseif level == SECURITY_192
        ring_dimension = 8192
        ciphertext_modulus = BigInt(2)^218
        noise_parameter = 3.2
        return (ring_dimension, ciphertext_modulus, noise_parameter)
    elseif level == SECURITY_256
        ring_dimension = 16384
        ciphertext_modulus = BigInt(2)^438
        noise_parameter = 3.2
        return (ring_dimension, ciphertext_modulus, noise_parameter)
    else
        error("Unsupported security level: $level")
    end
end

"""
    CKKSParameters <: SecurityParameters

Security parameters specific to CKKS scheme for approximate arithmetic.
"""
struct CKKSParameters <: SecurityParameters
    security_level::SecurityLevel
    ring_dimension::Int
    ciphertext_modulus::BigInt
    scale::Float64           # Scaling factor for encoding
    precision_bits::Int      # Precision in bits for real numbers
    max_depth::Int          # Maximum multiplicative depth

    function CKKSParameters(
        level::SecurityLevel = SECURITY_128;
        scale::Float64 = 2.0^40,
        precision_bits::Int = 50,
        max_depth::Int = 10,
    )
        ring_dim, cipher_mod, _ = lattice_params_for_security_level(level)
        # Adjust modulus for CKKS rescaling operations
        adjusted_mod = cipher_mod * BigInt(2)^(max_depth * 40)  # Reserve bits for rescaling
        new(level, ring_dim, adjusted_mod, scale, precision_bits, max_depth)
    end
end

"""
    TFHEParameters <: SecurityParameters

Security parameters specific to TFHE scheme for boolean operations.
"""
struct TFHEParameters <: SecurityParameters
    security_level::SecurityLevel
    lwe_dimension::Int       # n for LWE
    lwe_modulus::Int        # q for LWE
    rlwe_dimension::Int     # N for RLWE (bootstrapping key)
    rlwe_modulus::BigInt    # Q for RLWE
    noise_parameter::Float64 # σ for error distribution

    function TFHEParameters(level::SecurityLevel = SECURITY_128)
        if level == SECURITY_128
            # Standard TFHE parameters for 128-bit security
            lwe_dim = 630
            lwe_mod = 2^32
            rlwe_dim = 1024
            rlwe_mod = BigInt(2)^32
            noise_param = 2^(-15)  # Very small noise for TFHE
        else
            error("Only 128-bit security currently supported for TFHE")
        end
        new(level, lwe_dim, lwe_mod, rlwe_dim, rlwe_mod, noise_param)
    end
end

"""
    validate_parameters(params::SecurityParameters) -> Bool

Validate that security parameters meet minimum security requirements.
"""
function validate_parameters(params::PaillierParameters)
    # Check minimum key size for security level
    min_key_size = security_level_to_key_size(params.security_level)
    return params.key_size >= min_key_size
end

function validate_parameters(params::LatticeParameters)
    # Check that ring dimension and modulus size are sufficient
    min_ring_dim, min_mod, _ = lattice_params_for_security_level(params.security_level)
    return params.ring_dimension >= min_ring_dim && params.ciphertext_modulus >= min_mod
end

function validate_parameters(params::CKKSParameters)
    # Validate CKKS-specific constraints
    min_ring_dim, min_mod, _ = lattice_params_for_security_level(params.security_level)
    modulus_bits = length(string(params.ciphertext_modulus, base = 2))
    required_bits = length(string(min_mod, base = 2)) + params.max_depth * 40

    return (
        params.ring_dimension >= min_ring_dim &&
        modulus_bits >= required_bits &&
        params.scale > 1.0 &&
        params.precision_bits > 0
    )
end

function validate_parameters(params::TFHEParameters)
    # Basic validation for TFHE parameters
    return (
        params.lwe_dimension > 0 && params.rlwe_dimension > 0 && params.noise_parameter > 0
    )
end

"""
    get_recommended_parameters(scheme_type::Type{<:HomomorphicScheme},
                              level::SecurityLevel = SECURITY_128) -> SecurityParameters

Get recommended security parameters for a specific scheme type and security level.
"""
function get_recommended_parameters(
    scheme_type::Type{<:HomomorphicScheme},
    level::SecurityLevel = SECURITY_128,
)
    error("get_recommended_parameters not implemented for $scheme_type")
end
