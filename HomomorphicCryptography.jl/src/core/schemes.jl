# Core abstract types and interfaces for homomorphic encryption schemes
# This module defines the foundational abstractions that all HE schemes must implement

"""
    HomomorphicScheme

Abstract base type for all homomorphic encryption schemes.
"""
abstract type HomomorphicScheme end

"""
    PartiallyHomomorphicScheme <: HomomorphicScheme

Abstract type for partially homomorphic encryption schemes that support
either addition OR multiplication (but not both arbitrarily).
"""
abstract type PartiallyHomomorphicScheme <: HomomorphicScheme end

"""
    SomewhatHomomorphicScheme <: HomomorphicScheme

Abstract type for somewhat homomorphic encryption schemes that support
both addition and multiplication but with limited depth.
"""
abstract type SomewhatHomomorphicScheme <: HomomorphicScheme end

"""
    FullyHomomorphicScheme <: HomomorphicScheme

Abstract type for fully homomorphic encryption schemes that support
arbitrary computation (addition and multiplication with unlimited depth).
"""
abstract type FullyHomomorphicScheme <: HomomorphicScheme end

# Key types
"""
    PublicKey

Abstract base type for public keys in homomorphic encryption schemes.
"""
abstract type PublicKey end

"""
    PrivateKey

Abstract base type for private/secret keys in homomorphic encryption schemes.
"""
abstract type PrivateKey end

"""
    KeyPair

Container for a public-private key pair.
"""
struct KeyPair{PK<:PublicKey,SK<:PrivateKey}
    public_key::PK
    private_key::SK
end

# Data types
"""
    Plaintext

Abstract base type for plaintext data in homomorphic encryption.
"""
abstract type Plaintext end

"""
    Ciphertext

Abstract base type for ciphertext data in homomorphic encryption.
"""
abstract type Ciphertext end

# Security parameters
"""
    SecurityParameters

Abstract base type for security parameters of homomorphic encryption schemes.
"""
abstract type SecurityParameters end

"""
    SecurityLevel

Enumeration of standard security levels.
"""
@enum SecurityLevel begin
    SECURITY_128 = 128
    SECURITY_192 = 192
    SECURITY_256 = 256
end

# Core operations that all schemes must implement
"""
    keygen(scheme::HomomorphicScheme, params::SecurityParameters) -> KeyPair

Generate a public-private key pair for the given scheme and security parameters.
"""
function keygen(scheme::HomomorphicScheme, params::SecurityParameters)
    error("keygen not implemented for $(typeof(scheme))")
end

"""
    encrypt(pk::PublicKey, plaintext::Plaintext) -> Ciphertext

Encrypt plaintext using the public key.
"""
function encrypt(pk::PublicKey, plaintext::Plaintext)
    error("encrypt not implemented for $(typeof(pk)) and $(typeof(plaintext))")
end

"""
    decrypt(sk::PrivateKey, ciphertext::Ciphertext) -> Plaintext

Decrypt ciphertext using the private key.
"""
function decrypt(sk::PrivateKey, ciphertext::Ciphertext)
    error("decrypt not implemented for $(typeof(sk)) and $(typeof(ciphertext))")
end

"""
    add_encrypted(c1::Ciphertext, c2::Ciphertext) -> Ciphertext

Perform homomorphic addition on two ciphertexts.
"""
function add_encrypted(c1::Ciphertext, c2::Ciphertext)
    error("add_encrypted not implemented for $(typeof(c1)) and $(typeof(c2))")
end

"""
    multiply_encrypted(c1::Ciphertext, c2::Ciphertext) -> Ciphertext

Perform homomorphic multiplication on two ciphertexts.
Only available for SHE and FHE schemes.
"""
function multiply_encrypted(c1::Ciphertext, c2::Ciphertext)
    error("multiply_encrypted not implemented for $(typeof(c1)) and $(typeof(c2))")
end

"""
    add_plain(c::Ciphertext, p::Plaintext) -> Ciphertext

Add a plaintext value to an encrypted value.
"""
function add_plain(c::Ciphertext, p::Plaintext)
    error("add_plain not implemented for $(typeof(c)) and $(typeof(p))")
end

"""
    multiply_plain(c::Ciphertext, p::Plaintext) -> Ciphertext

Multiply an encrypted value by a plaintext value.
"""
function multiply_plain(c::Ciphertext, p::Plaintext)
    error("multiply_plain not implemented for $(typeof(c)) and $(typeof(p))")
end

# Utility functions
"""
    scheme_name(scheme::HomomorphicScheme) -> String

Get the name of the homomorphic encryption scheme.
"""
function scheme_name(scheme::HomomorphicScheme)
    return string(typeof(scheme))
end

"""
    is_fully_homomorphic(scheme::HomomorphicScheme) -> Bool

Check if a scheme supports full homomorphic operations.
"""
is_fully_homomorphic(scheme::FullyHomomorphicScheme) = true
is_fully_homomorphic(scheme::HomomorphicScheme) = false

"""
    is_somewhat_homomorphic(scheme::HomomorphicScheme) -> Bool

Check if a scheme supports somewhat homomorphic operations.
"""
is_somewhat_homomorphic(scheme::SomewhatHomomorphicScheme) = true
is_somewhat_homomorphic(scheme::FullyHomomorphicScheme) = true
is_somewhat_homomorphic(scheme::HomomorphicScheme) = false

"""
    supports_addition(scheme::HomomorphicScheme) -> Bool

Check if a scheme supports homomorphic addition.
"""
supports_addition(scheme::HomomorphicScheme) = true

"""
    supports_multiplication(scheme::HomomorphicScheme) -> Bool

Check if a scheme supports homomorphic multiplication.
"""
supports_multiplication(scheme::PartiallyHomomorphicScheme) = false
supports_multiplication(scheme::SomewhatHomomorphicScheme) = true
supports_multiplication(scheme::FullyHomomorphicScheme) = true
