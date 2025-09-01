# Paillier Cryptosystem Implementation
# Compliant with ISO/IEC 18033-6:2019 standard for homomorphic encryption

using Random
using ..HomomorphicCryptography:
    PartiallyHomomorphicScheme,
    PublicKey,
    PrivateKey,
    Plaintext,
    Ciphertext,
    SecurityParameters,
    KeyPair,
    keygen,
    encrypt,
    decrypt,
    add_encrypted,
    add_plain,
    multiply_plain,
    get_recommended_parameters,
    PaillierParameters,
    SecurityLevel,
    SECURITY_128,
    generate_coprime_primes,
    carmichael_lambda,
    mod_inverse,
    miller_rabin_test

# Note: number_theory and parameters are included in the main module

"""
    PaillierScheme <: PartiallyHomomorphicScheme

Paillier cryptosystem implementation following ISO/IEC 18033-6:2019 standard.
Supports additive homomorphic operations on encrypted integers.
"""
struct PaillierScheme <: PartiallyHomomorphicScheme
    name::String

    PaillierScheme() = new("Paillier")
end

"""
    PaillierPublicKey <: PublicKey

Public key for Paillier cryptosystem.
Contains n = p*q and g (generator), along with n² for efficiency.
"""
struct PaillierPublicKey <: PublicKey
    n::BigInt          # n = p * q where p, q are large primes
    g::BigInt          # generator, typically g = n + 1
    n_squared::BigInt  # n² precomputed for efficiency
    key_size::Int      # Key size in bits

    function PaillierPublicKey(n::BigInt, g::BigInt)
        new(n, g, n^2, length(string(n, base = 2)))
    end
end

"""
    PaillierPrivateKey <: PrivateKey

Private key for Paillier cryptosystem.
Contains λ = lcm(p-1, q-1) and μ for efficient decryption.
"""
struct PaillierPrivateKey <: PrivateKey
    λ::BigInt          # λ = lcm(p-1, q-1)
    μ::BigInt          # μ = (L(g^λ mod n²))^(-1) mod n
    n::BigInt          # n = p * q (needed for decryption)
    n_squared::BigInt  # n² precomputed for efficiency

    function PaillierPrivateKey(λ::BigInt, μ::BigInt, n::BigInt)
        new(λ, μ, n, n^2)
    end
end

"""
    PaillierPlaintext <: Plaintext

Plaintext for Paillier cryptosystem - integer in range [0, n-1].
"""
struct PaillierPlaintext <: Plaintext
    value::BigInt

    function PaillierPlaintext(value::Integer)
        new(BigInt(value))
    end
end

"""
    PaillierCiphertext <: Ciphertext

Ciphertext for Paillier cryptosystem - integer in range [0, n²-1].
"""
struct PaillierCiphertext <: Ciphertext
    value::BigInt
    n::BigInt          # Modulus for homomorphic operations
    n_squared::BigInt  # n² for efficiency

    function PaillierCiphertext(value::BigInt, n::BigInt)
        new(value, n, n^2)
    end
end

# Implement required parameter interface
function get_recommended_parameters(
    ::Type{PaillierScheme},
    level::SecurityLevel = SECURITY_128,
)
    return PaillierParameters(level)
end

"""
    L_function(x::BigInt, n::BigInt) -> BigInt

Compute L(x) = (x - 1) / n for Paillier decryption.
This is a key component of the Paillier decryption algorithm.
"""
function L_function(x::BigInt, n::BigInt)
    return div(x - 1, n)
end

"""
    keygen(scheme::PaillierScheme, params::PaillierParameters;
           rng::AbstractRNG = Random.default_rng()) -> KeyPair

Generate Paillier key pair according to ISO/IEC 18033-6:2019.

# Algorithm Steps (ISO/IEC 18033-6:2019):
1. Generate two distinct primes p and q of equal bit length
2. Compute n = p * q
3. Compute λ = lcm(p-1, q-1)
4. Select generator g (typically g = n + 1 for efficiency)
5. Compute μ = (L(g^λ mod n²))^(-1) mod n
6. Public key: (n, g), Private key: (λ, μ)
"""
function keygen(
    scheme::PaillierScheme,
    params::PaillierParameters;
    rng::AbstractRNG = Random.default_rng(),
)

    # Step 1: Generate two distinct primes p and q
    p, q = generate_coprime_primes(params.p_size, rng)

    # Ensure p ≠ q (should be guaranteed by generate_coprime_primes)
    while p == q
        p, q = generate_coprime_primes(params.p_size, rng)
    end

    # Step 2: Compute n = p * q
    n = p * q

    # Step 3: Compute λ = lcm(p-1, q-1)
    λ = carmichael_lambda(p, q)

    # Step 4: Select generator g
    # For efficiency, we use g = n + 1 (this is valid and commonly used)
    g = n + 1

    # Step 5: Compute μ = (L(g^λ mod n²))^(-1) mod n
    n_squared = n^2
    g_lambda_mod_n_squared = powermod(g, λ, n_squared)
    l_value = L_function(g_lambda_mod_n_squared, n)
    μ = mod_inverse(l_value, n)

    # Create key pair
    public_key = PaillierPublicKey(n, g)
    private_key = PaillierPrivateKey(λ, μ, n)

    return KeyPair(public_key, private_key)
end

"""
    encrypt(pk::PaillierPublicKey, plaintext::PaillierPlaintext;
            rng::AbstractRNG = Random.default_rng()) -> PaillierCiphertext

Encrypt plaintext using Paillier public key according to ISO/IEC 18033-6:2019.

# Algorithm (ISO/IEC 18033-6:2019):
1. Select random r ∈ Z*_n (coprime to n)
2. Compute c = g^m * r^n mod n²
"""
function encrypt(
    pk::PaillierPublicKey,
    plaintext::PaillierPlaintext;
    rng::AbstractRNG = Random.default_rng(),
)

    m = plaintext.value

    # Validate plaintext is in valid range [0, n-1]
    if m < 0 || m >= pk.n
        throw(ArgumentError("Plaintext must be in range [0, n-1]"))
    end

    # Step 1: Select random r ∈ Z*_n
    # We need gcd(r, n) = 1
    r = rand(rng, BigInt(1):(pk.n-1))
    while gcd(r, pk.n) != 1
        r = rand(rng, BigInt(1):(pk.n-1))
    end

    # Step 2: Compute c = g^m * r^n mod n²
    g_to_m = powermod(pk.g, m, pk.n_squared)
    r_to_n = powermod(r, pk.n, pk.n_squared)
    c = mod(g_to_m * r_to_n, pk.n_squared)

    return PaillierCiphertext(c, pk.n)
end

"""
    decrypt(sk::PaillierPrivateKey, ciphertext::PaillierCiphertext) -> PaillierPlaintext

Decrypt ciphertext using Paillier private key according to ISO/IEC 18033-6:2019.

# Algorithm (ISO/IEC 18033-6:2019):
1. Compute m = L(c^λ mod n²) * μ mod n
"""
function decrypt(sk::PaillierPrivateKey, ciphertext::PaillierCiphertext)
    c = ciphertext.value

    # Validate ciphertext is in valid range [0, n²-1]
    if c < 0 || c >= sk.n_squared
        throw(ArgumentError("Ciphertext must be in range [0, n²-1]"))
    end

    # Step 1: Compute m = L(c^λ mod n²) * μ mod n
    c_lambda_mod_n_squared = powermod(c, sk.λ, sk.n_squared)
    l_value = L_function(c_lambda_mod_n_squared, sk.n)
    m = mod(l_value * sk.μ, sk.n)

    return PaillierPlaintext(m)
end

"""
    add_encrypted(c1::PaillierCiphertext, c2::PaillierCiphertext) -> PaillierCiphertext

Perform homomorphic addition of two Paillier ciphertexts.
E(m1) ⊕ E(m2) = E(m1 + m2) computed as c1 * c2 mod n².
"""
function add_encrypted(c1::PaillierCiphertext, c2::PaillierCiphertext)
    # Verify both ciphertexts use the same modulus
    if c1.n != c2.n
        throw(ArgumentError("Ciphertexts must have the same modulus"))
    end

    # Homomorphic addition: c1 * c2 mod n²
    result = mod(c1.value * c2.value, c1.n_squared)

    return PaillierCiphertext(result, c1.n)
end

"""
    add_plain(c::PaillierCiphertext, p::PaillierPlaintext) -> PaillierCiphertext

Add a plaintext value to an encrypted value.
E(m1) ⊕ m2 = E(m1 + m2) computed as c * g^m2 mod n².
"""
function add_plain(c::PaillierCiphertext, p::PaillierPlaintext)
    # For Paillier with g = n + 1, g^m = (n + 1)^m mod n²
    # We can compute this efficiently using binomial theorem
    g = c.n + 1  # Assuming standard generator
    g_to_m = powermod(g, p.value, c.n_squared)

    result = mod(c.value * g_to_m, c.n_squared)

    return PaillierCiphertext(result, c.n)
end

"""
    multiply_plain(c::PaillierCiphertext, scalar::Integer) -> PaillierCiphertext

Multiply an encrypted value by a plaintext scalar.
E(m) ⊗ k = E(k * m) computed as c^k mod n².
"""
function multiply_plain(c::PaillierCiphertext, scalar::Integer)
    if scalar < 0
        throw(ArgumentError("Scalar must be non-negative"))
    end

    # Homomorphic scalar multiplication: c^scalar mod n²
    result = powermod(c.value, scalar, c.n_squared)

    return PaillierCiphertext(result, c.n)
end

# Convenience functions for working with regular integers
"""
    encrypt(pk::PaillierPublicKey, plaintext::Integer; kwargs...) -> PaillierCiphertext

Convenience function to encrypt an integer directly.
"""
function encrypt(pk::PaillierPublicKey, plaintext::Integer; kwargs...)
    return encrypt(pk, PaillierPlaintext(plaintext); kwargs...)
end

"""
    decrypt_to_int(sk::PaillierPrivateKey, ciphertext::PaillierCiphertext) -> BigInt

Convenience function to decrypt directly to an integer.
"""
function decrypt_to_int(sk::PaillierPrivateKey, ciphertext::PaillierCiphertext)
    plaintext = decrypt(sk, ciphertext)
    return plaintext.value
end

# ISO/IEC 18033-6:2019 specific validation functions
"""
    validate_iso18033_6_compliance(scheme::PaillierScheme, params::PaillierParameters) -> Bool

Validate that the Paillier implementation complies with ISO/IEC 18033-6:2019 requirements.
"""
function validate_iso18033_6_compliance(scheme::PaillierScheme, params::PaillierParameters)
    try
        # Test key generation
        keypair = keygen(scheme, params)

        # Test encryption/decryption with known values
        test_values = [BigInt(0), BigInt(1), BigInt(42), BigInt(1337)]

        for val in test_values
            if val < keypair.public_key.n  # Ensure value is in valid range
                plaintext = PaillierPlaintext(val)
                ciphertext = encrypt(keypair.public_key, plaintext)
                decrypted = decrypt(keypair.private_key, ciphertext)

                if decrypted.value != val
                    return false
                end
            end
        end

        # Test homomorphic addition
        m1, m2 = BigInt(10), BigInt(20)
        if m1 + m2 < keypair.public_key.n
            c1 = encrypt(keypair.public_key, PaillierPlaintext(m1))
            c2 = encrypt(keypair.public_key, PaillierPlaintext(m2))
            c_sum = add_encrypted(c1, c2)
            decrypted_sum = decrypt(keypair.private_key, c_sum)

            if decrypted_sum.value != m1 + m2
                return false
            end
        end

        return true
    catch
        return false
    end
end

# Export main functions
export PaillierScheme,
    PaillierPublicKey,
    PaillierPrivateKey,
    PaillierPlaintext,
    PaillierCiphertext,
    encrypt,
    decrypt,
    add_encrypted,
    add_plain,
    multiply_plain,
    decrypt_to_int,
    validate_iso18033_6_compliance
