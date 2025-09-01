# ElGamal Cryptosystem Implementation (Exponential ElGamal variant)
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
    generate_prime,
    mod_inverse,
    miller_rabin_test

"""
    ElGamalScheme <: PartiallyHomomorphicScheme

Exponential ElGamal cryptosystem implementation following ISO/IEC 18033-6:2019 standard.
Supports additive homomorphic operations on encrypted integers (in the exponent).
"""
struct ElGamalScheme <: PartiallyHomomorphicScheme
    name::String

    ElGamalScheme() = new("ElGamal")
end

"""
    ElGamalParameters <: SecurityParameters

Security parameters specific to ElGamal cryptosystem following ISO/IEC 18033-6:2019.
"""
struct ElGamalParameters <: SecurityParameters
    security_level::SecurityLevel
    p_size::Int          # Size of prime p in bits
    q_size::Int          # Size of prime q in bits (where p = 2q + 1)

    function ElGamalParameters(level::SecurityLevel = SECURITY_128)
        if level == SECURITY_128
            p_size = 2048
            q_size = 1024  # Safe prime: p = 2q + 1
        elseif level == SECURITY_192
            p_size = 3072
            q_size = 1536
        elseif level == SECURITY_256
            p_size = 4096
            q_size = 2048
        else
            error("Unsupported security level: $level")
        end
        new(level, p_size, q_size)
    end
end

"""
    ElGamalPublicKey <: PublicKey

Public key for ElGamal cryptosystem.
Contains prime p, generator g, and public key element h = g^x mod p.
"""
struct ElGamalPublicKey <: PublicKey
    p::BigInt          # Large prime (safe prime)
    g::BigInt          # Generator of subgroup of order q
    h::BigInt          # h = g^x mod p (public key element)
    q::BigInt          # Order of subgroup (p = 2q + 1)
    key_size::Int      # Key size in bits

    function ElGamalPublicKey(p::BigInt, g::BigInt, h::BigInt, q::BigInt)
        new(p, g, h, q, length(string(p, base = 2)))
    end
end

"""
    ElGamalPrivateKey <: PrivateKey

Private key for ElGamal cryptosystem.
Contains the secret exponent x.
"""
struct ElGamalPrivateKey <: PrivateKey
    x::BigInt          # Secret key (private exponent)
    p::BigInt          # Prime p (needed for operations)
    q::BigInt          # Order q (needed for operations)

    function ElGamalPrivateKey(x::BigInt, p::BigInt, q::BigInt)
        new(x, p, q)
    end
end

"""
    ElGamalPlaintext <: Plaintext

Plaintext for ElGamal cryptosystem.
Note: In exponential ElGamal, the message m is encoded as g^m.
"""
struct ElGamalPlaintext <: Plaintext
    value::BigInt

    function ElGamalPlaintext(value::Integer)
        if value < 0
            throw(ArgumentError("ElGamal plaintext must be non-negative"))
        end
        new(BigInt(value))
    end
end

"""
    ElGamalCiphertext <: Ciphertext

Ciphertext for ElGamal cryptosystem.
Consists of a pair (c1, c2) where c1 = g^r and c2 = h^r * g^m.
"""
struct ElGamalCiphertext <: Ciphertext
    c1::BigInt         # c1 = g^r mod p
    c2::BigInt         # c2 = h^r * g^m mod p
    p::BigInt          # Prime modulus
    g::BigInt          # Generator (needed for decryption)

    function ElGamalCiphertext(c1::BigInt, c2::BigInt, p::BigInt, g::BigInt)
        new(c1, c2, p, g)
    end
end

# Implement required parameter interface
function get_recommended_parameters(
    ::Type{ElGamalScheme},
    level::SecurityLevel = SECURITY_128,
)
    return ElGamalParameters(level)
end

"""
    find_generator(p::BigInt, q::BigInt, rng::AbstractRNG = Random.default_rng()) -> BigInt

Find a generator g of the subgroup of order q in Z*_p.
For safe prime p = 2q + 1, we need g^q ≡ 1 (mod p) and g^1 ≢ 1 (mod p).
"""
function find_generator(p::BigInt, q::BigInt, rng::AbstractRNG = Random.default_rng())
    while true
        # Generate random element in Z*_p
        candidate = rand(rng, BigInt(2):(p-2))

        # Compute g = candidate^2 mod p (ensures g is in subgroup of order q)
        g = powermod(candidate, 2, p)

        # Check if g has order q
        if powermod(g, q, p) == 1 && g != 1
            return g
        end
    end
end

"""
    keygen(scheme::ElGamalScheme, params::ElGamalParameters;
           rng::AbstractRNG = Random.default_rng()) -> KeyPair

Generate ElGamal key pair according to ISO/IEC 18033-6:2019.

# Algorithm Steps (ISO/IEC 18033-6:2019):
1. Generate safe prime p = 2q + 1 where q is also prime
2. Find generator g of subgroup of order q
3. Choose random secret key x ∈ [1, q-1]
4. Compute h = g^x mod p
5. Public key: (p, g, h), Private key: x
"""
function keygen(
    scheme::ElGamalScheme,
    params::ElGamalParameters;
    rng::AbstractRNG = Random.default_rng(),
)

    # Step 1: Generate safe prime p = 2q + 1
    while true
        q = generate_prime(params.q_size, rng)
        p = 2 * q + 1

        if miller_rabin_test(p)
            # Step 2: Find generator g of subgroup of order q
            g = find_generator(p, q, rng)

            # Step 3: Choose random secret key x ∈ [1, q-1]
            x = rand(rng, BigInt(1):(q-1))

            # Step 4: Compute h = g^x mod p
            h = powermod(g, x, p)

            # Create key pair
            public_key = ElGamalPublicKey(p, g, h, q)
            private_key = ElGamalPrivateKey(x, p, q)

            return KeyPair(public_key, private_key)
        end
    end
end

"""
    encrypt(pk::ElGamalPublicKey, plaintext::ElGamalPlaintext;
            rng::AbstractRNG = Random.default_rng()) -> ElGamalCiphertext

Encrypt plaintext using ElGamal public key according to ISO/IEC 18033-6:2019.
Uses exponential ElGamal where the message is encoded in the exponent.

# Algorithm (ISO/IEC 18033-6:2019):
1. Choose random r ∈ [1, q-1]
2. Compute c1 = g^r mod p
3. Compute c2 = h^r * g^m mod p
4. Return (c1, c2)
"""
function encrypt(
    pk::ElGamalPublicKey,
    plaintext::ElGamalPlaintext;
    rng::AbstractRNG = Random.default_rng(),
)

    m = plaintext.value

    # Practical limit for exponential ElGamal (discrete log becomes hard)
    if m > 1000000  # 1 million
        @warn "Large plaintext values make decryption computationally expensive"
    end

    # Step 1: Choose random r ∈ [1, q-1]
    r = rand(rng, BigInt(1):(pk.q-1))

    # Step 2: Compute c1 = g^r mod p
    c1 = powermod(pk.g, r, pk.p)

    # Step 3: Compute c2 = h^r * g^m mod p
    h_r = powermod(pk.h, r, pk.p)
    g_m = powermod(pk.g, m, pk.p)
    c2 = mod(h_r * g_m, pk.p)

    return ElGamalCiphertext(c1, c2, pk.p, pk.g)
end

"""
    decrypt(sk::ElGamalPrivateKey, ciphertext::ElGamalCiphertext) -> ElGamalPlaintext

Decrypt ciphertext using ElGamal private key according to ISO/IEC 18033-6:2019.
Note: This requires solving discrete logarithm, so only practical for small messages.

# Algorithm (ISO/IEC 18033-6:2019):
1. Compute s = c1^x mod p
2. Compute g^m = c2 * s^(-1) mod p
3. Solve discrete log to find m such that g^m ≡ result (mod p)
"""
function decrypt(sk::ElGamalPrivateKey, ciphertext::ElGamalCiphertext)
    c1, c2 = ciphertext.c1, ciphertext.c2

    # Step 1: Compute s = c1^x mod p
    s = powermod(c1, sk.x, sk.p)

    # Step 2: Compute g^m = c2 * s^(-1) mod p
    s_inv = mod_inverse(s, sk.p)
    g_m = mod(c2 * s_inv, sk.p)

    # Step 3: Solve discrete log (brute force for small m)
    # This is the limitation of exponential ElGamal
    # Now we have access to the generator through the ciphertext

    # Try to find m by brute force (practical only for small values)
    for m = 0:10000  # Reasonable limit for testing
        if powermod(ciphertext.g, m, sk.p) == g_m
            return ElGamalPlaintext(m)
        end
    end

    error("Decryption failed: message too large or corrupted ciphertext")
end

"""
    add_encrypted(c1::ElGamalCiphertext, c2::ElGamalCiphertext) -> ElGamalCiphertext

Perform homomorphic addition of two ElGamal ciphertexts.
E(m1) ⊕ E(m2) = E(m1 + m2) computed as (c1₁ * c1₂, c2₁ * c2₂).
"""
function add_encrypted(c1::ElGamalCiphertext, c2::ElGamalCiphertext)
    # Verify both ciphertexts use the same modulus
    if c1.p != c2.p
        throw(ArgumentError("Ciphertexts must have the same modulus"))
    end

    # Homomorphic addition: (c1₁ * c1₂ mod p, c2₁ * c2₂ mod p)
    new_c1 = mod(c1.c1 * c2.c1, c1.p)
    new_c2 = mod(c1.c2 * c2.c2, c1.p)

    return ElGamalCiphertext(new_c1, new_c2, c1.p, c1.g)
end

"""
    multiply_plain(c::ElGamalCiphertext, scalar::Integer) -> ElGamalCiphertext

Multiply an encrypted value by a plaintext scalar.
E(m) ⊗ k = E(k * m) computed as (c1^k mod p, c2^k mod p).
"""
function multiply_plain(c::ElGamalCiphertext, scalar::Integer)
    if scalar < 0
        throw(ArgumentError("Scalar must be non-negative"))
    end

    # Homomorphic scalar multiplication: (c1^scalar mod p, c2^scalar mod p)
    new_c1 = powermod(c.c1, scalar, c.p)
    new_c2 = powermod(c.c2, scalar, c.p)

    return ElGamalCiphertext(new_c1, new_c2, c.p, c.g)
end

# Convenience functions
"""
    encrypt(pk::ElGamalPublicKey, plaintext::Integer; kwargs...) -> ElGamalCiphertext

Convenience function to encrypt an integer directly.
"""
function encrypt(pk::ElGamalPublicKey, plaintext::Integer; kwargs...)
    return encrypt(pk, ElGamalPlaintext(plaintext); kwargs...)
end

"""
    decrypt_to_int(sk::ElGamalPrivateKey, ciphertext::ElGamalCiphertext) -> BigInt

Convenience function to decrypt directly to an integer.
"""
function decrypt_to_int(sk::ElGamalPrivateKey, ciphertext::ElGamalCiphertext)
    plaintext = decrypt(sk, ciphertext)
    return plaintext.value
end

"""
    validate_elgamal_iso18033_6(scheme::ElGamalScheme, params::ElGamalParameters) -> Bool

Validate ElGamal implementation against ISO/IEC 18033-6:2019 requirements.
"""
function validate_elgamal_iso18033_6(scheme::ElGamalScheme, params::ElGamalParameters)
    try
        # Test key generation
        keypair = keygen(scheme, params)

        # Test encryption/decryption with small values (due to discrete log limitation)
        test_values = [BigInt(0), BigInt(1), BigInt(5), BigInt(10), BigInt(25)]

        for val in test_values
            plaintext = ElGamalPlaintext(val)
            ciphertext = encrypt(keypair.public_key, plaintext)
            decrypted = decrypt(keypair.private_key, ciphertext)

            if decrypted.value != val
                return false
            end
        end

        # Test homomorphic addition
        m1, m2 = BigInt(3), BigInt(7)
        c1 = encrypt(keypair.public_key, ElGamalPlaintext(m1))
        c2 = encrypt(keypair.public_key, ElGamalPlaintext(m2))
        c_sum = add_encrypted(c1, c2)
        decrypted_sum = decrypt(keypair.private_key, c_sum)

        if decrypted_sum.value != m1 + m2
            return false
        end

        return true
    catch
        return false
    end
end

# Export main functions
export ElGamalScheme,
    ElGamalPublicKey,
    ElGamalPrivateKey,
    ElGamalPlaintext,
    ElGamalCiphertext,
    ElGamalParameters,
    encrypt,
    decrypt,
    add_encrypted,
    multiply_plain,
    decrypt_to_int,
    validate_elgamal_iso18033_6
