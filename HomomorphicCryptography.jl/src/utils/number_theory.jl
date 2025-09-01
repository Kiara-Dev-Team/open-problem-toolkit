# Number theory utilities for homomorphic encryption
# Provides essential mathematical operations needed for cryptographic schemes

using Random

"""
    generate_safe_prime(bits::Int, rng::AbstractRNG = Random.default_rng()) -> BigInt

Generate a safe prime p such that p = 2q + 1 where q is also prime.
Used in some cryptographic constructions for enhanced security.
"""
function generate_safe_prime(bits::Int, rng::AbstractRNG = Random.default_rng())
    while true
        # Generate candidate q
        q = generate_prime(bits - 1, rng)
        p = 2 * q + 1

        if miller_rabin_test(p)
            return p
        end
    end
end

"""
    generate_prime(bits::Int, rng::AbstractRNG = Random.default_rng()) -> BigInt

Generate a random prime of specified bit length.
"""
function generate_prime(bits::Int, rng::AbstractRNG = Random.default_rng())
    while true
        # Generate random odd number of correct bit length
        candidate = rand(rng, (BigInt(2)^(bits-1)):(BigInt(2)^bits-1))
        # Ensure it's odd
        candidate |= 1

        if miller_rabin_test(candidate)
            return candidate
        end
    end
end

"""
    generate_coprime_primes(bits::Int, rng::AbstractRNG = Random.default_rng()) -> Tuple{BigInt, BigInt}

Generate two coprime primes of specified bit length.
Used for schemes like Paillier where we need gcd(p-1, q-1) to be small.
"""
function generate_coprime_primes(bits::Int, rng::AbstractRNG = Random.default_rng())
    while true
        p = generate_prime(bits, rng)
        q = generate_prime(bits, rng)

        # Ensure p ≠ q and that they don't share small factors
        if p != q && gcd(p-1, q-1) <= 2
            return p, q
        end
    end
end

"""
    mod_inverse(a::Integer, m::Integer) -> Integer

Compute the modular inverse of a modulo m using extended Euclidean algorithm.
Returns x such that a*x ≡ 1 (mod m), or throws an error if gcd(a,m) ≠ 1.
"""
function mod_inverse(a::Integer, m::Integer)
    a = mod(a, m)
    if a == 0
        throw(ArgumentError("Cannot compute inverse of 0"))
    end

    # Extended Euclidean Algorithm
    old_r, r = a, m
    old_s, s = 1, 0

    while r != 0
        quotient = div(old_r, r)
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    end

    if old_r != 1
        throw(ArgumentError("$a and $m are not coprime"))
    end

    return mod(old_s, m)
end

"""
    chinese_remainder_theorem(remainders::Vector{T}, moduli::Vector{T}) where T<:Integer -> T

Solve system of congruences using Chinese Remainder Theorem.
Returns x such that x ≡ remainders[i] (mod moduli[i]) for all i.
"""
function chinese_remainder_theorem(
    remainders::Vector{T},
    moduli::Vector{T},
) where {T<:Integer}
    if length(remainders) != length(moduli)
        throw(ArgumentError("remainders and moduli must have same length"))
    end

    if length(remainders) == 0
        return zero(T)
    end

    # Check that moduli are pairwise coprime
    for i = 1:length(moduli)
        for j = (i+1):length(moduli)
            if gcd(moduli[i], moduli[j]) != 1
                throw(ArgumentError("moduli must be pairwise coprime"))
            end
        end
    end

    # Compute product of all moduli
    M = prod(moduli)

    result = zero(T)
    for i = 1:length(remainders)
        Mi = div(M, moduli[i])
        yi = mod_inverse(Mi, moduli[i])
        result += remainders[i] * Mi * yi
    end

    return mod(result, M)
end

"""
    jacobi_symbol(a::Integer, n::Integer) -> Int

Compute the Jacobi symbol (a/n).
Returns -1, 0, or 1.
"""
function jacobi_symbol(a::Integer, n::Integer)
    if n <= 0 || iseven(n)
        throw(ArgumentError("n must be positive and odd"))
    end

    a = mod(a, n)
    result = 1

    while a != 0
        while iseven(a)
            a = div(a, 2)
            r = mod(n, 8)
            if r == 3 || r == 5
                result = -result
            end
        end

        a, n = n, a
        if mod(a, 4) == 3 && mod(n, 4) == 3
            result = -result
        end
        a = mod(a, n)
    end

    return n == 1 ? result : 0
end

"""
    legendre_symbol(a::Integer, p::Integer) -> Int

Compute the Legendre symbol (a/p) for prime p.
Returns -1 if a is a quadratic non-residue mod p,
         0 if a ≡ 0 (mod p),
         1 if a is a quadratic residue mod p.
"""
function legendre_symbol(a::Integer, p::Integer)
    if !miller_rabin_test(p) || p == 2
        throw(ArgumentError("p must be an odd prime"))
    end
    return jacobi_symbol(a, p)
end

"""
    quadratic_residue_test(a::Integer, n::Integer) -> Bool

Test if a is a quadratic residue modulo n.
"""
function quadratic_residue_test(a::Integer, n::Integer)
    return jacobi_symbol(a, n) == 1
end

"""
    random_quadratic_residue(n::Integer, rng::AbstractRNG = Random.default_rng()) -> BigInt

Generate a random quadratic residue modulo n.
"""
function random_quadratic_residue(n::Integer, rng::AbstractRNG = Random.default_rng())
    while true
        x = rand(rng, 1:(n-1))
        if gcd(x, n) == 1
            return mod(x^2, n)
        end
    end
end

"""
    random_quadratic_nonresidue(n::Integer, rng::AbstractRNG = Random.default_rng()) -> BigInt

Generate a random quadratic non-residue modulo n.
"""
function random_quadratic_nonresidue(n::Integer, rng::AbstractRNG = Random.default_rng())
    while true
        x = rand(rng, 1:(n-1))
        if gcd(x, n) == 1 && jacobi_symbol(x, n) == -1
            return x
        end
    end
end

"""
    lcm(a::Integer, b::Integer) -> Integer

Compute the least common multiple of a and b.
"""
function lcm(a::Integer, b::Integer)
    return abs(a * b) ÷ gcd(a, b)
end

"""
    euler_totient(n::Integer) -> Integer

Compute Euler's totient function φ(n).
For efficiency, this assumes n = p*q where p and q are prime.
"""
function euler_totient(n::Integer)
    # For general case, we'd need factorization
    # For cryptographic use, we typically know the factorization
    throw(
        ArgumentError(
            "euler_totient requires factorization - use euler_totient(p, q) for n = p*q",
        ),
    )
end

"""
    euler_totient(p::Integer, q::Integer) -> Integer

Compute φ(n) where n = p*q and p, q are prime.
φ(n) = (p-1)(q-1)
"""
function euler_totient(p::Integer, q::Integer)
    return (p - 1) * (q - 1)
end

"""
    carmichael_lambda(p::Integer, q::Integer) -> Integer

Compute Carmichael's lambda function λ(n) where n = p*q.
λ(n) = lcm(p-1, q-1)
"""
function carmichael_lambda(p::Integer, q::Integer)
    return lcm(p - 1, q - 1)
end

"""
    miller_rabin_test(n::Integer, k::Int = 10) -> Bool

Miller-Rabin primality test with k rounds.
Returns true if n is probably prime, false if definitely composite.
"""
function miller_rabin_test(n::Integer, k::Int = 10)
    if n < 2
        return false
    end
    if n == 2 || n == 3
        return true
    end
    if iseven(n)
        return false
    end

    # Write n-1 = d * 2^r
    d = n - 1
    r = 0
    while iseven(d)
        d = div(d, 2)
        r += 1
    end

    # Perform k rounds of testing
    for _ = 1:k
        a = rand(2:(n-2))
        x = powermod(a, d, n)

        if x == 1 || x == n - 1
            continue
        end

        composite = true
        for _ = 1:(r-1)
            x = powermod(x, 2, n)
            if x == n - 1
                composite = false
                break
            end
        end

        if composite
            return false
        end
    end

    return true
end
