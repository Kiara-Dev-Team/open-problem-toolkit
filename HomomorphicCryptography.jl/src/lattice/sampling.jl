# Discrete sampling utilities for lattice-based schemes

using Random

"""
    discrete_gaussian(n::Integer; sigma::Float64 = 3.2, rng=Random.default_rng()) -> Vector{BigInt}

Generate n samples from a discrete Gaussian by rounding a normal `N(0, sigma^2)`.
Note: This is a simple, non-constant-time sampler suitable for prototyping.
"""
function discrete_gaussian(
    n::Integer;
    sigma::Float64 = 3.2,
    rng::AbstractRNG = Random.default_rng(),
)
    vals = Vector{BigInt}(undef, Int(n))
    for i = 1:Int(n)
        x = randn(rng) * sigma
        vals[i] = BigInt(round(Int, x))
    end
    return vals
end

"""
    centered_binomial_distribution(n::Integer, eta::Integer; rng=Random.default_rng()) -> Vector{Int}

Sample n values from the centered binomial distribution CBD_η.
Each sample is the difference of two binomial random variables: Binomial(η, 1/2) - Binomial(η, 1/2).
This produces values in [-η, η] with a distribution that approximates a discrete Gaussian.

Parameters:
- n: Number of samples to generate
- eta: Parameter controlling the standard deviation (σ ≈ √(η/2))
- rng: Random number generator

Common values:
- eta=2 gives standard deviation ≈ 1.0 (used in Kyber)
- eta=3 gives standard deviation ≈ 1.22
"""
function centered_binomial_distribution(
    n::Integer,
    eta::Integer;
    rng::AbstractRNG = Random.default_rng()
)
    vals = Vector{Int}(undef, Int(n))
    eta_int = Int(eta)
    
    for i = 1:Int(n)
        # Generate two binomial(eta, 1/2) samples by counting bits
        sum1 = 0
        sum2 = 0
        
        # Use efficient bit sampling for small eta
        if eta_int <= 16
            # Generate 2*eta random bits
            bits = rand(rng, UInt32) & ((1 << (2 * eta_int)) - 1)
            
            # Count bits in first eta positions for sum1
            for j = 0:(eta_int-1)
                sum1 += (bits >> j) & 1
            end
            
            # Count bits in next eta positions for sum2
            for j = eta_int:(2*eta_int-1)
                sum2 += (bits >> j) & 1
            end
        else
            # For larger eta, use individual coin flips
            for _ = 1:eta_int
                sum1 += rand(rng, Bool)
                sum2 += rand(rng, Bool)
            end
        end
        
        vals[i] = sum1 - sum2
    end
    
    return vals
end

"""
    binomial_poly(n::Integer, q::Integer, eta::Integer; rng=Random.default_rng()) -> PolyZqN

Create a polynomial with coefficients sampled from the centered binomial distribution.
This is the preferred sampling method for BFV, BGV, and similar schemes.
"""
function binomial_poly(
    n::Integer,
    q::Integer,
    eta::Integer;
    rng::AbstractRNG = Random.default_rng()
)
    coeffs = centered_binomial_distribution(n, eta; rng=rng)
    # Map to [0, q-1] using mod operation
    qc = BigInt(q)
    big_coeffs = [mod(BigInt(c), qc) for c in coeffs]
    return PolyZqN(q, n; coeffs=big_coeffs)
end

"""
    gaussian_poly(n::Integer, q::Integer; sigma=3.2, rng=Random.default_rng()) -> PolyZqN

Create a polynomial with small (centered) coefficients modulo q using discrete Gaussian sampling.
"""
function gaussian_poly(
    n::Integer,
    q::Integer;
    sigma::Float64 = 3.2,
    rng::AbstractRNG = Random.default_rng(),
)
    coeffs = discrete_gaussian(n; sigma = sigma, rng = rng)
    # Map to [0, q-1]
    qc = BigInt(q)
    coeffs = [mod(c, qc) for c in coeffs]
    return PolyZqN(q, n; coeffs)
end

 

"""
    hamming_weight_poly(n::Integer, q::Integer, weight::Integer; rng=Random.default_rng()) -> PolyZqN

Create a polynomial with exactly `weight` non-zero coefficients from {-1, 1}.
This gives precise control over the sparsity and can be useful for certain applications.
"""
function hamming_weight_poly(
    n::Integer,
    q::Integer,
    weight::Integer;
    rng::AbstractRNG = Random.default_rng()
)
    n_int = Int(n)
    weight_int = Int(weight)
    
    @assert 0 <= weight_int <= n_int "Weight must be between 0 and n"
    
    # Start with zero polynomial
    coeffs = zeros(Int, n_int)
    
    # Randomly select positions for non-zero coefficients
    positions = randperm(rng, n_int)[1:weight_int]
    
    # Set selected positions to ±1 randomly
    for pos in positions
        coeffs[pos] = rand(rng, [-1, 1])
    end
    
    qc = BigInt(q)
    big_coeffs = [mod(BigInt(c), qc) for c in coeffs]
    return PolyZqN(q, n; coeffs=big_coeffs)
end

export discrete_gaussian, gaussian_poly

"""
    centered_binomial(n::Integer; k::Int=8, rng=Random.default_rng()) -> Vector{Int}

Sample n values from centered binomial distribution CBD(k):
sum_{i=1..k} b_i - sum_{i=1..k} b'_i where b_i, b'_i ~ Ber(1/2).
"""
function centered_binomial(n::Integer; k::Int = 8, rng::AbstractRNG = Random.default_rng())
    nn = Int(n)
    vals = Vector{Int}(undef, nn)
    for i in 1:nn
        s1 = 0
        s2 = 0
        @inbounds for _ in 1:k
            s1 += rand(rng, Bool) ? 1 : 0
            s2 += rand(rng, Bool) ? 1 : 0
        end
        vals[i] = s1 - s2
    end
    return vals
end

"""
    centered_binomial_poly(n::Integer, q::Integer; k::Int=8, rng=Random.default_rng()) -> PolyZqN

Centered binomial sampler lifted to polynomial modulo q.
"""
function centered_binomial_poly(
    n::Integer,
    q::Integer;
    k::Int = 8,
    rng::AbstractRNG = Random.default_rng(),
)
    qc = BigInt(q)
    coeffs = centered_binomial(n; k=k, rng=rng)
    coeffs_q = [mod(BigInt(c), qc) for c in coeffs]
    return PolyZqN(q, n; coeffs=coeffs_q)
end

"""
    ternary_poly(n::Integer, q::Integer; p_nonzero=0.5, rng=Random.default_rng()) -> PolyZqN

Sample coefficients in {-1, 0, 1} with given nonzero probability.
"""
function ternary_poly(
    n::Integer,
    q::Integer;
    p_nonzero::Float64 = 0.5,
    rng::AbstractRNG = Random.default_rng(),
)
    qc = BigInt(q)
    coeffs = Vector{BigInt}(undef, Int(n))
    for i in 1:Int(n)
        u = rand(rng)
        if u < p_nonzero / 2
            coeffs[i] = mod(BigInt(1), qc)
        elseif u < p_nonzero
            coeffs[i] = mod(BigInt(-1), qc)
        else
            coeffs[i] = BigInt(0)
        end
    end
    return PolyZqN(q, n; coeffs)
end

export centered_binomial, centered_binomial_poly, ternary_poly
export centered_binomial_distribution, binomial_poly
export hamming_weight_poly
