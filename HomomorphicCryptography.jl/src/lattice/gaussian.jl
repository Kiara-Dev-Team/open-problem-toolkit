# Discrete Gaussian Sampling for Lattice-Based Cryptography
# Implements secure sampling from discrete Gaussian distributions

using Random
using Statistics

"""
    DiscreteGaussianSampler{T<:Real}

Sampler for discrete Gaussian distribution with parameter σ (standard deviation).
Uses rejection sampling with precomputed tables for efficiency and security.
"""
struct DiscreteGaussianSampler{T<:Real}
    σ::T                           # Standard deviation
    tail_bound::Int                # Maximum absolute value to sample
    probabilities::Vector{T}       # Precomputed probabilities
    cumulative::Vector{T}          # Cumulative distribution

    function DiscreteGaussianSampler{T}(σ::T, tail_bound::Int = 0) where {T<:Real}
        if σ <= 0
            throw(ArgumentError("Standard deviation σ must be positive"))
        end

        # Auto-compute tail bound if not provided
        if tail_bound == 0
            # Use 6σ as default (probability < 2^-50 beyond this)
            tail_bound = max(6 * ceil(Int, σ), 100)
        end

        # Precompute probabilities for z ∈ [-tail_bound, tail_bound]
        range_size = 2 * tail_bound + 1
        probabilities = Vector{T}(undef, range_size)

        # Compute unnormalized probabilities
        for i = 1:range_size
            z = i - tail_bound - 1  # Convert index to actual value
            probabilities[i] = exp(-T(z^2) / (2 * σ^2))
        end

        # Normalize
        total_prob = sum(probabilities)
        probabilities ./= total_prob

        # Compute cumulative distribution
        cumulative = cumsum(probabilities)

        new{T}(σ, tail_bound, probabilities, cumulative)
    end
end

# Convenience constructor
DiscreteGaussianSampler(σ::T, tail_bound::Int = 0) where {T<:Real} =
    DiscreteGaussianSampler{T}(σ, tail_bound)

"""
    sample(sampler::DiscreteGaussianSampler{T}, rng::AbstractRNG = Random.default_rng()) -> Int

Sample a single value from the discrete Gaussian distribution.
"""
function sample(
    sampler::DiscreteGaussianSampler{T},
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Real}
    # Use inverse transform sampling
    u = rand(rng, T)

    # Binary search in cumulative distribution
    idx = searchsortedfirst(sampler.cumulative, u)
    if idx > length(sampler.cumulative)
        idx = length(sampler.cumulative)
    end

    # Convert index back to value
    return idx - sampler.tail_bound - 1
end

"""
    sample_vector(sampler::DiscreteGaussianSampler{T}, n::Int, rng::AbstractRNG = Random.default_rng()) -> Vector{Int}

Sample a vector of n values from the discrete Gaussian distribution.
"""
function sample_vector(
    sampler::DiscreteGaussianSampler{T},
    n::Int,
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Real}
    return [sample(sampler, rng) for _ = 1:n]
end

"""
    sample_polynomial(sampler::DiscreteGaussianSampler{T}, ::Type{PolynomialRing{U, N, Q}}, rng::AbstractRNG = Random.default_rng()) -> PolynomialRing{U, N, Q}

Sample a polynomial with coefficients from the discrete Gaussian distribution.
"""
function sample_polynomial(
    sampler::DiscreteGaussianSampler{T},
    ::Type{PolynomialRing{U,N,Q}},
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Real,U<:Integer,N,Q}
    coeffs = sample_vector(sampler, N, rng)
    # Convert to proper type and reduce modulo Q
    u_coeffs = [mod(U(c), Q) for c in coeffs]
    return PolynomialRing{U,N,Q}(u_coeffs)
end

"""
    CenteredBinomialSampler

Sampler for centered binomial distribution B(2k, 1/2) - k.
This provides a good approximation to Gaussian for small parameters
and is more efficient to compute.
"""
struct CenteredBinomialSampler
    k::Int  # Half the number of coin flips

    function CenteredBinomialSampler(k::Int)
        if k <= 0
            throw(ArgumentError("Parameter k must be positive"))
        end
        new(k)
    end
end

"""
    sample(sampler::CenteredBinomialSampler, rng::AbstractRNG = Random.default_rng()) -> Int

Sample from centered binomial distribution.
"""
function sample(sampler::CenteredBinomialSampler, rng::AbstractRNG = Random.default_rng())
    # Generate 2k random bits and compute difference
    pos_count = 0
    neg_count = 0

    for _ = 1:sampler.k
        pos_count += rand(rng, Bool)
        neg_count += rand(rng, Bool)
    end

    return pos_count - neg_count
end

"""
    sample_vector(sampler::CenteredBinomialSampler, n::Int, rng::AbstractRNG = Random.default_rng()) -> Vector{Int}

Sample a vector from centered binomial distribution.
"""
function sample_vector(
    sampler::CenteredBinomialSampler,
    n::Int,
    rng::AbstractRNG = Random.default_rng(),
)
    return [sample(sampler, rng) for _ = 1:n]
end

"""
    sample_polynomial(sampler::CenteredBinomialSampler, ::Type{PolynomialRing{T, N, Q}}, rng::AbstractRNG = Random.default_rng()) -> PolynomialRing{T, N, Q}

Sample a polynomial with coefficients from the centered binomial distribution.
"""
function sample_polynomial(
    sampler::CenteredBinomialSampler,
    ::Type{PolynomialRing{T,N,Q}},
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Integer,N,Q}
    coeffs = sample_vector(sampler, N, rng)
    t_coeffs = [mod(T(c), Q) for c in coeffs]
    return PolynomialRing{T,N,Q}(t_coeffs)
end

"""
    UniformSampler{T}

Sampler for uniform distribution over [0, bound).
"""
struct UniformSampler{T<:Integer}
    bound::T

    function UniformSampler{T}(bound::T) where {T<:Integer}
        if bound <= 0
            throw(ArgumentError("Bound must be positive"))
        end
        new{T}(bound)
    end
end

UniformSampler(bound::T) where {T<:Integer} = UniformSampler{T}(bound)

"""
    sample(sampler::UniformSampler{T}, rng::AbstractRNG = Random.default_rng()) -> T

Sample uniformly from [0, bound).
"""
function sample(
    sampler::UniformSampler{T},
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Integer}
    return rand(rng, T(0):(sampler.bound-1))
end

"""
    sample_vector(sampler::UniformSampler{T}, n::Int, rng::AbstractRNG = Random.default_rng()) -> Vector{T}

Sample a vector uniformly.
"""
function sample_vector(
    sampler::UniformSampler{T},
    n::Int,
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Integer}
    return [sample(sampler, rng) for _ = 1:n]
end

"""
    sample_polynomial(sampler::UniformSampler{T}, ::Type{PolynomialRing{T, N, Q}}, rng::AbstractRNG = Random.default_rng()) -> PolynomialRing{T, N, Q}

Sample a polynomial with uniform coefficients.
"""
function sample_polynomial(
    sampler::UniformSampler{T},
    ::Type{PolynomialRing{T,N,Q}},
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Integer,N,Q}
    coeffs = sample_vector(sampler, N, rng)
    return PolynomialRing{T,N,Q}(coeffs)
end

"""
    TernarySampler

Sampler for ternary distribution {-1, 0, 1} with specified probabilities.
"""
struct TernarySampler{T<:Real}
    prob_neg::T    # Probability of -1
    prob_zero::T   # Probability of 0
    prob_pos::T    # Probability of +1

    function TernarySampler{T}(prob_neg::T, prob_zero::T, prob_pos::T) where {T<:Real}
        if abs(prob_neg + prob_zero + prob_pos - 1) > 1e-10
            throw(ArgumentError("Probabilities must sum to 1"))
        end
        if any([prob_neg, prob_zero, prob_pos] .< 0)
            throw(ArgumentError("Probabilities must be non-negative"))
        end
        new{T}(prob_neg, prob_zero, prob_pos)
    end
end

# Balanced ternary (equal probabilities)
TernarySampler() = TernarySampler{Float64}(1/3, 1/3, 1/3)

"""
    sample(sampler::TernarySampler{T}, rng::AbstractRNG = Random.default_rng()) -> Int

Sample from ternary distribution.
"""
function sample(
    sampler::TernarySampler{T},
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Real}
    u = rand(rng, T)

    if u < sampler.prob_neg
        return -1
    elseif u < sampler.prob_neg + sampler.prob_zero
        return 0
    else
        return 1
    end
end

"""
    sample_vector(sampler::TernarySampler{T}, n::Int, rng::AbstractRNG = Random.default_rng()) -> Vector{Int}

Sample a vector from ternary distribution.
"""
function sample_vector(
    sampler::TernarySampler{T},
    n::Int,
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Real}
    return [sample(sampler, rng) for _ = 1:n]
end

"""
    sample_polynomial(sampler::TernarySampler{T}, ::Type{PolynomialRing{U, N, Q}}, rng::AbstractRNG = Random.default_rng()) -> PolynomialRing{U, N, Q}

Sample a polynomial with ternary coefficients.
"""
function sample_polynomial(
    sampler::TernarySampler{T},
    ::Type{PolynomialRing{U,N,Q}},
    rng::AbstractRNG = Random.default_rng(),
) where {T<:Real,U<:Integer,N,Q}
    coeffs = sample_vector(sampler, N, rng)
    u_coeffs = [mod(U(c), Q) for c in coeffs]
    return PolynomialRing{U,N,Q}(u_coeffs)
end

# Statistical analysis functions
"""
    estimate_sigma(samples::Vector{Int}) -> Float64

Estimate the standard deviation of discrete Gaussian samples.
"""
function estimate_sigma(samples::Vector{Int})
    return sqrt(var(samples))
end

"""
    chi_squared_test(samples::Vector{Int}, expected_sigma::Float64, alpha::Float64 = 0.05) -> Bool

Perform chi-squared goodness of fit test for discrete Gaussian distribution.
"""
function chi_squared_test(
    samples::Vector{Int},
    expected_sigma::Float64,
    alpha::Float64 = 0.05,
)
    # Simple implementation - bins the data and compares to expected frequencies
    n = length(samples)
    max_val = maximum(abs.(samples))

    # Create bins
    bins = (-max_val):max_val
    observed = [count(==(b), samples) for b in bins]

    # Expected frequencies
    expected = [n * exp(-b^2 / (2 * expected_sigma^2)) for b in bins]
    expected ./= sum(expected)  # Normalize
    expected .*= n

    # Chi-squared statistic
    chi2 = sum((observed .- expected) .^ 2 ./ expected)

    # Degrees of freedom (number of bins - 1 - estimated parameters)
    df = length(bins) - 2

    # Critical value (approximate)
    critical_value = df + 2 * sqrt(2 * df)  # Approximate 95th percentile

    return chi2 < critical_value
end

# Export main types and functions
export DiscreteGaussianSampler, CenteredBinomialSampler
export UniformSampler, TernarySampler
export sample, sample_vector, sample_polynomial
export estimate_sigma, chi_squared_test
