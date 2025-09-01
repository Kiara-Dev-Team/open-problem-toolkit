# Polynomial Ring Arithmetic for Lattice-Based Cryptography
# Implements operations in the ring Zq[X]/(X^n + 1) used in RLWE-based schemes

using Random
using LinearAlgebra

"""
    PolynomialRing{T, N, Q}

Represents the polynomial ring Zq[X]/(X^n + 1) where:
- T: coefficient type (typically Int64 or BigInt)
- N: polynomial degree (power of 2)
- Q: modulus
"""
struct PolynomialRing{T<:Integer,N,Q}
    coefficients::Vector{T}

    function PolynomialRing{T,N,Q}(coeffs::Vector{T}) where {T<:Integer,N,Q}
        if length(coeffs) != N
            throw(ArgumentError("Polynomial must have exactly $N coefficients"))
        end
        # Reduce coefficients modulo Q
        reduced_coeffs = [mod(c, Q) for c in coeffs]
        new{T,N,Q}(reduced_coeffs)
    end
end

# Convenience constructors
PolynomialRing{T,N,Q}(coeffs::Vector{<:Integer}) where {T,N,Q} =
    PolynomialRing{T,N,Q}(convert(Vector{T}, coeffs))

"""
    degree(p::PolynomialRing{T, N, Q}) -> Int

Get the degree of the polynomial ring.
"""
degree(::PolynomialRing{T,N,Q}) where {T,N,Q} = N

"""
    modulus(p::PolynomialRing{T, N, Q}) -> Q

Get the coefficient modulus.
"""
modulus(::PolynomialRing{T,N,Q}) where {T,N,Q} = Q

"""
    zero_polynomial(::Type{PolynomialRing{T, N, Q}}) -> PolynomialRing{T, N, Q}

Create the zero polynomial.
"""
zero_polynomial(::Type{PolynomialRing{T,N,Q}}) where {T,N,Q} =
    PolynomialRing{T,N,Q}(zeros(T, N))

"""
    one_polynomial(::Type{PolynomialRing{T, N, Q}}) -> PolynomialRing{T, N, Q}

Create the polynomial 1 (constant term 1, all others 0).
"""
function one_polynomial(::Type{PolynomialRing{T,N,Q}}) where {T,N,Q}
    coeffs = zeros(T, N)
    coeffs[1] = one(T)
    PolynomialRing{T,N,Q}(coeffs)
end

"""
    random_polynomial(::Type{PolynomialRing{T, N, Q}}, rng::AbstractRNG = Random.default_rng()) -> PolynomialRing{T, N, Q}

Generate a random polynomial with coefficients in [0, Q).
"""
function random_polynomial(
    ::Type{PolynomialRing{T,N,Q}},
    rng::AbstractRNG = Random.default_rng(),
) where {T,N,Q}
    coeffs = [rand(rng, T(0):T(Q-1)) for _ = 1:N]
    PolynomialRing{T,N,Q}(coeffs)
end

# Basic arithmetic operations

"""
    +(p1::PolynomialRing{T, N, Q}, p2::PolynomialRing{T, N, Q}) -> PolynomialRing{T, N, Q}

Add two polynomials in the ring.
"""
function Base.:+(p1::PolynomialRing{T,N,Q}, p2::PolynomialRing{T,N,Q}) where {T,N,Q}
    result_coeffs = [mod(p1.coefficients[i] + p2.coefficients[i], Q) for i = 1:N]
    PolynomialRing{T,N,Q}(result_coeffs)
end

"""
    -(p1::PolynomialRing{T, N, Q}, p2::PolynomialRing{T, N, Q}) -> PolynomialRing{T, N, Q}

Subtract two polynomials in the ring.
"""
function Base.:-(p1::PolynomialRing{T,N,Q}, p2::PolynomialRing{T,N,Q}) where {T,N,Q}
    result_coeffs = [mod(p1.coefficients[i] - p2.coefficients[i], Q) for i = 1:N]
    PolynomialRing{T,N,Q}(result_coeffs)
end

"""
    -(p::PolynomialRing{T, N, Q}) -> PolynomialRing{T, N, Q}

Negate a polynomial.
"""
function Base.:-(p::PolynomialRing{T,N,Q}) where {T,N,Q}
    result_coeffs = [mod(-c, Q) for c in p.coefficients]
    PolynomialRing{T,N,Q}(result_coeffs)
end

"""
    *(p1::PolynomialRing{T, N, Q}, p2::PolynomialRing{T, N, Q}) -> PolynomialRing{T, N, Q}

Multiply two polynomials in the ring Zq[X]/(X^n + 1).
This is the key operation that implements the cyclotomic polynomial reduction.
"""
function Base.:*(p1::PolynomialRing{T,N,Q}, p2::PolynomialRing{T,N,Q}) where {T,N,Q}
    # Naive polynomial multiplication followed by reduction
    # For production use, this should be replaced with NTT-based multiplication

    # Full multiplication (degree up to 2N-2)
    full_coeffs = zeros(T, 2*N - 1)

    for i = 1:N
        for j = 1:N
            full_coeffs[i+j-1] += p1.coefficients[i] * p2.coefficients[j]
        end
    end

    # Reduce by X^n + 1
    # X^n ≡ -1 (mod X^n + 1)
    # So X^(n+k) ≡ -X^k
    result_coeffs = zeros(T, N)

    for i = 1:N
        result_coeffs[i] = full_coeffs[i]
    end

    for i = (N+1):(2*N-1)
        result_coeffs[i-N] -= full_coeffs[i]
    end

    # Reduce modulo Q
    result_coeffs = [mod(c, Q) for c in result_coeffs]

    PolynomialRing{T,N,Q}(result_coeffs)
end

"""
    *(p::PolynomialRing{T, N, Q}, scalar::Integer) -> PolynomialRing{T, N, Q}

Multiply polynomial by a scalar.
"""
function Base.:*(p::PolynomialRing{T,N,Q}, scalar::Integer) where {T,N,Q}
    result_coeffs = [mod(c * scalar, Q) for c in p.coefficients]
    PolynomialRing{T,N,Q}(result_coeffs)
end

Base.:*(scalar::Integer, p::PolynomialRing{T,N,Q}) where {T,N,Q} = p * scalar

"""
    ==(p1::PolynomialRing{T, N, Q}, p2::PolynomialRing{T, N, Q}) -> Bool

Check equality of two polynomials.
"""
function Base.:(==)(p1::PolynomialRing{T,N,Q}, p2::PolynomialRing{T,N,Q}) where {T,N,Q}
    return p1.coefficients == p2.coefficients
end

"""
    norm_infinity(p::PolynomialRing{T, N, Q}) -> T

Compute the infinity norm (maximum absolute coefficient) of the polynomial.
"""
function norm_infinity(p::PolynomialRing{T,N,Q}) where {T,N,Q}
    max_coeff = zero(T)
    half_q = Q ÷ 2

    for c in p.coefficients
        # Convert to centered representation [-Q/2, Q/2)
        centered_c = c > half_q ? c - Q : c
        max_coeff = max(max_coeff, abs(centered_c))
    end

    return max_coeff
end

"""
    norm_2_squared(p::PolynomialRing{T, N, Q}) -> T

Compute the squared L2 norm of the polynomial.
"""
function norm_2_squared(p::PolynomialRing{T,N,Q}) where {T,N,Q}
    sum_squares = zero(T)
    half_q = Q ÷ 2

    for c in p.coefficients
        # Convert to centered representation
        centered_c = c > half_q ? c - Q : c
        sum_squares += centered_c^2
    end

    return sum_squares
end

"""
    to_centered_form(p::PolynomialRing{T, N, Q}) -> Vector{T}

Convert polynomial coefficients to centered form [-Q/2, Q/2).
"""
function to_centered_form(p::PolynomialRing{T,N,Q}) where {T,N,Q}
    half_q = Q ÷ 2
    return [c > half_q ? c - Q : c for c in p.coefficients]
end

"""
    from_centered_form(coeffs::Vector{T}, ::Type{PolynomialRing{T, N, Q}}) -> PolynomialRing{T, N, Q}

Create polynomial from coefficients in centered form.
"""
function from_centered_form(coeffs::Vector{T}, ::Type{PolynomialRing{T,N,Q}}) where {T,N,Q}
    if length(coeffs) != N
        throw(ArgumentError("Must have exactly $N coefficients"))
    end

    # Convert to [0, Q) representation
    positive_coeffs = [mod(c, Q) for c in coeffs]
    return PolynomialRing{T,N,Q}(positive_coeffs)
end

# Display
function Base.show(io::IO, p::PolynomialRing{T,N,Q}) where {T,N,Q}
    print(io, "PolynomialRing{$T, $N, $Q}(")
    if N <= 8
        print(io, p.coefficients)
    else
        print(
            io,
            "[$(p.coefficients[1]), $(p.coefficients[2]), ..., $(p.coefficients[N-1]), $(p.coefficients[N])]",
        )
    end
    print(io, ")")
end

# Common parameter sets for lattice cryptography
"""
Standard parameter sets for common lattice-based schemes.
"""
const LATTICE_PARAMS = Dict(
    # BFV/BGV parameters
    :BFV_128 => (N = 1024, Q = 132120577, T = Int64),
    :BFV_192 => (N = 2048, Q = 137438953471, T = Int64),
    :BFV_256 => (N = 4096, Q = 1152921504606846975, T = Int64),

    # CKKS parameters (approximate)
    :CKKS_128 => (N = 2048, Q = 1152921504606846975, T = Int64),
    :CKKS_192 => (N = 4096, Q = 1152921504606846975, T = Int64),
    :CKKS_256 => (N = 8192, Q = 1152921504606846975, T = Int64),
)

"""
    create_polynomial_ring(param_set::Symbol) -> Type

Create a polynomial ring type for a standard parameter set.
"""
function create_polynomial_ring(param_set::Symbol)
    if !haskey(LATTICE_PARAMS, param_set)
        throw(ArgumentError("Unknown parameter set: $param_set"))
    end

    params = LATTICE_PARAMS[param_set]
    return PolynomialRing{params.T,params.N,params.Q}
end

# Export main types and functions
export PolynomialRing, degree, modulus
export zero_polynomial, one_polynomial, random_polynomial
export norm_infinity, norm_2_squared
export to_centered_form, from_centered_form
export LATTICE_PARAMS, create_polynomial_ring
