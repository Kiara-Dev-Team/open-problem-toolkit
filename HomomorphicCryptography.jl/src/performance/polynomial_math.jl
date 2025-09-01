# Fast polynomial multiplication algorithms
# Phase 3 implementation: Preparation for Phase 2 lattice-based cryptography

using LinearAlgebra

"""
    Polynomial{T}

Represents a polynomial with coefficients of type T.
Coefficients are stored in ascending order of powers (constant term first).
"""
struct Polynomial{T}
    coefficients::Vector{T}

    function Polynomial{T}(coeffs::Vector{T}) where {T}
        # Remove leading zeros
        while length(coeffs) > 1 && coeffs[end] == zero(T)
            pop!(coeffs)
        end
        new{T}(coeffs)
    end
end

# Convenience constructors
Polynomial(coeffs::Vector{T}) where {T} = Polynomial{T}(coeffs)
Polynomial{T}() where {T} = Polynomial{T}([zero(T)])

"""
    degree(p::Polynomial) -> Int

Return the degree of the polynomial.
"""
degree(p::Polynomial) = length(p.coefficients) - 1

"""
    evaluate(p::Polynomial{T}, x::T) -> T where T

Evaluate polynomial at point x using Horner's method.
"""
function evaluate(p::Polynomial{T}, x::T) where {T}
    if isempty(p.coefficients)
        return zero(T)
    end

    # Horner's method for efficient evaluation
    result = p.coefficients[end]
    for i = (length(p.coefficients)-1):-1:1
        result = result * x + p.coefficients[i]
    end

    return result
end

"""
    schoolbook_multiply(a::Polynomial{T}, b::Polynomial{T}) -> Polynomial{T} where T

Standard O(n²) polynomial multiplication algorithm.
"""
function schoolbook_multiply(a::Polynomial{T}, b::Polynomial{T}) where {T}
    if isempty(a.coefficients) || isempty(b.coefficients)
        return Polynomial{T}([zero(T)])
    end

    n, m = length(a.coefficients), length(b.coefficients)
    result_coeffs = zeros(T, n + m - 1)

    for i = 1:n
        for j = 1:m
            result_coeffs[i+j-1] += a.coefficients[i] * b.coefficients[j]
        end
    end

    return Polynomial{T}(result_coeffs)
end

"""
    karatsuba_multiply(a::Polynomial{T}, b::Polynomial{T}) -> Polynomial{T} where T

Karatsuba algorithm for O(n^log₂3) polynomial multiplication.
"""
function karatsuba_multiply(a::Polynomial{T}, b::Polynomial{T}) where {T}
    # Base case: use schoolbook for small polynomials
    if max(length(a.coefficients), length(b.coefficients)) <= 32
        return schoolbook_multiply(a, b)
    end

    # Pad to equal lengths
    n = max(length(a.coefficients), length(b.coefficients))
    a_padded = pad_polynomial(a, n)
    b_padded = pad_polynomial(b, n)

    # Handle odd lengths
    if isodd(n)
        n += 1
        a_padded = pad_polynomial(a_padded, n)
        b_padded = pad_polynomial(b_padded, n)
    end

    m = n ÷ 2

    # Split polynomials: a = a₁x^m + a₀, b = b₁x^m + b₀
    a0 = Polynomial{T}(a_padded.coefficients[1:m])
    a1 = Polynomial{T}(a_padded.coefficients[(m+1):end])
    b0 = Polynomial{T}(b_padded.coefficients[1:m])
    b1 = Polynomial{T}(b_padded.coefficients[(m+1):end])

    # Recursive calls
    z0 = karatsuba_multiply(a0, b0)           # a₀ * b₀
    z2 = karatsuba_multiply(a1, b1)           # a₁ * b₁
    z1 = karatsuba_multiply(polynomial_add(a0, a1), polynomial_add(b0, b1))                                         # (a₁ + a₀) * (b₁ + b₀)

    # z₁ = z₁ - z₂ - z₀
    z1 = polynomial_subtract(z1, polynomial_add(z2, z0))

    # Result = z₂x^(2m) + z₁x^m + z₀
    result = polynomial_add(
        polynomial_add(shift_polynomial(z2, 2*m), shift_polynomial(z1, m)),
        z0,
    )

    return result
end

"""
    fft_multiply(a::Polynomial{Complex{Float64}}, b::Polynomial{Complex{Float64}}) -> Polynomial{Complex{Float64}}

FFT-based polynomial multiplication in O(n log n).
"""
function fft_multiply(a::Polynomial{Complex{Float64}}, b::Polynomial{Complex{Float64}})
    n = length(a.coefficients) + length(b.coefficients) - 1

    # Find next power of 2
    fft_size = 2^ceil(Int, log2(n))

    # Pad polynomials
    a_padded = pad_polynomial(a, fft_size)
    b_padded = pad_polynomial(b, fft_size)

    # Forward FFT
    a_fft = fft(a_padded.coefficients)
    b_fft = fft(b_padded.coefficients)

    # Pointwise multiplication
    result_fft = a_fft .* b_fft

    # Inverse FFT
    result_coeffs = ifft(result_fft)

    # Remove padding and convert back to desired precision
    trimmed_coeffs = result_coeffs[1:n]

    return Polynomial{Complex{Float64}}(trimmed_coeffs)
end

"""
    number_theoretic_transform_multiply(a::Polynomial{T}, b::Polynomial{T}, 
                                      prime::T, root::T) -> Polynomial{T} where T

Number Theoretic Transform (NTT) based polynomial multiplication.
Essential for lattice-based cryptography.
"""
function number_theoretic_transform_multiply(
    a::Polynomial{T},
    b::Polynomial{T},
    prime::T,
    root::T,
) where {T<:Integer}
    n = length(a.coefficients) + length(b.coefficients) - 1

    # Find next power of 2
    ntt_size = 2^ceil(Int, log2(n))

    # Verify that prime supports NTT of this size
    if mod(prime - 1, ntt_size) != 0
        throw(ArgumentError("Prime $prime does not support NTT of size $ntt_size"))
    end

    # Pad polynomials
    a_padded = pad_polynomial(a, ntt_size)
    b_padded = pad_polynomial(b, ntt_size)

    # Forward NTT
    a_ntt = number_theoretic_transform(a_padded.coefficients, prime, root, false)
    b_ntt = number_theoretic_transform(b_padded.coefficients, prime, root, false)

    # Pointwise multiplication
    result_ntt = Vector{T}(undef, ntt_size)
    for i = 1:ntt_size
        result_ntt[i] = mod(a_ntt[i] * b_ntt[i], prime)
    end

    # Inverse NTT
    result_coeffs = number_theoretic_transform(result_ntt, prime, root, true)

    # Trim to actual result size
    trimmed_coeffs = result_coeffs[1:n]

    return Polynomial{T}(trimmed_coeffs)
end

"""
    number_theoretic_transform(data::Vector{T}, prime::T, root::T, inverse::Bool) -> Vector{T} where T

Compute Number Theoretic Transform or its inverse.
"""
function number_theoretic_transform(
    data::Vector{T},
    prime::T,
    root::T,
    inverse::Bool,
) where {T<:Integer}
    n = length(data)
    result = copy(data)

    if n <= 1
        return result
    end

    # Bit-reverse permutation
    j = 1
    for i = 2:n
        bit = n ÷ 2
        while j > bit
            j -= bit
            bit ÷= 2
        end
        j += bit
        if i < j
            result[i], result[j] = result[j], result[i]
        end
    end

    # Main NTT computation
    length_step = 2
    while length_step <= n
        # Root of unity for this step
        w = inverse ? mod_inverse(root, prime) : root
        w = powermod(w, (prime - 1) ÷ length_step, prime)

        for i = 1:length_step:n
            wn = T(1)
            for j = 0:(length_step÷2-1)
                u = result[i+j]
                v = mod(result[i+j+length_step÷2] * wn, prime)
                result[i+j] = mod(u + v, prime)
                result[i+j+length_step÷2] = mod(u - v + prime, prime)
                wn = mod(wn * w, prime)
            end
        end
        length_step *= 2
    end

    # Normalize for inverse transform
    if inverse
        n_inv = mod_inverse(T(n), prime)
        for i = 1:n
            result[i] = mod(result[i] * n_inv, prime)
        end
    end

    return result
end

"""
    mod_inverse(a::T, m::T) -> T where T <: Integer

Compute modular inverse of a modulo m using extended Euclidean algorithm.
"""
function mod_inverse(a::T, m::T) where {T<:Integer}
    if gcd(a, m) != 1
        throw(ArgumentError("$a and $m are not coprime"))
    end

    # Extended Euclidean Algorithm
    old_r, r = a, m
    old_s, s = T(1), T(0)

    while r != 0
        quotient = old_r ÷ r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    end

    return mod(old_s, m)
end

# Helper functions

"""
    pad_polynomial(p::Polynomial{T}, target_length::Int) -> Polynomial{T} where T

Pad polynomial with zeros to reach target length.
"""
function pad_polynomial(p::Polynomial{T}, target_length::Int) where {T}
    if length(p.coefficients) >= target_length
        return p
    end

    padded_coeffs = vcat(p.coefficients, zeros(T, target_length - length(p.coefficients)))
    return Polynomial{T}(padded_coeffs)
end

"""
    shift_polynomial(p::Polynomial{T}, shift::Int) -> Polynomial{T} where T

Multiply polynomial by x^shift (shift coefficients).
"""
function shift_polynomial(p::Polynomial{T}, shift::Int) where {T}
    if shift <= 0
        return p
    end

    shifted_coeffs = vcat(zeros(T, shift), p.coefficients)
    return Polynomial{T}(shifted_coeffs)
end

"""
    polynomial_add(a::Polynomial{T}, b::Polynomial{T}) -> Polynomial{T} where T

Add two polynomials.
"""
function polynomial_add(a::Polynomial{T}, b::Polynomial{T}) where {T}
    len_a = length(a.coefficients)
    len_b = length(b.coefficients)
    max_len = max(len_a, len_b)
    
    result_coeffs = zeros(T, max_len)
    
    # Add coefficients from polynomial a
    for i in 1:len_a
        result_coeffs[i] += a.coefficients[i]
    end
    
    # Add coefficients from polynomial b  
    for i in 1:len_b
        result_coeffs[i] += b.coefficients[i]
    end

    return Polynomial{T}(result_coeffs)
end

"""
    polynomial_subtract(a::Polynomial{T}, b::Polynomial{T}) -> Polynomial{T} where T

Subtract polynomial b from polynomial a.
"""
function polynomial_subtract(a::Polynomial{T}, b::Polynomial{T}) where {T}
    len_a = length(a.coefficients)
    len_b = length(b.coefficients)
    max_len = max(len_a, len_b)
    
    result_coeffs = zeros(T, max_len)
    
    # Add coefficients from polynomial a
    for i in 1:len_a
        result_coeffs[i] += a.coefficients[i]
    end
    
    # Subtract coefficients from polynomial b  
    for i in 1:len_b
        result_coeffs[i] -= b.coefficients[i]
    end

    return Polynomial{T}(result_coeffs)
end

"""
    benchmark_polynomial_multiplication(sizes::Vector{Int} = [64, 128, 256, 512])

Benchmark different polynomial multiplication algorithms.
"""
function benchmark_polynomial_multiplication(sizes::Vector{Int} = [64, 128, 256, 512])
    println("🧮 Polynomial Multiplication Benchmark")
    println("=" ^ 50)

    for size in sizes
        println("\nPolynomial size: $size")

        # Generate random polynomials
        a_coeffs = rand(1:100, size)
        b_coeffs = rand(1:100, size)
        a = Polynomial(a_coeffs)
        b = Polynomial(b_coeffs)

        # Schoolbook multiplication
        schoolbook_time = @elapsed schoolbook_result = schoolbook_multiply(a, b)
        println("  Schoolbook: $(round(schoolbook_time * 1000, digits=2)) ms")

        # Karatsuba multiplication
        karatsuba_time = @elapsed karatsuba_result = karatsuba_multiply(a, b)
        println("  Karatsuba:  $(round(karatsuba_time * 1000, digits=2)) ms")

        # Verify results match
        if schoolbook_result.coefficients ≈ karatsuba_result.coefficients
            println("  ✅ Results verified")
        else
            println("  ❌ Results don't match!")
        end
    end
end

# Simple FFT implementation for completeness
"""
    fft(x::Vector{Complex{T}}) -> Vector{Complex{T}} where T

Compute Fast Fourier Transform using Cooley-Tukey algorithm.
"""
function fft(x::Vector{Complex{T}}) where {T}
    N = length(x)

    if N <= 1
        return x
    end

    # Divide
    even = fft(x[1:2:end])
    odd = fft(x[2:2:end])

    # Combine
    result = Vector{Complex{T}}(undef, N)
    for k = 1:(N÷2)
        t = exp(-2im * π * (k-1) / N) * odd[k]
        result[k] = even[k] + t
        result[k+N÷2] = even[k] - t
    end

    return result
end

"""
    ifft(x::Vector{Complex{T}}) -> Vector{Complex{T}} where T

Compute Inverse Fast Fourier Transform.
"""
function ifft(x::Vector{Complex{T}}) where {T}
    N = length(x)
    # Conjugate, apply FFT, conjugate, and normalize
    result = conj.(fft(conj.(x))) ./ N
    return result
end

# Export polynomial functions
export Polynomial, degree, evaluate
export schoolbook_multiply, karatsuba_multiply, fft_multiply
export number_theoretic_transform_multiply, number_theoretic_transform
export mod_inverse, benchmark_polynomial_multiplication
export polynomial_add, polynomial_subtract, pad_polynomial, shift_polynomial
export fft, ifft
