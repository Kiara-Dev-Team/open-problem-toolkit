# Optimized Paillier operations with Phase 3 performance enhancements
# Hardware acceleration, multi-threading, and memory optimization

using Random
using Base.Threads
using ..HomomorphicCryptography:
    PaillierScheme,
    PaillierPublicKey,
    PaillierPrivateKey,
    PaillierPlaintext,
    PaillierCiphertext,
    encrypt,
    decrypt,
    add_encrypted,
    multiply_plain,
    MemoryPool,
    get_pooled_bigint,
    return_pooled_bigint!,
    batch_modular_exponentiation,
    batch_modular_multiplication,
    PerformanceMetrics,
    record_operation!,
    secure_zero!

"""
    OptimizedPaillierOperations

Collection of performance-optimized Paillier cryptographic operations.
Implements Phase 3 features: hardware acceleration, multi-threading, and memory optimization.
"""
struct OptimizedPaillierOperations end

"""
    batch_encrypt(pk::PaillierPublicKey, plaintexts::Vector{<:Integer}; 
                 rng::AbstractRNG = Random.default_rng()) -> Vector{PaillierCiphertext}

Batch encrypt multiple plaintexts in parallel for improved performance.
Uses threading and optimized memory allocation.
"""
function batch_encrypt(
    pk::PaillierPublicKey,
    plaintexts::Vector{<:Integer};
    rng::AbstractRNG = Random.default_rng(),
    pool::MemoryPool = MemoryPool(),
    metrics::Union{PerformanceMetrics,Nothing} = nothing,
)
    n = length(plaintexts)
    ciphertexts = Vector{PaillierCiphertext}(undef, n)

    # Pre-allocate random values for all encryptions
    randoms = Vector{BigInt}(undef, n)

    # Generate all random values in parallel
    Threads.@threads for i = 1:n
        # Generate random r ∈ Z*_n with gcd(r, n) = 1
        r = rand(rng, BigInt(1):(pk.n-1))
        while gcd(r, pk.n) != 1
            r = rand(rng, BigInt(1):(pk.n-1))
        end
        randoms[i] = r
    end

    # Prepare batch operations
    g_powers = Vector{BigInt}(undef, n)
    r_powers = Vector{BigInt}(undef, n)
    moduli_g = fill(pk.n_squared, n)
    moduli_r = fill(pk.n_squared, n)

    # Convert plaintexts to BigInt and validate
    bigint_plaintexts = Vector{BigInt}(undef, n)
    for i = 1:n
        m = BigInt(plaintexts[i])
        if m < 0 || m >= pk.n
            throw(ArgumentError("Plaintext $i must be in range [0, n-1]"))
        end
        bigint_plaintexts[i] = m
    end

    start_time = time()

    # Batch compute g^m mod n² for all plaintexts
    g_bases = fill(pk.g, n)
    g_powers = batch_modular_exponentiation(g_bases, bigint_plaintexts, moduli_g)

    # Batch compute r^n mod n² for all randoms  
    r_bases = randoms
    n_exponents = fill(pk.n, n)
    r_powers = batch_modular_exponentiation(r_bases, n_exponents, moduli_r)

    # Batch multiply g^m * r^n mod n²
    final_values = batch_modular_multiplication(g_powers, r_powers, moduli_g)

    # Create ciphertext objects
    Threads.@threads for i = 1:n
        ciphertexts[i] = PaillierCiphertext(final_values[i], pk.n)
    end

    # Securely clear temporary values
    for i = 1:n
        secure_zero!(randoms[i])
    end

    elapsed_time = time() - start_time
    if metrics !== nothing
        record_operation!(metrics, elapsed_time, n * sizeof(BigInt) * 4)
    end

    return ciphertexts
end

"""
    batch_decrypt(sk::PaillierPrivateKey, ciphertexts::Vector{PaillierCiphertext}) -> Vector{BigInt}

Batch decrypt multiple ciphertexts in parallel for improved performance.
"""
function batch_decrypt(
    sk::PaillierPrivateKey,
    ciphertexts::Vector{PaillierCiphertext};
    metrics::Union{PerformanceMetrics,Nothing} = nothing,
)
    n = length(ciphertexts)
    plaintexts = Vector{BigInt}(undef, n)

    # Validate all ciphertexts first
    for i = 1:n
        c = ciphertexts[i].value
        if c < 0 || c >= sk.n_squared
            throw(ArgumentError("Ciphertext $i must be in range [0, n²-1]"))
        end
    end

    start_time = time()

    # Prepare batch operations for c^λ mod n²
    c_values = [ct.value for ct in ciphertexts]
    lambda_exponents = fill(sk.λ, n)
    moduli = fill(sk.n_squared, n)

    # Batch compute c^λ mod n² 
    c_lambda_values = batch_modular_exponentiation(c_values, lambda_exponents, moduli)

    # Compute L function and final result in parallel
    Threads.@threads for i = 1:n
        # L(c^λ mod n²) = (c^λ mod n² - 1) / n
        l_value = div(c_lambda_values[i] - 1, sk.n)
        # m = L_value * μ mod n
        plaintexts[i] = mod(l_value * sk.μ, sk.n)
    end

    elapsed_time = time() - start_time
    if metrics !== nothing
        record_operation!(metrics, elapsed_time, n * sizeof(BigInt) * 2)
    end

    return plaintexts
end

"""
    batch_add_encrypted(c1_vec::Vector{PaillierCiphertext}, c2_vec::Vector{PaillierCiphertext}) -> Vector{PaillierCiphertext}

Batch homomorphic addition of multiple ciphertext pairs.
"""
function batch_add_encrypted(
    c1_vec::Vector{PaillierCiphertext},
    c2_vec::Vector{PaillierCiphertext};
    metrics::Union{PerformanceMetrics,Nothing} = nothing,
)
    @assert length(c1_vec) == length(c2_vec) "Input vectors must have equal length"

    n = length(c1_vec)
    results = Vector{PaillierCiphertext}(undef, n)

    start_time = time()

    # Verify moduli compatibility and prepare batch operations
    c1_values = Vector{BigInt}(undef, n)
    c2_values = Vector{BigInt}(undef, n)
    moduli = Vector{BigInt}(undef, n)

    for i = 1:n
        if c1_vec[i].n != c2_vec[i].n
            throw(ArgumentError("Ciphertexts $i must have the same modulus"))
        end
        c1_values[i] = c1_vec[i].value
        c2_values[i] = c2_vec[i].value
        moduli[i] = c1_vec[i].n_squared
    end

    # Batch multiplication (homomorphic addition)
    result_values = batch_modular_multiplication(c1_values, c2_values, moduli)

    # Create result ciphertexts
    Threads.@threads for i = 1:n
        results[i] = PaillierCiphertext(result_values[i], c1_vec[i].n)
    end

    elapsed_time = time() - start_time
    if metrics !== nothing
        record_operation!(metrics, elapsed_time, n * sizeof(BigInt) * 3)
    end

    return results
end

"""
    batch_multiply_plain(ciphertexts::Vector{PaillierCiphertext}, scalars::Vector{<:Integer}) -> Vector{PaillierCiphertext}

Batch homomorphic scalar multiplication.
"""
function batch_multiply_plain(
    ciphertexts::Vector{PaillierCiphertext},
    scalars::Vector{<:Integer};
    metrics::Union{PerformanceMetrics,Nothing} = nothing,
)
    @assert length(ciphertexts) == length(scalars) "Input vectors must have equal length"

    n = length(ciphertexts)
    results = Vector{PaillierCiphertext}(undef, n)

    # Validate scalars
    for i = 1:n
        if scalars[i] < 0
            throw(ArgumentError("Scalar $i must be non-negative"))
        end
    end

    start_time = time()

    # Prepare batch operations
    c_values = [ct.value for ct in ciphertexts]
    scalar_bigints = [BigInt(s) for s in scalars]
    moduli = [ct.n_squared for ct in ciphertexts]

    # Batch compute c^scalar mod n²
    result_values = batch_modular_exponentiation(c_values, scalar_bigints, moduli)

    # Create result ciphertexts
    Threads.@threads for i = 1:n
        results[i] = PaillierCiphertext(result_values[i], ciphertexts[i].n)
    end

    elapsed_time = time() - start_time
    if metrics !== nothing
        record_operation!(metrics, elapsed_time, n * sizeof(BigInt) * 3)
    end

    return results
end

"""
    optimized_homomorphic_sum(ciphertexts::Vector{PaillierCiphertext}) -> PaillierCiphertext

Compute the homomorphic sum of multiple ciphertexts using tree reduction for optimal performance.
"""
function optimized_homomorphic_sum(
    ciphertexts::Vector{PaillierCiphertext};
    metrics::Union{PerformanceMetrics,Nothing} = nothing,
)
    if isempty(ciphertexts)
        throw(ArgumentError("Cannot compute sum of empty vector"))
    end

    if length(ciphertexts) == 1
        return ciphertexts[1]
    end

    start_time = time()

    # Verify all ciphertexts have same modulus
    n_mod = ciphertexts[1].n
    for ct in ciphertexts
        if ct.n != n_mod
            throw(ArgumentError("All ciphertexts must have the same modulus"))
        end
    end

    # Tree reduction for optimal parallel performance
    current_level = copy(ciphertexts)

    while length(current_level) > 1
        next_level = Vector{PaillierCiphertext}()

        # Process pairs in parallel
        pairs =
            [(current_level[i], current_level[i+1]) for i = 1:2:(length(current_level)-1)]

        if !isempty(pairs)
            pair_results = Vector{PaillierCiphertext}(undef, length(pairs))

            Threads.@threads for i = 1:length(pairs)
                c1, c2 = pairs[i]
                result_val = mod(c1.value * c2.value, c1.n_squared)
                pair_results[i] = PaillierCiphertext(result_val, c1.n)
            end

            append!(next_level, pair_results)
        end

        # Handle odd element
        if isodd(length(current_level))
            push!(next_level, current_level[end])
        end

        current_level = next_level
    end

    elapsed_time = time() - start_time
    if metrics !== nothing
        record_operation!(metrics, elapsed_time, length(ciphertexts) * sizeof(BigInt))
    end

    return current_level[1]
end

"""
    memory_efficient_encrypt(pk::PaillierPublicKey, plaintext::Integer; 
                            pool::MemoryPool = GLOBAL_MEMORY_POOL) -> PaillierCiphertext

Memory-efficient encryption using object pooling to reduce allocations.
"""
function memory_efficient_encrypt(
    pk::PaillierPublicKey,
    plaintext::Integer;
    rng::AbstractRNG = Random.default_rng(),
    pool::MemoryPool = MemoryPool(),
)
    # Use pooled BigInts for intermediate calculations
    m = get_pooled_bigint(pool)
    r = get_pooled_bigint(pool)
    temp1 = get_pooled_bigint(pool)
    temp2 = get_pooled_bigint(pool)

    try
        # Set plaintext value
        m = BigInt(plaintext)

        # Validate range
        if m < 0 || m >= pk.n
            throw(ArgumentError("Plaintext must be in range [0, n-1]"))
        end

        # Generate random r
        r = rand(rng, BigInt(1):(pk.n-1))
        while gcd(r, pk.n) != 1
            r = rand(rng, BigInt(1):(pk.n-1))
        end

        # Compute c = g^m * r^n mod n²
        temp1 = powermod(pk.g, m, pk.n_squared)  # g^m mod n²
        temp2 = powermod(r, pk.n, pk.n_squared)  # r^n mod n²
        result_val = mod(temp1 * temp2, pk.n_squared)

        # Securely clear sensitive values
        secure_zero!(r)

        return PaillierCiphertext(result_val, pk.n)

    finally
        # Return BigInts to pool
        return_pooled_bigint!(pool, m)
        return_pooled_bigint!(pool, r)
        return_pooled_bigint!(pool, temp1)
        return_pooled_bigint!(pool, temp2)
    end
end

# Export optimized operations
export OptimizedPaillierOperations
export batch_encrypt, batch_decrypt, batch_add_encrypted, batch_multiply_plain
export optimized_homomorphic_sum, memory_efficient_encrypt
