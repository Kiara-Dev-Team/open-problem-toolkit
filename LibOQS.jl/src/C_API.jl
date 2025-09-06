module C_API

using CEnum: CEnum, @cenum

using Libdl: dlext
const liboqs =
    joinpath(pkgdir(@__MODULE__), "deps", "liboqs", "build", "lib", "liboqs.$(dlext)")


"""
    OQS_SIG

Signature schemes object
"""
struct OQS_SIG
    method_name::Ptr{Cchar}
    alg_version::Ptr{Cchar}
    claimed_nist_level::UInt8
    euf_cma::Bool
    suf_cma::Bool
    sig_with_ctx_support::Bool
    length_public_key::Csize_t
    length_secret_key::Csize_t
    length_signature::Csize_t
    keypair::Ptr{Cvoid}
    sign::Ptr{Cvoid}
    sign_with_ctx_str::Ptr{Cvoid}
    verify::Ptr{Cvoid}
    verify_with_ctx_str::Ptr{Cvoid}
end

"""
    OQS_STATUS

Represents return values from functions.

Callers should compare with the symbol rather than the individual value. For example,

ret = [`OQS_KEM_encaps`](@ref)(...); if (ret == OQS\\_SUCCESS) { ... }

rather than

if (![`OQS_KEM_encaps`](@ref)(...) { ... }
"""
@cenum OQS_STATUS::Int32 begin
    OQS_ERROR = -1
    OQS_SUCCESS = 0
    OQS_EXTERNAL_LIB_ERROR_OPENSSL = 50
end

"""
    OQS_CPU_EXT

CPU runtime detection flags
"""
@cenum OQS_CPU_EXT::UInt32 begin
    OQS_CPU_EXT_INIT = 0
    OQS_CPU_EXT_ADX = 1
    OQS_CPU_EXT_AES = 2
    OQS_CPU_EXT_AVX = 3
    OQS_CPU_EXT_AVX2 = 4
    OQS_CPU_EXT_AVX512 = 5
    OQS_CPU_EXT_BMI1 = 6
    OQS_CPU_EXT_BMI2 = 7
    OQS_CPU_EXT_PCLMULQDQ = 8
    OQS_CPU_EXT_VPCLMULQDQ = 9
    OQS_CPU_EXT_POPCNT = 10
    OQS_CPU_EXT_SSE = 11
    OQS_CPU_EXT_SSE2 = 12
    OQS_CPU_EXT_SSE3 = 13
    OQS_CPU_EXT_ARM_AES = 14
    OQS_CPU_EXT_ARM_SHA2 = 15
    OQS_CPU_EXT_ARM_SHA3 = 16
    OQS_CPU_EXT_ARM_NEON = 17
    OQS_CPU_EXT_COUNT = 18
end

"""
    OQS_CPU_has_extension(ext)

Checks if the CPU supports a given extension

# Returns
1 if the given CPU extension is available, 0 otherwise.
"""
function OQS_CPU_has_extension(ext)
    ccall((:OQS_CPU_has_extension, liboqs), Cint, (OQS_CPU_EXT,), ext)
end

"""
    OQS_init()

This currently sets the values in the OQS\\_CPU\\_EXTENSIONS and prefetches the OpenSSL objects if necessary.
"""
function OQS_init()
    ccall((:OQS_init, liboqs), Cvoid, ())
end

"""
    OQS_thread_stop()

This function stops OpenSSL threads, which allows resources to be cleaned up in the correct order.

!!! note

    When liboqs is used in a multithreaded application, each thread should call this function prior to stopping.
"""
function OQS_thread_stop()
    ccall((:OQS_thread_stop, liboqs), Cvoid, ())
end

"""
    OQS_destroy()

This function frees prefetched OpenSSL objects
"""
function OQS_destroy()
    ccall((:OQS_destroy, liboqs), Cvoid, ())
end

"""
    OQS_version()

Return library version string.
"""
function OQS_version()
    ccall((:OQS_version, liboqs), Ptr{Cchar}, ())
end

"""
    OQS_MEM_malloc(size)

Allocates memory of a given size.

# Arguments
* `size`: The size of the memory to be allocated in bytes.
# Returns
A pointer to the allocated memory.
"""
function OQS_MEM_malloc(size)
    ccall((:OQS_MEM_malloc, liboqs), Ptr{Cvoid}, (Csize_t,), size)
end

"""
    OQS_MEM_calloc(num_elements, element_size)

Allocates memory for an array of elements of a given size.

# Arguments
* `num_elements`: The number of elements to allocate.
* `element_size`: The size of each element in bytes.
# Returns
A pointer to the allocated memory.
"""
function OQS_MEM_calloc(num_elements, element_size)
    ccall(
        (:OQS_MEM_calloc, liboqs),
        Ptr{Cvoid},
        (Csize_t, Csize_t),
        num_elements,
        element_size,
    )
end

"""
    OQS_MEM_strdup(str)

Duplicates a string.

# Arguments
* `str`: The string to be duplicated.
# Returns
A pointer to the newly allocated string.
"""
function OQS_MEM_strdup(str)
    ccall((:OQS_MEM_strdup, liboqs), Ptr{Cchar}, (Ptr{Cchar},), str)
end

"""
    OQS_MEM_secure_bcmp(a, b, len)

Constant time comparison of byte sequences `a` and `b` of length `len`. Returns 0 if the byte sequences are equal or if `len`=0. Returns 1 otherwise.

# Arguments
* `a`:\\[in\\] A byte sequence of length at least `len`.
* `b`:\\[in\\] A byte sequence of length at least `len`.
* `len`:\\[in\\] The number of bytes to compare.
"""
function OQS_MEM_secure_bcmp(a, b, len)
    ccall(
        (:OQS_MEM_secure_bcmp, liboqs),
        Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
        a,
        b,
        len,
    )
end

"""
    OQS_MEM_cleanse(ptr, len)

Zeros out `len` bytes of memory starting at `ptr`.

Designed to be protected against optimizing compilers which try to remove "unnecessary" operations. Should be used for all buffers containing secret data.

# Arguments
* `ptr`:\\[in\\] The start of the memory to zero out.
* `len`:\\[in\\] The number of bytes to zero out.
"""
function OQS_MEM_cleanse(ptr, len)
    ccall((:OQS_MEM_cleanse, liboqs), Cvoid, (Ptr{Cvoid}, Csize_t), ptr, len)
end

"""
    OQS_MEM_secure_free(ptr, len)

Zeros out `len` bytes of memory starting at `ptr`, then frees `ptr`.

Can be called with `ptr = NULL`, in which case no operation is performed.

Designed to be protected against optimizing compilers which try to remove "unnecessary" operations. Should be used for all buffers containing secret data.

# Arguments
* `ptr`:\\[in\\] The start of the memory to zero out and free.
* `len`:\\[in\\] The number of bytes to zero out.
"""
function OQS_MEM_secure_free(ptr, len)
    ccall((:OQS_MEM_secure_free, liboqs), Cvoid, (Ptr{Cvoid}, Csize_t), ptr, len)
end

"""
    OQS_MEM_insecure_free(ptr)

Frees `ptr`.

Can be called with `ptr = NULL`, in which case no operation is performed.

Should only be used on non-secret data.

# Arguments
* `ptr`:\\[in\\] The start of the memory to free.
"""
function OQS_MEM_insecure_free(ptr)
    ccall((:OQS_MEM_insecure_free, liboqs), Cvoid, (Ptr{Cvoid},), ptr)
end

"""
    OQS_MEM_aligned_alloc(alignment, size)

Internal implementation of C11 aligned\\_alloc to work around compiler quirks.

Allocates size bytes of uninitialized memory with a base pointer that is a multiple of alignment. Alignment must be a power of two and a multiple of sizeof(void *). Size must be a multiple of alignment.

!!! note

    The allocated memory should be freed with [`OQS_MEM_aligned_free`](@ref) when it is no longer needed.
"""
function OQS_MEM_aligned_alloc(alignment, size)
    ccall((:OQS_MEM_aligned_alloc, liboqs), Ptr{Cvoid}, (Csize_t, Csize_t), alignment, size)
end

"""
    OQS_MEM_aligned_free(ptr)

Free memory allocated with [`OQS_MEM_aligned_alloc`](@ref).
"""
function OQS_MEM_aligned_free(ptr)
    ccall((:OQS_MEM_aligned_free, liboqs), Cvoid, (Ptr{Cvoid},), ptr)
end

"""
    OQS_MEM_aligned_secure_free(ptr, len)

Free and zeroize memory allocated with [`OQS_MEM_aligned_alloc`](@ref).
"""
function OQS_MEM_aligned_secure_free(ptr, len)
    ccall((:OQS_MEM_aligned_secure_free, liboqs), Cvoid, (Ptr{Cvoid}, Csize_t), ptr, len)
end

"""
    OQS_randombytes_switch_algorithm(algorithm)

Switches [`OQS_randombytes`](@ref) to use the specified algorithm.

!!! warning

    In case you have set a custom algorithm using [`OQS_randombytes_custom_algorithm`](@ref) before, this function will overwrite it again. Hence, you have to set your custom algorithm again after calling this function.

# Arguments
* `algorithm`:\\[in\\] The name of the algorithm to use.
# Returns
OQS\\_SUCCESS if `algorithm` is a supported algorithm name, OQS\\_ERROR otherwise.
"""
function OQS_randombytes_switch_algorithm(algorithm)
    ccall((:OQS_randombytes_switch_algorithm, liboqs), OQS_STATUS, (Ptr{Cchar},), algorithm)
end

"""
    OQS_randombytes_custom_algorithm(algorithm_ptr)

Switches [`OQS_randombytes`](@ref) to use the given function.

This allows additional custom RNGs besides the provided ones. The provided RNG function must have the same signature as [`OQS_randombytes`](@ref).

# Arguments
* `algorithm_ptr`:\\[in\\] Pointer to the RNG function to use.
"""
function OQS_randombytes_custom_algorithm(algorithm_ptr)
    ccall((:OQS_randombytes_custom_algorithm, liboqs), Cvoid, (Ptr{Cvoid},), algorithm_ptr)
end

"""
    OQS_randombytes(random_array, bytes_to_read)

Fills the given memory with the requested number of (pseudo)random bytes.

This implementation uses whichever algorithm has been selected by [`OQS_randombytes_switch_algorithm`](@ref). The default is OQS\\_randombytes\\_system, which reads bytes from a system specific default source.

The caller is responsible for providing a buffer allocated with sufficient room.

# Arguments
* `random_array`:\\[out\\] Pointer to the memory to fill with (pseudo)random bytes
* `bytes_to_read`:\\[in\\] The number of random bytes to read into memory
"""
function OQS_randombytes(random_array, bytes_to_read)
    ccall(
        (:OQS_randombytes, liboqs),
        Cvoid,
        (Ptr{UInt8}, Csize_t),
        random_array,
        bytes_to_read,
    )
end

"""
    OQS_KEM_alg_identifier(i)

Returns identifiers for available key encapsulation mechanisms in liboqs. Used with [`OQS_KEM_new`](@ref).

Note that algorithm identifiers are present in this list even when the algorithm is disabled at compile time.

# Arguments
* `i`:\\[in\\] Index of the algorithm identifier to return, 0 <= i < [`OQS_KEM_algs_length`](@ref)
# Returns
Algorithm identifier as a string, or NULL.
"""
function OQS_KEM_alg_identifier(i)
    ccall((:OQS_KEM_alg_identifier, liboqs), Ptr{Cchar}, (Csize_t,), i)
end

"""
    OQS_KEM_alg_count()

Returns the number of key encapsulation mechanisms in liboqs. They can be enumerated with [`OQS_KEM_alg_identifier`](@ref).

Note that some mechanisms may be disabled at compile time.

# Returns
The number of key encapsulation mechanisms.
"""
function OQS_KEM_alg_count()
    ccall((:OQS_KEM_alg_count, liboqs), Cint, ())
end

"""
    OQS_KEM_alg_is_enabled(method_name)

Indicates whether the specified algorithm was enabled at compile-time or not.

# Arguments
* `method_name`:\\[in\\] Name of the desired algorithm; one of the names in `OQS_KEM_algs`.
# Returns
1 if enabled, 0 if disabled or not found
"""
function OQS_KEM_alg_is_enabled(method_name)
    ccall((:OQS_KEM_alg_is_enabled, liboqs), Cint, (Ptr{Cchar},), method_name)
end

"""
    OQS_KEM

Key encapsulation mechanism object
"""
struct OQS_KEM
    method_name::Ptr{Cchar}
    alg_version::Ptr{Cchar}
    claimed_nist_level::UInt8
    ind_cca::Bool
    length_public_key::Csize_t
    length_secret_key::Csize_t
    length_ciphertext::Csize_t
    length_shared_secret::Csize_t
    length_keypair_seed::Csize_t
    keypair_derand::Ptr{Cvoid}
    keypair::Ptr{Cvoid}
    encaps::Ptr{Cvoid}
    decaps::Ptr{Cvoid}
end

"""
    OQS_KEM_new(method_name)

Constructs an [`OQS_KEM`](@ref) object for a particular algorithm.

Callers should always check whether the return value is `NULL`, which indicates either than an invalid algorithm name was provided, or that the requested algorithm was disabled at compile-time.

# Arguments
* `method_name`:\\[in\\] Name of the desired algorithm; one of the names in `OQS_KEM_algs`.
# Returns
An [`OQS_KEM`](@ref) for the particular algorithm, or `NULL` if the algorithm has been disabled at compile-time.
"""
function OQS_KEM_new(method_name)
    ccall((:OQS_KEM_new, liboqs), Ptr{OQS_KEM}, (Ptr{Cchar},), method_name)
end

"""
    OQS_KEM_keypair_derand(kem, public_key, secret_key, seed)

Derandomized keypair generation algorithm.

Caller is responsible for allocating sufficient memory for `public_key` and `secret_key`, based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_KEM\\_*\\_length\\_*`.

# Arguments
* `kem`:\\[in\\] The [`OQS_KEM`](@ref) object representing the KEM.
* `public_key`:\\[out\\] The public key represented as a byte string.
* `secret_key`:\\[out\\] The secret key represented as a byte string.
* `seed`:\\[in\\] The input randomness represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_KEM_keypair_derand(kem, public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{OQS_KEM}, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        kem,
        public_key,
        secret_key,
        seed,
    )
end

"""
    OQS_KEM_keypair(kem, public_key, secret_key)

Keypair generation algorithm.

Caller is responsible for allocating sufficient memory for `public_key` and `secret_key`, based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_KEM\\_*\\_length\\_*`.

# Arguments
* `kem`:\\[in\\] The [`OQS_KEM`](@ref) object representing the KEM.
* `public_key`:\\[out\\] The public key represented as a byte string.
* `secret_key`:\\[out\\] The secret key represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_KEM_keypair(kem, public_key, secret_key)
    ccall(
        (:OQS_KEM_keypair, liboqs),
        OQS_STATUS,
        (Ptr{OQS_KEM}, Ptr{UInt8}, Ptr{UInt8}),
        kem,
        public_key,
        secret_key,
    )
end

"""
    OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key)

Encapsulation algorithm.

Caller is responsible for allocating sufficient memory for `ciphertext` and `shared_secret`, based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_KEM\\_*\\_length\\_*`.

# Arguments
* `kem`:\\[in\\] The [`OQS_KEM`](@ref) object representing the KEM.
* `ciphertext`:\\[out\\] The ciphertext (encapsulation) represented as a byte string.
* `shared_secret`:\\[out\\] The shared secret represented as a byte string.
* `public_key`:\\[in\\] The public key represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_encaps, liboqs),
        OQS_STATUS,
        (Ptr{OQS_KEM}, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        kem,
        ciphertext,
        shared_secret,
        public_key,
    )
end

"""
    OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key)

Decapsulation algorithm.

Caller is responsible for allocating sufficient memory for `shared_secret`, based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_KEM\\_*\\_length\\_*`.

# Arguments
* `kem`:\\[in\\] The [`OQS_KEM`](@ref) object representing the KEM.
* `shared_secret`:\\[out\\] The shared secret represented as a byte string.
* `ciphertext`:\\[in\\] The ciphertext (encapsulation) represented as a byte string.
* `secret_key`:\\[in\\] The secret key represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_decaps, liboqs),
        OQS_STATUS,
        (Ptr{OQS_KEM}, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        kem,
        shared_secret,
        ciphertext,
        secret_key,
    )
end

"""
    OQS_KEM_free(kem)

Frees an [`OQS_KEM`](@ref) object that was constructed by [`OQS_KEM_new`](@ref).

# Arguments
* `kem`:\\[in\\] The [`OQS_KEM`](@ref) object to free.
"""
function OQS_KEM_free(kem)
    ccall((:OQS_KEM_free, liboqs), Cvoid, (Ptr{OQS_KEM},), kem)
end

function OQS_KEM_bike_l1_new()
    ccall((:OQS_KEM_bike_l1_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_bike_l1_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_bike_l1_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_bike_l1_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_bike_l1_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_bike_l1_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_bike_l1_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_bike_l1_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_bike_l1_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Cuchar}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_bike_l3_new()
    ccall((:OQS_KEM_bike_l3_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_bike_l3_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_bike_l3_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_bike_l3_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_bike_l3_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_bike_l3_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_bike_l3_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_bike_l3_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_bike_l3_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Cuchar}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_bike_l5_new()
    ccall((:OQS_KEM_bike_l5_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_bike_l5_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_bike_l5_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_bike_l5_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_bike_l5_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_bike_l5_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_bike_l5_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_bike_l5_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_bike_l5_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Cuchar}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_348864_new()
    ccall((:OQS_KEM_classic_mceliece_348864_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_348864_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_348864_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_348864_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_348864_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_348864_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_348864_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_348864_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_348864_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_348864f_new()
    ccall((:OQS_KEM_classic_mceliece_348864f_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_348864f_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_348864f_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_348864f_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_348864f_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_348864f_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_348864f_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_348864f_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_348864f_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_460896_new()
    ccall((:OQS_KEM_classic_mceliece_460896_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_460896_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_460896_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_460896_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_460896_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_460896_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_460896_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_460896_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_460896_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_460896f_new()
    ccall((:OQS_KEM_classic_mceliece_460896f_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_460896f_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_460896f_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_460896f_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_460896f_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_460896f_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_460896f_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_460896f_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_460896f_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_6688128_new()
    ccall((:OQS_KEM_classic_mceliece_6688128_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_6688128_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6688128_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_6688128_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_6688128_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_6688128_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6688128_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_6688128_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6688128_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_6688128f_new()
    ccall((:OQS_KEM_classic_mceliece_6688128f_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_6688128f_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6688128f_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_6688128f_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_6688128f_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_6688128f_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6688128f_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_6688128f_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6688128f_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_6960119_new()
    ccall((:OQS_KEM_classic_mceliece_6960119_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_6960119_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6960119_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_6960119_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_6960119_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_6960119_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6960119_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_6960119_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6960119_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_6960119f_new()
    ccall((:OQS_KEM_classic_mceliece_6960119f_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_6960119f_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6960119f_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_6960119f_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_6960119f_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_6960119f_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6960119f_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_6960119f_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_6960119f_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_8192128_new()
    ccall((:OQS_KEM_classic_mceliece_8192128_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_8192128_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_8192128_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_8192128_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_8192128_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_8192128_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_8192128_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_8192128_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_8192128_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_8192128f_new()
    ccall((:OQS_KEM_classic_mceliece_8192128f_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_classic_mceliece_8192128f_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_8192128f_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_classic_mceliece_8192128f_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_classic_mceliece_8192128f_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_classic_mceliece_8192128f_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_classic_mceliece_8192128f_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_classic_mceliece_8192128f_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_classic_mceliece_8192128f_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_kyber_512_new()
    ccall((:OQS_KEM_kyber_512_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_kyber_512_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_kyber_512_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_kyber_512_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_kyber_512_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_kyber_512_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_kyber_512_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_kyber_512_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_kyber_512_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_kyber_768_new()
    ccall((:OQS_KEM_kyber_768_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_kyber_768_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_kyber_768_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_kyber_768_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_kyber_768_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_kyber_768_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_kyber_768_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_kyber_768_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_kyber_768_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_kyber_1024_new()
    ccall((:OQS_KEM_kyber_1024_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_kyber_1024_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_kyber_1024_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_kyber_1024_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_kyber_1024_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_kyber_1024_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_kyber_1024_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_kyber_1024_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_kyber_1024_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_ml_kem_512_new()
    ccall((:OQS_KEM_ml_kem_512_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_ml_kem_512_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_ml_kem_512_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_ml_kem_512_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_ml_kem_512_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_ml_kem_512_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_ml_kem_512_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_ml_kem_512_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_ml_kem_512_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_ml_kem_768_new()
    ccall((:OQS_KEM_ml_kem_768_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_ml_kem_768_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_ml_kem_768_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_ml_kem_768_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_ml_kem_768_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_ml_kem_768_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_ml_kem_768_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_ml_kem_768_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_ml_kem_768_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_ml_kem_1024_new()
    ccall((:OQS_KEM_ml_kem_1024_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_ml_kem_1024_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_ml_kem_1024_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_ml_kem_1024_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_ml_kem_1024_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_ml_kem_1024_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_ml_kem_1024_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_ml_kem_1024_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_ml_kem_1024_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_ntruprime_sntrup761_new()
    ccall((:OQS_KEM_ntruprime_sntrup761_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_ntruprime_sntrup761_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_ntruprime_sntrup761_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_ntruprime_sntrup761_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_ntruprime_sntrup761_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_ntruprime_sntrup761_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_ntruprime_sntrup761_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_ntruprime_sntrup761_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_ntruprime_sntrup761_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_frodokem_640_aes_new()
    ccall((:OQS_KEM_frodokem_640_aes_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_frodokem_640_aes_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_frodokem_640_aes_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_frodokem_640_aes_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_frodokem_640_aes_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_frodokem_640_aes_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_frodokem_640_aes_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_frodokem_640_aes_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_frodokem_640_aes_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_frodokem_640_shake_new()
    ccall((:OQS_KEM_frodokem_640_shake_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_frodokem_640_shake_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_frodokem_640_shake_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_frodokem_640_shake_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_frodokem_640_shake_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_frodokem_640_shake_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_frodokem_640_shake_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_frodokem_640_shake_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_frodokem_640_shake_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_frodokem_976_aes_new()
    ccall((:OQS_KEM_frodokem_976_aes_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_frodokem_976_aes_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_frodokem_976_aes_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_frodokem_976_aes_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_frodokem_976_aes_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_frodokem_976_aes_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_frodokem_976_aes_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_frodokem_976_aes_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_frodokem_976_aes_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_frodokem_976_shake_new()
    ccall((:OQS_KEM_frodokem_976_shake_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_frodokem_976_shake_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_frodokem_976_shake_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_frodokem_976_shake_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_frodokem_976_shake_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_frodokem_976_shake_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_frodokem_976_shake_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_frodokem_976_shake_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_frodokem_976_shake_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_frodokem_1344_aes_new()
    ccall((:OQS_KEM_frodokem_1344_aes_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_frodokem_1344_aes_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_frodokem_1344_aes_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_frodokem_1344_aes_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_frodokem_1344_aes_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_frodokem_1344_aes_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_frodokem_1344_aes_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_frodokem_1344_aes_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_frodokem_1344_aes_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

function OQS_KEM_frodokem_1344_shake_new()
    ccall((:OQS_KEM_frodokem_1344_shake_new, liboqs), Ptr{OQS_KEM}, ())
end

function OQS_KEM_frodokem_1344_shake_keypair(public_key, secret_key)
    ccall(
        (:OQS_KEM_frodokem_1344_shake_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_KEM_frodokem_1344_shake_keypair_derand(public_key, secret_key, seed)
    ccall(
        (:OQS_KEM_frodokem_1344_shake_keypair_derand, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
        seed,
    )
end

function OQS_KEM_frodokem_1344_shake_encaps(ciphertext, shared_secret, public_key)
    ccall(
        (:OQS_KEM_frodokem_1344_shake_encaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext,
        shared_secret,
        public_key,
    )
end

function OQS_KEM_frodokem_1344_shake_decaps(shared_secret, ciphertext, secret_key)
    ccall(
        (:OQS_KEM_frodokem_1344_shake_decaps, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared_secret,
        ciphertext,
        secret_key,
    )
end

"""
    OQS_SIG_alg_identifier(i)

Returns identifiers for available signature schemes in liboqs. Used with [`OQS_SIG_new`](@ref).

Note that algorithm identifiers are present in this list even when the algorithm is disabled at compile time.

# Arguments
* `i`:\\[in\\] Index of the algorithm identifier to return, 0 <= i < [`OQS_SIG_algs_length`](@ref)
# Returns
Algorithm identifier as a string, or NULL.
"""
function OQS_SIG_alg_identifier(i)
    ccall((:OQS_SIG_alg_identifier, liboqs), Ptr{Cchar}, (Csize_t,), i)
end

"""
    OQS_SIG_alg_count()

Returns the number of signature mechanisms in liboqs. They can be enumerated with [`OQS_SIG_alg_identifier`](@ref).

Note that some mechanisms may be disabled at compile time.

# Returns
The number of signature mechanisms.
"""
function OQS_SIG_alg_count()
    ccall((:OQS_SIG_alg_count, liboqs), Cint, ())
end

"""
    OQS_SIG_alg_is_enabled(method_name)

Indicates whether the specified algorithm was enabled at compile-time or not.

# Arguments
* `method_name`:\\[in\\] Name of the desired algorithm; one of the names in `OQS_SIG_algs`.
# Returns
1 if enabled, 0 if disabled or not found
"""
function OQS_SIG_alg_is_enabled(method_name)
    ccall((:OQS_SIG_alg_is_enabled, liboqs), Cint, (Ptr{Cchar},), method_name)
end

"""
    OQS_SIG_new(method_name)

Constructs an [`OQS_SIG`](@ref) object for a particular algorithm.

Callers should always check whether the return value is `NULL`, which indicates either than an invalid algorithm name was provided, or that the requested algorithm was disabled at compile-time.

# Arguments
* `method_name`:\\[in\\] Name of the desired algorithm; one of the names in `OQS_SIG_algs`.
# Returns
An [`OQS_SIG`](@ref) for the particular algorithm, or `NULL` if the algorithm has been disabled at compile-time.
"""
function OQS_SIG_new(method_name)
    ccall((:OQS_SIG_new, liboqs), Ptr{OQS_SIG}, (Ptr{Cchar},), method_name)
end

"""
    OQS_SIG_keypair(sig, public_key, secret_key)

Keypair generation algorithm.

Caller is responsible for allocating sufficient memory for `public_key` and `secret_key`, based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_SIG\\_*\\_length\\_*`.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG`](@ref) object representing the signature scheme.
* `public_key`:\\[out\\] The public key represented as a byte string.
* `secret_key`:\\[out\\] The secret key represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_keypair(sig, public_key, secret_key)
    ccall(
        (:OQS_SIG_keypair, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG}, Ptr{UInt8}, Ptr{UInt8}),
        sig,
        public_key,
        secret_key,
    )
end

"""
    OQS_SIG_sign(sig, signature, signature_len, message, message_len, secret_key)

Signature generation algorithm.

Caller is responsible for allocating sufficient memory for `signnature`, based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_SIG\\_*\\_length\\_*`.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG`](@ref) object representing the signature scheme.
* `signature`:\\[out\\] The signature on the message represented as a byte string.
* `signature_len`:\\[out\\] The length of the signature.
* `message`:\\[in\\] The message to sign represented as a byte string.
* `message_len`:\\[in\\] The length of the message to sign.
* `secret_key`:\\[in\\] The secret key represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_sign(sig, signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_sign, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG}, Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        sig,
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

"""
    OQS_SIG_sign_with_ctx_str(sig, signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key)

Signature generation algorithm, with custom context string.

Caller is responsible for allocating sufficient memory for `signature`, based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_SIG\\_*\\_length\\_*`.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG`](@ref) object representing the signature scheme.
* `signature`:\\[out\\] The signature on the message represented as a byte string.
* `signature_len`:\\[out\\] The actual length of the signature. May be smaller than `length_signature` for some algorithms since some algorithms have variable length signatures.
* `message`:\\[in\\] The message to sign represented as a byte string.
* `message_len`:\\[in\\] The length of the message to sign.
* `ctx_str`:\\[in\\] The context string used for the signature. This value can be set to NULL if a context string is not needed (i.e., for algorithms that do not support context strings or if an empty context string is used).
* `ctx_str_len`:\\[in\\] The context string used for the signature. This value can be set to 0 if a context string is not needed (i.e., for algorithms that do not support context strings or if an empty context string is used).
* `secret_key`:\\[in\\] The secret key represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_sign_with_ctx_str(
    sig,
    signature,
    signature_len,
    message,
    message_len,
    ctx_str,
    ctx_str_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (
            Ptr{OQS_SIG},
            Ptr{UInt8},
            Ptr{Csize_t},
            Ptr{UInt8},
            Csize_t,
            Ptr{UInt8},
            Csize_t,
            Ptr{UInt8},
        ),
        sig,
        signature,
        signature_len,
        message,
        message_len,
        ctx_str,
        ctx_str_len,
        secret_key,
    )
end

"""
    OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key)

Signature verification algorithm.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG`](@ref) object representing the signature scheme.
* `message`:\\[in\\] The message represented as a byte string.
* `message_len`:\\[in\\] The length of the message.
* `signature`:\\[in\\] The signature on the message represented as a byte string.
* `signature_len`:\\[in\\] The length of the signature.
* `public_key`:\\[in\\] The public key represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key)
    ccall(
        (:OQS_SIG_verify, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        sig,
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

"""
    OQS_SIG_verify_with_ctx_str(sig, message, message_len, signature, signature_len, ctx_str, ctx_str_len, public_key)

Signature verification algorithm, with custom context string.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG`](@ref) object representing the signature scheme.
* `message`:\\[in\\] The message represented as a byte string.
* `message_len`:\\[in\\] The length of the message.
* `signature`:\\[in\\] The signature on the message represented as a byte string.
* `signature_len`:\\[in\\] The length of the signature.
* `ctx_str`:\\[in\\] The context string used for the signature. This value can be set to NULL if a context string is not needed (i.e., for algorithms that do not support context strings or if an empty context string is used).
* `ctx_str_len`:\\[in\\] The context string used for the signature. This value can be set to 0 if a context string is not needed (i.e., for algorithms that do not support context strings or if an empty context string is used).
* `public_key`:\\[in\\] The public key represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_verify_with_ctx_str(
    sig,
    message,
    message_len,
    signature,
    signature_len,
    ctx_str,
    ctx_str_len,
    public_key,
)
    ccall(
        (:OQS_SIG_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (
            Ptr{OQS_SIG},
            Ptr{UInt8},
            Csize_t,
            Ptr{UInt8},
            Csize_t,
            Ptr{UInt8},
            Csize_t,
            Ptr{UInt8},
        ),
        sig,
        message,
        message_len,
        signature,
        signature_len,
        ctx_str,
        ctx_str_len,
        public_key,
    )
end

"""
    OQS_SIG_free(sig)

Frees an [`OQS_SIG`](@ref) object that was constructed by [`OQS_SIG_new`](@ref).

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG`](@ref) object to free.
"""
function OQS_SIG_free(sig)
    ccall((:OQS_SIG_free, liboqs), Cvoid, (Ptr{OQS_SIG},), sig)
end

"""
    OQS_SIG_supports_ctx_str(alg_name)

Indicates whether the specified signature algorithm supports signing with a context string.

# Arguments
* `alg_name`:\\[in\\] Name of the desired algorithm; one of the names in `OQS_SIG_algs`.
# Returns
true if the algorithm supports context string signing, false otherwise.
"""
function OQS_SIG_supports_ctx_str(alg_name)
    ccall((:OQS_SIG_supports_ctx_str, liboqs), Bool, (Ptr{Cchar},), alg_name)
end

function OQS_SIG_dilithium_2_new()
    ccall((:OQS_SIG_dilithium_2_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_dilithium_2_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_dilithium_2_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_dilithium_2_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_dilithium_2_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_dilithium_2_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_dilithium_2_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_dilithium_2_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_dilithium_2_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_dilithium_2_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_dilithium_2_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_dilithium_3_new()
    ccall((:OQS_SIG_dilithium_3_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_dilithium_3_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_dilithium_3_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_dilithium_3_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_dilithium_3_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_dilithium_3_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_dilithium_3_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_dilithium_3_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_dilithium_3_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_dilithium_3_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_dilithium_3_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_dilithium_5_new()
    ccall((:OQS_SIG_dilithium_5_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_dilithium_5_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_dilithium_5_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_dilithium_5_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_dilithium_5_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_dilithium_5_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_dilithium_5_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_dilithium_5_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_dilithium_5_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_dilithium_5_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_dilithium_5_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_ml_dsa_44_new()
    ccall((:OQS_SIG_ml_dsa_44_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_ml_dsa_44_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_ml_dsa_44_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_44_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_ml_dsa_44_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_44_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_44_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_ml_dsa_44_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_44_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_44_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_44_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_ml_dsa_65_new()
    ccall((:OQS_SIG_ml_dsa_65_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_ml_dsa_65_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_ml_dsa_65_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_65_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_ml_dsa_65_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_65_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_65_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_ml_dsa_65_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_65_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_65_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_65_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_ml_dsa_87_new()
    ccall((:OQS_SIG_ml_dsa_87_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_ml_dsa_87_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_ml_dsa_87_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_87_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_ml_dsa_87_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_87_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_87_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_ml_dsa_87_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_87_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_ml_dsa_87_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_ml_dsa_87_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_falcon_512_new()
    ccall((:OQS_SIG_falcon_512_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_falcon_512_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_falcon_512_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_falcon_512_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_falcon_512_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_falcon_512_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_falcon_512_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_falcon_512_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_falcon_512_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_falcon_512_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_falcon_512_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_falcon_1024_new()
    ccall((:OQS_SIG_falcon_1024_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_falcon_1024_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_falcon_1024_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_falcon_1024_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_falcon_1024_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_falcon_1024_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_falcon_1024_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_falcon_1024_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_falcon_1024_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_falcon_1024_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_falcon_1024_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_falcon_padded_512_new()
    ccall((:OQS_SIG_falcon_padded_512_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_falcon_padded_512_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_falcon_padded_512_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_falcon_padded_512_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_falcon_padded_512_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_falcon_padded_512_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_falcon_padded_512_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_falcon_padded_512_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_falcon_padded_512_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_falcon_padded_512_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_falcon_padded_512_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_falcon_padded_1024_new()
    ccall((:OQS_SIG_falcon_padded_1024_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_falcon_padded_1024_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_falcon_padded_1024_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_falcon_padded_1024_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_falcon_padded_1024_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_falcon_padded_1024_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_falcon_padded_1024_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_falcon_padded_1024_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_falcon_padded_1024_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_falcon_padded_1024_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_falcon_padded_1024_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_128f_simple_new()
    ccall((:OQS_SIG_sphincs_sha2_128f_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_sha2_128f_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_sha2_128f_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_128f_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_128f_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_128f_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_128f_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_128f_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_128f_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_128f_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_128f_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_128s_simple_new()
    ccall((:OQS_SIG_sphincs_sha2_128s_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_sha2_128s_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_sha2_128s_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_128s_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_128s_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_128s_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_128s_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_128s_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_128s_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_128s_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_128s_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_192f_simple_new()
    ccall((:OQS_SIG_sphincs_sha2_192f_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_sha2_192f_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_sha2_192f_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_192f_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_192f_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_192f_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_192f_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_192f_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_192f_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_192f_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_192f_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_192s_simple_new()
    ccall((:OQS_SIG_sphincs_sha2_192s_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_sha2_192s_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_sha2_192s_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_192s_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_192s_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_192s_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_192s_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_192s_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_192s_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_192s_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_192s_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_256f_simple_new()
    ccall((:OQS_SIG_sphincs_sha2_256f_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_sha2_256f_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_sha2_256f_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_256f_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_256f_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_256f_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_256f_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_256f_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_256f_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_256f_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_256f_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_256s_simple_new()
    ccall((:OQS_SIG_sphincs_sha2_256s_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_sha2_256s_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_sha2_256s_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_256s_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_256s_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_256s_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_256s_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_sha2_256s_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_256s_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_sha2_256s_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_sha2_256s_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_128f_simple_new()
    ccall((:OQS_SIG_sphincs_shake_128f_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_shake_128f_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_shake_128f_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_128f_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_128f_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_128f_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_128f_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_128f_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_128f_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_128f_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_128f_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_128s_simple_new()
    ccall((:OQS_SIG_sphincs_shake_128s_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_shake_128s_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_shake_128s_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_128s_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_128s_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_128s_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_128s_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_128s_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_128s_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_128s_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_128s_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_192f_simple_new()
    ccall((:OQS_SIG_sphincs_shake_192f_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_shake_192f_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_shake_192f_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_192f_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_192f_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_192f_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_192f_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_192f_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_192f_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_192f_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_192f_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_192s_simple_new()
    ccall((:OQS_SIG_sphincs_shake_192s_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_shake_192s_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_shake_192s_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_192s_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_192s_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_192s_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_192s_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_192s_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_192s_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_192s_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_192s_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_256f_simple_new()
    ccall((:OQS_SIG_sphincs_shake_256f_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_shake_256f_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_shake_256f_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_256f_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_256f_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_256f_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_256f_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_256f_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_256f_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_256f_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_256f_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_256s_simple_new()
    ccall((:OQS_SIG_sphincs_shake_256s_simple_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_sphincs_shake_256s_simple_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_sphincs_shake_256s_simple_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_256s_simple_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_256s_simple_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_256s_simple_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_256s_simple_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_sphincs_shake_256s_simple_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_256s_simple_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_sphincs_shake_256s_simple_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_sphincs_shake_256s_simple_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_mayo_1_new()
    ccall((:OQS_SIG_mayo_1_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_mayo_1_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_mayo_1_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_mayo_1_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_mayo_1_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_mayo_1_verify(message, message_len, signature, signature_len, public_key)
    ccall(
        (:OQS_SIG_mayo_1_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_mayo_1_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_mayo_1_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_mayo_1_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_mayo_1_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_mayo_2_new()
    ccall((:OQS_SIG_mayo_2_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_mayo_2_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_mayo_2_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_mayo_2_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_mayo_2_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_mayo_2_verify(message, message_len, signature, signature_len, public_key)
    ccall(
        (:OQS_SIG_mayo_2_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_mayo_2_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_mayo_2_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_mayo_2_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_mayo_2_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_mayo_3_new()
    ccall((:OQS_SIG_mayo_3_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_mayo_3_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_mayo_3_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_mayo_3_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_mayo_3_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_mayo_3_verify(message, message_len, signature, signature_len, public_key)
    ccall(
        (:OQS_SIG_mayo_3_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_mayo_3_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_mayo_3_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_mayo_3_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_mayo_3_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_mayo_5_new()
    ccall((:OQS_SIG_mayo_5_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_mayo_5_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_mayo_5_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_mayo_5_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_mayo_5_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_mayo_5_verify(message, message_len, signature, signature_len, public_key)
    ccall(
        (:OQS_SIG_mayo_5_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_mayo_5_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_mayo_5_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_mayo_5_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_mayo_5_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_128_balanced_new()
    ccall((:OQS_SIG_cross_rsdp_128_balanced_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_128_balanced_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_128_balanced_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_balanced_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_balanced_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_balanced_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_balanced_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_128_balanced_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_balanced_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_balanced_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_balanced_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_128_fast_new()
    ccall((:OQS_SIG_cross_rsdp_128_fast_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_128_fast_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_128_fast_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_fast_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_fast_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_fast_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_fast_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_128_fast_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_fast_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_fast_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_fast_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_128_small_new()
    ccall((:OQS_SIG_cross_rsdp_128_small_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_128_small_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_128_small_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_small_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_small_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_small_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_small_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_128_small_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_small_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_128_small_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_128_small_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_192_balanced_new()
    ccall((:OQS_SIG_cross_rsdp_192_balanced_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_192_balanced_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_192_balanced_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_balanced_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_balanced_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_balanced_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_balanced_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_192_balanced_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_balanced_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_balanced_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_balanced_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_192_fast_new()
    ccall((:OQS_SIG_cross_rsdp_192_fast_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_192_fast_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_192_fast_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_fast_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_fast_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_fast_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_fast_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_192_fast_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_fast_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_fast_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_fast_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_192_small_new()
    ccall((:OQS_SIG_cross_rsdp_192_small_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_192_small_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_192_small_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_small_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_small_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_small_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_small_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_192_small_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_small_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_192_small_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_192_small_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_256_balanced_new()
    ccall((:OQS_SIG_cross_rsdp_256_balanced_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_256_balanced_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_256_balanced_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_balanced_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_balanced_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_balanced_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_balanced_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_256_balanced_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_balanced_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_balanced_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_balanced_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_256_fast_new()
    ccall((:OQS_SIG_cross_rsdp_256_fast_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_256_fast_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_256_fast_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_fast_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_fast_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_fast_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_fast_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_256_fast_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_fast_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_fast_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_fast_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_256_small_new()
    ccall((:OQS_SIG_cross_rsdp_256_small_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdp_256_small_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdp_256_small_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_small_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_small_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_small_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_small_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdp_256_small_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_small_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdp_256_small_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdp_256_small_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_128_balanced_new()
    ccall((:OQS_SIG_cross_rsdpg_128_balanced_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_128_balanced_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_balanced_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_balanced_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_balanced_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_balanced_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_balanced_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_128_balanced_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_balanced_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_balanced_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_balanced_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_128_fast_new()
    ccall((:OQS_SIG_cross_rsdpg_128_fast_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_128_fast_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_fast_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_fast_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_fast_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_fast_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_fast_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_128_fast_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_fast_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_fast_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_fast_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_128_small_new()
    ccall((:OQS_SIG_cross_rsdpg_128_small_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_128_small_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_small_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_small_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_small_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_small_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_small_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_128_small_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_small_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_128_small_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_128_small_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_192_balanced_new()
    ccall((:OQS_SIG_cross_rsdpg_192_balanced_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_192_balanced_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_balanced_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_balanced_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_balanced_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_balanced_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_balanced_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_192_balanced_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_balanced_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_balanced_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_balanced_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_192_fast_new()
    ccall((:OQS_SIG_cross_rsdpg_192_fast_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_192_fast_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_fast_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_fast_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_fast_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_fast_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_fast_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_192_fast_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_fast_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_fast_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_fast_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_192_small_new()
    ccall((:OQS_SIG_cross_rsdpg_192_small_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_192_small_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_small_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_small_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_small_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_small_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_small_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_192_small_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_small_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_192_small_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_192_small_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_256_balanced_new()
    ccall((:OQS_SIG_cross_rsdpg_256_balanced_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_256_balanced_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_balanced_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_balanced_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_balanced_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_balanced_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_balanced_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_256_balanced_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_balanced_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_balanced_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_balanced_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_256_fast_new()
    ccall((:OQS_SIG_cross_rsdpg_256_fast_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_256_fast_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_fast_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_fast_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_fast_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_fast_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_fast_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_256_fast_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_fast_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_fast_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_fast_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_256_small_new()
    ccall((:OQS_SIG_cross_rsdpg_256_small_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_cross_rsdpg_256_small_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_small_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_small_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_small_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_small_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_small_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_cross_rsdpg_256_small_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_small_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_cross_rsdpg_256_small_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_cross_rsdpg_256_small_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_Is_new()
    ccall((:OQS_SIG_uov_ov_Is_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_Is_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_Is_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_Is_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_Is_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_Ip_new()
    ccall((:OQS_SIG_uov_ov_Ip_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_Ip_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_Ip_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_Ip_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_Ip_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_III_new()
    ccall((:OQS_SIG_uov_ov_III_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_III_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_III_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_III_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_III_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_V_new()
    ccall((:OQS_SIG_uov_ov_V_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_V_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_V_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_sign(signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_V_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_verify(message, message_len, signature, signature_len, public_key)
    ccall(
        (:OQS_SIG_uov_ov_V_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_V_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_new()
    ccall((:OQS_SIG_uov_ov_Is_pkc_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_Is_pkc_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_new()
    ccall((:OQS_SIG_uov_ov_Ip_pkc_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_Ip_pkc_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_new()
    ccall((:OQS_SIG_uov_ov_III_pkc_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_III_pkc_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_new()
    ccall((:OQS_SIG_uov_ov_V_pkc_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_V_pkc_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_skc_new()
    ccall((:OQS_SIG_uov_ov_Is_pkc_skc_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_Is_pkc_skc_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_skc_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_skc_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_skc_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_skc_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_skc_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_skc_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_skc_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Is_pkc_skc_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Is_pkc_skc_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_skc_new()
    ccall((:OQS_SIG_uov_ov_Ip_pkc_skc_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_Ip_pkc_skc_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_skc_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_skc_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_skc_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_skc_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_skc_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_skc_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_skc_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_Ip_pkc_skc_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_Ip_pkc_skc_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_skc_new()
    ccall((:OQS_SIG_uov_ov_III_pkc_skc_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_III_pkc_skc_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_skc_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_skc_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_skc_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_skc_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_skc_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_skc_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_skc_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_III_pkc_skc_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_III_pkc_skc_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_skc_new()
    ccall((:OQS_SIG_uov_ov_V_pkc_skc_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_uov_ov_V_pkc_skc_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_skc_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_skc_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_skc_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_skc_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_skc_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_skc_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_skc_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_uov_ov_V_pkc_skc_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_uov_ov_V_pkc_skc_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_new()
    ccall((:OQS_SIG_snova_SNOVA_24_5_4_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_24_5_4_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_new()
    ccall((:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_esk_new()
    ccall((:OQS_SIG_snova_SNOVA_24_5_4_esk_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_24_5_4_esk_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_esk_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_esk_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_esk_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_esk_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_esk_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_esk_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_esk_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_esk_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_esk_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_new()
    ccall((:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_37_17_2_new()
    ccall((:OQS_SIG_snova_SNOVA_37_17_2_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_37_17_2_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_17_2_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_37_17_2_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_17_2_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_37_17_2_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_17_2_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_37_17_2_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_17_2_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_37_17_2_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_17_2_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_25_8_3_new()
    ccall((:OQS_SIG_snova_SNOVA_25_8_3_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_25_8_3_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_25_8_3_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_25_8_3_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_25_8_3_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_25_8_3_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_25_8_3_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_25_8_3_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_25_8_3_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_25_8_3_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_25_8_3_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_56_25_2_new()
    ccall((:OQS_SIG_snova_SNOVA_56_25_2_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_56_25_2_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_56_25_2_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_56_25_2_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_56_25_2_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_56_25_2_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_56_25_2_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_56_25_2_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_56_25_2_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_56_25_2_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_56_25_2_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_49_11_3_new()
    ccall((:OQS_SIG_snova_SNOVA_49_11_3_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_49_11_3_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_49_11_3_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_49_11_3_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_49_11_3_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_49_11_3_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_49_11_3_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_49_11_3_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_49_11_3_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_49_11_3_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_49_11_3_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_37_8_4_new()
    ccall((:OQS_SIG_snova_SNOVA_37_8_4_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_37_8_4_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_8_4_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_37_8_4_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_8_4_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_37_8_4_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_8_4_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_37_8_4_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_8_4_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_37_8_4_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_37_8_4_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_5_new()
    ccall((:OQS_SIG_snova_SNOVA_24_5_5_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_24_5_5_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_5_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_5_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_5_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_5_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_5_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_5_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_5_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_24_5_5_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_24_5_5_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_60_10_4_new()
    ccall((:OQS_SIG_snova_SNOVA_60_10_4_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_60_10_4_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_60_10_4_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_60_10_4_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_60_10_4_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_60_10_4_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_60_10_4_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_60_10_4_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_60_10_4_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_60_10_4_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_60_10_4_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_29_6_5_new()
    ccall((:OQS_SIG_snova_SNOVA_29_6_5_new, liboqs), Ptr{OQS_SIG}, ())
end

function OQS_SIG_snova_SNOVA_29_6_5_keypair(public_key, secret_key)
    ccall(
        (:OQS_SIG_snova_SNOVA_29_6_5_keypair, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_29_6_5_sign(
    signature,
    signature_len,
    message,
    message_len,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_29_6_5_sign, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_29_6_5_verify(
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_29_6_5_verify, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

function OQS_SIG_snova_SNOVA_29_6_5_sign_with_ctx_str(
    signature,
    signature_len,
    message,
    message_len,
    ctx,
    ctxlen,
    secret_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_29_6_5_sign_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        signature,
        signature_len,
        message,
        message_len,
        ctx,
        ctxlen,
        secret_key,
    )
end

function OQS_SIG_snova_SNOVA_29_6_5_verify_with_ctx_str(
    message,
    message_len,
    signature,
    signature_len,
    ctx,
    ctxlen,
    public_key,
)
    ccall(
        (:OQS_SIG_snova_SNOVA_29_6_5_verify_with_ctx_str, liboqs),
        OQS_STATUS,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        message,
        message_len,
        signature,
        signature_len,
        ctx,
        ctxlen,
        public_key,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY

[`OQS_SIG_STFL_SECRET_KEY`](@ref) object for stateful signature schemes
"""
struct OQS_SIG_STFL_SECRET_KEY
    length_secret_key::Csize_t
    secret_key_data::Ptr{Cvoid}
    mutex::Ptr{Cvoid}
    context::Ptr{Cvoid}
    serialize_key::Ptr{Cvoid}
    deserialize_key::Ptr{Cvoid}
    lock_key::Ptr{Cvoid}
    unlock_key::Ptr{Cvoid}
    secure_store_scrt_key::Ptr{Cvoid}
    free_key::Ptr{Cvoid}
    set_scrt_key_store_cb::Ptr{Cvoid}
end

# typedef OQS_STATUS ( * secure_store_sk ) ( uint8_t * sk_buf , size_t buf_len , void * context )
"""
Application provided function to securely store data

# Arguments
* `sk_buf`:\\[in\\] pointer to the data to be saved
* `buf_len`:\\[in\\] length of the data to be stored
* `context`:\\[out\\] pass back application data related to secret key data storage. return OQS\\_SUCCESS if successful, otherwise OQS\\_ERROR
"""
const secure_store_sk = Ptr{Cvoid}

# typedef OQS_STATUS ( * lock_key ) ( void * mutex )
"""
Application provided function to lock secret key object serialize access

# Arguments
* `mutex`:\\[in\\] pointer to mutex struct return OQS\\_SUCCESS if successful, otherwise OQS\\_ERROR
"""
const lock_key = Ptr{Cvoid}

# typedef OQS_STATUS ( * unlock_key ) ( void * mutex )
"""
Application provided function to unlock secret key object

# Arguments
* `mutex`:\\[in\\] pointer to mutex struct return OQS\\_SUCCESS if successful, otherwise OQS\\_ERROR
"""
const unlock_key = Ptr{Cvoid}

"""
    OQS_SIG_STFL_alg_identifier(i)

Returns identifiers for available signature schemes in liboqs. Used with [`OQS_SIG_STFL_new`](@ref).

Note that algorithm identifiers are present in this list even when the algorithm is disabled at compile time.

# Arguments
* `i`:\\[in\\] Index of the algorithm identifier to return, 0 <= i < [`OQS_SIG_algs_length`](@ref)
# Returns
Algorithm identifier as a string, or NULL.
"""
function OQS_SIG_STFL_alg_identifier(i)
    ccall((:OQS_SIG_STFL_alg_identifier, liboqs), Ptr{Cchar}, (Csize_t,), i)
end

"""
    OQS_SIG_STFL_alg_count()

Returns the number of stateful signature mechanisms in liboqs. They can be enumerated with [`OQS_SIG_STFL_alg_identifier`](@ref).

Note that some mechanisms may be disabled at compile time.

# Returns
The number of stateful signature mechanisms.
"""
function OQS_SIG_STFL_alg_count()
    ccall((:OQS_SIG_STFL_alg_count, liboqs), Cint, ())
end

"""
    OQS_SIG_STFL_alg_is_enabled(method_name)

Indicates whether the specified algorithm was enabled at compile-time or not.

# Arguments
* `method_name`:\\[in\\] Name of the desired algorithm; one of the names in `OQS_SIG_STFL_algs`.
# Returns
1 if enabled, 0 if disabled or not found
"""
function OQS_SIG_STFL_alg_is_enabled(method_name)
    ccall((:OQS_SIG_STFL_alg_is_enabled, liboqs), Cint, (Ptr{Cchar},), method_name)
end

"""
    OQS_SIG_STFL_new(method_name)

Constructs an [`OQS_SIG_STFL`](@ref) object for a particular algorithm.

Callers should always check whether the return value is `NULL`, which indicates either than an invalid algorithm name was provided, or that the requested algorithm was disabled at compile-time.

# Arguments
* `method_name`:\\[in\\] Name of the desired algorithm; one of the names in `OQS_SIG_STFL_algs`.
# Returns
An [`OQS_SIG_STFL`](@ref) for the particular algorithm, or `NULL` if the algorithm has been disabled at compile-time.
"""
function OQS_SIG_STFL_new(method_name)
    ccall((:OQS_SIG_STFL_new, liboqs), Ptr{OQS_SIG}, (Ptr{Cchar},), method_name)
end

"""
    OQS_SIG_STFL_keypair(sig, public_key, secret_key)

Keypair generation algorithm.

Caller is responsible for allocating sufficient memory for `public_key` based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_SIG\\_STFL\\_*\\_length\\_*`. The caller is also responsible for initializing `secret_key` using the [`OQS_SIG_STFL_SECRET_KEY`](@ref)(*) function.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG_STFL`](@ref) object representing the signature scheme.
* `public_key`:\\[out\\] The public key is represented as a byte string.
* `secret_key`:\\[out\\] The secret key object pointer.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_STFL_keypair(sig, public_key, secret_key)
    ccall(
        (:OQS_SIG_STFL_keypair, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG}, Ptr{UInt8}, Ptr{OQS_SIG_STFL_SECRET_KEY}),
        sig,
        public_key,
        secret_key,
    )
end

"""
    OQS_SIG_STFL_sign(sig, signature, signature_len, message, message_len, secret_key)

Signature generation algorithm.

For stateful signatures, there is always a limited number of signatures that can be used, The private key signature counter is increased by one once a signature is successfully generated, When the signature counter reaches the maximum number of available signatures, the signature generation always fails.

Caller is responsible for allocating sufficient memory for `signature`, based on the `length\\_*` members in this object or the per-scheme compile-time macros `OQS\\_SIG\\_STFL\\_*\\_length\\_*`.

!!! note

    Internally, if `lock/unlock` functions and `mutex` are set, it will attempt to lock the private key and unlock the private key after the Signing operation is completed.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG_STFL`](@ref) object representing the signature scheme.
* `signature`:\\[out\\] The signature on the message is represented as a byte string.
* `signature_len`:\\[out\\] The length of the signature.
* `message`:\\[in\\] The message to sign is represented as a byte string.
* `message_len`:\\[in\\] The length of the message to sign.
* `secret_key`:\\[in\\] The secret key object pointer.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_STFL_sign(sig, signature, signature_len, message, message_len, secret_key)
    ccall(
        (:OQS_SIG_STFL_sign, liboqs),
        OQS_STATUS,
        (
            Ptr{OQS_SIG},
            Ptr{UInt8},
            Ptr{Csize_t},
            Ptr{UInt8},
            Csize_t,
            Ptr{OQS_SIG_STFL_SECRET_KEY},
        ),
        sig,
        signature,
        signature_len,
        message,
        message_len,
        secret_key,
    )
end

"""
    OQS_SIG_STFL_verify(sig, message, message_len, signature, signature_len, public_key)

Signature verification algorithm.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG_STFL`](@ref) object representing the signature scheme.
* `message`:\\[in\\] The message is represented as a byte string.
* `message_len`:\\[in\\] The length of the message.
* `signature`:\\[in\\] The signature on the message is represented as a byte string.
* `signature_len`:\\[in\\] The length of the signature.
* `public_key`:\\[in\\] The public key is represented as a byte string.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_STFL_verify(
    sig,
    message,
    message_len,
    signature,
    signature_len,
    public_key,
)
    ccall(
        (:OQS_SIG_STFL_verify, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        sig,
        message,
        message_len,
        signature,
        signature_len,
        public_key,
    )
end

"""
    OQS_SIG_STFL_sigs_remaining(sig, remain, secret_key)

Query the number of remaining signatures.

The remaining signatures are the number of signatures available before the private key runs out of its total signature and expires.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG_STFL`](@ref) object representing the signature scheme.
* `remain`:\\[in\\] The number of remaining signatures.
* `secret_key`:\\[in\\] The secret key object.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_STFL_sigs_remaining(sig, remain, secret_key)
    ccall(
        (:OQS_SIG_STFL_sigs_remaining, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG}, Ptr{Culonglong}, Ptr{OQS_SIG_STFL_SECRET_KEY}),
        sig,
        remain,
        secret_key,
    )
end

"""
    OQS_SIG_STFL_sigs_total(sig, max, secret_key)

Query the total number of signatures.

The total number of signatures is the constant number present in how many signatures can be generated from a private key.

# Arguments
* `sig`:\\[in\\] The [`OQS_SIG_STFL`](@ref) object representing the signature scheme.
* `max`:\\[out\\] The number of remaining signatures
* `secret_key`:\\[in\\] The secret key object.
# Returns
OQS\\_SUCCESS or OQS\\_ERROR
"""
function OQS_SIG_STFL_sigs_total(sig, max, secret_key)
    ccall(
        (:OQS_SIG_STFL_sigs_total, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG}, Ptr{Culonglong}, Ptr{OQS_SIG_STFL_SECRET_KEY}),
        sig,
        max,
        secret_key,
    )
end

"""
    OQS_SIG_STFL_free(sig)

Free an [`OQS_SIG_STFL`](@ref) object that was constructed by [`OQS_SIG_STFL_new`](@ref).
"""
function OQS_SIG_STFL_free(sig)
    ccall((:OQS_SIG_STFL_free, liboqs), Cvoid, (Ptr{OQS_SIG},), sig)
end

"""
    OQS_SIG_STFL_SECRET_KEY_new(method_name)

Construct an [`OQS_SIG_STFL_SECRET_KEY`](@ref) object for a particular algorithm.

Callers should always check whether the return value is `NULL`, which indicates either than an invalid algorithm name was provided, or that the requested algorithm was disabled at compile-time.

# Arguments
* `method_name`:\\[in\\] Name of the desired algorithm; one of the names in `OQS_SIG_STFL_algs`.
# Returns
An [`OQS_SIG_STFL_SECRET_KEY`](@ref) for the particular algorithm, or `NULL` if the algorithm has been disabled at compile-time.
"""
function OQS_SIG_STFL_SECRET_KEY_new(method_name)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_new, liboqs),
        Ptr{OQS_SIG_STFL_SECRET_KEY},
        (Ptr{Cchar},),
        method_name,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_free(sk)

Free an [`OQS_SIG_STFL_SECRET_KEY`](@ref) object that was constructed by OQS\\_SECRET\\_KEY\\_new.

# Arguments
* `sk`:\\[in\\] The [`OQS_SIG_STFL_SECRET_KEY`](@ref) object to free.
"""
function OQS_SIG_STFL_SECRET_KEY_free(sk)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_free, liboqs),
        Cvoid,
        (Ptr{OQS_SIG_STFL_SECRET_KEY},),
        sk,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_SET_lock(sk, lock)

Attach a locking mechanism to a secret key object.

This allows for proper synchronization in a multi-threaded or multi-process environment, by ensuring that a secret key is not used concurrently by multiple entities, which could otherwise lead to security issues.

!!! note

    It's not required to set the lock and unlock functions in a single-threaded environment.

!!! note

    Once the `lock` function is set, users must also set the `mutex` and `unlock` functions.

!!! note

    By default, the internal value of `sk->lock` is NULL, which does nothing to lock the private key.

# Arguments
* `sk`:\\[in\\] Pointer to the secret key object whose lock function is to be set.
* `lock`:\\[in\\] Function pointer to the locking routine provided by the application.
"""
function OQS_SIG_STFL_SECRET_KEY_SET_lock(sk, lock)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_SET_lock, liboqs),
        Cvoid,
        (Ptr{OQS_SIG_STFL_SECRET_KEY}, lock_key),
        sk,
        lock,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_SET_unlock(sk, unlock)

Attach an unlock mechanism to a secret key object.

This allows for proper synchronization in a multi-threaded or multi-process environment, by ensuring that a secret key is not used concurrently by multiple entities, which could otherwise lead to security issues.

!!! note

    It's not required to set the lock and unlock functions in a single-threaded environment.

!!! note

    Once the `unlock` function is set, users must also set the `mutex` and `lock` functions.

!!! note

    By default, the internal value of `sk->unlock` is NULL, which does nothing to unlock the private key.

# Arguments
* `sk`:\\[in\\] Pointer to the secret key object whose unlock function is to be set.
* `unlock`:\\[in\\] Function pointer to the unlock routine provided by the application.
"""
function OQS_SIG_STFL_SECRET_KEY_SET_unlock(sk, unlock)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_SET_unlock, liboqs),
        Cvoid,
        (Ptr{OQS_SIG_STFL_SECRET_KEY}, unlock_key),
        sk,
        unlock,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_SET_mutex(sk, mutex)

Assign a mutex function to handle concurrency control over the secret key.

This is to ensure that only one process can access or modify the key at any given time.

!!! note

    It's not required to set the lock and unlock functions in a single-threaded environment.

!!! note

    By default, the internal value of `sk->mutex` is NULL, it must be set to be used in `lock` or `unlock` the private key.

# Arguments
* `sk`:\\[in\\] A pointer to the secret key that the mutex functionality will protect.
* `mutex`:\\[in\\] A function pointer to the desired concurrency control mechanism.
"""
function OQS_SIG_STFL_SECRET_KEY_SET_mutex(sk, mutex)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_SET_mutex, liboqs),
        Cvoid,
        (Ptr{OQS_SIG_STFL_SECRET_KEY}, Ptr{Cvoid}),
        sk,
        mutex,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_lock(sk)

Lock the secret key to ensure exclusive access in a concurrent environment.

If the `mutex` is not set, this lock operation will fail. This lock operation is essential in multi-threaded or multi-process contexts to prevent simultaneous Signing operations that could compromise the stateful signature security.

!!! warning

    If the `lock` function is set and `mutex` is not set, this lock operation will fail.

!!! note

    It's not necessary to use this function in either Keygen or Verifying operations. In a concurrent environment, the user is responsible for locking and unlocking the private key, to make sure that only one thread can access the private key during a Signing operation.

!!! note

    If the `lock` function and `mutex` are both set, proceed to lock the private key.

# Arguments
* `sk`:\\[in\\] Pointer to the secret key to be locked.
# Returns
OQS\\_SUCCESS if the lock is successfully applied; OQS\\_ERROR otherwise.
"""
function OQS_SIG_STFL_SECRET_KEY_lock(sk)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_lock, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG_STFL_SECRET_KEY},),
        sk,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_unlock(sk)

Unlock the secret key, making it accessible to other processes.

This function is crucial in environments where multiple processes need to coordinate access to the secret key, as it allows a process to signal that it has finished using the key, so others can safely use it.

!!! warning

    If the `unlock` function is set and `mutex` is not set, this unlock operation will fail.

!!! note

    It's not necessary to use this function in either Keygen or Verifying operations. In a concurrent environment, the user is responsible for locking and unlocking the private key, to make sure that only one thread can access the private key during a Signing operation.

!!! note

    If the `unlock` function and `mutex` are both set, proceed to unlock the private key.

# Arguments
* `sk`:\\[in\\] Pointer to the secret key whose lock should be released.
# Returns
OQS\\_SUCCESS if the lock was successfully released; otherwise, OQS\\_ERROR.
"""
function OQS_SIG_STFL_SECRET_KEY_unlock(sk)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_unlock, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG_STFL_SECRET_KEY},),
        sk,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk, store_cb, context)

Set the callback and context for securely storing a stateful secret key.

This function is designed to be called after a new stateful secret key has been generated. It enables the library to securely store secret key and update it every time a Signing operation occurs. Without properly setting this callback and context, signature generation will not succeed as the updated state of the secret key cannot be preserved.

# Arguments
* `sk`:\\[in\\] Pointer to the stateful secret key to be managed.
* `store_cb`:\\[in\\] Callback function that handles the secure storage of the key.
* `context`:\\[in\\] Application-specific context that assists in the storage of secret key data. This context is managed by the application, which allocates it, keeps track of it, and deallocates it as necessary.
"""
function OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk, store_cb, context)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_SET_store_cb, liboqs),
        Cvoid,
        (Ptr{OQS_SIG_STFL_SECRET_KEY}, secure_store_sk, Ptr{Cvoid}),
        sk,
        store_cb,
        context,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_serialize(sk_buf_ptr, sk_buf_len, sk)

Serialize the stateful secret key data into a byte array.

Converts an [`OQS_SIG_STFL_SECRET_KEY`](@ref) object into a byte array for storage or transmission.

!!! note

    The function allocates memory for the byte array, and it is the caller's responsibility to free this memory after use.

# Arguments
* `sk_buf_ptr`:\\[out\\] Pointer to the allocated byte array containing the serialized key.
* `sk_buf_len`:\\[out\\] Length of the serialized key byte array.
* `sk`:\\[in\\] Pointer to the [`OQS_SIG_STFL_SECRET_KEY`](@ref) object to be serialized.
# Returns
OQS\\_SUCCESS on success, or an OQS error code on failure.
"""
function OQS_SIG_STFL_SECRET_KEY_serialize(sk_buf_ptr, sk_buf_len, sk)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_serialize, liboqs),
        OQS_STATUS,
        (Ptr{Ptr{UInt8}}, Ptr{Csize_t}, Ptr{OQS_SIG_STFL_SECRET_KEY}),
        sk_buf_ptr,
        sk_buf_len,
        sk,
    )
end

"""
    OQS_SIG_STFL_SECRET_KEY_deserialize(sk, sk_buf, sk_buf_len, context)

Deserialize a byte array into an [`OQS_SIG_STFL_SECRET_KEY`](@ref) object.

Transforms a binary representation of a secret key into an [`OQS_SIG_STFL_SECRET_KEY`](@ref) structure. After deserialization, the secret key object can be used for subsequent cryptographic operations.

\\attention The caller is responsible for freeing the `sk_buf` memory when it is no longer needed.

# Arguments
* `sk`:\\[out\\] A pointer to the secret key object that will be populated from the binary data.
* `sk_buf`:\\[in\\] The buffer containing the serialized secret key data.
* `sk_buf_len`:\\[in\\] The length of the binary secret key data in bytes.
* `context`:\\[in\\] Application-specific data used to maintain context about the secret key.
# Returns
OQS\\_SUCCESS if deserialization was successful; otherwise, OQS\\_ERROR.
"""
function OQS_SIG_STFL_SECRET_KEY_deserialize(sk, sk_buf, sk_buf_len, context)
    ccall(
        (:OQS_SIG_STFL_SECRET_KEY_deserialize, liboqs),
        OQS_STATUS,
        (Ptr{OQS_SIG_STFL_SECRET_KEY}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}),
        sk,
        sk_buf,
        sk_buf_len,
        context,
    )
end

"""
    OQS_AES_callbacks

Data structure implemented by cryptographic provider for AES operations.
"""
struct OQS_AES_callbacks
    AES128_ECB_load_schedule::Ptr{Cvoid}
    AES128_CTR_inc_init::Ptr{Cvoid}
    AES128_CTR_inc_iv::Ptr{Cvoid}
    AES128_CTR_inc_ivu64::Ptr{Cvoid}
    AES128_free_schedule::Ptr{Cvoid}
    AES128_ECB_enc::Ptr{Cvoid}
    AES128_ECB_enc_sch::Ptr{Cvoid}
    AES128_CTR_inc_stream_iv::Ptr{Cvoid}
    AES256_ECB_load_schedule::Ptr{Cvoid}
    AES256_CTR_inc_init::Ptr{Cvoid}
    AES256_CTR_inc_iv::Ptr{Cvoid}
    AES256_CTR_inc_ivu64::Ptr{Cvoid}
    AES256_free_schedule::Ptr{Cvoid}
    AES256_ECB_enc::Ptr{Cvoid}
    AES256_ECB_enc_sch::Ptr{Cvoid}
    AES256_CTR_inc_stream_iv::Ptr{Cvoid}
    AES256_CTR_inc_stream_blks::Ptr{Cvoid}
end

"""
    OQS_AES_set_callbacks(new_callbacks)

Set callback functions for AES operations.

This function may be called before [`OQS_init`](@ref) to switch the cryptographic provider for AES operations. If it is not called, the default provider determined at build time will be used.

# Arguments
* `new_callbacks`:\\[in\\] Callback functions defined in [`OQS_AES_callbacks`](@ref)
"""
function OQS_AES_set_callbacks(new_callbacks)
    ccall((:OQS_AES_set_callbacks, liboqs), Cvoid, (Ptr{OQS_AES_callbacks},), new_callbacks)
end

"""
    OQS_SHA2_sha224_ctx

Data structure for the state of the SHA-224 incremental hashing API.
"""
struct OQS_SHA2_sha224_ctx
    ctx::Ptr{Cvoid}
    data_len::Csize_t
    data::NTuple{128,UInt8}
end

"""
    OQS_SHA2_sha256_ctx

Data structure for the state of the SHA-256 incremental hashing API.
"""
struct OQS_SHA2_sha256_ctx
    ctx::Ptr{Cvoid}
    data_len::Csize_t
    data::NTuple{128,UInt8}
end

"""
    OQS_SHA2_sha384_ctx

Data structure for the state of the SHA-384 incremental hashing API.
"""
struct OQS_SHA2_sha384_ctx
    ctx::Ptr{Cvoid}
    data_len::Csize_t
    data::NTuple{128,UInt8}
end

"""
    OQS_SHA2_sha512_ctx

Data structure for the state of the SHA-512 incremental hashing API.
"""
struct OQS_SHA2_sha512_ctx
    ctx::Ptr{Cvoid}
    data_len::Csize_t
    data::NTuple{128,UInt8}
end

"""
    OQS_SHA2_callbacks

Data structure implemented by cryptographic provider for SHA-2 operations.
"""
struct OQS_SHA2_callbacks
    SHA2_sha256::Ptr{Cvoid}
    SHA2_sha256_inc_init::Ptr{Cvoid}
    SHA2_sha256_inc_ctx_clone::Ptr{Cvoid}
    SHA2_sha256_inc::Ptr{Cvoid}
    SHA2_sha256_inc_blocks::Ptr{Cvoid}
    SHA2_sha256_inc_finalize::Ptr{Cvoid}
    SHA2_sha256_inc_ctx_release::Ptr{Cvoid}
    SHA2_sha384::Ptr{Cvoid}
    SHA2_sha384_inc_init::Ptr{Cvoid}
    SHA2_sha384_inc_ctx_clone::Ptr{Cvoid}
    SHA2_sha384_inc_blocks::Ptr{Cvoid}
    SHA2_sha384_inc_finalize::Ptr{Cvoid}
    SHA2_sha384_inc_ctx_release::Ptr{Cvoid}
    SHA2_sha512::Ptr{Cvoid}
    SHA2_sha512_inc_init::Ptr{Cvoid}
    SHA2_sha512_inc_ctx_clone::Ptr{Cvoid}
    SHA2_sha512_inc_blocks::Ptr{Cvoid}
    SHA2_sha512_inc_finalize::Ptr{Cvoid}
    SHA2_sha512_inc_ctx_release::Ptr{Cvoid}
end

"""
    OQS_SHA2_set_callbacks(new_callbacks)

Set callback functions for SHA2 operations.

This function may be called before [`OQS_init`](@ref) to switch the cryptographic provider for SHA2 operations. If it is not called, the default provider determined at build time will be used.

# Arguments
* `new_callbacks`:\\[in\\] Callback functions defined in [`OQS_SHA2_callbacks`](@ref)
"""
function OQS_SHA2_set_callbacks(new_callbacks)
    ccall(
        (:OQS_SHA2_set_callbacks, liboqs),
        Cvoid,
        (Ptr{OQS_SHA2_callbacks},),
        new_callbacks,
    )
end

"""
    OQS_SHA3_sha3_256_inc_ctx

Data structure for the state of the incremental SHA3-256 API.
"""
struct OQS_SHA3_sha3_256_inc_ctx
    ctx::Ptr{Cvoid}
end

"""
    OQS_SHA3_sha3_384_inc_ctx

Data structure for the state of the incremental SHA3-384 API.
"""
struct OQS_SHA3_sha3_384_inc_ctx
    ctx::Ptr{Cvoid}
end

"""
    OQS_SHA3_sha3_512_inc_ctx

Data structure for the state of the incremental SHA3-512 API.
"""
struct OQS_SHA3_sha3_512_inc_ctx
    ctx::Ptr{Cvoid}
end

"""
    OQS_SHA3_shake128_inc_ctx

Data structure for the state of the incremental SHAKE-128 API.
"""
struct OQS_SHA3_shake128_inc_ctx
    ctx::Ptr{Cvoid}
end

"""
    OQS_SHA3_shake256_inc_ctx

Data structure for the state of the incremental SHAKE-256 API.
"""
struct OQS_SHA3_shake256_inc_ctx
    ctx::Ptr{Cvoid}
end

"""
    OQS_SHA3_callbacks

Data structure implemented by cryptographic provider for SHA-3 operations.
"""
struct OQS_SHA3_callbacks
    SHA3_sha3_256::Ptr{Cvoid}
    SHA3_sha3_256_inc_init::Ptr{Cvoid}
    SHA3_sha3_256_inc_absorb::Ptr{Cvoid}
    SHA3_sha3_256_inc_finalize::Ptr{Cvoid}
    SHA3_sha3_256_inc_ctx_release::Ptr{Cvoid}
    SHA3_sha3_256_inc_ctx_reset::Ptr{Cvoid}
    SHA3_sha3_256_inc_ctx_clone::Ptr{Cvoid}
    SHA3_sha3_384::Ptr{Cvoid}
    SHA3_sha3_384_inc_init::Ptr{Cvoid}
    SHA3_sha3_384_inc_absorb::Ptr{Cvoid}
    SHA3_sha3_384_inc_finalize::Ptr{Cvoid}
    SHA3_sha3_384_inc_ctx_release::Ptr{Cvoid}
    SHA3_sha3_384_inc_ctx_reset::Ptr{Cvoid}
    SHA3_sha3_384_inc_ctx_clone::Ptr{Cvoid}
    SHA3_sha3_512::Ptr{Cvoid}
    SHA3_sha3_512_inc_init::Ptr{Cvoid}
    SHA3_sha3_512_inc_absorb::Ptr{Cvoid}
    SHA3_sha3_512_inc_finalize::Ptr{Cvoid}
    SHA3_sha3_512_inc_ctx_release::Ptr{Cvoid}
    SHA3_sha3_512_inc_ctx_reset::Ptr{Cvoid}
    SHA3_sha3_512_inc_ctx_clone::Ptr{Cvoid}
    SHA3_shake128::Ptr{Cvoid}
    SHA3_shake128_inc_init::Ptr{Cvoid}
    SHA3_shake128_inc_absorb::Ptr{Cvoid}
    SHA3_shake128_inc_finalize::Ptr{Cvoid}
    SHA3_shake128_inc_squeeze::Ptr{Cvoid}
    SHA3_shake128_inc_ctx_release::Ptr{Cvoid}
    SHA3_shake128_inc_ctx_clone::Ptr{Cvoid}
    SHA3_shake128_inc_ctx_reset::Ptr{Cvoid}
    SHA3_shake256::Ptr{Cvoid}
    SHA3_shake256_inc_init::Ptr{Cvoid}
    SHA3_shake256_inc_absorb::Ptr{Cvoid}
    SHA3_shake256_inc_finalize::Ptr{Cvoid}
    SHA3_shake256_inc_squeeze::Ptr{Cvoid}
    SHA3_shake256_inc_ctx_release::Ptr{Cvoid}
    SHA3_shake256_inc_ctx_clone::Ptr{Cvoid}
    SHA3_shake256_inc_ctx_reset::Ptr{Cvoid}
end

"""
    OQS_SHA3_set_callbacks(new_callbacks)

Set callback functions for SHA3 operations.

This function may be called before [`OQS_init`](@ref) to switch the cryptographic provider for SHA3 operations. If it is not called, the default provider determined at build time will be used.

# Arguments
* `new_callbacks`: Callback functions defined in [`OQS_SHA3_callbacks`](@ref) struct
"""
function OQS_SHA3_set_callbacks(new_callbacks)
    ccall(
        (:OQS_SHA3_set_callbacks, liboqs),
        Cvoid,
        (Ptr{OQS_SHA3_callbacks},),
        new_callbacks,
    )
end

"""
    OQS_SHA3_shake128_x4_inc_ctx

Data structure for the state of the four-way parallel incremental SHAKE-128 API.
"""
struct OQS_SHA3_shake128_x4_inc_ctx
    ctx::Ptr{Cvoid}
end

"""
    OQS_SHA3_shake256_x4_inc_ctx

Data structure for the state of the four-way parallel incremental SHAKE-256 API.
"""
struct OQS_SHA3_shake256_x4_inc_ctx
    ctx::Ptr{Cvoid}
end

"""
    OQS_SHA3_x4_callbacks

Data structure implemented by cryptographic provider for the four-way parallel incremental SHAKE-256 operations.
"""
struct OQS_SHA3_x4_callbacks
    SHA3_shake128_x4::Ptr{Cvoid}
    SHA3_shake128_x4_inc_init::Ptr{Cvoid}
    SHA3_shake128_x4_inc_absorb::Ptr{Cvoid}
    SHA3_shake128_x4_inc_finalize::Ptr{Cvoid}
    SHA3_shake128_x4_inc_squeeze::Ptr{Cvoid}
    SHA3_shake128_x4_inc_ctx_release::Ptr{Cvoid}
    SHA3_shake128_x4_inc_ctx_clone::Ptr{Cvoid}
    SHA3_shake128_x4_inc_ctx_reset::Ptr{Cvoid}
    SHA3_shake256_x4::Ptr{Cvoid}
    SHA3_shake256_x4_inc_init::Ptr{Cvoid}
    SHA3_shake256_x4_inc_absorb::Ptr{Cvoid}
    SHA3_shake256_x4_inc_finalize::Ptr{Cvoid}
    SHA3_shake256_x4_inc_squeeze::Ptr{Cvoid}
    SHA3_shake256_x4_inc_ctx_release::Ptr{Cvoid}
    SHA3_shake256_x4_inc_ctx_clone::Ptr{Cvoid}
    SHA3_shake256_x4_inc_ctx_reset::Ptr{Cvoid}
end

"""
    OQS_SHA3_x4_set_callbacks(new_callbacks)

Set callback functions for 4-parallel SHA3 operations.

This function may be called before [`OQS_init`](@ref) to switch the cryptographic provider for 4-parallel SHA3 operations. If it is not called, the default provider determined at build time will be used.

# Arguments
* `new_callbacks`: Callback functions defined in [`OQS_SHA3_x4_callbacks`](@ref) struct
"""
function OQS_SHA3_x4_set_callbacks(new_callbacks)
    ccall(
        (:OQS_SHA3_x4_set_callbacks, liboqs),
        Cvoid,
        (Ptr{OQS_SHA3_x4_callbacks},),
        new_callbacks,
    )
end

const OQS_VERSION_TEXT = "0.14.0"

const OQS_VERSION_MAJOR = 0

const OQS_VERSION_MINOR = 14

const OQS_VERSION_PATCH = 0

const OQS_COMPILE_BUILD_TARGET = "arm64-Darwin-24.6.0"

const OQS_DIST_BUILD = 1

const OQS_DIST_ARM64_V8_BUILD = 1

const ARCH_ARM64v8 = 1

const BUILD_SHARED_LIBS = 1

const OQS_OPT_TARGET = "generic"

const OQS_USE_OPENSSL = 1

const OQS_USE_AES_OPENSSL = 1

const OQS_USE_SHA2_OPENSSL = 1

const OQS_USE_PTHREADS = 1

const OQS_USE_CUPQC = 0

const OQS_ENABLE_KEM_BIKE = 1

const OQS_ENABLE_KEM_bike_l1 = 1

const OQS_ENABLE_KEM_bike_l3 = 1

const OQS_ENABLE_KEM_bike_l5 = 1

const OQS_ENABLE_KEM_FRODOKEM = 1

const OQS_ENABLE_KEM_frodokem_640_aes = 1

const OQS_ENABLE_KEM_frodokem_640_shake = 1

const OQS_ENABLE_KEM_frodokem_976_aes = 1

const OQS_ENABLE_KEM_frodokem_976_shake = 1

const OQS_ENABLE_KEM_frodokem_1344_aes = 1

const OQS_ENABLE_KEM_frodokem_1344_shake = 1

const OQS_ENABLE_KEM_NTRUPRIME = 1

const OQS_ENABLE_KEM_ntruprime_sntrup761 = 1

const OQS_ENABLE_KEM_CLASSIC_MCELIECE = 1

const OQS_ENABLE_KEM_classic_mceliece_348864 = 1

const OQS_ENABLE_KEM_classic_mceliece_348864f = 1

const OQS_ENABLE_KEM_classic_mceliece_460896 = 1

const OQS_ENABLE_KEM_classic_mceliece_460896f = 1

const OQS_ENABLE_KEM_classic_mceliece_6688128 = 1

const OQS_ENABLE_KEM_classic_mceliece_6688128f = 1

const OQS_ENABLE_KEM_classic_mceliece_6960119 = 1

const OQS_ENABLE_KEM_classic_mceliece_6960119f = 1

const OQS_ENABLE_KEM_classic_mceliece_8192128 = 1

const OQS_ENABLE_KEM_classic_mceliece_8192128f = 1

const OQS_ENABLE_KEM_KYBER = 1

const OQS_ENABLE_KEM_kyber_512 = 1

const OQS_ENABLE_KEM_kyber_512_aarch64 = 1

const OQS_ENABLE_KEM_kyber_768 = 1

const OQS_ENABLE_KEM_kyber_768_aarch64 = 1

const OQS_ENABLE_KEM_kyber_1024 = 1

const OQS_ENABLE_KEM_kyber_1024_aarch64 = 1

const OQS_ENABLE_KEM_ML_KEM = 1

const OQS_ENABLE_KEM_ml_kem_512 = 1

const OQS_ENABLE_KEM_ml_kem_512_aarch64 = 1

const OQS_ENABLE_KEM_ml_kem_768 = 1

const OQS_ENABLE_KEM_ml_kem_768_aarch64 = 1

const OQS_ENABLE_KEM_ml_kem_1024 = 1

const OQS_ENABLE_KEM_ml_kem_1024_aarch64 = 1

const OQS_ENABLE_SIG_DILITHIUM = 1

const OQS_ENABLE_SIG_dilithium_2 = 1

const OQS_ENABLE_SIG_dilithium_2_aarch64 = 1

const OQS_ENABLE_SIG_dilithium_3 = 1

const OQS_ENABLE_SIG_dilithium_3_aarch64 = 1

const OQS_ENABLE_SIG_dilithium_5 = 1

const OQS_ENABLE_SIG_dilithium_5_aarch64 = 1

const OQS_ENABLE_SIG_ML_DSA = 1

const OQS_ENABLE_SIG_ml_dsa_44 = 1

const OQS_ENABLE_SIG_ml_dsa_65 = 1

const OQS_ENABLE_SIG_ml_dsa_87 = 1

const OQS_ENABLE_SIG_FALCON = 1

const OQS_ENABLE_SIG_falcon_512 = 1

const OQS_ENABLE_SIG_falcon_512_aarch64 = 1

const OQS_ENABLE_SIG_falcon_1024 = 1

const OQS_ENABLE_SIG_falcon_1024_aarch64 = 1

const OQS_ENABLE_SIG_falcon_padded_512 = 1

const OQS_ENABLE_SIG_falcon_padded_512_aarch64 = 1

const OQS_ENABLE_SIG_falcon_padded_1024 = 1

const OQS_ENABLE_SIG_falcon_padded_1024_aarch64 = 1

const OQS_ENABLE_SIG_SPHINCS = 1

const OQS_ENABLE_SIG_sphincs_sha2_128f_simple = 1

const OQS_ENABLE_SIG_sphincs_sha2_128s_simple = 1

const OQS_ENABLE_SIG_sphincs_sha2_192f_simple = 1

const OQS_ENABLE_SIG_sphincs_sha2_192s_simple = 1

const OQS_ENABLE_SIG_sphincs_sha2_256f_simple = 1

const OQS_ENABLE_SIG_sphincs_sha2_256s_simple = 1

const OQS_ENABLE_SIG_sphincs_shake_128f_simple = 1

const OQS_ENABLE_SIG_sphincs_shake_128s_simple = 1

const OQS_ENABLE_SIG_sphincs_shake_192f_simple = 1

const OQS_ENABLE_SIG_sphincs_shake_192s_simple = 1

const OQS_ENABLE_SIG_sphincs_shake_256f_simple = 1

const OQS_ENABLE_SIG_sphincs_shake_256s_simple = 1

const OQS_ENABLE_SIG_MAYO = 1

const OQS_ENABLE_SIG_mayo_1 = 1

const OQS_ENABLE_SIG_mayo_1_neon = 1

const OQS_ENABLE_SIG_mayo_2 = 1

const OQS_ENABLE_SIG_mayo_2_neon = 1

const OQS_ENABLE_SIG_mayo_3 = 1

const OQS_ENABLE_SIG_mayo_3_neon = 1

const OQS_ENABLE_SIG_mayo_5 = 1

const OQS_ENABLE_SIG_mayo_5_neon = 1

const OQS_ENABLE_SIG_CROSS = 1

const OQS_ENABLE_SIG_cross_rsdp_128_balanced = 1

const OQS_ENABLE_SIG_cross_rsdp_128_fast = 1

const OQS_ENABLE_SIG_cross_rsdp_128_small = 1

const OQS_ENABLE_SIG_cross_rsdp_192_balanced = 1

const OQS_ENABLE_SIG_cross_rsdp_192_fast = 1

const OQS_ENABLE_SIG_cross_rsdp_192_small = 1

const OQS_ENABLE_SIG_cross_rsdp_256_balanced = 1

const OQS_ENABLE_SIG_cross_rsdp_256_fast = 1

const OQS_ENABLE_SIG_cross_rsdp_256_small = 1

const OQS_ENABLE_SIG_cross_rsdpg_128_balanced = 1

const OQS_ENABLE_SIG_cross_rsdpg_128_fast = 1

const OQS_ENABLE_SIG_cross_rsdpg_128_small = 1

const OQS_ENABLE_SIG_cross_rsdpg_192_balanced = 1

const OQS_ENABLE_SIG_cross_rsdpg_192_fast = 1

const OQS_ENABLE_SIG_cross_rsdpg_192_small = 1

const OQS_ENABLE_SIG_cross_rsdpg_256_balanced = 1

const OQS_ENABLE_SIG_cross_rsdpg_256_fast = 1

const OQS_ENABLE_SIG_cross_rsdpg_256_small = 1

const OQS_ENABLE_SIG_UOV = 1

const OQS_ENABLE_SIG_uov_ov_Is = 1

const OQS_ENABLE_SIG_uov_ov_Is_neon = 1

const OQS_ENABLE_SIG_uov_ov_Ip = 1

const OQS_ENABLE_SIG_uov_ov_Ip_neon = 1

const OQS_ENABLE_SIG_uov_ov_III = 1

const OQS_ENABLE_SIG_uov_ov_III_neon = 1

const OQS_ENABLE_SIG_uov_ov_V = 1

const OQS_ENABLE_SIG_uov_ov_V_neon = 1

const OQS_ENABLE_SIG_uov_ov_Is_pkc = 1

const OQS_ENABLE_SIG_uov_ov_Is_pkc_neon = 1

const OQS_ENABLE_SIG_uov_ov_Ip_pkc = 1

const OQS_ENABLE_SIG_uov_ov_Ip_pkc_neon = 1

const OQS_ENABLE_SIG_uov_ov_III_pkc = 1

const OQS_ENABLE_SIG_uov_ov_III_pkc_neon = 1

const OQS_ENABLE_SIG_uov_ov_V_pkc = 1

const OQS_ENABLE_SIG_uov_ov_V_pkc_neon = 1

const OQS_ENABLE_SIG_uov_ov_Is_pkc_skc = 1

const OQS_ENABLE_SIG_uov_ov_Is_pkc_skc_neon = 1

const OQS_ENABLE_SIG_uov_ov_Ip_pkc_skc = 1

const OQS_ENABLE_SIG_uov_ov_Ip_pkc_skc_neon = 1

const OQS_ENABLE_SIG_uov_ov_III_pkc_skc = 1

const OQS_ENABLE_SIG_uov_ov_III_pkc_skc_neon = 1

const OQS_ENABLE_SIG_uov_ov_V_pkc_skc = 1

const OQS_ENABLE_SIG_uov_ov_V_pkc_skc_neon = 1

const OQS_ENABLE_SIG_SNOVA = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_4 = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_4_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_4_esk = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_4_esk_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE_esk = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_4_SHAKE_esk_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_37_17_2 = 1

const OQS_ENABLE_SIG_snova_SNOVA_37_17_2_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_25_8_3 = 1

const OQS_ENABLE_SIG_snova_SNOVA_25_8_3_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_56_25_2 = 1

const OQS_ENABLE_SIG_snova_SNOVA_56_25_2_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_49_11_3 = 1

const OQS_ENABLE_SIG_snova_SNOVA_49_11_3_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_37_8_4 = 1

const OQS_ENABLE_SIG_snova_SNOVA_37_8_4_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_5 = 1

const OQS_ENABLE_SIG_snova_SNOVA_24_5_5_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_60_10_4 = 1

const OQS_ENABLE_SIG_snova_SNOVA_60_10_4_neon = 1

const OQS_ENABLE_SIG_snova_SNOVA_29_6_5 = 1

const OQS_ENABLE_SIG_snova_SNOVA_29_6_5_neon = 1

const OQS_LIBJADE_BUILD = 0

# Skipping MacroDefinition: OQS_API __attribute__ ( ( visibility ( "default" ) ) )

const OQS_RAND_alg_system = "system"

const OQS_RAND_alg_openssl = "OpenSSL"

const OQS_KEM_alg_bike_l1 = "BIKE-L1"

const OQS_KEM_alg_bike_l3 = "BIKE-L3"

const OQS_KEM_alg_bike_l5 = "BIKE-L5"

const OQS_KEM_alg_classic_mceliece_348864 = "Classic-McEliece-348864"

const OQS_KEM_alg_classic_mceliece_348864f = "Classic-McEliece-348864f"

const OQS_KEM_alg_classic_mceliece_460896 = "Classic-McEliece-460896"

const OQS_KEM_alg_classic_mceliece_460896f = "Classic-McEliece-460896f"

const OQS_KEM_alg_classic_mceliece_6688128 = "Classic-McEliece-6688128"

const OQS_KEM_alg_classic_mceliece_6688128f = "Classic-McEliece-6688128f"

const OQS_KEM_alg_classic_mceliece_6960119 = "Classic-McEliece-6960119"

const OQS_KEM_alg_classic_mceliece_6960119f = "Classic-McEliece-6960119f"

const OQS_KEM_alg_classic_mceliece_8192128 = "Classic-McEliece-8192128"

const OQS_KEM_alg_classic_mceliece_8192128f = "Classic-McEliece-8192128f"

const OQS_KEM_alg_hqc_128 = "HQC-128"

const OQS_KEM_alg_hqc_192 = "HQC-192"

const OQS_KEM_alg_hqc_256 = "HQC-256"

const OQS_KEM_alg_kyber_512 = "Kyber512"

const OQS_KEM_alg_kyber_768 = "Kyber768"

const OQS_KEM_alg_kyber_1024 = "Kyber1024"

const OQS_KEM_alg_ml_kem_512 = "ML-KEM-512"

const OQS_KEM_alg_ml_kem_768 = "ML-KEM-768"

const OQS_KEM_alg_ml_kem_1024 = "ML-KEM-1024"

const OQS_KEM_alg_ntruprime_sntrup761 = "sntrup761"

const OQS_KEM_alg_frodokem_640_aes = "FrodoKEM-640-AES"

const OQS_KEM_alg_frodokem_640_shake = "FrodoKEM-640-SHAKE"

const OQS_KEM_alg_frodokem_976_aes = "FrodoKEM-976-AES"

const OQS_KEM_alg_frodokem_976_shake = "FrodoKEM-976-SHAKE"

const OQS_KEM_alg_frodokem_1344_aes = "FrodoKEM-1344-AES"

const OQS_KEM_alg_frodokem_1344_shake = "FrodoKEM-1344-SHAKE"

const OQS_KEM_algs_length = 29

const OQS_KEM_bike_l1_length_secret_key = 5223

const OQS_KEM_bike_l1_length_public_key = 1541

const OQS_KEM_bike_l1_length_ciphertext = 1573

const OQS_KEM_bike_l1_length_shared_secret = 32

const OQS_KEM_bike_l1_length_keypair_seed = 0

const OQS_KEM_bike_l3_length_secret_key = 10105

const OQS_KEM_bike_l3_length_public_key = 3083

const OQS_KEM_bike_l3_length_ciphertext = 3115

const OQS_KEM_bike_l3_length_shared_secret = 32

const OQS_KEM_bike_l3_length_keypair_seed = 0

const OQS_KEM_bike_l5_length_secret_key = 16494

const OQS_KEM_bike_l5_length_public_key = 5122

const OQS_KEM_bike_l5_length_ciphertext = 5154

const OQS_KEM_bike_l5_length_shared_secret = 32

const OQS_KEM_bike_l5_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_348864_length_public_key = 261120

const OQS_KEM_classic_mceliece_348864_length_secret_key = 6492

const OQS_KEM_classic_mceliece_348864_length_ciphertext = 96

const OQS_KEM_classic_mceliece_348864_length_shared_secret = 32

const OQS_KEM_classic_mceliece_348864_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_348864f_length_public_key = 261120

const OQS_KEM_classic_mceliece_348864f_length_secret_key = 6492

const OQS_KEM_classic_mceliece_348864f_length_ciphertext = 96

const OQS_KEM_classic_mceliece_348864f_length_shared_secret = 32

const OQS_KEM_classic_mceliece_348864f_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_460896_length_public_key = 524160

const OQS_KEM_classic_mceliece_460896_length_secret_key = 13608

const OQS_KEM_classic_mceliece_460896_length_ciphertext = 156

const OQS_KEM_classic_mceliece_460896_length_shared_secret = 32

const OQS_KEM_classic_mceliece_460896_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_460896f_length_public_key = 524160

const OQS_KEM_classic_mceliece_460896f_length_secret_key = 13608

const OQS_KEM_classic_mceliece_460896f_length_ciphertext = 156

const OQS_KEM_classic_mceliece_460896f_length_shared_secret = 32

const OQS_KEM_classic_mceliece_460896f_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_6688128_length_public_key = 1044992

const OQS_KEM_classic_mceliece_6688128_length_secret_key = 13932

const OQS_KEM_classic_mceliece_6688128_length_ciphertext = 208

const OQS_KEM_classic_mceliece_6688128_length_shared_secret = 32

const OQS_KEM_classic_mceliece_6688128_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_6688128f_length_public_key = 1044992

const OQS_KEM_classic_mceliece_6688128f_length_secret_key = 13932

const OQS_KEM_classic_mceliece_6688128f_length_ciphertext = 208

const OQS_KEM_classic_mceliece_6688128f_length_shared_secret = 32

const OQS_KEM_classic_mceliece_6688128f_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_6960119_length_public_key = 1047319

const OQS_KEM_classic_mceliece_6960119_length_secret_key = 13948

const OQS_KEM_classic_mceliece_6960119_length_ciphertext = 194

const OQS_KEM_classic_mceliece_6960119_length_shared_secret = 32

const OQS_KEM_classic_mceliece_6960119_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_6960119f_length_public_key = 1047319

const OQS_KEM_classic_mceliece_6960119f_length_secret_key = 13948

const OQS_KEM_classic_mceliece_6960119f_length_ciphertext = 194

const OQS_KEM_classic_mceliece_6960119f_length_shared_secret = 32

const OQS_KEM_classic_mceliece_6960119f_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_8192128_length_public_key = 1357824

const OQS_KEM_classic_mceliece_8192128_length_secret_key = 14120

const OQS_KEM_classic_mceliece_8192128_length_ciphertext = 208

const OQS_KEM_classic_mceliece_8192128_length_shared_secret = 32

const OQS_KEM_classic_mceliece_8192128_length_keypair_seed = 0

const OQS_KEM_classic_mceliece_8192128f_length_public_key = 1357824

const OQS_KEM_classic_mceliece_8192128f_length_secret_key = 14120

const OQS_KEM_classic_mceliece_8192128f_length_ciphertext = 208

const OQS_KEM_classic_mceliece_8192128f_length_shared_secret = 32

const OQS_KEM_classic_mceliece_8192128f_length_keypair_seed = 0

const OQS_KEM_kyber_512_length_public_key = 800

const OQS_KEM_kyber_512_length_secret_key = 1632

const OQS_KEM_kyber_512_length_ciphertext = 768

const OQS_KEM_kyber_512_length_shared_secret = 32

const OQS_KEM_kyber_512_length_keypair_seed = 0

const OQS_KEM_kyber_768_length_public_key = 1184

const OQS_KEM_kyber_768_length_secret_key = 2400

const OQS_KEM_kyber_768_length_ciphertext = 1088

const OQS_KEM_kyber_768_length_shared_secret = 32

const OQS_KEM_kyber_768_length_keypair_seed = 0

const OQS_KEM_kyber_1024_length_public_key = 1568

const OQS_KEM_kyber_1024_length_secret_key = 3168

const OQS_KEM_kyber_1024_length_ciphertext = 1568

const OQS_KEM_kyber_1024_length_shared_secret = 32

const OQS_KEM_kyber_1024_length_keypair_seed = 0

const OQS_KEM_ml_kem_512_length_public_key = 800

const OQS_KEM_ml_kem_512_length_secret_key = 1632

const OQS_KEM_ml_kem_512_length_ciphertext = 768

const OQS_KEM_ml_kem_512_length_shared_secret = 32

const OQS_KEM_ml_kem_512_length_keypair_seed = 64

const OQS_KEM_ml_kem_768_length_public_key = 1184

const OQS_KEM_ml_kem_768_length_secret_key = 2400

const OQS_KEM_ml_kem_768_length_ciphertext = 1088

const OQS_KEM_ml_kem_768_length_shared_secret = 32

const OQS_KEM_ml_kem_768_length_keypair_seed = 64

const OQS_KEM_ml_kem_1024_length_public_key = 1568

const OQS_KEM_ml_kem_1024_length_secret_key = 3168

const OQS_KEM_ml_kem_1024_length_ciphertext = 1568

const OQS_KEM_ml_kem_1024_length_shared_secret = 32

const OQS_KEM_ml_kem_1024_length_keypair_seed = 64

const OQS_KEM_ntruprime_sntrup761_length_public_key = 1158

const OQS_KEM_ntruprime_sntrup761_length_secret_key = 1763

const OQS_KEM_ntruprime_sntrup761_length_ciphertext = 1039

const OQS_KEM_ntruprime_sntrup761_length_shared_secret = 32

const OQS_KEM_ntruprime_sntrup761_length_keypair_seed = 0

const OQS_KEM_frodokem_640_aes_length_public_key = 9616

const OQS_KEM_frodokem_640_aes_length_secret_key = 19888

const OQS_KEM_frodokem_640_aes_length_ciphertext = 9720

const OQS_KEM_frodokem_640_aes_length_shared_secret = 16

const OQS_KEM_frodokem_640_aes_length_keypair_seed = 0

const OQS_KEM_frodokem_640_shake_length_public_key = 9616

const OQS_KEM_frodokem_640_shake_length_secret_key = 19888

const OQS_KEM_frodokem_640_shake_length_ciphertext = 9720

const OQS_KEM_frodokem_640_shake_length_shared_secret = 16

const OQS_KEM_frodokem_640_shake_length_keypair_seed = 0

const OQS_KEM_frodokem_976_aes_length_public_key = 15632

const OQS_KEM_frodokem_976_aes_length_secret_key = 31296

const OQS_KEM_frodokem_976_aes_length_ciphertext = 15744

const OQS_KEM_frodokem_976_aes_length_shared_secret = 24

const OQS_KEM_frodokem_976_aes_length_keypair_seed = 0

const OQS_KEM_frodokem_976_shake_length_public_key = 15632

const OQS_KEM_frodokem_976_shake_length_secret_key = 31296

const OQS_KEM_frodokem_976_shake_length_ciphertext = 15744

const OQS_KEM_frodokem_976_shake_length_shared_secret = 24

const OQS_KEM_frodokem_976_shake_length_keypair_seed = 0

const OQS_KEM_frodokem_1344_aes_length_public_key = 21520

const OQS_KEM_frodokem_1344_aes_length_secret_key = 43088

const OQS_KEM_frodokem_1344_aes_length_ciphertext = 21632

const OQS_KEM_frodokem_1344_aes_length_shared_secret = 32

const OQS_KEM_frodokem_1344_aes_length_keypair_seed = 0

const OQS_KEM_frodokem_1344_shake_length_public_key = 21520

const OQS_KEM_frodokem_1344_shake_length_secret_key = 43088

const OQS_KEM_frodokem_1344_shake_length_ciphertext = 21632

const OQS_KEM_frodokem_1344_shake_length_shared_secret = 32

const OQS_KEM_frodokem_1344_shake_length_keypair_seed = 0

const OQS_SIG_alg_dilithium_2 = "Dilithium2"

const OQS_SIG_alg_dilithium_3 = "Dilithium3"

const OQS_SIG_alg_dilithium_5 = "Dilithium5"

const OQS_SIG_alg_ml_dsa_44 = "ML-DSA-44"

const OQS_SIG_alg_ml_dsa_65 = "ML-DSA-65"

const OQS_SIG_alg_ml_dsa_87 = "ML-DSA-87"

const OQS_SIG_alg_falcon_512 = "Falcon-512"

const OQS_SIG_alg_falcon_1024 = "Falcon-1024"

const OQS_SIG_alg_falcon_padded_512 = "Falcon-padded-512"

const OQS_SIG_alg_falcon_padded_1024 = "Falcon-padded-1024"

const OQS_SIG_alg_sphincs_sha2_128f_simple = "SPHINCS+-SHA2-128f-simple"

const OQS_SIG_alg_sphincs_sha2_128s_simple = "SPHINCS+-SHA2-128s-simple"

const OQS_SIG_alg_sphincs_sha2_192f_simple = "SPHINCS+-SHA2-192f-simple"

const OQS_SIG_alg_sphincs_sha2_192s_simple = "SPHINCS+-SHA2-192s-simple"

const OQS_SIG_alg_sphincs_sha2_256f_simple = "SPHINCS+-SHA2-256f-simple"

const OQS_SIG_alg_sphincs_sha2_256s_simple = "SPHINCS+-SHA2-256s-simple"

const OQS_SIG_alg_sphincs_shake_128f_simple = "SPHINCS+-SHAKE-128f-simple"

const OQS_SIG_alg_sphincs_shake_128s_simple = "SPHINCS+-SHAKE-128s-simple"

const OQS_SIG_alg_sphincs_shake_192f_simple = "SPHINCS+-SHAKE-192f-simple"

const OQS_SIG_alg_sphincs_shake_192s_simple = "SPHINCS+-SHAKE-192s-simple"

const OQS_SIG_alg_sphincs_shake_256f_simple = "SPHINCS+-SHAKE-256f-simple"

const OQS_SIG_alg_sphincs_shake_256s_simple = "SPHINCS+-SHAKE-256s-simple"

const OQS_SIG_alg_mayo_1 = "MAYO-1"

const OQS_SIG_alg_mayo_2 = "MAYO-2"

const OQS_SIG_alg_mayo_3 = "MAYO-3"

const OQS_SIG_alg_mayo_5 = "MAYO-5"

const OQS_SIG_alg_cross_rsdp_128_balanced = "cross-rsdp-128-balanced"

const OQS_SIG_alg_cross_rsdp_128_fast = "cross-rsdp-128-fast"

const OQS_SIG_alg_cross_rsdp_128_small = "cross-rsdp-128-small"

const OQS_SIG_alg_cross_rsdp_192_balanced = "cross-rsdp-192-balanced"

const OQS_SIG_alg_cross_rsdp_192_fast = "cross-rsdp-192-fast"

const OQS_SIG_alg_cross_rsdp_192_small = "cross-rsdp-192-small"

const OQS_SIG_alg_cross_rsdp_256_balanced = "cross-rsdp-256-balanced"

const OQS_SIG_alg_cross_rsdp_256_fast = "cross-rsdp-256-fast"

const OQS_SIG_alg_cross_rsdp_256_small = "cross-rsdp-256-small"

const OQS_SIG_alg_cross_rsdpg_128_balanced = "cross-rsdpg-128-balanced"

const OQS_SIG_alg_cross_rsdpg_128_fast = "cross-rsdpg-128-fast"

const OQS_SIG_alg_cross_rsdpg_128_small = "cross-rsdpg-128-small"

const OQS_SIG_alg_cross_rsdpg_192_balanced = "cross-rsdpg-192-balanced"

const OQS_SIG_alg_cross_rsdpg_192_fast = "cross-rsdpg-192-fast"

const OQS_SIG_alg_cross_rsdpg_192_small = "cross-rsdpg-192-small"

const OQS_SIG_alg_cross_rsdpg_256_balanced = "cross-rsdpg-256-balanced"

const OQS_SIG_alg_cross_rsdpg_256_fast = "cross-rsdpg-256-fast"

const OQS_SIG_alg_cross_rsdpg_256_small = "cross-rsdpg-256-small"

const OQS_SIG_alg_uov_ov_Is = "OV-Is"

const OQS_SIG_alg_uov_ov_Ip = "OV-Ip"

const OQS_SIG_alg_uov_ov_III = "OV-III"

const OQS_SIG_alg_uov_ov_V = "OV-V"

const OQS_SIG_alg_uov_ov_Is_pkc = "OV-Is-pkc"

const OQS_SIG_alg_uov_ov_Ip_pkc = "OV-Ip-pkc"

const OQS_SIG_alg_uov_ov_III_pkc = "OV-III-pkc"

const OQS_SIG_alg_uov_ov_V_pkc = "OV-V-pkc"

const OQS_SIG_alg_uov_ov_Is_pkc_skc = "OV-Is-pkc-skc"

const OQS_SIG_alg_uov_ov_Ip_pkc_skc = "OV-Ip-pkc-skc"

const OQS_SIG_alg_uov_ov_III_pkc_skc = "OV-III-pkc-skc"

const OQS_SIG_alg_uov_ov_V_pkc_skc = "OV-V-pkc-skc"

const OQS_SIG_alg_snova_SNOVA_24_5_4 = "SNOVA_24_5_4"

const OQS_SIG_alg_snova_SNOVA_24_5_4_SHAKE = "SNOVA_24_5_4_SHAKE"

const OQS_SIG_alg_snova_SNOVA_24_5_4_esk = "SNOVA_24_5_4_esk"

const OQS_SIG_alg_snova_SNOVA_24_5_4_SHAKE_esk = "SNOVA_24_5_4_SHAKE_esk"

const OQS_SIG_alg_snova_SNOVA_37_17_2 = "SNOVA_37_17_2"

const OQS_SIG_alg_snova_SNOVA_25_8_3 = "SNOVA_25_8_3"

const OQS_SIG_alg_snova_SNOVA_56_25_2 = "SNOVA_56_25_2"

const OQS_SIG_alg_snova_SNOVA_49_11_3 = "SNOVA_49_11_3"

const OQS_SIG_alg_snova_SNOVA_37_8_4 = "SNOVA_37_8_4"

const OQS_SIG_alg_snova_SNOVA_24_5_5 = "SNOVA_24_5_5"

const OQS_SIG_alg_snova_SNOVA_60_10_4 = "SNOVA_60_10_4"

const OQS_SIG_alg_snova_SNOVA_29_6_5 = "SNOVA_29_6_5"

const OQS_SIG_algs_length = 68

const OQS_SIG_dilithium_2_length_public_key = 1312

const OQS_SIG_dilithium_2_length_secret_key = 2528

const OQS_SIG_dilithium_2_length_signature = 2420

const OQS_SIG_dilithium_3_length_public_key = 1952

const OQS_SIG_dilithium_3_length_secret_key = 4000

const OQS_SIG_dilithium_3_length_signature = 3293

const OQS_SIG_dilithium_5_length_public_key = 2592

const OQS_SIG_dilithium_5_length_secret_key = 4864

const OQS_SIG_dilithium_5_length_signature = 4595

const OQS_SIG_ml_dsa_44_length_public_key = 1312

const OQS_SIG_ml_dsa_44_length_secret_key = 2560

const OQS_SIG_ml_dsa_44_length_signature = 2420

const OQS_SIG_ml_dsa_65_length_public_key = 1952

const OQS_SIG_ml_dsa_65_length_secret_key = 4032

const OQS_SIG_ml_dsa_65_length_signature = 3309

const OQS_SIG_ml_dsa_87_length_public_key = 2592

const OQS_SIG_ml_dsa_87_length_secret_key = 4896

const OQS_SIG_ml_dsa_87_length_signature = 4627

const OQS_SIG_falcon_512_length_public_key = 897

const OQS_SIG_falcon_512_length_secret_key = 1281

const OQS_SIG_falcon_512_length_signature = 752

const OQS_SIG_falcon_1024_length_public_key = 1793

const OQS_SIG_falcon_1024_length_secret_key = 2305

const OQS_SIG_falcon_1024_length_signature = 1462

const OQS_SIG_falcon_padded_512_length_public_key = 897

const OQS_SIG_falcon_padded_512_length_secret_key = 1281

const OQS_SIG_falcon_padded_512_length_signature = 666

const OQS_SIG_falcon_padded_1024_length_public_key = 1793

const OQS_SIG_falcon_padded_1024_length_secret_key = 2305

const OQS_SIG_falcon_padded_1024_length_signature = 1280

const OQS_SIG_sphincs_sha2_128f_simple_length_public_key = 32

const OQS_SIG_sphincs_sha2_128f_simple_length_secret_key = 64

const OQS_SIG_sphincs_sha2_128f_simple_length_signature = 17088

const OQS_SIG_sphincs_sha2_128s_simple_length_public_key = 32

const OQS_SIG_sphincs_sha2_128s_simple_length_secret_key = 64

const OQS_SIG_sphincs_sha2_128s_simple_length_signature = 7856

const OQS_SIG_sphincs_sha2_192f_simple_length_public_key = 48

const OQS_SIG_sphincs_sha2_192f_simple_length_secret_key = 96

const OQS_SIG_sphincs_sha2_192f_simple_length_signature = 35664

const OQS_SIG_sphincs_sha2_192s_simple_length_public_key = 48

const OQS_SIG_sphincs_sha2_192s_simple_length_secret_key = 96

const OQS_SIG_sphincs_sha2_192s_simple_length_signature = 16224

const OQS_SIG_sphincs_sha2_256f_simple_length_public_key = 64

const OQS_SIG_sphincs_sha2_256f_simple_length_secret_key = 128

const OQS_SIG_sphincs_sha2_256f_simple_length_signature = 49856

const OQS_SIG_sphincs_sha2_256s_simple_length_public_key = 64

const OQS_SIG_sphincs_sha2_256s_simple_length_secret_key = 128

const OQS_SIG_sphincs_sha2_256s_simple_length_signature = 29792

const OQS_SIG_sphincs_shake_128f_simple_length_public_key = 32

const OQS_SIG_sphincs_shake_128f_simple_length_secret_key = 64

const OQS_SIG_sphincs_shake_128f_simple_length_signature = 17088

const OQS_SIG_sphincs_shake_128s_simple_length_public_key = 32

const OQS_SIG_sphincs_shake_128s_simple_length_secret_key = 64

const OQS_SIG_sphincs_shake_128s_simple_length_signature = 7856

const OQS_SIG_sphincs_shake_192f_simple_length_public_key = 48

const OQS_SIG_sphincs_shake_192f_simple_length_secret_key = 96

const OQS_SIG_sphincs_shake_192f_simple_length_signature = 35664

const OQS_SIG_sphincs_shake_192s_simple_length_public_key = 48

const OQS_SIG_sphincs_shake_192s_simple_length_secret_key = 96

const OQS_SIG_sphincs_shake_192s_simple_length_signature = 16224

const OQS_SIG_sphincs_shake_256f_simple_length_public_key = 64

const OQS_SIG_sphincs_shake_256f_simple_length_secret_key = 128

const OQS_SIG_sphincs_shake_256f_simple_length_signature = 49856

const OQS_SIG_sphincs_shake_256s_simple_length_public_key = 64

const OQS_SIG_sphincs_shake_256s_simple_length_secret_key = 128

const OQS_SIG_sphincs_shake_256s_simple_length_signature = 29792

const OQS_SIG_mayo_1_length_public_key = 1420

const OQS_SIG_mayo_1_length_secret_key = 24

const OQS_SIG_mayo_1_length_signature = 454

const OQS_SIG_mayo_2_length_public_key = 4912

const OQS_SIG_mayo_2_length_secret_key = 24

const OQS_SIG_mayo_2_length_signature = 186

const OQS_SIG_mayo_3_length_public_key = 2986

const OQS_SIG_mayo_3_length_secret_key = 32

const OQS_SIG_mayo_3_length_signature = 681

const OQS_SIG_mayo_5_length_public_key = 5554

const OQS_SIG_mayo_5_length_secret_key = 40

const OQS_SIG_mayo_5_length_signature = 964

const OQS_SIG_cross_rsdp_128_balanced_length_public_key = 77

const OQS_SIG_cross_rsdp_128_balanced_length_secret_key = 32

const OQS_SIG_cross_rsdp_128_balanced_length_signature = 13152

const OQS_SIG_cross_rsdp_128_fast_length_public_key = 77

const OQS_SIG_cross_rsdp_128_fast_length_secret_key = 32

const OQS_SIG_cross_rsdp_128_fast_length_signature = 18432

const OQS_SIG_cross_rsdp_128_small_length_public_key = 77

const OQS_SIG_cross_rsdp_128_small_length_secret_key = 32

const OQS_SIG_cross_rsdp_128_small_length_signature = 12432

const OQS_SIG_cross_rsdp_192_balanced_length_public_key = 115

const OQS_SIG_cross_rsdp_192_balanced_length_secret_key = 48

const OQS_SIG_cross_rsdp_192_balanced_length_signature = 29853

const OQS_SIG_cross_rsdp_192_fast_length_public_key = 115

const OQS_SIG_cross_rsdp_192_fast_length_secret_key = 48

const OQS_SIG_cross_rsdp_192_fast_length_signature = 41406

const OQS_SIG_cross_rsdp_192_small_length_public_key = 115

const OQS_SIG_cross_rsdp_192_small_length_secret_key = 48

const OQS_SIG_cross_rsdp_192_small_length_signature = 28391

const OQS_SIG_cross_rsdp_256_balanced_length_public_key = 153

const OQS_SIG_cross_rsdp_256_balanced_length_secret_key = 64

const OQS_SIG_cross_rsdp_256_balanced_length_signature = 53527

const OQS_SIG_cross_rsdp_256_fast_length_public_key = 153

const OQS_SIG_cross_rsdp_256_fast_length_secret_key = 64

const OQS_SIG_cross_rsdp_256_fast_length_signature = 74590

const OQS_SIG_cross_rsdp_256_small_length_public_key = 153

const OQS_SIG_cross_rsdp_256_small_length_secret_key = 64

const OQS_SIG_cross_rsdp_256_small_length_signature = 50818

const OQS_SIG_cross_rsdpg_128_balanced_length_public_key = 54

const OQS_SIG_cross_rsdpg_128_balanced_length_secret_key = 32

const OQS_SIG_cross_rsdpg_128_balanced_length_signature = 9120

const OQS_SIG_cross_rsdpg_128_fast_length_public_key = 54

const OQS_SIG_cross_rsdpg_128_fast_length_secret_key = 32

const OQS_SIG_cross_rsdpg_128_fast_length_signature = 11980

const OQS_SIG_cross_rsdpg_128_small_length_public_key = 54

const OQS_SIG_cross_rsdpg_128_small_length_secret_key = 32

const OQS_SIG_cross_rsdpg_128_small_length_signature = 8960

const OQS_SIG_cross_rsdpg_192_balanced_length_public_key = 83

const OQS_SIG_cross_rsdpg_192_balanced_length_secret_key = 48

const OQS_SIG_cross_rsdpg_192_balanced_length_signature = 22464

const OQS_SIG_cross_rsdpg_192_fast_length_public_key = 83

const OQS_SIG_cross_rsdpg_192_fast_length_secret_key = 48

const OQS_SIG_cross_rsdpg_192_fast_length_signature = 26772

const OQS_SIG_cross_rsdpg_192_small_length_public_key = 83

const OQS_SIG_cross_rsdpg_192_small_length_secret_key = 48

const OQS_SIG_cross_rsdpg_192_small_length_signature = 20452

const OQS_SIG_cross_rsdpg_256_balanced_length_public_key = 106

const OQS_SIG_cross_rsdpg_256_balanced_length_secret_key = 64

const OQS_SIG_cross_rsdpg_256_balanced_length_signature = 40100

const OQS_SIG_cross_rsdpg_256_fast_length_public_key = 106

const OQS_SIG_cross_rsdpg_256_fast_length_secret_key = 64

const OQS_SIG_cross_rsdpg_256_fast_length_signature = 48102

const OQS_SIG_cross_rsdpg_256_small_length_public_key = 106

const OQS_SIG_cross_rsdpg_256_small_length_secret_key = 64

const OQS_SIG_cross_rsdpg_256_small_length_signature = 36454

const OQS_SIG_uov_ov_Is_length_public_key = 412160

const OQS_SIG_uov_ov_Is_length_secret_key = 348704

const OQS_SIG_uov_ov_Is_length_signature = 96

const OQS_SIG_uov_ov_Ip_length_public_key = 278432

const OQS_SIG_uov_ov_Ip_length_secret_key = 237896

const OQS_SIG_uov_ov_Ip_length_signature = 128

const OQS_SIG_uov_ov_III_length_public_key = 1225440

const OQS_SIG_uov_ov_III_length_secret_key = 1044320

const OQS_SIG_uov_ov_III_length_signature = 200

const OQS_SIG_uov_ov_V_length_public_key = 2869440

const OQS_SIG_uov_ov_V_length_secret_key = 2436704

const OQS_SIG_uov_ov_V_length_signature = 260

const OQS_SIG_uov_ov_Is_pkc_length_public_key = 66576

const OQS_SIG_uov_ov_Is_pkc_length_secret_key = 348704

const OQS_SIG_uov_ov_Is_pkc_length_signature = 96

const OQS_SIG_uov_ov_Ip_pkc_length_public_key = 43576

const OQS_SIG_uov_ov_Ip_pkc_length_secret_key = 237896

const OQS_SIG_uov_ov_Ip_pkc_length_signature = 128

const OQS_SIG_uov_ov_III_pkc_length_public_key = 189232

const OQS_SIG_uov_ov_III_pkc_length_secret_key = 1044320

const OQS_SIG_uov_ov_III_pkc_length_signature = 200

const OQS_SIG_uov_ov_V_pkc_length_public_key = 446992

const OQS_SIG_uov_ov_V_pkc_length_secret_key = 2436704

const OQS_SIG_uov_ov_V_pkc_length_signature = 260

const OQS_SIG_uov_ov_Is_pkc_skc_length_public_key = 66576

const OQS_SIG_uov_ov_Is_pkc_skc_length_secret_key = 32

const OQS_SIG_uov_ov_Is_pkc_skc_length_signature = 96

const OQS_SIG_uov_ov_Ip_pkc_skc_length_public_key = 43576

const OQS_SIG_uov_ov_Ip_pkc_skc_length_secret_key = 32

const OQS_SIG_uov_ov_Ip_pkc_skc_length_signature = 128

const OQS_SIG_uov_ov_III_pkc_skc_length_public_key = 189232

const OQS_SIG_uov_ov_III_pkc_skc_length_secret_key = 32

const OQS_SIG_uov_ov_III_pkc_skc_length_signature = 200

const OQS_SIG_uov_ov_V_pkc_skc_length_public_key = 446992

const OQS_SIG_uov_ov_V_pkc_skc_length_secret_key = 32

const OQS_SIG_uov_ov_V_pkc_skc_length_signature = 260

const OQS_SIG_snova_SNOVA_24_5_4_length_public_key = 1016

const OQS_SIG_snova_SNOVA_24_5_4_length_secret_key = 48

const OQS_SIG_snova_SNOVA_24_5_4_length_signature = 248

const OQS_SIG_snova_SNOVA_24_5_4_SHAKE_length_public_key = 1016

const OQS_SIG_snova_SNOVA_24_5_4_SHAKE_length_secret_key = 48

const OQS_SIG_snova_SNOVA_24_5_4_SHAKE_length_signature = 248

const OQS_SIG_snova_SNOVA_24_5_4_esk_length_public_key = 1016

const OQS_SIG_snova_SNOVA_24_5_4_esk_length_secret_key = 36848

const OQS_SIG_snova_SNOVA_24_5_4_esk_length_signature = 248

const OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_length_public_key = 1016

const OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_length_secret_key = 36848

const OQS_SIG_snova_SNOVA_24_5_4_SHAKE_esk_length_signature = 248

const OQS_SIG_snova_SNOVA_37_17_2_length_public_key = 9842

const OQS_SIG_snova_SNOVA_37_17_2_length_secret_key = 48

const OQS_SIG_snova_SNOVA_37_17_2_length_signature = 124

const OQS_SIG_snova_SNOVA_25_8_3_length_public_key = 2320

const OQS_SIG_snova_SNOVA_25_8_3_length_secret_key = 48

const OQS_SIG_snova_SNOVA_25_8_3_length_signature = 165

const OQS_SIG_snova_SNOVA_56_25_2_length_public_key = 31266

const OQS_SIG_snova_SNOVA_56_25_2_length_secret_key = 48

const OQS_SIG_snova_SNOVA_56_25_2_length_signature = 178

const OQS_SIG_snova_SNOVA_49_11_3_length_public_key = 6006

const OQS_SIG_snova_SNOVA_49_11_3_length_secret_key = 48

const OQS_SIG_snova_SNOVA_49_11_3_length_signature = 286

const OQS_SIG_snova_SNOVA_37_8_4_length_public_key = 4112

const OQS_SIG_snova_SNOVA_37_8_4_length_secret_key = 48

const OQS_SIG_snova_SNOVA_37_8_4_length_signature = 376

const OQS_SIG_snova_SNOVA_24_5_5_length_public_key = 1579

const OQS_SIG_snova_SNOVA_24_5_5_length_secret_key = 48

const OQS_SIG_snova_SNOVA_24_5_5_length_signature = 379

const OQS_SIG_snova_SNOVA_60_10_4_length_public_key = 8016

const OQS_SIG_snova_SNOVA_60_10_4_length_secret_key = 48

const OQS_SIG_snova_SNOVA_60_10_4_length_signature = 576

const OQS_SIG_snova_SNOVA_29_6_5_length_public_key = 2716

const OQS_SIG_snova_SNOVA_29_6_5_length_secret_key = 48

const OQS_SIG_snova_SNOVA_29_6_5_length_signature = 454

const OQS_SIG_STFL_alg_xmss_sha256_h10 = "XMSS-SHA2_10_256"

const OQS_SIG_STFL_alg_xmss_sha256_h16 = "XMSS-SHA2_16_256"

const OQS_SIG_STFL_alg_xmss_sha256_h20 = "XMSS-SHA2_20_256"

const OQS_SIG_STFL_alg_xmss_shake128_h10 = "XMSS-SHAKE_10_256"

const OQS_SIG_STFL_alg_xmss_shake128_h16 = "XMSS-SHAKE_16_256"

const OQS_SIG_STFL_alg_xmss_shake128_h20 = "XMSS-SHAKE_20_256"

const OQS_SIG_STFL_alg_xmss_sha512_h10 = "XMSS-SHA2_10_512"

const OQS_SIG_STFL_alg_xmss_sha512_h16 = "XMSS-SHA2_16_512"

const OQS_SIG_STFL_alg_xmss_sha512_h20 = "XMSS-SHA2_20_512"

const OQS_SIG_STFL_alg_xmss_shake256_h10 = "XMSS-SHAKE_10_512"

const OQS_SIG_STFL_alg_xmss_shake256_h16 = "XMSS-SHAKE_16_512"

const OQS_SIG_STFL_alg_xmss_shake256_h20 = "XMSS-SHAKE_20_512"

const OQS_SIG_STFL_alg_xmss_sha256_h10_192 = "XMSS-SHA2_10_192"

const OQS_SIG_STFL_alg_xmss_sha256_h16_192 = "XMSS-SHA2_16_192"

const OQS_SIG_STFL_alg_xmss_sha256_h20_192 = "XMSS-SHA2_20_192"

const OQS_SIG_STFL_alg_xmss_shake256_h10_192 = "XMSS-SHAKE256_10_192"

const OQS_SIG_STFL_alg_xmss_shake256_h16_192 = "XMSS-SHAKE256_16_192"

const OQS_SIG_STFL_alg_xmss_shake256_h20_192 = "XMSS-SHAKE256_20_192"

const OQS_SIG_STFL_alg_xmss_shake256_h10_256 = "XMSS-SHAKE256_10_256"

const OQS_SIG_STFL_alg_xmss_shake256_h16_256 = "XMSS-SHAKE256_16_256"

const OQS_SIG_STFL_alg_xmss_shake256_h20_256 = "XMSS-SHAKE256_20_256"

const OQS_SIG_STFL_alg_xmssmt_sha256_h20_2 = "XMSSMT-SHA2_20/2_256"

const OQS_SIG_STFL_alg_xmssmt_sha256_h20_4 = "XMSSMT-SHA2_20/4_256"

const OQS_SIG_STFL_alg_xmssmt_sha256_h40_2 = "XMSSMT-SHA2_40/2_256"

const OQS_SIG_STFL_alg_xmssmt_sha256_h40_4 = "XMSSMT-SHA2_40/4_256"

const OQS_SIG_STFL_alg_xmssmt_sha256_h40_8 = "XMSSMT-SHA2_40/8_256"

const OQS_SIG_STFL_alg_xmssmt_sha256_h60_3 = "XMSSMT-SHA2_60/3_256"

const OQS_SIG_STFL_alg_xmssmt_sha256_h60_6 = "XMSSMT-SHA2_60/6_256"

const OQS_SIG_STFL_alg_xmssmt_sha256_h60_12 = "XMSSMT-SHA2_60/12_256"

const OQS_SIG_STFL_alg_xmssmt_shake128_h20_2 = "XMSSMT-SHAKE_20/2_256"

const OQS_SIG_STFL_alg_xmssmt_shake128_h20_4 = "XMSSMT-SHAKE_20/4_256"

const OQS_SIG_STFL_alg_xmssmt_shake128_h40_2 = "XMSSMT-SHAKE_40/2_256"

const OQS_SIG_STFL_alg_xmssmt_shake128_h40_4 = "XMSSMT-SHAKE_40/4_256"

const OQS_SIG_STFL_alg_xmssmt_shake128_h40_8 = "XMSSMT-SHAKE_40/8_256"

const OQS_SIG_STFL_alg_xmssmt_shake128_h60_3 = "XMSSMT-SHAKE_60/3_256"

const OQS_SIG_STFL_alg_xmssmt_shake128_h60_6 = "XMSSMT-SHAKE_60/6_256"

const OQS_SIG_STFL_alg_xmssmt_shake128_h60_12 = "XMSSMT-SHAKE_60/12_256"

const OQS_SIG_STFL_alg_lms_sha256_h5_w1 = "LMS_SHA256_H5_W1"

const OQS_SIG_STFL_alg_lms_sha256_h5_w2 = "LMS_SHA256_H5_W2"

const OQS_SIG_STFL_alg_lms_sha256_h5_w4 = "LMS_SHA256_H5_W4"

const OQS_SIG_STFL_alg_lms_sha256_h5_w8 = "LMS_SHA256_H5_W8"

const OQS_SIG_STFL_alg_lms_sha256_h10_w1 = "LMS_SHA256_H10_W1"

const OQS_SIG_STFL_alg_lms_sha256_h10_w2 = "LMS_SHA256_H10_W2"

const OQS_SIG_STFL_alg_lms_sha256_h10_w4 = "LMS_SHA256_H10_W4"

const OQS_SIG_STFL_alg_lms_sha256_h10_w8 = "LMS_SHA256_H10_W8"

const OQS_SIG_STFL_alg_lms_sha256_h15_w1 = "LMS_SHA256_H15_W1"

const OQS_SIG_STFL_alg_lms_sha256_h15_w2 = "LMS_SHA256_H15_W2"

const OQS_SIG_STFL_alg_lms_sha256_h15_w4 = "LMS_SHA256_H15_W4"

const OQS_SIG_STFL_alg_lms_sha256_h15_w8 = "LMS_SHA256_H15_W8"

const OQS_SIG_STFL_alg_lms_sha256_h20_w1 = "LMS_SHA256_H20_W1"

const OQS_SIG_STFL_alg_lms_sha256_h20_w2 = "LMS_SHA256_H20_W2"

const OQS_SIG_STFL_alg_lms_sha256_h20_w4 = "LMS_SHA256_H20_W4"

const OQS_SIG_STFL_alg_lms_sha256_h20_w8 = "LMS_SHA256_H20_W8"

const OQS_SIG_STFL_alg_lms_sha256_h25_w1 = "LMS_SHA256_H25_W1"

const OQS_SIG_STFL_alg_lms_sha256_h25_w2 = "LMS_SHA256_H25_W2"

const OQS_SIG_STFL_alg_lms_sha256_h25_w4 = "LMS_SHA256_H25_W4"

const OQS_SIG_STFL_alg_lms_sha256_h25_w8 = "LMS_SHA256_H25_W8"

const OQS_SIG_STFL_alg_lms_sha256_h5_w8_h5_w8 = "LMS_SHA256_H5_W8_H5_W8"

const OQS_SIG_STFL_alg_lms_sha256_h10_w4_h5_w8 = "LMS_SHA256_H10_W4_H5_W8"

const OQS_SIG_STFL_alg_lms_sha256_h10_w8_h5_w8 = "LMS_SHA256_H10_W8_H5_W8"

const OQS_SIG_STFL_alg_lms_sha256_h10_w2_h10_w2 = "LMS_SHA256_H10_W2_H10_W2"

const OQS_SIG_STFL_alg_lms_sha256_h10_w4_h10_w4 = "LMS_SHA256_H10_W4_H10_W4"

const OQS_SIG_STFL_alg_lms_sha256_h10_w8_h10_w8 = "LMS_SHA256_H10_W8_H10_W8"

const OQS_SIG_STFL_alg_lms_sha256_h15_w8_h5_w8 = "LMS_SHA256_H15_W8_H5_W8"

const OQS_SIG_STFL_alg_lms_sha256_h15_w8_h10_w8 = "LMS_SHA256_H15_W8_H10_W8"

const OQS_SIG_STFL_alg_lms_sha256_h15_w8_h15_w8 = "LMS_SHA256_H15_W8_H15_W8"

const OQS_SIG_STFL_alg_lms_sha256_h20_w8_h5_w8 = "LMS_SHA256_H20_W8_H5_W8"

const OQS_SIG_STFL_alg_lms_sha256_h20_w8_h10_w8 = "LMS_SHA256_H20_W8_H10_W8"

const OQS_SIG_STFL_alg_lms_sha256_h20_w8_h15_w8 = "LMS_SHA256_H20_W8_H15_W8"

const OQS_SIG_STFL_alg_lms_sha256_h20_w8_h20_w8 = "LMS_SHA256_H20_W8_H20_W8"

const OQS_SIG_STFL_algs_length = 70

const OQS_SIG_STFL = OQS_SIG

# exports
const PREFIXES = ["OQS_"]
for name in names(@__MODULE__; all = true), prefix in PREFIXES
    if startswith(string(name), prefix)
        @eval export $name
    end
end

end # module
