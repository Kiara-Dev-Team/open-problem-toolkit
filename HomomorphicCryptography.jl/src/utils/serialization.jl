# Serialization utilities for homomorphic encryption keys and ciphertexts
# Provides secure and efficient serialization/deserialization capabilities

using Base64
using Dates

"""
    SerializationFormat

Enumeration of supported serialization formats.
"""
@enum SerializationFormat begin
    BINARY_FORMAT
    BASE64_FORMAT
    JSON_FORMAT
end

"""
    serialize_bigint(value::BigInt, format::SerializationFormat = BASE64_FORMAT) -> String

Serialize a BigInt to string format.
"""
function serialize_bigint(value::BigInt, format::SerializationFormat = BASE64_FORMAT)
    if format == BINARY_FORMAT
        return string(value, base = 2)
    elseif format == BASE64_FORMAT
        hex_str = string(value, base = 16)
        return base64encode(hex_str)
    elseif format == JSON_FORMAT
        return string(value)
    else
        error("Unsupported serialization format: $format")
    end
end

"""
    deserialize_bigint(data::String, format::SerializationFormat = BASE64_FORMAT) -> BigInt

Deserialize a string to BigInt.
"""
function deserialize_bigint(data::String, format::SerializationFormat = BASE64_FORMAT)
    if format == BINARY_FORMAT
        return parse(BigInt, data, base = 2)
    elseif format == BASE64_FORMAT
        hex_str = String(base64decode(data))
        return parse(BigInt, hex_str, base = 16)
    elseif format == JSON_FORMAT
        return parse(BigInt, data)
    else
        error("Unsupported serialization format: $format")
    end
end

# Paillier serialization
"""
    serialize(pk::PaillierPublicKey, format::SerializationFormat = BASE64_FORMAT) -> Dict{String, Any}

Serialize Paillier public key to dictionary format.
"""
function serialize(pk::PaillierPublicKey, format::SerializationFormat = BASE64_FORMAT)
    return Dict{String,Any}(
        "type" => "PaillierPublicKey",
        "n" => serialize_bigint(pk.n, format),
        "g" => serialize_bigint(pk.g, format),
        "key_size" => pk.key_size,
        "format" => string(format),
    )
end

"""
    serialize(sk::PaillierPrivateKey, format::SerializationFormat = BASE64_FORMAT) -> Dict{String, Any}

Serialize Paillier private key to dictionary format.
"""
function serialize(sk::PaillierPrivateKey, format::SerializationFormat = BASE64_FORMAT)
    return Dict{String,Any}(
        "type" => "PaillierPrivateKey",
        "lambda" => serialize_bigint(sk.λ, format),
        "mu" => serialize_bigint(sk.μ, format),
        "n" => serialize_bigint(sk.n, format),
        "format" => string(format),
    )
end

"""
    serialize(c::PaillierCiphertext, format::SerializationFormat = BASE64_FORMAT) -> Dict{String, Any}

Serialize Paillier ciphertext to dictionary format.
"""
function serialize(c::PaillierCiphertext, format::SerializationFormat = BASE64_FORMAT)
    return Dict{String,Any}(
        "type" => "PaillierCiphertext",
        "value" => serialize_bigint(c.value, format),
        "n" => serialize_bigint(c.n, format),
        "format" => string(format),
    )
end

"""
    deserialize_paillier_public_key(data::Dict{String, Any}) -> PaillierPublicKey

Deserialize dictionary to Paillier public key.
"""
function deserialize_paillier_public_key(data::Dict{String,Any})
    if data["type"] != "PaillierPublicKey"
        error("Invalid data type for PaillierPublicKey deserialization")
    end

    format = parse(SerializationFormat, data["format"])
    n = deserialize_bigint(data["n"], format)
    g = deserialize_bigint(data["g"], format)

    return PaillierPublicKey(n, g)
end

"""
    deserialize_paillier_private_key(data::Dict{String, Any}) -> PaillierPrivateKey

Deserialize dictionary to Paillier private key.
"""
function deserialize_paillier_private_key(data::Dict{String,Any})
    if data["type"] != "PaillierPrivateKey"
        error("Invalid data type for PaillierPrivateKey deserialization")
    end

    format = parse(SerializationFormat, data["format"])
    λ = deserialize_bigint(data["lambda"], format)
    μ = deserialize_bigint(data["mu"], format)
    n = deserialize_bigint(data["n"], format)

    return PaillierPrivateKey(λ, μ, n)
end

"""
    deserialize_paillier_ciphertext(data::Dict{String, Any}) -> PaillierCiphertext

Deserialize dictionary to Paillier ciphertext.
"""
function deserialize_paillier_ciphertext(data::Dict{String,Any})
    if data["type"] != "PaillierCiphertext"
        error("Invalid data type for PaillierCiphertext deserialization")
    end

    format = parse(SerializationFormat, data["format"])
    value = deserialize_bigint(data["value"], format)
    n = deserialize_bigint(data["n"], format)

    return PaillierCiphertext(value, n)
end

# ElGamal serialization
"""
    serialize(pk::ElGamalPublicKey, format::SerializationFormat = BASE64_FORMAT) -> Dict{String, Any}

Serialize ElGamal public key to dictionary format.
"""
function serialize(pk::ElGamalPublicKey, format::SerializationFormat = BASE64_FORMAT)
    return Dict{String,Any}(
        "type" => "ElGamalPublicKey",
        "p" => serialize_bigint(pk.p, format),
        "g" => serialize_bigint(pk.g, format),
        "h" => serialize_bigint(pk.h, format),
        "q" => serialize_bigint(pk.q, format),
        "key_size" => pk.key_size,
        "format" => string(format),
    )
end

"""
    serialize(sk::ElGamalPrivateKey, format::SerializationFormat = BASE64_FORMAT) -> Dict{String, Any}

Serialize ElGamal private key to dictionary format.
"""
function serialize(sk::ElGamalPrivateKey, format::SerializationFormat = BASE64_FORMAT)
    return Dict{String,Any}(
        "type" => "ElGamalPrivateKey",
        "x" => serialize_bigint(sk.x, format),
        "p" => serialize_bigint(sk.p, format),
        "q" => serialize_bigint(sk.q, format),
        "format" => string(format),
    )
end

"""
    serialize(c::ElGamalCiphertext, format::SerializationFormat = BASE64_FORMAT) -> Dict{String, Any}

Serialize ElGamal ciphertext to dictionary format.
"""
function serialize(c::ElGamalCiphertext, format::SerializationFormat = BASE64_FORMAT)
    return Dict{String,Any}(
        "type" => "ElGamalCiphertext",
        "c1" => serialize_bigint(c.c1, format),
        "c2" => serialize_bigint(c.c2, format),
        "p" => serialize_bigint(c.p, format),
        "g" => serialize_bigint(c.g, format),
        "format" => string(format),
    )
end

"""
    deserialize_elgamal_public_key(data::Dict{String, Any}) -> ElGamalPublicKey

Deserialize dictionary to ElGamal public key.
"""
function deserialize_elgamal_public_key(data::Dict{String,Any})
    if data["type"] != "ElGamalPublicKey"
        error("Invalid data type for ElGamalPublicKey deserialization")
    end

    format = parse(SerializationFormat, data["format"])
    p = deserialize_bigint(data["p"], format)
    g = deserialize_bigint(data["g"], format)
    h = deserialize_bigint(data["h"], format)
    q = deserialize_bigint(data["q"], format)

    return ElGamalPublicKey(p, g, h, q)
end

"""
    deserialize_elgamal_private_key(data::Dict{String, Any}) -> ElGamalPrivateKey

Deserialize dictionary to ElGamal private key.
"""
function deserialize_elgamal_private_key(data::Dict{String,Any})
    if data["type"] != "ElGamalPrivateKey"
        error("Invalid data type for ElGamalPrivateKey deserialization")
    end

    format = parse(SerializationFormat, data["format"])
    x = deserialize_bigint(data["x"], format)
    p = deserialize_bigint(data["p"], format)
    q = deserialize_bigint(data["q"], format)

    return ElGamalPrivateKey(x, p, q)
end

"""
    deserialize_elgamal_ciphertext(data::Dict{String, Any}) -> ElGamalCiphertext

Deserialize dictionary to ElGamal ciphertext.
"""
function deserialize_elgamal_ciphertext(data::Dict{String,Any})
    if data["type"] != "ElGamalCiphertext"
        error("Invalid data type for ElGamalCiphertext deserialization")
    end

    format = parse(SerializationFormat, data["format"])
    c1 = deserialize_bigint(data["c1"], format)
    c2 = deserialize_bigint(data["c2"], format)
    p = deserialize_bigint(data["p"], format)
    g = deserialize_bigint(data["g"], format)

    return ElGamalCiphertext(c1, c2, p, g)
end

# File I/O functions
"""
    save_to_file(obj, filename::String, format::SerializationFormat = BASE64_FORMAT)

Save a serializable object to file.
"""
function save_to_file(obj, filename::String, format::SerializationFormat = BASE64_FORMAT)
    data = serialize(obj, format)

    # Add metadata
    data["created_at"] = string(now())
    data["library_version"] = "HomomorphicCryptography.jl v0.1.0"

    open(filename, "w") do io
        if format == JSON_FORMAT
            # Use JSON if available, otherwise use string representation
            println(io, data)
        else
            # Use Julia's built-in serialization for other formats
            println(io, data)
        end
    end
end

"""
    load_from_file(filename::String, object_type::Type) -> object_type

Load a serialized object from file.
"""
function load_from_file(filename::String, object_type::Type)
    data = nothing
    open(filename, "r") do io
        content = read(io, String)
        data = eval(Meta.parse(content))
    end

    if object_type == PaillierPublicKey
        return deserialize_paillier_public_key(data)
    elseif object_type == PaillierPrivateKey
        return deserialize_paillier_private_key(data)
    elseif object_type == PaillierCiphertext
        return deserialize_paillier_ciphertext(data)
    elseif object_type == ElGamalPublicKey
        return deserialize_elgamal_public_key(data)
    elseif object_type == ElGamalPrivateKey
        return deserialize_elgamal_private_key(data)
    elseif object_type == ElGamalCiphertext
        return deserialize_elgamal_ciphertext(data)
    else
        error("Unsupported object type for deserialization: $object_type")
    end
end

"""
    secure_delete_file(filename::String)

Securely delete a file by overwriting it with random data before deletion.
"""
function secure_delete_file(filename::String)
    if isfile(filename)
        # Get file size
        file_size = filesize(filename)

        # Overwrite with random data multiple times
        for _ = 1:3
            open(filename, "w") do io
                write(io, rand(UInt8, file_size))
            end
        end

        # Finally delete the file
        rm(filename)
    end
end

"""
    export_keypair(keypair::KeyPair, base_filename::String, format::SerializationFormat = BASE64_FORMAT)

Export a key pair to separate files for public and private keys.
"""
function export_keypair(
    keypair::KeyPair,
    base_filename::String,
    format::SerializationFormat = BASE64_FORMAT,
)
    public_filename = "$(base_filename)_public.key"
    private_filename = "$(base_filename)_private.key"

    save_to_file(keypair.public_key, public_filename, format)
    save_to_file(keypair.private_key, private_filename, format)

    println("✅ Key pair exported:")
    println("  Public key:  $public_filename")
    println("  Private key: $private_filename")
    println("⚠️  Keep the private key secure!")

    return (public_filename, private_filename)
end

"""
    import_keypair(base_filename::String, scheme_type::Type) -> KeyPair

Import a key pair from separate files.
"""
function import_keypair(base_filename::String, scheme_type::Type)
    public_filename = "$(base_filename)_public.key"
    private_filename = "$(base_filename)_private.key"

    if !isfile(public_filename) || !isfile(private_filename)
        error("Key files not found: $public_filename or $private_filename")
    end

    if scheme_type == PaillierScheme
        public_key = load_from_file(public_filename, PaillierPublicKey)
        private_key = load_from_file(private_filename, PaillierPrivateKey)
    elseif scheme_type == ElGamalScheme
        public_key = load_from_file(public_filename, ElGamalPublicKey)
        private_key = load_from_file(private_filename, ElGamalPrivateKey)
    else
        error("Unsupported scheme type: $scheme_type")
    end

    return KeyPair(public_key, private_key)
end

# Export serialization functions
export SerializationFormat, BINARY_FORMAT, BASE64_FORMAT, JSON_FORMAT
export serialize,
    deserialize_paillier_public_key,
    deserialize_paillier_private_key,
    deserialize_paillier_ciphertext
export deserialize_elgamal_public_key,
    deserialize_elgamal_private_key, deserialize_elgamal_ciphertext
export save_to_file, load_from_file, secure_delete_file
export export_keypair, import_keypair
