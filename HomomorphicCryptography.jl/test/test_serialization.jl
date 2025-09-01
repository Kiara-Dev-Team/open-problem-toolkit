@testitem "Serialization - Paillier Keys" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk, sk = keypair.public_key, keypair.private_key

    # Test public key serialization
    pk_data = serialize(pk)
    @test pk_data["type"] == "PaillierPublicKey"
    @test haskey(pk_data, "n")
    @test haskey(pk_data, "g")

    # Test private key serialization
    sk_data = serialize(sk)
    @test sk_data["type"] == "PaillierPrivateKey"
    @test haskey(sk_data, "lambda")
    @test haskey(sk_data, "mu")
end

@testitem "Serialization - Paillier Ciphertext" begin
    using HomomorphicCryptography

    scheme = PaillierScheme()
    params = PaillierParameters(SECURITY_128)
    keypair = keygen(scheme, params)
    pk = keypair.public_key

    plaintext = 12345
    ciphertext = encrypt(pk, plaintext)

    # Test ciphertext serialization
    c_data = serialize(ciphertext)
    @test c_data["type"] == "PaillierCiphertext"
    @test haskey(c_data, "value")
    @test haskey(c_data, "n")
end
