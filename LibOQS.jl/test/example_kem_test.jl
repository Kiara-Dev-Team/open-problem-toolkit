@testitem "example_kem" begin
    using LibOQS

    @testset "stack" begin
        public_key = Vector{UInt8}(undef, LibOQS.OQS_KEM_ml_kem_768_length_public_key)
        secret_key = Vector{UInt8}(undef, LibOQS.OQS_KEM_ml_kem_768_length_secret_key)
        ciphertext = Vector{UInt8}(undef, LibOQS.OQS_KEM_ml_kem_768_length_ciphertext)
        shared_secret_e =
            Vector{UInt8}(undef, LibOQS.OQS_KEM_ml_kem_768_length_shared_secret)
        shared_secret_d =
            Vector{UInt8}(undef, LibOQS.OQS_KEM_ml_kem_768_length_shared_secret)

        status = LibOQS.OQS_KEM_ml_kem_768_keypair(public_key, secret_key)
        @test status == LibOQS.OQS_SUCCESS

        status = LibOQS.OQS_KEM_ml_kem_768_encaps(ciphertext, shared_secret_e, public_key)
        @test status == LibOQS.OQS_SUCCESS

        status = LibOQS.OQS_KEM_ml_kem_768_decaps(shared_secret_d, ciphertext, secret_key)
        @test status == LibOQS.OQS_SUCCESS

        @test shared_secret_e == shared_secret_d
    end

    @testset "heap" begin
        kem_ptr = LibOQS.OQS_KEM_new(LibOQS.OQS_KEM_alg_kyber_768)
        kem = unsafe_load(kem_ptr)

        public_key = Vector{UInt8}(undef, kem.length_public_key)
        secret_key = Vector{UInt8}(undef, kem.length_secret_key)
        ciphertext = Vector{UInt8}(undef, kem.length_ciphertext)
        shared_secret_encap = Vector{UInt8}(undef, kem.length_shared_secret)
        shared_secret_decap = Vector{UInt8}(undef, kem.length_shared_secret)

        status = LibOQS.OQS_KEM_keypair(kem_ptr, public_key, secret_key)
        @test status == LibOQS.OQS_SUCCESS

        status = LibOQS.OQS_KEM_encaps(kem_ptr, ciphertext, shared_secret_encap, public_key)

        @test status == LibOQS.OQS_SUCCESS

        status = LibOQS.OQS_KEM_decaps(kem_ptr, shared_secret_decap, ciphertext, secret_key)
        @test status == LibOQS.OQS_SUCCESS

        @test shared_secret_encap == shared_secret_decap

        LibOQS.OQS_KEM_free(kem_ptr)
    end

end
