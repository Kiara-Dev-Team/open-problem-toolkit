@testitem "sig_linking" begin
    using LibOQS

    # Minimal Julia example of using a post-quantum signature implemented in liboqs.
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
    end

    @testset "heap" begin
        sig_ptr = LibOQS.OQS_SIG_new(LibOQS.OQS_SIG_alg_dilithium_2)
        sig = unsafe_load(sig_ptr)

        public_key = Vector{UInt8}(undef, sig.length_public_key)
        secret_key = Vector{UInt8}(undef, sig.length_secret_key)

        status = LibOQS.OQS_SIG_keypair(sig_ptr, public_key, secret_key)
        @test status == LibOQS.OQS_SUCCESS

        message = Vector{UInt8}("This is a message")
        message_len = Csize_t(length(message))

        signature = Vector{UInt8}(undef, sig.length_signature)
        ref_signature_len = Ref{Csize_t}(0)

        status = LibOQS.OQS_SIG_sign(
            sig_ptr,
            signature,
            ref_signature_len,
            message,
            message_len,
            secret_key,
        )

        @test status == LibOQS.OQS_SUCCESS

        status = LibOQS.OQS_SIG_verify(
            sig_ptr,
            message,
            message_len,
            signature,
            ref_signature_len[],
            public_key,
        )

        @test status == LibOQS.OQS_SUCCESS
        LibOQS.OQS_SIG_free(sig_ptr)
    end

end
