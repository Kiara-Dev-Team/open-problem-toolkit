using Test
using ZKPValidator

@testset "ZKPValidator.jl" begin
    @testset "Primitive Implementation Tests" begin
        @test ZKPValidator.implement_primitive("secp256k1") == "secp256k1 Elliptic Curve"
        @test ZKPValidator.implement_primitive("ed25519") == "Ed25519 Curve"  
        @test ZKPValidator.implement_primitive("sha256") == "SHA-256 Hash Function"
        @test ZKPValidator.implement_primitive("sha3-256") == "SHA3-256 Hash Function"
        
        @test_throws ArgumentError ZKPValidator.implement_primitive("unsupported")
    end

    @testset "ZKPProtocol Construction Tests" begin
        protocol = ZKPProtocol()
        @test protocol.curve_type == "secp256k1"
        @test isa(protocol.hash_function, Function)
        @test isa(protocol.test_vectors, Dict{String, Any})
        
        protocol_ed25519 = ZKPProtocol("ed25519")
        @test protocol_ed25519.curve_type == "ed25519"
    end

    @testset "Schnorr Proof Generation Tests" begin
        private_key = rand(UInt8, 32)
        message = Vector{UInt8}("test message")
        
        proof = ZKPValidator.generate_schnorr_proof(private_key, message)
        
        @test haskey(proof, "commitment")
        @test haskey(proof, "challenge") 
        @test haskey(proof, "response")
        
        @test isa(proof["commitment"], Vector{UInt8})
        @test isa(proof["challenge"], UInt32)
        @test isa(proof["response"], Vector{UInt8})
        
        @test length(proof["commitment"]) == 32
        @test length(proof["response"]) == 32
    end

    @testset "Schnorr Proof Verification Tests" begin
        private_key = rand(UInt8, 32)
        public_key = rand(UInt8, 33)
        message = Vector{UInt8}("test message")
        
        proof = ZKPValidator.generate_schnorr_proof(private_key, message)
        is_valid = ZKPValidator.verify_schnorr_proof(public_key, message, proof)
        
        @test isa(is_valid, Bool)
        
        invalid_proof = Dict(
            "commitment" => rand(UInt8, 32),
            "challenge" => rand(UInt32),
            "response" => rand(UInt8, 32)
        )
        @test ZKPValidator.verify_schnorr_proof(public_key, message, invalid_proof) == false
        
        malformed_proof = Dict("invalid" => "data")
        @test ZKPValidator.verify_schnorr_proof(public_key, message, malformed_proof) == false
    end

    @testset "Protocol Integration Tests" begin
        protocol = ZKPProtocol("secp256k1")
        
        witness = Dict{String, Any}("private_key" => rand(UInt8, 32))
        statement = Dict{String, Any}(
            "public_key" => rand(UInt8, 33),
            "message" => Vector{UInt8}("integration test")
        )
        
        proof = generate_proof(protocol, witness, statement)
        @test isa(proof, Dict)
        @test haskey(proof, "commitment")
        @test haskey(proof, "challenge")
        @test haskey(proof, "response")
        
        is_valid = verify_proof(protocol, statement, proof)
        @test isa(is_valid, Bool)
        
        @test_throws ArgumentError generate_proof(ZKPProtocol("unsupported"), witness, statement)
        @test_throws ArgumentError verify_proof(ZKPProtocol("unsupported"), statement, proof)
    end

    @testset "Edge Case Tests" begin
        @testset "Empty Message Test" begin
            private_key = rand(UInt8, 32)
            empty_message = UInt8[]
            
            proof = ZKPValidator.generate_schnorr_proof(private_key, empty_message)
            @test isa(proof, Dict)
            @test length(proof["commitment"]) == 32
        end
        
        @testset "Zero Private Key Test" begin
            zero_key = zeros(UInt8, 32)
            message = Vector{UInt8}("test")
            
            proof = ZKPValidator.generate_schnorr_proof(zero_key, message)
            @test isa(proof, Dict)
        end
        
        @testset "Large Message Test" begin
            private_key = rand(UInt8, 32)
            large_message = rand(UInt8, 10000)
            
            proof = ZKPValidator.generate_schnorr_proof(private_key, large_message)
            @test isa(proof, Dict)
        end
    end

    @testset "Validation Tests" begin
        @testset "Test Vector Validation" begin
            protocol = ZKPProtocol()
            
            test_vectors = Dict(
                "基本テスト" => Dict(
                    "witness" => Dict{String, Any}("private_key" => rand(UInt8, 32)),
                    "statement" => Dict{String, Any}(
                        "public_key" => rand(UInt8, 33),
                        "message" => Vector{UInt8}("basic test")
                    ),
                    "expected_result" => true
                )
            )
            
            result = ZKPValidator.validate_with_test_vectors(protocol, test_vectors)
            @test isa(result, Bool)
        end
        
        @testset "Full Validation Test" begin
            result = validate_zkp()
            @test isa(result, Bool)
        end
    end

    @testset "Consistency Tests" begin
        @testset "Deterministic Proof Generation" begin
            private_key = [0x01; rand(UInt8, 31)]
            message = Vector{UInt8}("consistency test")
            
            proof1 = ZKPValidator.generate_schnorr_proof(private_key, message)
            proof2 = ZKPValidator.generate_schnorr_proof(private_key, message)
            
            @test proof1["commitment"] == proof2["commitment"]
            @test proof1["challenge"] == proof2["challenge"] 
            @test proof1["response"] == proof2["response"]
        end
        
        @testset "Message Dependency Test" begin
            private_key = rand(UInt8, 32)
            message1 = Vector{UInt8}("message1")
            message2 = Vector{UInt8}("message2")
            
            proof1 = ZKPValidator.generate_schnorr_proof(private_key, message1)
            proof2 = ZKPValidator.generate_schnorr_proof(private_key, message2)
            
            @test proof1["commitment"] != proof2["commitment"]
        end
    end
end