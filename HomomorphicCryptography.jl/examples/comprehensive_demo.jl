# Comprehensive demonstration of HomomorphicCryptography.jl capabilities
# Shows all implemented features including multiple schemes, serialization, and benchmarking

using HomomorphicCryptography
using Random

println("🔐 HomomorphicCryptography.jl - Comprehensive Demo")
println("=" ^ 60)

# Set random seed for reproducibility
Random.seed!(42)

println("📚 Available schemes:")
for scheme in available_schemes()
    println("  • $scheme")
end
println()

# Demo 1: Paillier Cryptosystem
println("=" ^ 60)
println("🔑 Demo 1: Paillier Cryptosystem")
println("=" ^ 60)

paillier_scheme = PaillierScheme()
paillier_params = PaillierParameters(SECURITY_128)

println("Generating Paillier key pair (2048-bit)...")
paillier_keypair = keygen(paillier_scheme, paillier_params)
pk_paillier, sk_paillier = paillier_keypair.public_key, paillier_keypair.private_key

println("✅ Key generation complete!")
println("   Public key size: $(pk_paillier.key_size) bits")

# Demonstrate various operations
println("\n📊 Paillier Operations:")

# Basic encryption/decryption
secret_data = [1000, 2500, 750, 1200, 900]
println("Secret data: $secret_data")

encrypted_data = [encrypt(pk_paillier, x) for x in secret_data]
println("✅ All values encrypted")

# Homomorphic sum
println("\n🧮 Computing encrypted sum...")
global encrypted_sum = encrypted_data[1]
for i = 2:length(encrypted_data)
    global encrypted_sum = add_encrypted(encrypted_sum, encrypted_data[i])
end

decrypted_sum = decrypt_to_int(sk_paillier, encrypted_sum)
expected_sum = sum(secret_data)

println("Encrypted computation result: $decrypted_sum")
println("Expected result: $expected_sum")
println("✅ Homomorphic sum successful: $(decrypted_sum == expected_sum)")

# Weighted average (homomorphic)
println("\n📈 Computing encrypted weighted average...")
weights = [0.2, 0.3, 0.1, 0.25, 0.15]
println("Weights: $weights")

# Compute weighted sum homomorphically
global encrypted_weighted_sum =
    multiply_plain(encrypted_data[1], Int(round(weights[1] * 1000)))
for i = 2:length(encrypted_data)
    weighted_term = multiply_plain(encrypted_data[i], Int(round(weights[i] * 1000)))
    global encrypted_weighted_sum = add_encrypted(encrypted_weighted_sum, weighted_term)
end

decrypted_weighted_sum = decrypt_to_int(sk_paillier, encrypted_weighted_sum)
expected_weighted_sum = Int(round(sum(secret_data .* weights) * 1000))

println("Encrypted weighted sum (×1000): $decrypted_weighted_sum")
println("Expected weighted sum (×1000): $expected_weighted_sum")
println(
    "✅ Weighted computation successful: $(decrypted_weighted_sum == expected_weighted_sum)",
)

# Demo 2: ElGamal Cryptosystem
println("\n" * "=" ^ 60)
println("🔑 Demo 2: ElGamal Cryptosystem")
println("=" ^ 60)

elgamal_scheme = ElGamalScheme()
elgamal_params = ElGamalParameters(SECURITY_128)

println("Generating ElGamal key pair (2048-bit safe prime)...")
elgamal_keypair = keygen(elgamal_scheme, elgamal_params)
pk_elgamal, sk_elgamal = elgamal_keypair.public_key, elgamal_keypair.private_key

println("✅ Key generation complete!")
println("   Public key size: $(pk_elgamal.key_size) bits")

# ElGamal operations (limited to small values)
println("\n📊 ElGamal Operations:")
small_data = [5, 10, 15, 8, 12]  # Small values due to discrete log limitation
println("Secret data (small values): $small_data")

encrypted_elgamal = [encrypt(pk_elgamal, x) for x in small_data]
println("✅ All values encrypted")

# Homomorphic sum
println("\n🧮 Computing encrypted sum...")
global elgamal_sum = encrypted_elgamal[1]
for i = 2:length(encrypted_elgamal)
    global elgamal_sum = add_encrypted(elgamal_sum, encrypted_elgamal[i])
end

decrypted_elgamal_sum = decrypt_to_int(sk_elgamal, elgamal_sum)
expected_elgamal_sum = sum(small_data)

println("Encrypted computation result: $decrypted_elgamal_sum")
println("Expected result: $expected_elgamal_sum")
println(
    "✅ ElGamal homomorphic sum successful: $(decrypted_elgamal_sum == expected_elgamal_sum)",
)

# Demo 3: Serialization
println("\n" * "=" ^ 60)
println("💾 Demo 3: Serialization & Key Management")
println("=" ^ 60)

# Export Paillier keys
println("Exporting Paillier key pair...")
paillier_files = export_keypair(paillier_keypair, "demo_paillier", BASE64_FORMAT)

# Export ElGamal keys
println("\nExporting ElGamal key pair...")
elgamal_files = export_keypair(elgamal_keypair, "demo_elgamal", BASE64_FORMAT)

# Serialize and save a ciphertext
println("\nSaving encrypted data...")
sample_ciphertext = encrypted_data[1]
save_to_file(sample_ciphertext, "sample_ciphertext.dat", BASE64_FORMAT)
println("✅ Ciphertext saved to sample_ciphertext.dat")

# Demo 4: Standards Compliance
println("\n" * "=" ^ 60)
println("📋 Demo 4: Standards Compliance Validation")
println("=" ^ 60)

println("🔍 Validating Paillier ISO/IEC 18033-6:2019 compliance...")
paillier_compliant = validate_iso18033_6_compliance(paillier_scheme, paillier_params)
println("Paillier compliance: $(paillier_compliant ? "✅ PASS" : "❌ FAIL")")

println("\n🔍 Validating ElGamal ISO/IEC 18033-6:2019 compliance...")
elgamal_compliant = validate_elgamal_iso18033_6(elgamal_scheme, elgamal_params)
println("ElGamal compliance: $(elgamal_compliant ? "✅ PASS" : "❌ FAIL")")

# Generate detailed compliance report
println("\n📄 Generating detailed compliance report...")
compliance_report =
    ISO18033_6_Validation.generate_compliance_report(paillier_scheme, paillier_params)
println("Compliance report generated (sample):")
println(compliance_report[1:500] * "...")  # Show first 500 characters

# Demo 5: Performance Analysis
println("\n" * "=" ^ 60)
println("⚡ Demo 5: Performance Benchmarking")
println("=" ^ 60)

println("🏃‍♂️ Quick performance comparison (5 samples each)...")
results = compare_schemes(SECURITY_128; samples = 5)

# Demo 6: Practical Application Scenarios
println("\n" * "=" ^ 60)
println("🏢 Demo 6: Practical Application Scenarios")
println("=" ^ 60)

println("📊 Scenario 1: Secure Voting System")
println("─" ^ 40)
# Simulate votes: 1 = yes, 0 = no
votes = [1, 0, 1, 1, 0, 1, 0, 1, 1, 0]  # 6 yes, 4 no
println("Actual votes: $votes")

# Encrypt all votes
encrypted_votes = [encrypt(pk_paillier, vote) for vote in votes]
println("✅ All votes encrypted and submitted")

# Count votes homomorphically
global encrypted_total = encrypted_votes[1]
for i = 2:length(encrypted_votes)
    global encrypted_total = add_encrypted(encrypted_total, encrypted_votes[i])
end

total_yes_votes = decrypt_to_int(sk_paillier, encrypted_total)
total_no_votes = length(votes) - total_yes_votes

println("Vote counting results:")
println("  Yes votes: $total_yes_votes")
println("  No votes: $total_no_votes")
println("  Winner: $(total_yes_votes > total_no_votes ? "YES" : "NO")")
println("✅ Secure voting completed without revealing individual votes")

println("\n💰 Scenario 2: Privacy-Preserving Salary Analysis")
println("─" ^ 40)
# Simulate employee salaries (in thousands)
salaries = [45, 52, 38, 67, 41, 58, 49, 63, 44, 55]
println("Number of employees: $(length(salaries))")

# Encrypt all salaries
encrypted_salaries = [encrypt(pk_paillier, salary) for salary in salaries]
println("✅ All salaries encrypted")

# Compute average salary homomorphically
global encrypted_salary_sum = encrypted_salaries[1]
for i = 2:length(encrypted_salaries)
    global encrypted_salary_sum = add_encrypted(encrypted_salary_sum, encrypted_salaries[i])
end

total_salary = decrypt_to_int(sk_paillier, encrypted_salary_sum)
average_salary = total_salary / length(salaries)

println("Analysis results:")
println("  Total payroll: \$$(total_salary)k")
println("  Average salary: \$$(round(average_salary, digits=1))k")
println("  Expected average: \$$(round(sum(salaries)/length(salaries), digits=1))k")
println("✅ Salary analysis completed while preserving individual privacy")

# Demo 7: Security Recommendations
println("\n" * "=" ^ 60)
println("🛡️ Demo 7: Security Best Practices")
println("=" ^ 60)

println(security_recommendations())

# Clean up demo files
println("\n🧹 Cleaning up demo files...")
for file in [paillier_files..., elgamal_files..., "sample_ciphertext.dat"]
    if isfile(file)
        secure_delete_file(file)
        println("🗑️  Securely deleted: $file")
    end
end

println("\n" * "=" ^ 60)
println("🎉 Comprehensive Demo Complete!")
println("=" ^ 60)
println("✅ All features demonstrated successfully:")
println("   • Multiple homomorphic encryption schemes")
println("   • ISO/IEC 18033-6:2019 standards compliance")
println("   • Secure key generation and management")
println("   • Homomorphic arithmetic operations")
println("   • Serialization and key export/import")
println("   • Performance benchmarking")
println("   • Real-world application scenarios")
println("   • Security best practices")
println()
println("📚 For more information:")
println("   • Documentation: ?HomomorphicCryptography")
println("   • Available schemes: available_schemes()")
println("   • Scheme details: scheme_info(\"Paillier\")")
println("   • Security guidelines: security_recommendations()")
println()
println("🔒 Remember: Keep your private keys secure!")
