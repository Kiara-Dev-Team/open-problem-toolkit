# Basic Paillier Cryptosystem Usage Example
# Demonstrates ISO/IEC 18033-6:2019 compliant Paillier encryption

using HomomorphicCryptography

println("=== Paillier Cryptosystem Example ===")
println()

# Create a Paillier scheme instance
scheme = PaillierScheme()
println("Scheme: $(scheme_name(scheme))")
println("Supports addition: $(supports_addition(scheme))")
println("Supports multiplication: $(supports_multiplication(scheme))")
println()

# Set up security parameters (128-bit security level)
params = PaillierParameters(SECURITY_128)
println("Security level: $(params.security_level)")
println("Key size: $(params.key_size) bits")
println("Prime sizes: $(params.p_size) bits each")
println()

# Generate key pair
println("Generating key pair...")
keypair = keygen(scheme, params)
pk, sk = keypair.public_key, keypair.private_key

println("Public key modulus n has $(pk.key_size) bits")
println("Key generation complete!")
println()

# Example 1: Basic encryption and decryption
println("=== Example 1: Basic Encryption/Decryption ===")
secret_number = 12345
println("Secret number: $secret_number")

# Encrypt the number
ciphertext = encrypt(pk, secret_number)
println(
    "Encrypted successfully (ciphertext has $(length(string(ciphertext.value))) digits)",
)

# Decrypt the number
decrypted = decrypt_to_int(sk, ciphertext)
println("Decrypted: $decrypted")
println("Encryption/decryption successful: $(decrypted == secret_number)")
println()

# Example 2: Homomorphic addition
println("=== Example 2: Homomorphic Addition ===")
a, b = 100, 200
println("Numbers to add: $a + $b")

# Encrypt both numbers
c_a = encrypt(pk, a)
c_b = encrypt(pk, b)
println("Both numbers encrypted")

# Perform homomorphic addition (without decrypting)
c_sum = add_encrypted(c_a, c_b)
println("Homomorphic addition performed on encrypted data")

# Decrypt the result
decrypted_sum = decrypt_to_int(sk, c_sum)
println("Decrypted sum: $decrypted_sum")
println("Expected sum: $(a + b)")
println("Homomorphic addition successful: $(decrypted_sum == a + b)")
println()

# Example 3: Adding plaintext to ciphertext
println("=== Example 3: Adding Plaintext to Ciphertext ===")
encrypted_value = 500
plaintext_addition = 75
println("Encrypted value: $encrypted_value")
println("Plaintext to add: $plaintext_addition")

c_encrypted = encrypt(pk, encrypted_value)
p_addition = PaillierPlaintext(plaintext_addition)

# Add plaintext to ciphertext
c_result = add_plain(c_encrypted, p_addition)
decrypted_result = decrypt_to_int(sk, c_result)

println("Result: $decrypted_result")
println("Expected: $(encrypted_value + plaintext_addition)")
println(
    "Plaintext addition successful: $(decrypted_result == encrypted_value + plaintext_addition)",
)
println()

# Example 4: Scalar multiplication
println("=== Example 4: Scalar Multiplication ===")
value = 25
multiplier = 4
println("Value: $value")
println("Multiplier: $multiplier")

c_value = encrypt(pk, value)
c_multiplied = multiply_plain(c_value, multiplier)
decrypted_multiplied = decrypt_to_int(sk, c_multiplied)

println("Result: $decrypted_multiplied")
println("Expected: $(value * multiplier)")
println("Scalar multiplication successful: $(decrypted_multiplied == value * multiplier)")
println()

# Example 5: Complex computation
println("=== Example 5: Complex Homomorphic Computation ===")
# Compute 3*x + 2*y + z where x=10, y=20, z=5
x, y, z = 10, 20, 5
println("Computing: 3*$x + 2*$y + $z")

# Encrypt all values
c_x = encrypt(pk, x)
c_y = encrypt(pk, y)
c_z = encrypt(pk, z)

# Perform computation homomorphically
c_3x = multiply_plain(c_x, 3)      # 3*x
c_2y = multiply_plain(c_y, 2)      # 2*y
c_3x_plus_2y = add_encrypted(c_3x, c_2y)  # 3*x + 2*y
c_result = add_encrypted(c_3x_plus_2y, c_z)  # 3*x + 2*y + z

# Decrypt final result
final_result = decrypt_to_int(sk, c_result)
expected = 3*x + 2*y + z

println("Homomorphic result: $final_result")
println("Expected result: $expected")
println("Complex computation successful: $(final_result == expected)")
println()

# Validate ISO/IEC 18033-6 compliance
println("=== ISO/IEC 18033-6:2019 Compliance Check ===")
is_compliant = validate_iso18033_6_compliance(scheme, params)
println("ISO/IEC 18033-6:2019 compliant: $is_compliant")
println()

println("=== Example Complete ===")
println("The Paillier implementation successfully demonstrates:")
println("✓ ISO/IEC 18033-6:2019 compliance")
println("✓ Additive homomorphic encryption")
println("✓ Secure key generation")
println("✓ Efficient encryption/decryption")
println("✓ Homomorphic operations on encrypted data")
