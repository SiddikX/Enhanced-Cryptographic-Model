from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from keygen import aes_key

print("\n+++ENCRYPTION+++")

# Encryption using AES
plaintext = input("""Enter your message: """).encode()
# plaintext = b"""Hello Jello"""
print("[Plaintext]: ", plaintext)

padded_plaintext = pad(plaintext, AES.block_size)
ciphertext = b""
iv = Random.new().read(AES.block_size)
aes = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = iv + aes.encrypt(padded_plaintext)
# print("Encryption Key (AES KEY): ", aes_key.hex())

# Print encrypted message
print(">>Running Encryption of Plaintext using AES Secret Key...")
print("[Ciphertext]: ", ciphertext.hex())
# generate a new RSA key pair (use a longer key size for real-world use)
key = RSA.generate(2048)

# encrypt the AES key using RSA with OAEP padding
cipher_rsa = PKCS1_OAEP.new(key)
encrypted_aes_key = cipher_rsa.encrypt(aes_key)
print(">>Running Encryption of AES Secret Key using RSA Public Key...")
print("[Encrypted AES Key]: ", encrypted_aes_key.hex())
print("\n")
