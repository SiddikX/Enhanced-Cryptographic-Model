from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from sender import cipher_rsa, encrypted_aes_key, ciphertext

print("+++DECRYPTION+++")

# prompt user to enter the encrypted AES key
encrypted_aes_key = bytes.fromhex(input("Enter the encrypted AES key: "))

# decrypt the AES key using RSA with OAEP padding
decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
print(">>Runnning Decryption of AES Secret Key using RSA Private Key...")
print("[Decrypted AES Key]: ", decrypted_aes_key.hex())

# prompt user to enter the ciphertext
ciphertext = bytes.fromhex(input("Enter the ciphertext: "))

# Decryption using AES
iv = ciphertext[:AES.block_size]
ciphertext = ciphertext[AES.block_size:]
aes2 = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
decryptedtext = unpad(aes2.decrypt(ciphertext), AES.block_size)
print(">>Running Decryption of Ciphertext using AES Secret Key...")

# Print decrypted message
print("[Decrypted Message]: ", decryptedtext.decode())
print("\n")
