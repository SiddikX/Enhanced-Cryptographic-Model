import random
import math
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
# Returns the greatest common divisor of two numbers


def gcd(a, b):
    if a == 0:
        return b
    return gcd(b % a, a)

# Returns the modular multiplicative inverse of a number


def modInverse(a, m):
    """
    Compute the modular multiplicative inverse of a modulo m.
    """
    def extendedEuclideanAlgorithm(a, b):
        if b == 0:
            return (a, 1, 0)
        else:
            d, x, y = extendedEuclideanAlgorithm(b, a % b)
            return (d, y, x - y * (a // b))

    d, x, y = extendedEuclideanAlgorithm(a, m)
    if d != 1:
        raise ValueError("No modular multiplicative inverse exists")
    else:
        return x % m

# Step 1: Select two prime numbers p and q


def isPrime(n):
    """
    Primality test.
    Return True if n is prime, False otherwise.
    """
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i*i <= n:
        if n % i == 0 or n % (i+2) == 0:
            return False
        i += 6
    return True


def generateLargePrime(bits):
    """
    Generate a large prime number with the given number of bits.
    """
    while True:
        p = random.getrandbits(bits)
        if isPrime(p):
            return p


# Select two large prime numbers
p = generateLargePrime(32)
q = generateLargePrime(32)

# print("p =", p)
# print("q =", q)


# Step 2: Calculate r = p * q
r = p * q
# print("r=", r)

# Step 3: Calculate Ø(r) = (p-1) * (q-1)
phi = (p-1) * (q-1)
# print("phi=", phi)

# Step 4: Generate a random number PK (encryption key) where GCD(PK, Ø(r)) = 1
pk = 0
while gcd(pk, phi) != 1:
    pk = random.randint(1, phi)  # Generate random number between 1 and Ø(r)
# print("encryption_key pk=", pk)

# Step 5: Compute decryption key SK = PK^(-1) mod Ø(r)
sk = modInverse(pk, phi)


# Step 6: Set PK = g and SK = x for ElGamal algorithm
g = pk
x = sk

# Step 7: Generate a random number pEl where PK < pEl and SK < pEl
pEl = 0
while pEl <= pk or pEl <= sk:
    # Generate random number between 100 and 1000
    pEl = random.randint(10**19, 10**100 - 1)
    # print(pEl, pk, sk)

# Step 8: Calculate public key for ElGamal algorithm (y = PK^SK mod pEl) where GCD(y, Ø(r)) = 1
y = pow(g, x, pEl)
while gcd(y, phi) != 1:
    # generate a new value for pEl and y
    pEl = random.randint(10**19, 10**20 - 1)
    y = pow(g, x, pEl)
# print("ElGamal public key: ", y)

# Recalculate Sk = y-1 mod phi(r)
sk = pow(y, -1, pEl) % phi
# print("AES secret key: ", sk)


# Step 9: Use SK as the AES secret key
aes_key = sk.to_bytes(16, 'big')

# print("AES key: ", aes_key.hex())

# Use SK as the AES secret key
aes_key = sk.to_bytes(16, 'big')
