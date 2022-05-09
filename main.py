import string, random, os, time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as pd
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from nbformat import write

# 1) Generation of public-private key pairs.
# a. Generate an RSA public-private key pair. 𝐾𝐴+ and 𝐾𝐴−.
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    f = open("key_a_private.pem", "wb")
    f.write(pem_private)
    f.close()

    f = open("key_a_public.pem", "wb")
    f.write(pem_public)
    f.close()

    return private_key, public_key

# b. Generate two Elliptic-Curve Diffie Helman public-private key pairs. (𝐾𝐵+, 𝐾𝐵−)
def generate_elliptic_curve_diffie_helman_key_pair(key_name):
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
     
    write_to_file(key_name + "_private.pem", pem_private)
    write_to_file(key_name + "_public.pem", pem_public)

    return private_key, public_key

# 2. Generation of Symmetric Keys
def generate_symmetric_key(length):
    salt = os.urandom(length)
    
    key_derivation_func = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=390000,
    )

    key = key_derivation_func.derive(b"secretKey")
    print("Key length:\n" + str(length) + "\n" + str(key))

    return key


def key_encrypt_decrypt(public_key, private_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Encrypted key:" + str(ciphertext))
    print("Decrypted key:" + str(plaintext))
    print("Are decrypted key and original key same: " + str(plaintext == message))

    return ciphertext, plaintext

# 2-b) symmetric key using Elliptic Curve Diffie Helman using 𝐾𝐶+ and 𝐾𝐵−.
def generate_symmetric_with_ECDH(private_key_1, public_key_1, private_key_2, public_key_2):
    shared_key = private_key_1.exchange(
        ec.ECDH(), public_key_2)

    key_3 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    shared_key_test = private_key_2.exchange(
        ec.ECDH(), public_key_1)
    
    key_3_test = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key_test)


    print("First key:\n" + str(key_3))
    print("Second key:\n" + str(key_3_test))
    print("Are the ECDH keys same: " + str(key_3 == key_3_test))

    return key_3

    
# 3. Generation and Verification of Digital Signature
def generate_digital_signature(private_key, message):
    digest, hash_function = hasher_fn(message)
   
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hash_function)
    )
    
    data = "****************Generator*************" + '\n' 
    data += "m: " + message + '\n'
    data += "H(m): " + str(digest) + '\n'
    data += "Digital Signature: " + str(signature)
    filename = "digital_signiture.txt"
    write_to_file(filename, bytes(data, "utf-8"))

    return signature

def verify_digital_signature(public_key, message, signature):
   
    digest, hash_function = hasher_fn(message)

    # If the signature does not match, verify() will raise an InvalidSignature exception
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hash_function)
        )
        print("Successfully Verified Digital Signature")
    except:
        print("\nAn exception occurred while verifying Digital Signature\n")

    
    data = "****************Verifier*************" + '\n' 
    data += "m: " + message + '\n'
    data += "H(m): " + str(digest) + '\n'
    data += "Verified Digital Signature: " + str(signature)
    filename = "digital_signiture_verified.txt"
    write_to_file(filename, bytes(data, "utf-8"))
    

# 4. AES Encryption
def encrypt_with_AES(key, mode, data, size, file_name):
    padder = pd.PKCS7(len(key)* 8).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    iv_nonce = os.urandom(size)
    cipher = Cipher(algorithms.AES(key), mode(iv_nonce))
    encryptor = cipher.encryptor()

    start = time.time()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    end = time.time()
    print("Elapsed time while encrypting with AES: " + str(end - start) + ' secs')

    write_to_file(file_name, cipher_text)
    return cipher_text, cipher

def decrypt_with_AES(cipher_text, cipher, file_name):
    decryptor = cipher.decryptor()
    
    start = time.time()
    decrypted = decryptor.update(cipher_text) + decryptor.finalize()
    end = time.time()
    print("Elapsed time while decrypting with AES: " + str(end - start) + ' secs')

    write_to_file(file_name, decrypted)
    return decrypted

# 5. Message Authentication Codes
def message_auth(key, message):

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(bytes(message, "utf-8"))
    signature = h.finalize()

    return signature

def hasher_fn(message):
    hash_function = hashes.SHA256()
    hasher = hashes.Hash(hash_function)
    hasher.update(bytes(message, "utf-8"))
    digest = hasher.finalize()

    return digest, hash_function


def write_to_file(fileName, data):
    f = open(fileName, "wb")
    f.write(data)
    f.close()


# 1-a Generation of public-private key pairs.
key_a_private, key_a_public = generate_rsa_key_pair()
# 1-b Generation of ECDH key pairs
key_b_private, key_b_public = generate_elliptic_curve_diffie_helman_key_pair("key_b")
key_c_private, key_c_public = generate_elliptic_curve_diffie_helman_key_pair("key_c")


# 2-a Generation of symmetric keys using SDKF
print('\n\n\n')
print("----------------------2-a-----------------------------------")
print("***Key_1***")
key_1 = generate_symmetric_key(16)
key_encrypt_decrypt(key_a_public, key_a_private, key_1)
print("***Key_2***")
key_2 = generate_symmetric_key(32)
key_encrypt_decrypt(key_a_public, key_a_private, key_2)
# 2-b Generation of symmetric keys using ECDH
print("\n----------------------2-b-----------------------------------")
key_3 = generate_symmetric_with_ECDH(key_b_private, key_b_public, key_c_private, key_c_public)


# 3 Generation and Verification of Digital Signature
print('\n\n\n')
print("----------------------3-----------------------------------")
string_1001len = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1001))
signature = generate_digital_signature(key_a_private, string_1001len)
verify_digital_signature(key_a_public, string_1001len, signature)


# 4. AES Encryption
print('\n\n\n')
print("----------------------4-----------------------------------")

img = "img.jpg"
f = open(img, "rb")
data = f.read()

## 4. i (128 bit key1 in CBC mode) - a-b-c-d
print('\n')
print("----------------------4-i-----------------------------------")

cipher_text, cipher = encrypt_with_AES(key_1, modes.CBC, data, 16, "aes-cbc-128-encrypted.jpg")
cipher_text_2, cipher_2 = encrypt_with_AES(key_1, modes.CBC, data, 16, "aes-cbc-128-encrypted.jpg")
print("For 128 bit key1 in CBC mode, Are ciphertexts same with different IVs: " + str(cipher_text == cipher_text_2))
decrypted_data = decrypt_with_AES(cipher_text, cipher, "aes-cbc-128-decrypted.png")

## 4. ii (256 bit key2 in CBC mode) - a-b-c-d
print('\n')
print("----------------------4-ii-----------------------------------")

cipher_text, cipher = encrypt_with_AES(key_2, modes.CBC, data, 16, "aes-cbc-256-encrypted.jpg")
cipher_text_2, cipher_2 = encrypt_with_AES(key_2, modes.CBC, data, 16, "aes-cbc-256-encrypted.jpg")
print("For 256 bit key2 in CBC mode, Are ciphertexts same with different IVs: " + str(cipher_text == cipher_text_2))
decrypted_data = decrypt_with_AES(cipher_text, cipher, "aes-cbc-256-decrypted.png")

## 4. iii (256 bit key3 in CTR mode) - a-b-c-d
print('\n')
print("----------------------4-iii-----------------------------------")

cipher_text, cipher = encrypt_with_AES(key_3, modes.CTR, data, 16, "aes-ctr-256-encrypted.jpg")
cipher_text_2, cipher_2 = encrypt_with_AES(key_3, modes.CTR, data, 16, "aes-ctr-256-encrypted.jpg")
print("For 256 bit key3 in CTR mode, Are ciphertexts same with different nonces: " + str(cipher_text == cipher_text_2))
decrypted_data = decrypt_with_AES(cipher_text, cipher, "aes-ctr-256-decrypted.png")



# 5-a Message Authentication Codes
print('\n\n\n')
print("----------------------5a-----------------------------------")
signature1 = message_auth(key_2, string_1001len)
print("Message auth code using key2: " + str(signature1))

# 5-b Message Authentication Codes
print("\n----------------------5b-----------------------------------")
signature2 = message_auth(key_2, str(key_2))
print("New key2 with message auth code: " + str(signature2))
