import string
import random
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1) Generation of public-private key pairs.
# a. Generate an RSA public-private key pair. 𝐾𝐴+ and 𝐾𝐴−.
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
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


def generate_elliptic_curve_diffie_helman_key_pair(key):
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

    write_to_file("_private.pem", pem_private, key)
    write_to_file("_public.pem", pem_public, key)

    return private_key, public_key

# 2. Generation of Symmetric Keys
def generate_symmetric_key(length):

    salt = os.urandom(599)
    key_derivation_func = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=390000,
    )
    key = key_derivation_func.derive(b"secretKey")
    #str = unicode(str, errors='ignore')
    # print("Key length:\n" + str(length) + "\n" + key.decode("utf-8"))

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

    #print("Cipher:" + ciphertext.decode("utf-8"))
    #print("Plain:" + plaintext.decode("utf-8"))
    print("Is plaintext and message same: " + str(plaintext == message))

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
        info=b'handshake data',
    ).derive(shared_key_test)

    print("Are the ECDH keys same: " + str(key_3 == key_3_test))

    return key_3

    
# 3. Generation and Verification of Digital Signature
def generate_digital_signature(private_key, message):
    digest, chosen_hash = hasher_fn(message)

    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )

    print("****************Generator*************")
    print("m: " + message)
    print("H(m): " + str(digest))
    print("Digital Signature: " + str(signature))

    return signature

def verify_digital_signature(public_key, message, signature):
   
    digest, chosen_hash = hasher_fn(message)

    
    ## If the signature does not match, verify() will raise an InvalidSignature exception.
    ## TODO: error check yapip validationi yazdirabiliriz
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )
        print("Successfully Verified")
    except:
        print("\n\n************************************************An exception occurred while verifying***************************************\n\n")

    # print("****************Verifier*************")
    # print("m: " + message)
    # print("H(m): " + str(digest))
    # print("Digital Signature: " + str(signature))
    

# 4. AES Encryption

def encrypt_with_AES(key, mode, data, size):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    
    iv = os.urandom(size)
    cipher = Cipher(algorithms.AES(key), mode(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return ct, cipher

def decrypt_with_AES(ct, cipher):
    decryptor = cipher.decryptor()
    
    return decryptor.update(ct) + decryptor.finalize()

# 5. Message Authentication Codes
def message_auth(key, message):

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(bytes(message, "utf-8"))
    signature = h.finalize()

    return signature

def hasher_fn(message):
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(bytes(message, "utf-8"))
    digest = hasher.finalize()

    return digest, chosen_hash


def write_to_file(fileName, pem, key):
    f = open(key + fileName, "wb")
    f.write(pem)
    f.close()


# 1-a Generation of public-private key pairs.
key_a_private, key_a_public = generate_rsa_key_pair()
# 1-b Generation of ECDH key pairs
key_b_private, key_b_public = generate_elliptic_curve_diffie_helman_key_pair("key_b")
key_c_private, key_c_public = generate_elliptic_curve_diffie_helman_key_pair("key_c")


# 2-a Generation of symmetric keys using SDKF
print("***Key_1***")
key_1 = generate_symmetric_key(16)
key_encrypt_decrypt(key_a_public, key_a_private, key_1)
key_encrypt_decrypt(key_a_public, key_a_private, key_1)
print("***Key_2***")
key_2 = generate_symmetric_key(32)
key_encrypt_decrypt(key_a_public, key_a_private, key_2)
key_encrypt_decrypt(key_a_public, key_a_private, key_2)
# 2-b Generation of symmetric keys using ECDH
key_3 = generate_symmetric_with_ECDH(key_b_private, key_b_public, key_c_private, key_c_public)


# 3 Generation and Verification of Digital Signature
string_1001len = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1001))
#signature = generate_digital_signature(key_a_private, string_1001len)
#verify_digital_signature(key_a_public, string_1001len, signature)


# 5-a Message Authentication Codes
signature1 = message_auth(key_2, string_1001len)
print("Message auth digest: " + str(signature1))
# 5-b Message Authentication Codes
signature2 = message_auth(key_2, str(key_2))
print("Message auth digest: " + str(signature2))


# 4. AES Encryption
f = open("img.PNG", "rb")
data = f.read()

ct, cipher = encrypt_with_AES(key_1, modes.CBC, [], 16)
print(decrypt_with_AES(ct, cipher))
##encrypt_with_AES(key_2, modes.CBC, data, 8)



