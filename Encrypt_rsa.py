from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os


def generate_rsa_keys():
    # Generate an RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Key Escrow
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key


def load_public_key():
    """Loading public key"""
    with open("public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def load_private_key():
    """Loading public key"""
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def encrypt_data_with_rsa(data, public_key):
    """Use RSA to encrypt data"""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_data_with_rsa(encrypted_data, private_key):
    """Use RSA to decrypt data"""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# File encryption
def encrypt_file_rsa(input_file, output_file, public_key):
    aes_key = os.urandom(32)  # 256 bit AES key
    encrypted_aes_key = encrypt_data_with_rsa(aes_key, public_key)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(len(encrypted_aes_key).to_bytes(4, 'big'))
        f_out.write(encrypted_aes_key)
        f_out.write(iv)

        while chunk := f_in.read(8192):
            f_out.write(encryptor.update(chunk))
        f_out.write(encryptor.finalize())

def decrypt_file_rsa(input_file, output_file, private_key):
    with open(input_file, 'rb') as f_in:
        encrypted_key_length = int.from_bytes(f_in.read(4), 'big')
        encrypted_aes_key = f_in.read(encrypted_key_length)
        iv = f_in.read(16)

        aes_key = decrypt_data_with_rsa(encrypted_aes_key, private_key)

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()

        with open(output_file, 'wb') as f_out:
            while chunk := f_in.read(8192):
                f_out.write(decryptor.update(chunk))
            f_out.write(decryptor.finalize())
