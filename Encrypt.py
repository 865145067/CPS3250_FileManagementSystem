import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PASSWORD_STORE = "passwords.txt"


def save_password(file_name, password):
    """
    Save the file encryption password to the password storage file
    :param file_name:
    :param password:
    """
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open(PASSWORD_STORE, "a") as f:
        f.write(f"{file_name}:{hashed_password}\n")


def verify_password(file_name, password):
    """

    :param file_name:
    :param password:
    :return:
    """
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if not os.path.exists(PASSWORD_STORE):
        return False

    with open(PASSWORD_STORE, "r") as f:
        for line in f:
            stored_file, stored_hash = line.strip().split(":")
            if stored_file == file_name and stored_hash == hashed_password:
                return True
    return False


def encrypt_file(input_file, output_file, password):
    """
    :param input_file:
    :param output_file:
    :param password:
    """
    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    try:
        with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
            f_out.write(iv)
            while chunk := f_in.read(8192):
                f_out.write(encryptor.update(chunk))
            f_out.write(encryptor.finalize())

        # Save password
        save_password(os.path.basename(output_file), password)
    except Exception as e:
        raise ValueError(f"failed：{str(e)}")


def decrypt_file(input_file, output_file, password):
    """
    :param input_file:
    :param output_file:
    :param password:
    """
    if not verify_password(os.path.basename(input_file), password):
        raise ValueError("wrong password")

    key = hashlib.sha256(password.encode()).digest()  # Generate a 256-bit AES key from the password

    try:
        with open(input_file, "rb") as f_in:
            iv = f_in.read(16)  # Read the initialization vector (IV) from the file header

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            with open(output_file, "wb") as f_out:
                while chunk := f_in.read(8192):
                    f_out.write(decryptor.update(chunk))
                f_out.write(decryptor.finalize())
    except Exception as e:
        raise ValueError(f"decryption failure：{str(e)}")


def lock_file(file_path, password):
    """
Lock the file (delete the original file after encryption)

    :param file_path:
    :param password:
    """
    encrypted_file = f"{file_path}.lock"
    encrypt_file(file_path, encrypted_file, password)
    os.remove(file_path)
    print(f"The file is locked and the original file is deleted")


def unlock_file(file_path, password):
    """
    Unlock files (delete encrypted files after decryption)
param file_path: indicates the path of the encrypted file to be decrypted
:param password: specifies the password provided by the user

    """
    if not file_path.endswith(".lock"):
        print("Error: The file is not an encrypted lock file.")
        return

    original_file = file_path.replace(".lock", "")
    decrypt_file(file_path, original_file, password)
    os.remove(file_path)
    print(f"Files are unlocked and encrypted files are deleted：{file_path}")
