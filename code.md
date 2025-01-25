# File-Encryption-Decryption-Tool
A file encryption tool using AES and password-based key derivation with a Tkinter GUI for easy encryption and decryption.


import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog, messagebox, Tk, Button, Label, Entry

# Derive a key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# AES Encryption
def encrypt_text(text: str, password: str) -> bytes:
    salt = os.urandom(16)  # Random salt
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Initialization vector for AES
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding text to be a multiple of AES block size (16 bytes)
    pad_length = 16 - (len(text) % 16)
    padded_text = text + chr(pad_length) * pad_length
    
    encrypted = encryptor.update(padded_text.encode()) + encryptor.finalize()
    return salt + iv + encrypted

# AES Decryption
def decrypt_text(encrypted_data: bytes, password: str) -> str:
    salt, iv, encrypted = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    
    # Remove padding
    pad_length = decrypted[-1]
    return decrypted[:-pad_length].decode()

# File Encryption
def encrypt_file(file_path: str, password: str) -> bytes:
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    pad_length = 16 - (len(file_data) % 16)
    padded_file_data = file_data + bytes([pad_length] * pad_length)
    
    encrypted = encryptor.update(padded_file_data) + encryptor.finalize()
    return salt + iv + encrypted

# File Decryption
def decrypt_file(encrypted_data: bytes, password: str) -> bytes:
    salt, iv, encrypted = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    
    # Remove padding
    pad_length = decrypted[-1]
    return decrypted[:-pad_length]

# GUI Functions
def select_file_to_encrypt():
    file_path = filedialog.askopenfilename()
    file_label.config(text=file_path)

def encrypt_file_gui():
    file_path = file_label.cget("text")
    password = password_entry.get()
    
    if file_path and password:
        encrypted_data = encrypt_file(file_path, password)
        with open(file_path + ".enc", 'wb') as f:
            f.write(encrypted_data)
        messagebox.showinfo("Success", "File encrypted successfully.")
    else:
        messagebox.showerror("Error", "Please select a file and enter a password.")

def select_file_to_decrypt():
    file_path = filedialog.askopenfilename()
    file_label.config(text=file_path)

def decrypt_file_gui():
    file_path = file_label.cget("text")
    password = password_entry.get()
    
    if file_path and password:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data, password)
        with open(file_path.replace(".enc", ".dec"), 'wb') as f:
            f.write(decrypted_data)
        
        messagebox.showinfo("Success", "File decrypted successfully.")
    else:
        messagebox.showerror("Error", "Please select a file and enter a password.")

# Set up the GUI
root = Tk()
root.title("File Encryption/Decryption Tool")

# File and Password input
file_label = Label(root, text="No file selected")
file_label.pack()

select_encrypt_button = Button(root, text="Select File to Encrypt", command=select_file_to_encrypt)
select_encrypt_button.pack()

select_decrypt_button = Button(root, text="Select File to Decrypt", command=select_file_to_decrypt)
select_decrypt_button.pack()

password_label = Label(root, text="Enter Password:")
password_label.pack()

password_entry = Entry(root, show="*")
password_entry.pack()

encrypt_button = Button(root, text="Encrypt File", command=encrypt_file_gui)
encrypt_button.pack()

decrypt_button = Button(root, text="Decrypt File", command=decrypt_file_gui)
decrypt_button.pack()

root.mainloop()
