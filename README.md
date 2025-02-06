import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# Function to encrypt
def encrypt():
    key = entry_key.get()
    plaintext = entry_text.get()

    # Ensure the key length is 16 bytes
    key = hashlib.sha256(key.encode()).digest()

    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    cipher_text = base64.b64encode(ciphertext).decode('utf-8')

    entry_encrypted.delete(0, tk.END)
    entry_encrypted.insert(0, f'IV: {iv} | Encrypted: {cipher_text}')

# Function to decrypt
def decrypt():
    key = entry_key.get()
    encrypted = entry_text.get()

    try:
        iv, cipher_text = encrypted.split(' | ')
        iv = base64.b64decode(iv.replace('IV: ', ''))
        cipher_text = base64.b64decode(cipher_text.replace('Encrypted: ', ''))

        # Ensure the key length is 16 bytes
        key = hashlib.sha256(key.encode()).digest()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(cipher_text), AES.block_size).decode('utf-8')

        entry_decrypted.delete(0, tk.END)
        entry_decrypted.insert(0, plaintext)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# Create the GUI window
window = tk.Tk()
window.title("AES Encryption Tool")

# Key input
tk.Label(window, text="Enter Key:").grid(row=0, column=0)
entry_key = tk.Entry(window, width=40)
entry_key.grid(row=0, column=1)

# Plaintext input
tk.Label(window, text="Enter Text:").grid(row=1, column=0)
entry_text = tk.Entry(window, width=40)
entry_text.grid(row=1, column=1)

# Encrypted output
tk.Label(window, text="Encrypted Text:").grid(row=2, column=0)
entry_encrypted = tk.Entry(window, width=40)
entry_encrypted.grid(row=2, column=1)

# Decrypted output
tk.Label(window, text="Decrypted Text:").grid(row=3, column=0)
entry_decrypted = tk.Entry(window, width=40)
entry_decrypted.grid(row=3, column=1)

# Encrypt button
button_encrypt = tk.Button(window, text="Encrypt", command=encrypt)
button_encrypt.grid(row=4, column=0)

# Decrypt button
button_decrypt = tk.Button(window, text="Decrypt", command=decrypt)
button_decrypt.grid(row=4, column=1)

# Run the application
window.mainloop()
