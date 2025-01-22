import os
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

# Function to generate a key
def generate_key():
    return Fernet.generate_key()

# Function to encrypt a file
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_path + '.encrypted', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

# Function to decrypt a file
def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(file_path.replace('.encrypted', ''), 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

# Function to handle file selection and encryption
def select_file_to_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        key = generate_key()
        show_loading("Encrypting...")
        root.after(100, lambda: encrypt_file_and_notify(file_path, key))

def encrypt_file_and_notify(file_path, key):
    encrypt_file(file_path, key)
    hide_loading()
    messagebox.showinfo("Success", f"File encrypted successfully!\nKey: {key.decode()}")

# Function to handle file selection and decryption
def select_file_to_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        key = simpledialog.askstring("Input", "Enter the encryption key:", show='*')
        if key:
            show_loading("Decrypting...")
            root.after(100, lambda: decrypt_file_and_notify(file_path, key))

def decrypt_file_and_notify(file_path, key):
    try:
        decrypt_file(file_path, key.encode())
        hide_loading()
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        hide_loading()
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Function to show loading message
def show_loading(message):
    loading_label.config(text=message)
    loading_frame.pack(pady=10)

# Function to hide loading message
def hide_loading():
    loading_frame.pack_forget()

# Create the main window
root = tk.Tk()
root.title("Cipher Hub")
root.geometry("600x400")
root.configure(bg="#2c3e50")

# Add app name label with shadow effect
app_name_label = tk.Label(root, text="Cipher Hub", font=("Helvetica", 26, "bold"), bg="#2c3e50", fg="#1abc9c")
app_name_label.pack(pady=(10, 5))  # Slightly lower for shadow effect

# Create a frame for better layout
frame = tk.Frame(root, bg="#2c3e50", padx=20, pady=20)
frame.pack(pady=20)

# Add a title label
title_label = tk.Label(frame, text="File Encryptor/Decryptor", font=("Helvetica", 20), bg="#2c3e50", fg="white")
title_label.pack(pady=10)

# Create buttons for encrypting and decrypting files
encrypt_button = tk.Button(frame, text="Encrypt File", command=select_file_to_encrypt, bg="#27ae60", fg="white", font=("Helvetica", 14), width=20, height=2)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(frame, text="Decrypt File", command=select_file_to_decrypt, bg="#c0392b", fg="white", font=("Helvetica", 14), width=20, height=2)
decrypt_button.pack(pady=10)

# Loading label
loading_frame = tk.Frame(frame, bg="#2c3e50")
loading_label = tk.Label(loading_frame, text="", font=("Helvetica", 14), bg="#2c3e50", fg="white")
loading_label.pack()

# Run the application
root.mainloop()
