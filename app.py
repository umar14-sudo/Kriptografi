import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from encryption import des_encrypt_decrypt, aes_encrypt_decrypt, xor_encrypt_decrypt, rc4_encrypt_decrypt
from file_utils import read_text_from_file, write_text_to_file, read_binary_from_file, write_binary_to_file
from Crypto.Cipher import DES, AES

# Fungsi enkripsi teks
def encrypt_text(plaintext, key, algorithm):
    """ Mengenkripsi teks dengan algoritma & mode yang dipilih """
    mode = mode_var.get()  # Ambil mode dari dropdown

    if algorithm == "DES":
        mode_type = DES.MODE_ECB if mode == "ECB" else DES.MODE_CBC if mode == "CBC" else DES.MODE_CTR
        return des_encrypt_decrypt(plaintext, key, mode_type, encrypt=True)
    elif algorithm == "AES":
        mode_type = AES.MODE_ECB if mode == "ECB" else AES.MODE_CBC if mode == "CBC" else AES.MODE_CTR
        return aes_encrypt_decrypt(plaintext, key, mode_type, encrypt=True)
    elif algorithm == "XOR":
        return xor_encrypt_decrypt(plaintext, key)
    elif algorithm == "RC4":
        return rc4_encrypt_decrypt(plaintext, key)
    else:
        print("❌ Algoritma tidak didukung!")
        return None

# Fungsi Deskripsi Teks
def decrypt_text(ciphertext, key, algorithm):
    """ Mendekripsi teks dengan algoritma & mode yang dipilih """
    mode = mode_var.get()  # Ambil mode dari dropdown

    if algorithm == "DES":
        mode_type = DES.MODE_ECB if mode == "ECB" else DES.MODE_CBC if mode == "CBC" else DES.MODE_CTR
        return des_encrypt_decrypt(ciphertext, key, mode_type, encrypt=False)
    elif algorithm == "AES":
        mode_type = AES.MODE_ECB if mode == "ECB" else AES.MODE_CBC if mode == "CBC" else AES.MODE_CTR
        return aes_encrypt_decrypt(ciphertext, key, mode_type, encrypt=False)
    elif algorithm == "XOR":
        return xor_encrypt_decrypt(ciphertext, key)
    elif algorithm == "RC4":
        return rc4_encrypt_decrypt(ciphertext, key)
    else:
        print("❌ Algoritma tidak didukung!")
        return None

def process_text(encrypt=True):
    """ Menggabungkan enkripsi & dekripsi untuk teks """
    text = text_input.get("1.0", tk.END).strip()
    key = key_input.get().strip()
    algorithm = algorithm_var.get()

    if not text or not key:
        messagebox.showerror("Error", "Teks dan kunci harus diisi!")
        return

    mode = DES.MODE_CTR if algorithm == "DES" else AES.MODE_CTR

    if encrypt:
        result = encrypt_text(text, key, algorithm)
    else:
        result = decrypt_text(text, key, algorithm)

    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, result)
    action = "dienkripsi" if encrypt else "didekripsi"
    messagebox.showinfo("Sukses", f"Teks berhasil {action}.")

# Fungsi untuk memilih file input
def select_file():
    filename = filedialog.askopenfilename()
    file_input.delete(0, tk.END)
    file_input.insert(0, filename)

# Fungsi untuk memilih file output
def select_output_file():
    filename = filedialog.asksaveasfilename(defaultextension=".enc")
    output_file_input.delete(0, tk.END)
    output_file_input.insert(0, filename)

# Fungsi untuk enkripsi file
def encrypt_file():
    """ Mengenkripsi file berdasarkan algoritma & mode yang dipilih """
    input_filename = file_input.get().strip()
    output_filename = output_file_input.get().strip()
    key = key_input.get().strip()
    algorithm = algorithm_var.get()

    if not input_filename or not output_filename or not key:
        messagebox.showerror("Error", "File input, output, dan kunci harus diisi!")
        return

    text = read_text_from_file(input_filename)
    if text is None:  # Jika gagal, baca sebagai file biner
        text = read_binary_from_file(input_filename)

    if text is None:
        messagebox.showerror("Error", "Gagal membaca file!")
        return

    encrypted = encrypt_text(text, key, algorithm)
    if encrypted:
        if read_text_from_file(input_filename) is not None:
            write_text_to_file(output_filename, encrypted)  # Simpan sebagai teks
        else:
            write_binary_to_file(output_filename, encrypted)  # Simpan sebagai file biner terenkripsi
        messagebox.showinfo("Sukses", f"File berhasil dienkripsi: {output_filename}")

# Fungsi untuk dekripsi file
def decrypt_file():
    """ Mendekripsi file berdasarkan algoritma & mode yang dipilih """
    input_filename = file_input.get().strip()
    output_filename = output_file_input.get().strip()
    key = key_input.get().strip()
    algorithm = algorithm_var.get()

    if not input_filename or not output_filename or not key:
        messagebox.showerror("Error", "File input, output, dan kunci harus diisi!")
        return

    encrypted_data = read_text_from_file(input_filename)
    if encrypted_data is None:  # Jika gagal, baca sebagai file biner
        encrypted_data = read_binary_from_file(input_filename)

    if encrypted_data is None:
        messagebox.showerror("Error", "Gagal membaca file!")
        return

    decrypted = decrypt_text(encrypted_data, key, algorithm)
    if decrypted:
        if read_text_from_file(input_filename) is not None:
            write_text_to_file(output_filename, decrypted)  # Simpan sebagai teks
        else:
            write_binary_to_file(output_filename, decrypted)  # Simpan sebagai file biner hasil dekripsi
        messagebox.showinfo("Sukses", f"File berhasil didekripsi: {output_filename}")

# Warna tema
BG_COLOR = "#f4f4f4"
FONT = ("Arial", 12)

# GUI
root = tk.Tk()
root.title("🔐 Aplikasi Enkripsi & Dekripsi")
root.geometry("600x500")
root.configure(bg=BG_COLOR)

# Style
style = ttk.Style()
style.configure("TButton", font=FONT, padding=5)
style.configure("TLabel", font=FONT, background=BG_COLOR)
style.configure("TEntry", font=FONT, padding=5)

# Frame Utama
main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill="both", expand=True)

# Pilihan Algoritma
ttk.Label(main_frame, text="Pilih Algoritma:").grid(row=0, column=0, sticky="w", pady=5)
algorithm_var = tk.StringVar(value="AES")
algorithm_menu = ttk.Combobox(main_frame, textvariable=algorithm_var, values=["DES", "AES", "XOR", "RC4"], state="readonly")
algorithm_menu.grid(row=0, column=1, sticky="ew", pady=5)

# Pilihan Mode Enkripsi
ttk.Label(main_frame, text="Pilih Mode:").grid(row=1, column=0, sticky="w", pady=5)
mode_var = tk.StringVar(value="ECB")  # Default mode ECB
mode_menu = ttk.Combobox(main_frame, textvariable=mode_var, values=["ECB", "CBC", "CTR"], state="readonly")
mode_menu.grid(row=1, column=1, sticky="ew", pady=5)

# Input Teks
ttk.Label(main_frame, text="Masukkan Teks:").grid(row=2, column=0, sticky="w", pady=5)
text_input = tk.Text(main_frame, height=3, width=50)
text_input.grid(row=2, column=1, sticky="ew", pady=5)

# Tombol Enkripsi & Dekripsi Teks (Digeser ke row=3)
button_frame = ttk.Frame(main_frame)
button_frame.grid(row=3, column=1, pady=10)
ttk.Button(button_frame, text="🔐 Enkripsi Teks", command=lambda: process_text(encrypt=True)).grid(row=0, column=0, padx=5)
ttk.Button(button_frame, text="🔓 Dekripsi Teks", command=lambda: process_text(encrypt=False)).grid(row=0, column=1, padx=5)

# Input Kunci (Digeser ke row=4 agar tidak bertabrakan)
ttk.Label(main_frame, text="Masukkan Kunci:").grid(row=4, column=0, sticky="w", pady=5)
key_input = ttk.Entry(main_frame, width=50)
key_input.grid(row=4, column=1, sticky="ew", pady=5)

# Output Hasil (Digeser ke row=5)
ttk.Label(main_frame, text="Hasil:").grid(row=5, column=0, sticky="w", pady=5)
result_output = tk.Text(main_frame, height=3, width=50)
result_output.grid(row=5, column=1, sticky="ew", pady=5)

# Input File (Digeser ke row=6)
ttk.Label(main_frame, text="File Input:").grid(row=6, column=0, sticky="w", pady=5)
file_input = ttk.Entry(main_frame, width=50)
file_input.grid(row=6, column=1, sticky="ew", pady=5)
ttk.Button(main_frame, text="Pilih File", command=select_file).grid(row=6, column=2, padx=5)

# Output File (Digeser ke row=7)
ttk.Label(main_frame, text="File Output:").grid(row=7, column=0, sticky="w", pady=5)
output_file_input = ttk.Entry(main_frame, width=50)
output_file_input.grid(row=7, column=1, sticky="ew", pady=5)
ttk.Button(main_frame, text="Pilih Lokasi Simpan", command=select_output_file).grid(row=7, column=2, padx=5)

# Tombol Enkripsi & Dekripsi File (Digeser ke row=8)
file_button_frame = ttk.Frame(main_frame)
file_button_frame.grid(row=8, column=1, pady=10)
ttk.Button(file_button_frame, text="🔐 Enkripsi File", command=lambda: encrypt_file()).grid(row=0, column=0, padx=5)
ttk.Button(file_button_frame, text="🔓 Dekripsi File", command=lambda: decrypt_file()).grid(row=0, column=1, padx=5)

# Menjalankan aplikasi
root.mainloop()
