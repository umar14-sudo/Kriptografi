import base64

def read_text_from_file(filename):
    """ Membaca teks dari file """
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return file.read()
    except UnicodeDecodeError:
        print(f"⚠ File {filename} adalah file biner, gunakan `read_binary_from_file`.")
        return None
    except Exception as e:
        print(f"❌ Error membaca file teks: {e}")
        return None

def write_text_to_file(filename, text):
    """ Menyimpan teks ke dalam file """
    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write(text)
        print(f"✅ Teks berhasil disimpan di {filename}")
    except Exception as e:
        print(f"❌ Error menulis file teks: {e}")

def read_binary_from_file(filename):
    """ Membaca data biner dari file dan mengubahnya ke Base64 """
    try:
        with open(filename, "rb") as file:
            return base64.b64encode(file.read()).decode()  # Encode ke Base64 agar bisa dienkripsi
    except Exception as e:
        print(f"❌ Error membaca file biner: {e}")
        return None

def write_binary_to_file(filename, base64_data):
    """ Menyimpan data biner hasil dekripsi kembali ke file """
    try:
        with open(filename, "wb") as file:
            file.write(base64.b64decode(base64_data))  # Decode Base64 ke bentuk biner asli
        print(f"✅ File biner berhasil disimpan: {filename}")
    except Exception as e:
        print(f"❌ Error menulis file biner: {e}")
