from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import os
from PIL import Image, UnidentifiedImageError
import json
from pyzbar.pyzbar import decode


# --- ECC Key Generation ---
def generate_ecc_keys():
    private_key = ECC.generate(curve="P-256")
    public_key = private_key.public_key()
    return private_key, public_key


# --- Shared Secret Derivation ---
def derive_shared_secret(private_key, public_key):
    shared_secret = private_key.d * public_key.pointQ
    return SHA256.new(int(shared_secret.x).to_bytes(32, byteorder="big")).digest()


# --- AES Encryption ---
def aes_encrypt(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, tag, ciphertext


# --- Image Encryption ---
def create_visual_encrypted_image(input_file_path):
    try:
        with Image.open(input_file_path) as img:
            width, height = img.size
            encrypted_image = Image.new("RGB", (width, height), (255, 0, 0))  # Solid red
            return encrypted_image
    except UnidentifiedImageError:
        return None


# --- QR Code AES Key Extraction ---
def extract_aes_key_from_qr(qr_code_path):
    try:
        qr_image = Image.open(qr_code_path)
        decoded_data = decode(qr_image)
        if not decoded_data:
            raise ValueError("QR code could not be decoded.")
        return base64.b64decode(decoded_data[0].data)
    except Exception:
        raise ValueError("Invalid QR code image file.")


# --- Hybrid Encryption for Text and Doc Files (Line-by-Line) ---
def encrypt_text_or_doc_file(input_file_path, aes_key):
    output_file_path = os.path.splitext(input_file_path)[0] + "_encrypted.txt"
    encrypted_lines = []

    with open(input_file_path, "r") as input_file:
        for line in input_file:
            # Encrypt each line
            nonce, tag, ciphertext = aes_encrypt(line.strip().encode(), aes_key)
            encrypted_line = {
                "nonce": base64.b64encode(nonce).decode(),
                "tag": base64.b64encode(tag).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }
            encrypted_lines.append(encrypted_line)

    # Write the encrypted content to the output file
    with open(output_file_path, "w") as output_file:
        json.dump(encrypted_lines, output_file, indent=4)

    encrypted_file_size = os.path.getsize(output_file_path)
    print(f"Encrypted text/doc file saved at: {output_file_path} (Size: {encrypted_file_size} bytes)")

    return output_file_path, encrypted_file_size


# --- Hybrid Encryption with JSON Output ---
def hybrid_encrypt_file(input_file_path, ecc_private_key, ecc_public_key):
    with open(input_file_path, "rb") as file:
        file_data = file.read()

    aes_key = get_random_bytes(32)
    nonce, tag, encrypted_content = aes_encrypt(file_data, aes_key)

    shared_secret = derive_shared_secret(ecc_private_key, ecc_public_key)
    cipher = AES.new(shared_secret[:16], AES.MODE_GCM)
    encrypted_aes_key, aes_key_tag = cipher.encrypt_and_digest(aes_key)

    file_extension = os.path.splitext(input_file_path)[1]
    output_file_name = os.path.splitext(input_file_path)[0]

    # Get the length of the encrypted file (in bytes)
    encrypted_length = len(encrypted_content)

    # JSON Output
    json_output = {
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "aes_key_tag": base64.b64encode(aes_key_tag).decode(),
        "encrypted_content": base64.b64encode(encrypted_content).decode(),
        "encrypted_length_bytes": encrypted_length,
    }

    json_output_path = output_file_name + "_encrypted.json"
    with open(json_output_path, "w") as json_file:
        json.dump(json_output, json_file, indent=4)
    print(f"Encrypted data saved as JSON: {json_output_path}")

    # For images, generate the visual encrypted version
    if file_extension in [".jpg", ".jpeg", ".png"]:
        encrypted_visual = create_visual_encrypted_image(input_file_path)
        if encrypted_visual:
            image_output_path = output_file_name + "_visual_encrypted.png"
            encrypted_visual.save(image_output_path)
            print(f"Visual encrypted image saved at: {image_output_path}")

    # Additional Output for Text and Document Files
    if file_extension in [".txt", ".doc", ".docx"]:
        text_output_path, encrypted_size = encrypt_text_or_doc_file(input_file_path, aes_key)
        print(f"Text/Doc encrypted file size: {encrypted_size} bytes")

    return json_output_path


# --- Main Program ---
def main():
    ecc_private_key, ecc_public_key = generate_ecc_keys()
    with open("ecc_private_key.pem", "wt") as priv_file:
        priv_file.write(ecc_private_key.export_key(format="PEM"))
    with open("ecc_public_key.pem", "wt") as pub_file:
        pub_file.write(ecc_public_key.export_key(format="PEM"))

    qr_code_path = input("Enter the path to the AES key QR code (or press Enter to skip): ")
    aes_key_from_qr = None
    if qr_code_path.strip():
        try:
            aes_key_from_qr = extract_aes_key_from_qr(qr_code_path)
            print("AES key successfully extracted from QR code.")
        except ValueError as e:
            print(e)

    input_file_path = input("Enter the path to the input file: ")
    hybrid_encrypt_file(input_file_path, ecc_private_key, ecc_public_key)


if __name__ == "__main__":
    main()
