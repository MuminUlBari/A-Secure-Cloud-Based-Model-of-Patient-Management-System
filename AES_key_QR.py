import qrcode
from Crypto.Random import get_random_bytes
import base64

def generate_aes_key():
    """Generate a random 256-bit AES key."""
    aes_key = get_random_bytes(32)  # 256-bit AES key
    return aes_key

def generate_qr_code(aes_key, output_file="aes_key_qr.png"):
    """Generate a QR code containing the AES key."""
    # Convert AES key to Base64 format
    aes_key_base64 = base64.b64encode(aes_key).decode()

    # Generate QR Code
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(aes_key_base64)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Save QR Code image
    img.save(output_file)
    print(f"QR code saved as {output_file}")
    return aes_key_base64

if __name__ == "__main__":
    # Generate AES key
    aes_key = generate_aes_key()

    # Generate QR code for the AES key
    print("Generating AES public key QR code...")
    aes_key_base64 = generate_qr_code(aes_key)

    # Display the AES key in Base64 format for reference
    print(f"AES Key (Base64): {aes_key_base64}")
