from Crypto.PublicKey import ECC

def generate_ecc_key_pair():
    """
    Generate an ECC public and private key pair and save them to files.
    """
    try:
        # Generate ECC private key
        private_key = ECC.generate(curve="P-256")
        public_key = private_key.public_key()

        # Save private key to file
        with open("ecc_private_key.pem", "wt") as private_file:
            private_file.write(private_key.export_key(format="PEM"))

        # Save public key to file
        with open("ecc_public_key.pem", "wt") as public_file:
            public_file.write(public_key.export_key(format="PEM"))

        print("ECC Key Pair Generated!")
        print("Private key saved as 'ecc_private_key.pem'")
        print("Public key saved as 'ecc_public_key.pem'")
    except Exception as e:
        print(f"Error generating ECC keys: {e}")


if __name__ == "__main__":
    generate_ecc_key_pair()
