from pathlib import Path
from Crypto.PublicKey import RSA


KEY_DIR = Path("keys")
KEY_DIR.mkdir(parents=True, exist_ok=True)

PUBLIC_KEY_PATH = KEY_DIR / "public.pem"
PRIVATE_KEY_PATH = KEY_DIR / "private.pem"


def generate_rsa_keypair(key_size: int = 2048):
    key = RSA.generate(key_size)

    PRIVATE_KEY_PATH.write_bytes(key.export_key())
    PUBLIC_KEY_PATH.write_bytes(key.publickey().export_key())

    print("RSA key pair generated:")
    print(f"Public key : {PUBLIC_KEY_PATH}")
    print(f"Private key: {PRIVATE_KEY_PATH}")


def load_public_key():
    if not PUBLIC_KEY_PATH.is_file():
        raise FileNotFoundError("Public key not found. Run: python main.py genkeys")
    return RSA.import_key(PUBLIC_KEY_PATH.read_bytes())


def load_private_key():
    if not PRIVATE_KEY_PATH.is_file():
        raise FileNotFoundError("Private key not found. Run: python main.py genkeys")
    return RSA.import_key(PRIVATE_KEY_PATH.read_bytes())
