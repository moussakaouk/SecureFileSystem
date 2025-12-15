from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from pathlib import Path
import json

from key_manager import load_public_key, load_private_key

SECURE_DIR = Path("secure_storage")
SECURE_DIR.mkdir(parents=True, exist_ok=True)


def hybrid_encrypt_file(input_path: str, target_dir: Path | None = None):
    if target_dir is None:
        target_dir = SECURE_DIR

    path = Path(input_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    data = path.read_bytes()
    aes_key = get_random_bytes(32)

    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(data)
    nonce = aes_cipher.nonce

    public_key = load_public_key()
    rsa_cipher = PKCS1_OAEP.new(public_key)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    target_dir.mkdir(parents=True, exist_ok=True)
    enc_file_path = target_dir / (path.name + ".enc")
    meta_file_path = target_dir / (path.name + ".meta")

    enc_file_path.write_bytes(ciphertext)
    meta = {
        "enc_aes_key": enc_aes_key.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "original_name": path.name,
    }
    meta_file_path.write_text(json.dumps(meta, indent=2))

    print(f"[+] Encrypted: {path} -> {enc_file_path}")


def hybrid_encrypt_folder(folder_path: str):
    folder = Path(folder_path)
    if not folder.is_dir():
        raise NotADirectoryError(f"Not a folder: {folder}")

    target_dir = SECURE_DIR / folder.name
    target_dir.mkdir(parents=True, exist_ok=True)

    for item in folder.rglob("*"):
        if item.is_file():
            print(f"\n[+] Encrypting: {item}")
            hybrid_encrypt_file(str(item), target_dir)


def hybrid_decrypt_file(
    base_name: str,
    folder_name: str = "",
    output_dir: str | Path = "decrypted_files",
):
    if isinstance(output_dir, str):
        output_dir = Path(output_dir)

    search_dir = SECURE_DIR / folder_name if folder_name else SECURE_DIR

    enc_file_path = search_dir / (base_name + ".enc")
    meta_file_path = search_dir / (base_name + ".meta")

    if not enc_file_path.is_file() or not meta_file_path.is_file():
        raise FileNotFoundError(f"Missing files for {base_name}")

    ciphertext = enc_file_path.read_bytes()
    meta = json.loads(meta_file_path.read_text())

    enc_aes_key = bytes.fromhex(meta["enc_aes_key"])
    nonce = bytes.fromhex(meta["nonce"])
    tag = bytes.fromhex(meta["tag"])
    original_name = meta.get("original_name", base_name)

    private_key = load_private_key()
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / original_name
    out_path.write_bytes(plaintext)

    print(f"[+] Decrypted: {base_name} -> {out_path}")


def hybrid_decrypt_folder(folder_name: str, output_root: str | Path = "decrypted_files"):
    folder_path = SECURE_DIR / folder_name
    if not folder_path.is_dir():
        raise NotADirectoryError(f"Encrypted folder not found: {folder_path}")

    if isinstance(output_root, str):
        output_root = Path(output_root)

    out_dir = output_root / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)

    for meta_file in folder_path.glob("*.meta"):
        base_name = meta_file.stem
        hybrid_decrypt_file(base_name, folder_name, out_dir)


def hybrid_decrypt_all(output_root: str | Path = "decrypted_files"):
    if isinstance(output_root, str):
        output_root = Path(output_root)

    output_root.mkdir(parents=True, exist_ok=True)

    # decrypt single-file encryptions (meta directly in SECURE_DIR)
    for meta_file in SECURE_DIR.glob("*.meta"):
        base_name = meta_file.stem
        hybrid_decrypt_file(base_name, "", output_root)

    # decrypt folder-based encryptions
    for sub in SECURE_DIR.iterdir():
        if sub.is_dir():
            hybrid_decrypt_folder(sub.name, output_root)

