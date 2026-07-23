"""
Core image encryption/decryption logic.

Two modes are offered:

1. FILE encryption (recommended, always safe):
   The image file's raw bytes are encrypted with AES-256-GCM. This is a
   perfect, authenticated encryption of the file -- decrypting always
   recovers the exact original image, byte for byte. Output is an
   arbitrary-looking .enc file (not viewable as an image), which is what
   you want for actually protecting a photo.

2. PIXEL (visual) encryption:
   The raw pixel bytes of the image are XORed with an AES-CTR keystream
   derived from the password, and the result is saved as a same-size PNG.
   This produces a genuinely scrambled, noise-like image you can *see* --
   great for demonstrating "encryption" visually in a demo video. It's
   still AES-CTR under the hood (XOR with a cryptographic keystream), so
   it's cryptographically the real thing, not a toy cipher -- but it only
   round-trips correctly if the encrypted PNG is never re-compressed/edited
   before decrypting.
"""

import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image

SALT_SIZE = 16
NONCE_SIZE = 16  # used as CTR initial counter / nonce material


def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    return PBKDF2(password, salt, dkLen=length, count=200_000)


# --------------------------------------------------------------------
# Mode 1: whole-file AES-GCM encryption (exact, lossless, recommended)
# --------------------------------------------------------------------
def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        raw = f.read()

    salt, nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:48], raw[48:]
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_path, "wb") as f:
        f.write(data)


# --------------------------------------------------------------------
# Mode 2: pixel-level visual encryption (produces a viewable "noise" PNG)
# --------------------------------------------------------------------
def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate `length` bytes of AES-CTR keystream."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce[:8])
    return cipher.encrypt(b"\x00" * length)


def encrypt_image_pixels(input_path: str, output_path: str, password: str) -> None:
    img = Image.open(input_path).convert("RGB")
    width, height = img.size
    pixel_bytes = img.tobytes()

    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(8)
    key = _derive_key(password, salt)
    ks = _keystream(key, nonce, len(pixel_bytes))

    scrambled = bytes(a ^ b for a, b in zip(pixel_bytes, ks))
    out_img = Image.frombytes("RGB", (width, height), scrambled)

    # Store salt/nonce/size in a small sidecar file next to the PNG so
    # decryption knows how to regenerate the exact same keystream.
    out_img.save(output_path, format="PNG")
    with open(output_path + ".meta", "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(width.to_bytes(4, "big"))
        f.write(height.to_bytes(4, "big"))


def decrypt_image_pixels(input_path: str, output_path: str, password: str) -> None:
    meta_path = input_path + ".meta"
    if not os.path.exists(meta_path):
        raise FileNotFoundError(
            f"Missing metadata file '{meta_path}'. Pixel-encrypted images need "
            "their .meta sidecar file to be decrypted."
        )
    with open(meta_path, "rb") as f:
        meta = f.read()
    salt, nonce = meta[:16], meta[16:24]
    width = int.from_bytes(meta[24:28], "big")
    height = int.from_bytes(meta[28:32], "big")

    img = Image.open(input_path).convert("RGB")
    pixel_bytes = img.tobytes()

    key = _derive_key(password, salt)
    ks = _keystream(key, nonce, len(pixel_bytes))
    original = bytes(a ^ b for a, b in zip(pixel_bytes, ks))

    out_img = Image.frombytes("RGB", (width, height), original)
    out_img.save(output_path)
