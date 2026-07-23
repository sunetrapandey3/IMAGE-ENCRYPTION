# Image Encryption Tool

A desktop app (Python + Tkinter) that secures image files with AES encryption,
protecting visual data from unauthorized access and tampering.

## Setup
```bash
pip install pycryptodome pillow
python3 image_encryption_tool.py
```

## Two modes

### 1. File Encryption (recommended)
Encrypts the image's raw file bytes with **AES-256-GCM** (authenticated —
detects tampering, not just confidentiality). The output is a `.enc` file
that isn't viewable as an image at all. Decrypting recovers the **exact
original file**, byte for byte. This is what you'd actually use to protect
a real photo.

### 2. Pixel (Visual) Encryption
Encrypts the *pixel data itself* using an AES-CTR keystream, so the
encrypted image is a real, viewable PNG that looks like colorful noise —
great for showing "this is what encryption does" in a demo video. It's
still genuine AES under the hood (XOR with a cryptographic keystream), just
applied directly to pixels instead of the file bytes. A small `.meta`
sidecar file is saved alongside it (holds the salt/nonce/dimensions needed
to reverse it) — keep it next to the encrypted PNG.

## How it works
- `image_crypto_core.py` — all the cryptography, independent of the GUI
  (so it's testable on its own).
- `image_encryption_tool.py` — the Tkinter GUI: choose a file, pick a mode,
  set a password, Encrypt/Decrypt, with live before/after previews.

## Demo tips for your submission video
1. Load a photo, pick **Pixel Encryption**, encrypt it — show the image
   turn into visible noise, then decrypt it back to the original.
2. Then show **File Encryption** — point out the `.enc` output can't be
   opened as an image at all, and mention this is the version you'd
   actually use to protect a real file.
3. Try decrypting with the wrong password to show it correctly rejects
   (GCM authentication catches tampering/wrong keys, rather than silently
   producing garbage).
