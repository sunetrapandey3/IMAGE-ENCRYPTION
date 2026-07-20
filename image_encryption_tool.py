"""
Image Encryption Tool
---------------------
Secures image files with AES encryption, protecting visual data from
unauthorized access and tampering.

Two modes:
  - File Encryption  : encrypts the raw file bytes (AES-256-GCM). Exact,
                        lossless, produces a .enc file. Use this to
                        actually protect a photo.
  - Pixel (Visual)    : encrypts the pixel data itself with an AES-CTR
                        keystream and saves a scrambled/noisy PNG you can
                        see -- good for demonstrating encryption visually.

Run with:  python3 image_encryption_tool.py
Requires:  pip install pycryptodome pillow
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk

from image_crypto_core import (
    encrypt_file, decrypt_file,
    encrypt_image_pixels, decrypt_image_pixels,
)

PREVIEW_SIZE = (260, 260)


class ImageEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption Tool  |  Secure your images with AES")
        self.root.geometry("760x620")
        self.root.minsize(700, 580)

        self.input_path = None
        self.output_path = None
        self._preview_refs = []  # keep PhotoImage refs alive

        self._build_ui()

    # ------------------------------------------------------------------
    def _build_ui(self):
        title = tk.Label(self.root, text="🖼️ Image Encryption Tool", font=("Helvetica", 18, "bold"))
        title.pack(pady=(14, 2))
        tk.Label(
            self.root, text="Protect image files from unauthorized access and tampering",
            font=("Helvetica", 10), fg="#555"
        ).pack(pady=(0, 10))

        # --- Mode selector ---
        mode_frame = tk.Frame(self.root)
        mode_frame.pack(fill="x", padx=14, pady=4)
        tk.Label(mode_frame, text="Mode:", font=("Helvetica", 11, "bold")).pack(side="left")
        self.mode_var = tk.StringVar(value="File Encryption (exact, recommended)")
        mode_menu = ttk.Combobox(
            mode_frame, textvariable=self.mode_var, state="readonly", width=42,
            values=[
                "File Encryption (exact, recommended)",
                "Pixel Encryption (visual scramble, for demos)",
            ],
        )
        mode_menu.pack(side="left", padx=10)

        # --- File selector ---
        file_frame = tk.Frame(self.root)
        file_frame.pack(fill="x", padx=14, pady=4)
        tk.Button(file_frame, text="📂 Choose Image / File...", command=self.choose_file).pack(side="left")
        self.file_label = tk.Label(file_frame, text="No file selected", fg="#555")
        self.file_label.pack(side="left", padx=10)

        # --- Password ---
        pw_frame = tk.Frame(self.root)
        pw_frame.pack(fill="x", padx=14, pady=4)
        tk.Label(pw_frame, text="Password:", font=("Helvetica", 10)).pack(side="left")
        self.password_var = tk.StringVar()
        entry = tk.Entry(pw_frame, textvariable=self.password_var, show="•", width=30)
        entry.pack(side="left", padx=8)
        self.show_pw_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            pw_frame, text="show", variable=self.show_pw_var,
            command=lambda: entry.config(show="" if self.show_pw_var.get() else "•")
        ).pack(side="left")

        # --- Action buttons ---
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=8)
        tk.Button(
            btn_frame, text="🔒 Encrypt", width=14, bg="#2e7d32", fg="white",
            font=("Helvetica", 10, "bold"), command=self.encrypt
        ).pack(side="left", padx=6)
        tk.Button(
            btn_frame, text="🔓 Decrypt", width=14, bg="#1565c0", fg="white",
            font=("Helvetica", 10, "bold"), command=self.decrypt
        ).pack(side="left", padx=6)
        tk.Button(btn_frame, text="🗑 Reset", width=14, command=self.reset).pack(side="left", padx=6)

        # --- Preview panels ---
        preview_frame = tk.Frame(self.root)
        preview_frame.pack(fill="both", expand=True, padx=14, pady=10)

        left_col = tk.Frame(preview_frame)
        left_col.pack(side="left", expand=True, fill="both", padx=6)
        tk.Label(left_col, text="Input", font=("Helvetica", 10, "bold")).pack()
        self.input_canvas = tk.Label(left_col, bg="#eeeeee", width=PREVIEW_SIZE[0], height=PREVIEW_SIZE[1])
        self.input_canvas.pack(pady=4)

        right_col = tk.Frame(preview_frame)
        right_col.pack(side="left", expand=True, fill="both", padx=6)
        tk.Label(right_col, text="Result", font=("Helvetica", 10, "bold")).pack()
        self.output_canvas = tk.Label(right_col, bg="#eeeeee", width=PREVIEW_SIZE[0], height=PREVIEW_SIZE[1])
        self.output_canvas.pack(pady=4)

        # --- Status bar ---
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(
            self.root, textvariable=self.status_var, anchor="w",
            font=("Helvetica", 9), fg="#666", bd=1, relief="sunken"
        ).pack(fill="x", side="bottom")

    # ------------------------------------------------------------------
    def _show_preview(self, canvas_label, path):
        try:
            img = Image.open(path).convert("RGB")
            img.thumbnail(PREVIEW_SIZE)
            photo = ImageTk.PhotoImage(img)
            self._preview_refs.append(photo)  # prevent garbage collection
            canvas_label.config(image=photo, text="")
        except Exception:
            canvas_label.config(image="", text="(not a viewable image)")

    def choose_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Images / encrypted files", "*.png *.jpg *.jpeg *.bmp *.enc"), ("All files", "*.*")]
        )
        if path:
            self.input_path = path
            self.file_label.config(text=os.path.basename(path))
            self._show_preview(self.input_canvas, path)
            self.output_canvas.config(image="", text="")
            self.status_var.set(f"Loaded: {path}")

    def reset(self):
        self.input_path = None
        self.output_path = None
        self.file_label.config(text="No file selected")
        self.input_canvas.config(image="", text="")
        self.output_canvas.config(image="", text="")
        self.password_var.set("")
        self.status_var.set("Ready.")

    # ------------------------------------------------------------------
    def _require_ready(self):
        if not self.input_path:
            messagebox.showwarning("No file", "Choose a file first.")
            return False
        if not self.password_var.get():
            messagebox.showwarning("No password", "Enter a password first.")
            return False
        return True

    def encrypt(self):
        if not self._require_ready():
            return
        pw = self.password_var.get()
        mode = self.mode_var.get()
        try:
            if mode.startswith("File"):
                out_path = filedialog.asksaveasfilename(
                    defaultextension=".enc",
                    initialfile=os.path.splitext(os.path.basename(self.input_path))[0] + ".enc",
                )
                if not out_path:
                    return
                encrypt_file(self.input_path, out_path, pw)
                self.output_canvas.config(image="", text="(encrypted .enc file\nnot viewable as image)")
            else:
                out_path = filedialog.asksaveasfilename(
                    defaultextension=".png",
                    initialfile=os.path.splitext(os.path.basename(self.input_path))[0] + "_encrypted.png",
                )
                if not out_path:
                    return
                encrypt_image_pixels(self.input_path, out_path, pw)
                self._show_preview(self.output_canvas, out_path)

            self.output_path = out_path
            self.status_var.set(f"Encrypted -> {out_path}")
            messagebox.showinfo("Done", f"Encrypted file saved:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Encryption failed", str(e))
            self.status_var.set("Encryption failed.")

    def decrypt(self):
        if not self._require_ready():
            return
        pw = self.password_var.get()
        mode = self.mode_var.get()
        try:
            if mode.startswith("File"):
                out_path = filedialog.asksaveasfilename(
                    defaultextension=".png",
                    initialfile="decrypted_output.png",
                )
                if not out_path:
                    return
                decrypt_file(self.input_path, out_path, pw)
            else:
                out_path = filedialog.asksaveasfilename(
                    defaultextension=".png",
                    initialfile="decrypted_output.png",
                )
                if not out_path:
                    return
                decrypt_image_pixels(self.input_path, out_path, pw)

            self._show_preview(self.output_canvas, out_path)
            self.output_path = out_path
            self.status_var.set(f"Decrypted -> {out_path}")
            messagebox.showinfo("Done", f"Decrypted file saved:\n{out_path}")
        except Exception as e:
            messagebox.showerror(
                "Decryption failed",
                "Could not decrypt. Check the password and mode match how it "
                "was encrypted.\n\nDetails: " + str(e)
            )
            self.status_var.set("Decryption failed.")


def main():
    root = tk.Tk()
    app = ImageEncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
