import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog
from certificate_utils import (
    view_certificate,
    generate_self_signed_certificate
)
from crypto_utils import (
    generate_rsa_keys,
    generate_file_hash,
    encrypt_file,
    decrypt_file,
    sign_file,
    verify_signature
)

def log_output(title, content):
    result_box.delete("1.0", tk.END)

    result_box.insert(
        tk.END,
        f"{'='*50}\n"
    )

    result_box.insert(
        tk.END,
        f"{title}\n"
    )

    result_box.insert(
        tk.END,
        f"{'='*50}\n\n"
    )

    result_box.insert(
        tk.END,
        content
    )

    result_box.insert(
        tk.END,
        "\n\n"
    )

def generate_keys():
    try:
        generate_rsa_keys()

        status.config(
            text="Status: RSA Keys Generated"
        )

        messagebox.showinfo(
            "Success",
            "RSA Key Pair Generated Successfully!"
        )

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )


def hash_file():
    try:
        file_path = filedialog.askopenfilename()

        if not file_path:
            return

        file_hash = generate_file_hash(file_path)

        status.config(
            text="Status: Hash Generated"
        )

        log_output(
    "SHA256 HASH",
    f"File:\n{file_path}\n\nHash:\n{file_hash}"
)

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )

def encrypt_selected_file():
    try:
        file_path = filedialog.askopenfilename()

        if not file_path:
            return

        encrypted_path = encrypt_file(file_path)

        status.config(
            text="Status: File Encrypted"
        )

        log_output(
    "FILE ENCRYPTION",
    f"Input File:\n{file_path}\n\nEncrypted File:\n{encrypted_path}"
)

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )

def decrypt_selected_file():
    try:
        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Files", "*.enc")]
        )

        if not file_path:
            return

        decrypted_path = decrypt_file(file_path)

        status.config(
            text="Status: File Decrypted"
        )

        log_output(
    "FILE DECRYPTION",
    f"Encrypted File:\n{file_path}\n\nOutput File:\n{decrypted_path}"
)

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )

def sign_selected_file():
    try:
        file_path = filedialog.askopenfilename()

        if not file_path:
            return

        signature_path = sign_file(file_path)

        status.config(
            text="Status: File Signed"
        )

        log_output(
    "SIGNATURE VERIFICATION",
    "Result: VALID"
)

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )
def create_certificate():
    try:
        cert_path = generate_self_signed_certificate()

        status.config(
            text="Status: Certificate Generated"
        )

        messagebox.showinfo(
            "Success",
            f"Certificate Created:\n{cert_path}"
        )

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )

def verify_selected_signature():
    try:
        file_path = filedialog.askopenfilename(
            title="Select Original File"
        )

        if not file_path:
            return

        signature_path = filedialog.askopenfilename(
            title="Select Signature File"
        )

        if not signature_path:
            return

        valid = verify_signature(
            file_path,
            signature_path
        )

        if valid:
            messagebox.showinfo(
                "Verification",
                "Signature is VALID"
            )

            status.config(
                text="Status: Signature Valid"
            )

        else:
            messagebox.showwarning(
                "Verification",
                "Signature is INVALID"
            )

            status.config(
                text="Status: Signature Invalid"
            )

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )

def view_selected_certificate():
    try:
        cert_path = filedialog.askopenfilename(
            filetypes=[
                ("Certificate Files", "*.pem *.crt *.cer"),
                ("All Files", "*.*")
            ]
        )

        if not cert_path:
            return

        cert_info = view_certificate(cert_path)

        status.config(
            text="Status: Certificate Loaded"
        )

        messagebox.showinfo(
            "Certificate Information",
            cert_info
        )

    except Exception as e:
        messagebox.showerror(
            "Error",
            str(e)
        )

root = tk.Tk()

root.iconbitmap("assets/logo.ico")
root.title("OpenSSL_GUI_App")
root.geometry("1000x700")
root.configure(bg="#1e1e1e")
root.resizable(False, False)

# ======================
# STYLE
# ======================

style = ttk.Style()
style.theme_use("clam")

style.configure(
    "TButton",
    font=("Segoe UI", 11, "bold"),
    padding=10
)

# ======================
# SIDEBAR
# ======================

sidebar = tk.Frame(
    root,
    bg="#252526",
    width=250
)

sidebar.pack(
    side="left",
    fill="y"
)

# ======================
# CONTENT AREA
# ======================

content = tk.Frame(
    root,
    bg="#1e1e1e"
)

content.pack(
    side="right",
    expand=True,
    fill="both"
)

# ======================
# TITLE
# ======================

title = tk.Label(
    content,
    text="OpenSSL GUI Application",
    font=("Segoe UI", 28, "bold"),
    bg="#1e1e1e",
    fg="#00d4ff"
)

title.pack(pady=20)

# ======================
# RESULTS BOX
# ======================

result_box = tk.Text(
    content,
    height=25,
    width=80,
    bg="#252526",
    fg="white",
    font=("Consolas", 11),
    insertbackground="white"
)

result_box.pack(
    padx=20,
    pady=20
)


# ======================
# BUTTONS
# ======================

ttk.Button(
    sidebar,
    text="Generate RSA Keys",
    command=generate_keys
).pack(fill="x", padx=10, pady=5)

ttk.Button(
    sidebar,
    text="Generate SHA256 Hash",
    command=hash_file
).pack(fill="x", padx=10, pady=5)

ttk.Button(
    sidebar,
    text="Encrypt File",
    command=encrypt_selected_file
).pack(fill="x", padx=10, pady=5)

ttk.Button(
    sidebar,
    text="Decrypt File",
    command=decrypt_selected_file
).pack(fill="x", padx=10, pady=5)

ttk.Button(
    sidebar,
    text="Sign File",
    command=sign_selected_file
).pack(fill="x", padx=10, pady=5)

ttk.Button(
    sidebar,
    text="Verify Signature",
    command=verify_selected_signature
).pack(fill="x", padx=10, pady=5)

ttk.Button(
    sidebar,
    text="Generate Certificate",
    command=create_certificate
).pack(fill="x", padx=10, pady=5)

ttk.Button(
    sidebar,
    text="View Certificate",
    command=view_selected_certificate
).pack(fill="x", padx=10, pady=5)

# ======================
# STATUS BAR
# ======================

status = tk.Label(
    root,
    text="Status: Ready",
    bg="#007acc",
    fg="white",
    anchor="w",
    font=("Segoe UI", 10)
)

status.pack(
    side="bottom",
    fill="x"
)

root.mainloop()