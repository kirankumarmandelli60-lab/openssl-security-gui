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
from tkinter import simpledialog

from threat_intel.ioc_utils import analyze_ioc
from threat_intel.risk_scoring import calculate_risk_score
from threat_intel.threat_report import generate_threat_report

from threat_intel.osint_utils import (
    generate_osint_checklist,
    format_osint_checklist
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
def analyze_selected_ioc():
    try:
        ioc = simpledialog.askstring(
            "Threat Intelligence",
            "Enter an IOC\n\n"
            "Examples:\n"
            "IPv4: 8.8.8.8\n"
            "Domain: example.com\n"
            "Email: analyst@example.com\n"
            "Hash: SHA256 value"
        )

        if not ioc:
            return

        ioc_analysis = analyze_ioc(ioc)

        # Analyst evidence window
        evidence_window = tk.Toplevel(root)
        evidence_window.title("Analyst Evidence Assessment")
        evidence_window.geometry("450x500")
        evidence_window.configure(bg="#1e1e1e")
        evidence_window.resizable(False, False)

        tk.Label(
            evidence_window,
            text=f"IOC: {ioc_analysis['normalized']}",
            font=("Segoe UI", 14, "bold"),
            bg="#1e1e1e",
            fg="#00d4ff"
        ).pack(pady=15)

        tk.Label(
            evidence_window,
            text=f"Type: {ioc_analysis['type']}",
            font=("Segoe UI", 11),
            bg="#1e1e1e",
            fg="white"
        ).pack(pady=5)

        tk.Label(
            evidence_window,
            text="Select observed intelligence evidence:",
            font=("Segoe UI", 11, "bold"),
            bg="#1e1e1e",
            fg="white"
        ).pack(pady=15)

        known_malicious = tk.BooleanVar()
        blacklisted = tk.BooleanVar()
        suspicious = tk.BooleanVar()
        darkweb_reference = tk.BooleanVar()
        breach_reference = tk.BooleanVar()

        evidence_frame = tk.Frame(
            evidence_window,
            bg="#1e1e1e"
        )

        evidence_frame.pack(
            padx=40,
            fill="x"
        )

        evidence_options = [
            ("Known malicious", known_malicious),
            ("Blacklist match", blacklisted),
            ("Suspicious behavior", suspicious),
            ("Darkweb reference", darkweb_reference),
            ("Breach reference", breach_reference),
        ]

        for text, variable in evidence_options:
            tk.Checkbutton(
                evidence_frame,
                text=text,
                variable=variable,
                bg="#1e1e1e",
                fg="white",
                selectcolor="#252526",
                activebackground="#1e1e1e",
                activeforeground="white",
                font=("Segoe UI", 11),
                anchor="w"
            ).pack(
                fill="x",
                pady=5
            )

        def generate_assessment():

            indicators = {
                "known_malicious": known_malicious.get(),
                "blacklisted": blacklisted.get(),
                "suspicious": suspicious.get(),
                "darkweb_reference": darkweb_reference.get(),
                "breach_reference": breach_reference.get(),
            }

            risk_analysis = calculate_risk_score(
                ioc_analysis["type"],
                indicators
            )

            osint_checklist = generate_osint_checklist(
                ioc_analysis
            )

            osint_report = format_osint_checklist(
                osint_checklist
            )

            report = generate_threat_report(
                ioc_analysis,
                risk_analysis
            )

            combined_report= report + "\n\n" + osint_report
            log_output(
                "THREAT INTELLIGENCE ANALYSIS",
                combined_report
            )

            status.config(
                text=(
                    f"Status: IOC Analyzed | "
                    f"{ioc_analysis['type']} | "
                    f"{risk_analysis['severity']} | "
                    f"Score: {risk_analysis['score']}/100"
                )
            )

            evidence_window.destroy()

        ttk.Button(
            evidence_window,
            text="Generate Threat Assessment",
            command=generate_assessment
        ).pack(
            pady=25,
            padx=40,
            fill="x"
        )

    except Exception as e:
        messagebox.showerror(
            "Threat Intelligence Error",
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

ttk.Separator(
    sidebar,
    orient="horizontal"
).pack(
    fill="x",
    padx=10,
    pady=10
)

ttk.Button(
    sidebar,
    text="Analyze IOC",
    command=analyze_selected_ioc
).pack(
    fill="x",
    padx=10,
    pady=5
)

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