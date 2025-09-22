#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import db
from detect import analyze, extract_domain_from_url, extract_domain_from_email
from report import generate_pdf


# --- Helper for colors ---
def get_color(status):
    if status == "Malicious":
        return "red"
    elif status == "Suspicious":
        return "orange"
    else:
        return "green"


# --- Scan Functions ---
def scan_url():
    url = url_entry.get().strip()
    if url:
        status, source, details = analyze(url, "url")
        domain = extract_domain_from_url(url)
        row = db.save_scan(url, domain, status, source, details)
        result_text.insert(tk.END, f"[{status}] {url}\nReason: {details}\n\n", status)
        result_text.tag_config(status, foreground=get_color(status))
        messagebox.showinfo("Scan Result", f"[{status}] {url}\nReason: {details}")
    else:
        messagebox.showwarning("Input Error", "Please enter a URL")


def scan_email():
    email = email_entry.get().strip()
    if email:
        status, source, details = analyze(email, "email")
        domain = extract_domain_from_email(email) or "N/A"
        row = db.save_scan(email, domain, status, source, details)
        result_text.insert(tk.END, f"[{status}] {email}\nReason: {details}\n\n", status)
        result_text.tag_config(status, foreground=get_color(status))
        messagebox.showinfo("Scan Result", f"[{status}] {email}\nReason: {details}")
    else:
        messagebox.showwarning("Input Error", "Please enter an Email")


def scan_file():
    file_path = filedialog.askopenfilename(title="Select File", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                input_type = "email" if "@" in line else "url"
                status, source, details = analyze(line, input_type)
                domain = extract_domain_from_email(line) if input_type == "email" else extract_domain_from_url(line)
                row = db.save_scan(line, domain, status, source, details)
                result_text.insert(tk.END, f"[{status}] {line}\nReason: {details}\n\n", status)
                result_text.tag_config(status, foreground=get_color(status))
        messagebox.showinfo("File Scan Completed", "All entries have been scanned.")


def export_pdf():
    results = db.fetch_history()
    if results:
        generate_pdf(results)
        messagebox.showinfo("PDF Generated", "Report saved as TrapScan_report.pdf")
    else:
        messagebox.showwarning("No Data", "No scan history found to export.")


def show_history():
    history_window = tk.Toplevel(root)
    history_window.title("Scan History - TrapScan")
    history_window.geometry("800x400")

    tree = ttk.Treeview(history_window, columns=("ID", "Input", "Domain", "Status", "Source", "Details", "Date"),
                        show="headings")
    tree.pack(fill="both", expand=True)

    for col in ("ID", "Input", "Domain", "Status", "Source", "Details", "Date"):
        tree.heading(col, text=col)
        tree.column(col, width=100, anchor="center")

    rows = db.fetch_history()
    for row in rows:
        tree.insert("", tk.END, values=row)


# --- GUI Layout ---
root = tk.Tk()
root.title("TrapScan - Phishing Detection Tool")
root.geometry("750x550")
root.configure(bg="#1e1e2e")

# Title
title_label = tk.Label(root, text="TrapScan - Phishing Detection Tool",
                       font=("Arial", 18, "bold"), fg="white", bg="#1e1e2e")
title_label.pack(pady=10)

# URL Section
tk.Label(root, text="Enter URL:", bg="#1e1e2e", fg="white").pack()
url_entry = tk.Entry(root, width=60)
url_entry.pack(pady=5)
tk.Button(root, text="Scan URL", command=scan_url, bg="#2ecc71", fg="white").pack(pady=5)

# Email Section
tk.Label(root, text="Enter Email:", bg="#1e1e2e", fg="white").pack()
email_entry = tk.Entry(root, width=60)
email_entry.pack(pady=5)
tk.Button(root, text="Scan Email", command=scan_email, bg="#3498db", fg="white").pack(pady=5)

# File Upload
tk.Button(root, text="Scan File", command=scan_file, bg="#9b59b6", fg="white").pack(pady=10)

# Results Box
tk.Label(root, text="Scan Results:", bg="#1e1e2e", fg="white").pack()
result_text = tk.Text(root, height=12, width=90, bg="#2c2c3e", fg="white")
result_text.pack(pady=5)

# Bottom Buttons
frame = tk.Frame(root, bg="#1e1e2e")
frame.pack(pady=10)

tk.Button(frame, text="View History", command=show_history, bg="#f39c12", fg="white").grid(row=0, column=0, padx=5)
tk.Button(frame, text="Export PDF", command=export_pdf, bg="#e74c3c", fg="white").grid(row=0, column=1, padx=5)
tk.Button(frame, text="Exit", command=root.quit, bg="#95a5a6", fg="black").grid(row=0, column=2, padx=5)

root.mainloop()
