#!/usr/bin/env python3
import sys
import argparse
import os

# Add project path
sys.path.insert(0, "/opt/trapscan")

import db
from detect import analyze, extract_domain_from_url, extract_domain_from_email
from report import generate_pdf

def scan_input(input_value, input_type="url"):
    status, source, details = analyze(input_value, input_type)
    domain = extract_domain_from_url(input_value) if input_type=="url" else extract_domain_from_email(input_value) or "N/A"
    row = db.save_scan(input_value, domain, status, source, details)
    print(f"[{status}] {input_value} - Reason: {details}")
    return row

def scan_file(file_path):
    results = []
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return results
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "@" in line:
                res = scan_input(line, "email")
            else:
                res = scan_input(line, "url")
            results.append(res)
    return results

def main():
    db.init_db()
    parser = argparse.ArgumentParser(prog="trapscan", description="TrapScan CLI - Detect phishing URLs & Emails")
    parser.add_argument("input", nargs='?', help="URL or Email to scan")
    parser.add_argument("-f", "--file", help="File containing URLs or Emails to scan")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF report after scan")
    args = parser.parse_args()

    scan_results = []

    if args.file:
        scan_results = scan_file(args.file)
    elif args.input:
        input_type = "email" if "@" in args.input else "url"
        scan_results.append(scan_input(args.input, input_type))
    else:
        # Interactive menu
        while True:
            print("\n1. Scan URL\n2. Scan Email\n3. Scan File\n4. Exit")
            choice = input("Enter choice: ").strip()
            if choice == "1":
                inp = input("Enter URL: ").strip()
                scan_results.append(scan_input(inp, "url"))
            elif choice == "2":
                inp = input("Enter Email: ").strip()
                scan_results.append(scan_input(inp, "email"))
            elif choice == "3":
                inp = input("Enter file path: ").strip()
                scan_results.extend(scan_file(inp))
            elif choice == "4":
                break
            else:
                print("Invalid choice!")

    if args.pdf and scan_results:
        generate_pdf(scan_results)

if __name__ == "__main__":
    main()
