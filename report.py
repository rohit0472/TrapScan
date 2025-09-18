from fpdf import FPDF

def generate_pdf(scan_results, filename="TrapScan_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "TrapScan Report", ln=True, align="C")
    pdf.set_font("Arial", '', 12)
    pdf.ln(5)

    for scan in scan_results:
        pdf.multi_cell(0, 8,
            f"ID: {scan[0]}\nInput: {scan[1]}\nDomain: {scan[2]}\nStatus: {scan[3]}\nSource: {scan[4]}\nDetails: {scan[5]}\nDate: {scan[6]}\n"
        )
        pdf.ln(3)

    pdf.output(filename)
    print(f"PDF report generated: {filename}")
