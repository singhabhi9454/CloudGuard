"""
CloudGuard PDF Security Report Generator
Generates clean, standards-compliant PDF/1.4 audit reports using pure Python standard library.
Requires no external C extensions or internet access.
"""
import os
import zlib
from datetime import datetime
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


class PDFBuilder:
    def __init__(self):
        self.objects = []
        self.pages = []
        self.current_stream = []

    def _add_object(self, content: bytes) -> int:
        self.objects.append(content)
        return len(self.objects)

    def escape_text(self, text: str) -> str:
        safe = (
            str(text)
            .replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("\r", " ")
            .replace("\n", " ")
        )
        return safe.encode("latin-1", "replace").decode("latin-1")


def generate_security_pdf(
    scan_id: str,
    score: int,
    total_findings: int,
    risk_summary: Dict[str, int],
    findings: List[Dict[str, Any]],
    account_id: str = "N/A",
    region: str = "ap-south-1",
    output_filename: str = None,
) -> str:
    """
    Generates a professional PDF report from real scan results and returns the absolute file path.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    if not output_filename:
        output_filename = f"CloudGuard_Report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    output_path = os.path.join(REPORTS_DIR, output_filename)

    # Page size: 612 x 792 (Letter)
    width, height = 612, 792

    def escape_str(s: str) -> str:
        s = str(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        return "".join(c if 32 <= ord(c) <= 126 else " " for c in s)

    # Multi-page handling
    items_per_page = 4
    pages_data = []

    # If no findings, single page
    if not findings:
        pages_data = [[]]
    else:
        for i in range(0, len(findings), items_per_page):
            pages_data.append(findings[i : i + items_per_page])

    total_pages = len(pages_data)
    stream_contents = []

    for page_idx, page_findings in enumerate(pages_data):
        page_num = page_idx + 1
        lines = []

        # Background color
        lines.append("0.05 0.08 0.14 rg")  # Dark navy #0d1424
        lines.append(f"0 0 {width} {height} re f")

        # Top Banner
        lines.append("0.08 0.14 0.24 rg")  # #14243d
        lines.append(f"0 {height - 90} {width} 90 re f")

        # Cyan Accent Stripe
        lines.append("0.08 0.51 1.0 rg")  # Cyan #1683ff
        lines.append(f"0 {height - 93} {width} 3 re f")

        # Header Title
        lines.append("BT")
        lines.append("/F2 22 Tf")
        lines.append("1.0 1.0 1.0 rg")
        lines.append(f"40 {height - 45} Td (CLOUDGUARD SECURITY ASSESSMENT) Tj")
        lines.append("ET")

        # Header Subtitle
        lines.append("BT")
        lines.append("/F1 10 Tf")
        lines.append("0.6 0.7 0.85 rg")
        lines.append(
            f"40 {height - 65} Td (Automated Cloud Posture Audit & Misconfiguration Report | AWS Region: {escape_str(region)}) Tj"
        )
        lines.append("ET")

        # Page 1 Executive Summary Box
        if page_num == 1:
            # Metadata Grid Box
            lines.append("0.09 0.15 0.26 rg")
            lines.append(f"40 {height - 180} {width - 80} 70 re f")
            lines.append("0.18 0.28 0.45 RG 1 w")
            lines.append(f"40 {height - 180} {width - 80} 70 re S")

            lines.append("BT")
            lines.append("/F2 10 Tf")
            lines.append("0.8 0.9 1.0 rg")
            lines.append(f"55 {height - 130} Td (AUDIT METRICS) Tj")
            lines.append("/F1 9 Tf")
            lines.append("0.7 0.8 0.9 rg")
            scan_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"55 {height - 148} Td (Scan ID: {escape_str(scan_id)}   |   Date: {scan_time_str}) Tj")
            lines.append(f"55 {height - 165} Td (Account ID: {escape_str(account_id)}   |   Total Scanned Services: EC2, S3, IAM, RDS) Tj")
            lines.append("ET")

            # Score Card Widget
            score_color = "0.12 0.83 0.54" if score >= 80 else ("1.0 0.7 0.2" if score >= 60 else "1.0 0.3 0.3")
            lines.append("0.09 0.15 0.26 rg")
            lines.append(f"40 {height - 275} 140 80 re f")
            lines.append("0.18 0.28 0.45 RG 1 w")
            lines.append(f"40 {height - 275} 140 80 re S")

            lines.append("BT")
            lines.append("/F1 9 Tf")
            lines.append("0.6 0.7 0.85 rg")
            lines.append(f"55 {height - 215} Td (SECURITY SCORE) Tj")
            lines.append(f"/F2 28 Tf {score_color} rg")
            lines.append(f"55 {height - 250} Td ({score}/100) Tj")
            lines.append("/F1 8 Tf 0.7 0.8 0.9 rg")
            score_label = "HEALTHY ENVIRONMENT" if score >= 80 else "ATTENTION REQUIRED"
            lines.append(f"55 {height - 265} Td ({score_label}) Tj")
            lines.append("ET")

            # Risk Summary Widget Boxes
            crit = risk_summary.get("critical", 0)
            high = risk_summary.get("high", 0)
            med = risk_summary.get("medium", 0)
            low = risk_summary.get("low", 0)

            boxes = [
                ("CRITICAL", crit, "1.0 0.25 0.25", 195),
                ("HIGH", high, "1.0 0.45 0.3", 285),
                ("MEDIUM", med, "1.0 0.75 0.2", 375),
                ("LOW", low, "0.2 0.8 0.5", 465),
            ]

            for label, count, color_code, x_pos in boxes:
                lines.append("0.09 0.15 0.26 rg")
                lines.append(f"{x_pos} {height - 275} 80 80 re f")
                lines.append("0.18 0.28 0.45 RG 1 w")
                lines.append(f"{x_pos} {height - 275} 80 80 re S")

                lines.append("BT")
                lines.append(f"/F2 20 Tf {color_code} rg")
                lines.append(f"{x_pos + 12} {height - 235} Td ({count}) Tj")
                lines.append("/F1 8 Tf 0.7 0.8 0.9 rg")
                lines.append(f"{x_pos + 12} {height - 258} Td ({label}) Tj")
                lines.append("ET")

            table_y_start = height - 310
        else:
            table_y_start = height - 120

        # Section Header
        lines.append("BT")
        lines.append("/F2 13 Tf 1.0 1.0 1.0 rg")
        lines.append(f"40 {table_y_start} Td (SECURITY FINDINGS DETAIL (Page {page_num} of {total_pages})) Tj")
        lines.append("ET")

        # Findings items
        current_y = table_y_start - 25
        card_height = 85

        for finding in page_findings:
            f_risk = finding.get("risk", "MEDIUM").upper()
            f_serv = finding.get("service", "AWS")
            f_res = finding.get("resource", "N/A")
            f_issue = finding.get("issue", "Misconfiguration detected")
            f_fix = finding.get("recommendation", "Review security policy")

            # Risk color
            badge_color = "1.0 0.3 0.3" if f_risk in ("CRITICAL", "HIGH") else ("1.0 0.7 0.2" if f_risk == "MEDIUM" else "0.2 0.8 0.5")

            # Card box
            lines.append("0.09 0.14 0.24 rg")
            lines.append(f"40 {current_y - card_height} {width - 80} {card_height} re f")
            lines.append("0.16 0.24 0.38 RG 1 w")
            lines.append(f"40 {current_y - card_height} {width - 80} {card_height} re S")

            # Left color bar
            lines.append(f"{badge_color} rg")
            lines.append(f"40 {current_y - card_height} 5 {card_height} re f")

            # Text content
            lines.append("BT")
            lines.append("/F2 9 Tf")
            lines.append(f"{badge_color} rg")
            lines.append(f"55 {current_y - 18} Td ([{escape_str(f_risk)}] {escape_str(f_serv)} - {escape_str(f_res)}) Tj")

            lines.append("/F2 10 Tf 1.0 1.0 1.0 rg")
            lines.append(f"55 {current_y - 36} Td ({escape_str(f_issue)[:75]}) Tj")

            lines.append("/F1 8 Tf 0.7 0.8 0.95 rg")
            lines.append(f"55 {current_y - 54} Td (Recommended Fix: {escape_str(f_fix)[:85]}) Tj")

            scan_ts = finding.get("scan_time", "")
            lines.append("/F1 7 Tf 0.5 0.6 0.75 rg")
            lines.append(f"55 {current_y - 70} Td (Detected: {escape_str(scan_ts)}) Tj")
            lines.append("ET")

            current_y -= card_height + 15

        if not page_findings and page_num == 1:
            # Clean environment notice
            lines.append("0.09 0.14 0.24 rg")
            lines.append(f"40 {table_y_start - 70} {width - 80} 50 re f")
            lines.append("BT")
            lines.append("/F2 11 Tf 0.2 0.85 0.5 rg")
            lines.append(f"55 {table_y_start - 42} Td (NO SECURITY MISCONFIGURATIONS FOUND) Tj")
            lines.append("/F1 9 Tf 0.7 0.8 0.9 rg")
            lines.append(f"55 {table_y_start - 58} Td (All evaluated rules across EC2, S3, IAM, and RDS passed successfully.) Tj")
            lines.append("ET")

        # Footer
        lines.append("0.15 0.22 0.35 RG 1 w")
        lines.append(f"40 45 {width - 80} 0 re S")

        lines.append("BT")
        lines.append("/F1 8 Tf 0.5 0.6 0.75 rg")
        lines.append(f"40 30 Td (CloudGuard AWS Security Scanner | Confidential Assessment Report) Tj")
        lines.append(f"{width - 130} 30 Td (Page {page_num} of {total_pages}) Tj")
        lines.append("ET")

        stream_contents.append("\n".join(lines).encode("latin-1"))

    # Assemble PDF Document
    pdf_bytes = bytearray()
    pdf_bytes.extend(b"%PDF-1.4\n")

    offsets = []

    def write_obj(content: bytes) -> int:
        offset = len(pdf_bytes)
        offsets.append(offset)
        obj_num = len(offsets)
        pdf_bytes.extend(f"{obj_num} 0 obj\n".encode("ascii"))
        pdf_bytes.extend(content)
        pdf_bytes.extend(b"\nendobj\n")
        return obj_num

    # Fonts
    f1_id = write_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    f2_id = write_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    page_obj_ids = []
    stream_obj_ids = []

    # Write content streams
    for stream_data in stream_contents:
        compressed = zlib.compress(stream_data)
        st_content = (
            f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode("ascii")
            + compressed
            + b"\nendstream"
        )
        s_id = write_obj(st_content)
        stream_obj_ids.append(s_id)

    # Placeholder for Pages obj
    pages_obj_id = len(offsets) + 1 + len(stream_obj_ids)

    # Write Page objects
    for i, s_id in enumerate(stream_obj_ids):
        p_content = (
            f"<< /Type /Page /Parent {pages_obj_id} 0 R "
            f"/MediaBox [0 0 {width} {height}] "
            f"/Contents {s_id} 0 R "
            f"/Resources << /Font << /F1 {f1_id} 0 R /F2 {f2_id} 0 R >> >> >>"
        ).encode("ascii")
        p_id = write_obj(p_content)
        page_obj_ids.append(p_id)

    # Write Pages object
    kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    pages_dict = f"<< /Type /Pages /Count {len(page_obj_ids)} /Kids [{kids_str}] >>".encode("ascii")
    actual_pages_obj_id = write_obj(pages_dict)

    # Catalog object
    catalog_dict = f"<< /Type /Catalog /Pages {actual_pages_obj_id} 0 R >>".encode("ascii")
    catalog_obj_id = write_obj(catalog_dict)

    # XRef table
    xref_offset = len(pdf_bytes)
    pdf_bytes.extend(f"xref\n0 {len(offsets) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets:
        pdf_bytes.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    # Trailer
    trailer_data = (
        f"trailer\n<< /Size {len(offsets) + 1} /Root {catalog_obj_id} 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
    pdf_bytes.extend(trailer_data)

    with open(output_path, "wb") as f:
        f.write(pdf_bytes)

    return output_path
