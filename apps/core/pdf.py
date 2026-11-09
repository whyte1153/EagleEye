"""Minimal text-only PDF writer (no third-party libraries).  Courier 8.5pt, A4."""
from __future__ import annotations

import textwrap


def _pdf_escape(text: str) -> str:
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def text_pdf(lines: list[str], footer: str) -> bytes:
    """Render ``lines`` to a PDF; ``footer`` is printed on every page with the page number."""
    wrapped: list[str] = []
    for line in lines:
        wrapped += textwrap.wrap(line, 96, subsequent_indent="      ", replace_whitespace=False,
                                 drop_whitespace=False, break_long_words=True) or [""]
    per_page = 64
    pages = [wrapped[i:i + per_page] for i in range(0, len(wrapped), per_page)] or [[""]]

    objects: list[bytes] = []  # object number = index + 1
    n_pages = len(pages)
    page_ids = [4 + 2 * i for i in range(n_pages)]
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
    for i, lines in enumerate(pages):
        stream = ["BT", "/F1 8.5 Tf", "11.5 TL", "45 800 Td"]
        for ln in lines:
            stream.append(f"({_pdf_escape(ln)}) '")
        stream.append("ET")
        footer_cmd = f"BT /F1 7 Tf 45 28 Td ({_pdf_escape(footer)} - page {i + 1} of {n_pages}) Tj ET"
        data = ("\n".join(stream) + "\n" + footer_cmd).encode("latin-1")
        content_id = page_ids[i] + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents {content_id} 0 R "
            f"/Resources << /Font << /F1 3 0 R >> >> >>".encode())
        objects.append(b"<< /Length " + str(len(data)).encode() + b" >>\nstream\n" + data + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for num, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{num} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)
