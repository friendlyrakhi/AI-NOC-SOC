"""Minimal PDF writer for text reports (no dependencies).

Produces PDF 1.4 with the standard Helvetica fonts (no embedding), A4 pages, word-wrapped lines
and simple tables rendered as aligned text. Text is encoded as Latin-1 (other characters become
"?"), and every string is escaped, so report content cannot inject PDF operators.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field

PAGE_W, PAGE_H = 595, 842  # A4 in points
MARGIN = 50
LINE = 13


def _escape(s: str) -> str:
    s = s.encode("latin-1", "replace").decode("latin-1")
    s = "".join(c if c >= " " else " " for c in s)
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


@dataclass
class Document:
    title: str
    landscape: bool = False
    lines: list[tuple[str, int, bool]] = field(default_factory=list)  # (text, size, bold)

    @property
    def size(self) -> tuple[int, int]:
        return (PAGE_H, PAGE_W) if self.landscape else (PAGE_W, PAGE_H)

    def heading(self, text: str) -> None:
        self.lines.append(("", 10, False))
        self.lines.append((text, 13, True))

    def text(self, text: str, size: int = 10, *, bold: bool = False) -> None:
        width = int((self.size[0] - 2 * MARGIN) / (size * 0.5))
        for part in textwrap.wrap(text, width=width) or [""]:
            self.lines.append((part, size, bold))

    def table(self, header: list[str], rows: list[list[str]], widths: list[int]) -> None:
        def fmt(cells: list[str]) -> str:
            return "  ".join(
                (c if len(c) <= w else c[: w - 1] + "~").ljust(w) for c, w in zip(cells, widths, strict=True)
            )

        self.lines.append((fmt(header), 8, True))
        for r in rows:
            self.lines.append((fmt(r), 8, False))

    def render(self) -> bytes:
        page_w, page_h = self.size
        pages: list[list[tuple[str, int, bool, int]]] = [[]]
        y = page_h - MARGIN
        for text, size, bold in [(self.title, 16, True), ("", 10, False), *self.lines]:
            step = int(size * 1.35) if size > 10 else LINE
            if y - step < MARGIN:
                pages.append([])
                y = page_h - MARGIN
            y -= step
            pages[-1].append((text, size, bold, y))

        objects: list[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        catalog = add(b"")  # placeholder, filled below
        pages_obj = add(b"")
        font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        bold_font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        mono = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
        mono_bold = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>")
        kids = []
        total = len(pages)
        for n, page in enumerate(pages, start=1):
            ops = ["BT"]
            for text, size, bold, y in page:
                face = ("F4" if bold else "F3") if size == 8 else ("F2" if bold else "F1")
                ops.append(f"/{face} {size} Tf 1 0 0 1 {MARGIN} {y} Tm ({_escape(text)}) Tj")
            ops.append(f"/F1 8 Tf 1 0 0 1 {MARGIN} 25 Tm ({_escape(f'{self.title} - page {n} of {total}')}) Tj")
            ops.append("ET")
            stream = "\n".join(ops).encode("latin-1")
            content = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
            kids.append(
                add(
                    (
                        f"<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 {page_w} {page_h}] "
                        f"/Resources << /Font << /F1 {font} 0 R /F2 {bold_font} 0 R /F3 {mono} 0 R /F4 {mono_bold} 0 "
                        f"R >> >> "
                        f"/Contents {content} 0 R >>"
                    ).encode()
                )
            )
        objects[catalog - 1] = f"<< /Type /Catalog /Pages {pages_obj} 0 R >>".encode()
        objects[pages_obj - 1] = (
            f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>".encode()
        )
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)
