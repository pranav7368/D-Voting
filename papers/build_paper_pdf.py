"""Build a preview PDF of D-Voting-Research-Paper.md.

A preview only: the venue's own template (LaTeX or Word) is used for submission.
Handles the Markdown the paper uses: headings, paragraphs, bold/italic/code,
tables, bullet and numbered lists, fenced and indented code blocks. Stops at the
"Submission checklist" section, which is a note to the authors.

Uses Times New Roman from the system when available, because the built-in PDF
Times lacks Greek letters, subscripts and mathematical symbols the paper uses.
"""

from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

root = Path(__file__).parent
src = root / "D-Voting-Research-Paper.md"
out = root / "D-Voting-Research-Paper.pdf"

# --- fonts --------------------------------------------------------------------
REGULAR, BOLD, ITALIC = "Times-Roman", "Times-Bold", "Times-Italic"
fonts = Path("C:/Windows/Fonts")
candidates = {"TNR": "times.ttf", "TNR-Bold": "timesbd.ttf", "TNR-Italic": "timesi.ttf", "TNR-BoldItalic": "timesbi.ttf"}
if all((fonts / f).exists() for f in candidates.values()):
    for name, file in candidates.items():
        pdfmetrics.registerFont(TTFont(name, str(fonts / file)))
    pdfmetrics.registerFontFamily("TNR", normal="TNR", bold="TNR-Bold", italic="TNR-Italic", boldItalic="TNR-BoldItalic")
    REGULAR, BOLD, ITALIC = "TNR", "TNR-Bold", "TNR-Italic"
MONO = "Courier"
if (fonts / "consola.ttf").exists():
    pdfmetrics.registerFont(TTFont("Consolas", str(fonts / "consola.ttf")))
    MONO = "Consolas"

ss = getSampleStyleSheet()
ink, accent = HexColor("#16304E"), HexColor("#1E4668")
ss.add(ParagraphStyle(name="TitleX", parent=ss["Title"], fontName=BOLD, fontSize=17, leading=21, alignment=TA_CENTER, textColor=ink, spaceAfter=10))
ss.add(ParagraphStyle(name="AuthorX", parent=ss["Normal"], fontName=REGULAR, fontSize=10, leading=13, alignment=TA_CENTER, spaceAfter=2))
ss.add(ParagraphStyle(name="H1X", parent=ss["Heading1"], fontName=BOLD, fontSize=13, leading=16, textColor=ink, spaceBefore=10, spaceAfter=5, keepWithNext=True))
ss.add(ParagraphStyle(name="H2X", parent=ss["Heading2"], fontName=BOLD, fontSize=11, leading=14, textColor=accent, spaceBefore=7, spaceAfter=3, keepWithNext=True))
ss.add(ParagraphStyle(name="BodyX", parent=ss["BodyText"], fontName=REGULAR, fontSize=10.2, leading=13.2, alignment=TA_JUSTIFY, spaceAfter=6))
ss.add(ParagraphStyle(name="ListX", parent=ss["BodyX"], leftIndent=6 * mm, firstLineIndent=-4 * mm, spaceAfter=3))
ss.add(ParagraphStyle(name="AbstractX", parent=ss["BodyX"], fontSize=9.8, leading=12.8, leftIndent=8 * mm, rightIndent=8 * mm))
ss.add(ParagraphStyle(name="SmallX", parent=ss["BodyText"], fontName=REGULAR, fontSize=8.4, leading=10.2, spaceAfter=1))
ss.add(ParagraphStyle(name="CodeX", parent=ss["Code"], fontName=MONO, fontSize=7.8, leading=9.6, leftIndent=4 * mm, backColor=HexColor("#F3F6FA"), borderPadding=4, spaceBefore=3, spaceAfter=7))


def fmt(s: str) -> str:
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"&lt;sup&gt;(.+?)&lt;/sup&gt;", r"<super>\1</super>", s)
    s = re.sub(r"`(.+?)`", lambda m: f'<font name="{MONO}">{m.group(1)}</font>', s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<i>\1</i>", s)
    return s


def footer(c, doc):
    c.saveState()
    c.setFont(REGULAR, 8)
    c.setFillColor(HexColor("#58636E"))
    c.drawString(20 * mm, 12 * mm, "D-Voting: preview build")
    c.drawRightString(190 * mm, 12 * mm, f"Page {doc.page}")
    c.restoreState()


lines = src.read_text(encoding="utf-8").splitlines()
story, i, first, in_abstract = [], 0, True, False
block_start = ("#", "|", "- ", "```", "    ")
numbered = re.compile(r"^\d+\.\s")

while i < len(lines):
    raw = lines[i]
    line = raw.strip()
    if line.startswith("## Submission checklist"):
        break
    if not line:
        i += 1
        continue
    if first and line.startswith("# "):
        story.append(Paragraph(fmt(line[2:]), ss["TitleX"]))
        first = False
        i += 1
        continue
    if line.startswith("**Pranav Kumar Singh**"):
        while i < len(lines) and lines[i].strip() and not lines[i].startswith("## "):
            story.append(Paragraph(fmt(lines[i].strip().rstrip()), ss["AuthorX"]))
            i += 1
        story.append(Spacer(1, 8))
        continue
    if line.startswith("## "):
        in_abstract = line[3:].strip().lower() == "abstract"
        story.append(Paragraph(fmt(line[3:]), ss["H1X"]))
        i += 1
        continue
    if line.startswith("### "):
        story.append(Paragraph(fmt(line[4:]), ss["H2X"]))
        i += 1
        continue
    if line.startswith("```"):
        i += 1
        code = []
        while i < len(lines) and not lines[i].strip().startswith("```"):
            code.append(lines[i])
            i += 1
        i += 1
        story.append(Preformatted("\n".join(code), ss["CodeX"]))
        continue
    if raw.startswith("    "):
        code = []
        while i < len(lines) and (lines[i].startswith("    ") or not lines[i].strip()):
            code.append(lines[i][4:])
            i += 1
        story.append(Preformatted("\n".join(code).rstrip(), ss["CodeX"]))
        continue
    if line.startswith("|"):
        rows = []
        while i < len(lines) and lines[i].strip().startswith("|"):
            cells = [x.strip() for x in lines[i].strip().strip("|").split("|")]
            if not all(set(x) <= set("-: ") for x in cells):
                rows.append([Paragraph(fmt(x), ss["SmallX"]) for x in cells])
            i += 1
        if rows:
            t = Table(rows, repeatRows=1, hAlign="CENTER")
            t.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B5C0CB")),
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#E8EEF5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.extend([Spacer(1, 3), t, Spacer(1, 6)])
        continue
    if line.startswith("- ") or numbered.match(line):
        marker = "•" if line.startswith("- ") else numbered.match(line).group(0).strip()
        text = [line[2:] if line.startswith("- ") else line[len(numbered.match(line).group(0)):]]
        i += 1
        while i < len(lines) and lines[i].startswith("   ") and lines[i].strip() and not lines[i].strip().startswith(("- ",)) and not numbered.match(lines[i].strip()):
            text.append(lines[i].strip())
            i += 1
        story.append(Paragraph(f"{marker}&nbsp;&nbsp;{fmt(' '.join(text))}", ss["ListX"]))
        continue
    if re.match(r"^\[\d+\]", line):
        story.append(Paragraph(fmt(line), ss["SmallX"]))
        i += 1
        continue
    acc = [line]
    i += 1
    while i < len(lines) and lines[i].strip() and not lines[i].startswith(block_start) and not numbered.match(lines[i].strip()):
        acc.append(lines[i].strip())
        i += 1
    story.append(Paragraph(fmt(" ".join(acc)), ss["AbstractX"] if in_abstract else ss["BodyX"]))

doc = SimpleDocTemplate(str(out), pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
                        title="Verifiability Voters Can Use (D-Voting)", author="Pranav Kumar Singh, Kavi Priya D")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(out)
