"""Generate professional PDF from whitepaper markdown.

White background, McKinsey/Google-style layout: navy primary, teal accent,
generous whitespace, minimal table borders, branded cover and footer.

Usage: python docs/generate_pdf.py
Output: docs/whitepaper-chinese-pii.pdf
"""

import markdown
from pathlib import Path
from weasyprint import HTML

DOCS_DIR = Path(__file__).parent
MD_FILE = DOCS_DIR / "whitepaper-chinese-pii.md"
PDF_FILE = DOCS_DIR / "whitepaper-chinese-pii.pdf"

CSS = """
/* ── Page setup ── */
@page {
    size: A4;
    margin: 28mm 22mm 25mm 22mm;
    background: #fff;

    @bottom-left {
        content: "argus-redact  ·  中文 PII 检测技术分析报告  ·  2026";
        font-size: 7.5pt;
        color: #999;
        font-family: "PingFang SC", "Noto Sans CJK SC", sans-serif;
    }
    @bottom-right {
        content: counter(page);
        font-size: 7.5pt;
        color: #999;
        font-family: "PingFang SC", sans-serif;
    }
    @top-right {
        content: "";
        display: block;
        border-bottom: 0.5pt solid #E5E7EB;
        width: 100%;
    }
}

@page :first {
    margin: 0;
    background: linear-gradient(160deg, #0F2A4A 0%, #1A5276 45%, #1A8A7D 100%);
    @bottom-left { content: none; }
    @bottom-right { content: none; }
    @top-right { content: none; border: none; }
}

/* ── Base ── */
body {
    font-family: "PingFang SC", "Noto Sans CJK SC", "Source Han Sans SC",
                 "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif;
    font-size: 10.5pt;
    line-height: 1.75;
    color: #1F2937;
    background: transparent;
    padding-top: 8px;
}

/* ── Cover page ── */
/* First h1 = cover title, entire first page is gradient via @page :first */
h1:first-of-type {
    font-size: 26pt;
    font-weight: 800;
    color: #fff;
    background: none;
    margin: 0;
    padding: 6.5cm 26mm 16px 26mm;
    letter-spacing: 1pt;
    border: none;
    border-bottom: 1pt solid rgba(255, 255, 255, 0.2);
    line-height: 1.35;
}

/* Cover metadata — simple left-aligned list, tight spacing */
h1:first-of-type + blockquote {
    border-left: none;
    background: transparent;
    color: rgba(255, 255, 255, 0.6);
    font-size: 9pt;
    line-height: 1.8;
    padding: 20px 26mm 0 26mm;
    margin: 0;
    page-break-after: always;
}

h1:first-of-type + blockquote p {
    margin-bottom: 6px;
}

h1:first-of-type + blockquote strong {
    color: rgba(255, 255, 255, 0.85);
}

h1:first-of-type + blockquote a {
    color: rgba(255, 255, 255, 0.8);
    border-bottom-color: rgba(255, 255, 255, 0.25);
}

/* English subtitle */
h1:first-of-type + blockquote em:first-of-type {
    display: block;
    font-size: 10.5pt;
    color: rgba(255, 255, 255, 0.35);
    letter-spacing: 0.06em;
    font-style: normal;
    margin-bottom: 20px;
}

/* Hide the hr after cover blockquote */
h1:first-of-type + blockquote + hr {
    display: none;
}

/* ── Headings ── */
h1 {
    font-size: 20pt;
    font-weight: 700;
    color: #0F2A4A;
    border-bottom: 2.5pt solid #1A5276;
    padding-bottom: 8px;
    margin-top: 36px;
    margin-bottom: 16px;
}

h2 {
    font-size: 15pt;
    font-weight: 600;
    color: #1A5276;
    border-bottom: 1pt solid #E5E7EB;
    padding-bottom: 5px;
    margin-top: 30px;
    margin-bottom: 12px;
    page-break-after: avoid;
}

h3 {
    font-size: 12pt;
    font-weight: 600;
    color: #1F2937;
    margin-top: 22px;
    margin-bottom: 8px;
    page-break-after: avoid;
}

h4 {
    font-size: 10.5pt;
    font-weight: 600;
    color: #6B7280;
    margin-top: 16px;
}

/* ── Blockquotes (sidebar callouts) ── */
blockquote {
    border-left: 3.5pt solid #1A8A7D;
    padding: 10px 18px;
    margin: 16px 0;
    background: #F0FDFA;
    color: #4B5563;
    font-size: 9.5pt;
    border-radius: 0 6px 6px 0;
}

blockquote strong {
    color: #0F2A4A;
}

/* ── Tables (McKinsey minimal) ── */
table {
    border-collapse: collapse;
    width: 100%;
    margin: 14px 0;
    font-size: 9.5pt;
    page-break-inside: avoid;
}

th {
    font-weight: 600;
    text-align: left;
    padding: 9px 12px;
    border-bottom: 2pt solid #0F2A4A;
    color: #0F2A4A;
    background: none;
}

td {
    padding: 7px 12px;
    border-bottom: 0.5pt solid #E5E7EB;
    vertical-align: top;
    color: #374151;
}

/* No vertical borders, no outer border — McKinsey style */
th, td {
    border-left: none;
    border-right: none;
}

tr:last-child td {
    border-bottom: 1.5pt solid #D1D5DB;
}

table th:first-child, table td:first-child {
    min-width: 80px;
    white-space: nowrap;
}

/* ── Code ── */
code {
    font-family: "SF Mono", "Menlo", "Cascadia Code", "Courier New", monospace;
    font-size: 9pt;
    background: #F3F4F6;
    padding: 1.5px 5px;
    border-radius: 3px;
    color: #1A5276;
}

pre {
    background: #F8F9FA;
    border: 1pt solid #E5E7EB;
    border-radius: 6px;
    padding: 14px 18px;
    font-size: 8.5pt;
    line-height: 1.55;
    overflow-x: auto;
    page-break-inside: avoid;
}

pre code {
    background: none;
    padding: 0;
    color: #1F2937;
}

/* ── Typography details ── */
strong {
    color: #0F2A4A;
    font-weight: 600;
}

em {
    color: #6B7280;
}

hr {
    border: none;
    border-top: 1pt solid #E5E7EB;
    margin: 24px 0;
}

a {
    color: #1A5276;
    text-decoration: none;
    border-bottom: 0.5pt solid #93C5FD;
}

p {
    margin: 8px 0;
}

li {
    margin: 3px 0;
}

ul, ol {
    padding-left: 1.5em;
}

/* ── Key findings accent ── */
li strong:first-child {
    color: #92400E;
}

/* ── Reference list: tighter, smaller, forced counter ── */
ol {
    list-style: none;
    counter-reset: ref-counter;
    padding-left: 2.5em;
}

ol li {
    font-size: 9pt;
    line-height: 1.6;
    margin-bottom: 3px;
    color: #4B5563;
    counter-increment: ref-counter;
    position: relative;
}

ol li::before {
    content: "[" counter(ref-counter) "]";
    position: absolute;
    left: -2.5em;
    color: #6B7280;
    font-size: 8.5pt;
}
"""


def strip_yaml_frontmatter(text: str) -> str:
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            return text[end + 3:].lstrip("\n")
    return text


def main():
    md_text = MD_FILE.read_text(encoding="utf-8")
    md_text = strip_yaml_frontmatter(md_text)

    html_body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "toc"],
    )

    full_html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="description" content="中文个人信息（PII）检测技术分析报告 — 系统分析8种中文PII类型的技术特征与检测难点">
    <meta name="keywords" content="中文PII, PIPL, 身份证号检测, 中文NER, LLM隐私, argus-redact, pii-bench-zh">
    <meta name="author" content="argus-redact">
    <title>中文个人信息（PII）检测技术分析报告 | argus-redact</title>
    <style>{CSS}</style>
</head>
<body>
{html_body}
</body>
</html>"""

    HTML(string=full_html).write_pdf(str(PDF_FILE))
    size_kb = PDF_FILE.stat().st_size / 1024
    print(f"Generated: {PDF_FILE} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
