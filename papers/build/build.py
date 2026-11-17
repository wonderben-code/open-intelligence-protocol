#!/usr/bin/env python3
"""
Typeset the OIP papers as PDFs: Markdown -> pandoc -> HTML -> Chromium.

    cd papers/build && npm install        # fonts (Source Serif 4, Inter, JetBrains Mono)
    python3 build.py                      # writes papers/pdf/*.pdf

Needs pandoc, Mermaid CLI (mmdc), Python Playwright with Chromium, and pypdf.
The Markdown is read as CommonMark, as GitHub renders it. Licensed Apache-2.0.
"""
import base64
import html
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright
from pypdf import PdfReader, PdfWriter

HERE = Path(__file__).resolve().parent
PAPERS = HERE.parent
OUT = PAPERS / "pdf"
FONTS = HERE / "node_modules" / "@fontsource"

PAPERS_META = {
    "01-founding-paper.md": {
        "pdf_title": "The Open Intelligence Protocol: "
                     "A Founding Paper for the Network of Minds",
        "runhead": "The Open Intelligence Protocol  ·  A Founding Paper",
        "toc": False,
        "keywords": "AI agents; multi-agent systems; open protocols; "
                    "decentralised identity; collective intelligence",
    },
    "02-technical-architecture.md": {
        "pdf_title": "The Open Intelligence Protocol: Technical Architecture",
        "runhead": "The Open Intelligence Protocol  ·  Technical Architecture",
        "toc": True,
        "keywords": "AI agents; agent communication protocol; decentralized "
                    "identifiers; did:oip; W3C Data Integrity; pre-rotation; "
                    "delegation; UCAN; commitments; multi-agent systems",
    },
}

FONT_CSS = [
    "source-serif-4/400.css", "source-serif-4/400-italic.css",
    "source-serif-4/600.css", "source-serif-4/600-italic.css",
    "source-serif-4/700.css",
    "inter/400.css", "inter/500.css", "inter/600.css", "inter/700.css",
    "jetbrains-mono/400.css", "jetbrains-mono/700.css",
]

READER = ("commonmark_x+autolink_bare_uris"
          "-emoji-tex_math_dollars-subscript-superscript")

# Short tables and code blocks are kept on one page, unless moving one
# whole could leave a large gap: measured at the printed text width
# (170 mm), a table taller than 60 mm, unless it has a caption, or a code
# block taller than 80 mm may break between rows or lines.
UNKEEP = """() => {
  const mm = 96 / 25.4;
  for (const el of document.querySelectorAll("table.keep, pre.keep")) {
    const table = el.tagName === "TABLE";
    const cap = el.previousElementSibling;
    if (table && cap && cap.matches("p.lead") &&
        /^Table \\d/.test(cap.textContent)) continue;
    if (el.getBoundingClientRect().height > (table ? 60 : 80) * mm)
      el.classList.remove("keep");
  }
}"""

MERMAID = {
    "theme": "base",
    "themeVariables": {
        "fontFamily": "Inter, sans-serif", "fontSize": "15px",
        "primaryColor": "#f3f5fa", "primaryBorderColor": "#22346a",
        "primaryTextColor": "#15171c", "lineColor": "#3b414d",
        "actorBkg": "#f3f5fa", "actorBorder": "#22346a",
        "actorTextColor": "#15171c", "actorLineColor": "#a3abbc",
        "signalColor": "#3b414d", "signalTextColor": "#15171c",
        "noteBkgColor": "#fbf5e4", "noteBorderColor": "#d9c27a",
        "noteTextColor": "#15171c",
    },
    "sequence": {"mirrorActors": False, "wrap": True, "width": 150,
                 "actorMargin": 64, "messageMargin": 30, "boxMargin": 8,
                 "noteMargin": 10, "messageFontSize": 15,
                 "actorFontSize": 15, "noteFontSize": 14},
}


def pandoc(markdown: str, *args) -> str:
    return subprocess.run(
        ["pandoc", f"--from={READER}", "--to=html5", "--no-highlight",
         "--wrap=none", *args],
        input=markdown, capture_output=True, text=True, check=True).stdout


def inline(markdown: str) -> str:
    """One line of Markdown as inline HTML."""
    out = pandoc(markdown).strip()
    return re.sub(r"^<p>(.*)</p>$", r"\1", out, flags=re.S)


def mermaid_figure(source: str, workdir: Path) -> str:
    """Render a Mermaid diagram as an SVG figure."""
    src, svg = workdir / "d.mmd", workdir / "d.svg"
    src.write_text(source, encoding="utf-8")
    (workdir / "cfg.json").write_text(json.dumps(MERMAID))
    subprocess.run(["mmdc", "-q", "-i", str(src), "-o", str(svg),
                    "-c", str(workdir / "cfg.json"), "-b", "white"],
                   check=True, capture_output=True)
    data = base64.b64encode(svg.read_bytes()).decode()
    return (f'<figure class="diagram"><img src="data:image/svg+xml;base64,'
            f'{data}" alt="Sequence diagram of the interaction"></figure>')


def stack_figure(box: str) -> str:
    """The layer stack, drawn with box characters in the Markdown, typeset
    as a figure: what is built above, the layers, and what lies below."""
    bands, current = [], []
    for row in box.strip().splitlines()[1:-1]:
        if row.startswith("├"):
            bands.append(current)
            current = []
        else:
            current.append(row.strip().strip("│").strip())
    bands.append(current)

    def lines(texts):
        # A line ending in "·" or "," continues on the next; others end.
        out = []
        for text in texts:
            if out and out[-1].endswith(("·", ",")):
                out[-1] += " " + text
            else:
                out.append(text)
        return "".join(f"<span>{html.escape(t.replace(chr(39), chr(8217)))}"
                       "</span>" for t in out)

    above, *layers, below = bands
    parts = [f'<div class="outer above">{lines(above)}</div>',
             '<div class="layers">']
    for band in layers:
        number, name = re.fullmatch(r"LAYER (\d+) · (.+)", band[0]).groups()
        parts.append(
            f'<div class="layer"><div class="label">'
            f'<span class="num">Layer {number}</span>'
            f'<span class="name">{html.escape(name.title())}</span></div>'
            f'<div class="items">{lines(band[1:])}</div></div>')
    parts.append("</div>")
    parts.append(f'<div class="outer below">{lines(below)}</div>')
    return f'<figure class="stack">{"".join(parts)}</figure>'


def split_front(md: str):
    """The title block is everything before the first horizontal rule."""
    front, _, body = md.partition("\n---\n")
    lines = [ln.rstrip() for ln in front.strip().splitlines() if ln.strip()]
    title = lines[0].lstrip("#").strip()
    subtitle = next((ln.lstrip("#").strip() for ln in lines[1:]
                     if ln.startswith("###")), "")
    rest = [ln for ln in lines[1:] if not ln.startswith("###")]
    author = rest[0].strip("* ")
    return title, subtitle, author, rest[1:], body


def table_of_contents(body_html: str) -> str:
    """Two levels, from pandoc's section divs."""
    items, current = [], None
    for ident, level, text in re.findall(
            r'<section id="([^"]+)" class="level([23])"[^>]*>\s*'
            r'<h[23][^>]*>(.*?)</h[23]>', body_html, re.S):
        text = re.sub(r"<[^>]+>", "", text).strip()
        if level == "2":
            current = [f'<a href="#{ident}">{text}</a>', []]
            items.append(current)
        elif current is not None:
            current[1].append(f'<li><a href="#{ident}">{text}</a></li>')
    out = ['<nav class="toc"><h2>Contents</h2><ol>']
    for head, subs in items:
        sub = f"<ol>{''.join(subs)}</ol>" if subs else ""
        out.append(f"<li>{head}{sub}</li>")
    out.append("</ol></nav>")
    return "".join(out)


def refine(body: str) -> str:
    """Print refinements on pandoc's HTML."""
    # Let the browser size table columns from their content.
    body = re.sub(r"<colgroup>.*?</colgroup>", "", body, flags=re.S)

    # Short code blocks and tables stay on one page.
    def keep_pre(m):
        lines = m.group(0).count("\n") + 1
        return m.group(0).replace("<pre", '<pre class="keep"', 1) \
            if lines <= 30 else m.group(0)
    body = re.sub(r"<pre[^>]*>.*?</pre>", keep_pre, body, flags=re.S)

    def keep_table(m):
        rows = m.group(0).count("<tr")
        return m.group(0).replace("<table", '<table class="keep"', 1) \
            if rows <= 14 else m.group(0)
    body = re.sub(r"<table.*?</table>", keep_table, body, flags=re.S)

    # A paragraph that introduces a code block, table, figure or list
    # stays with it: one ending in a colon, a caption, a bold label, or
    # one short enough to be an introduction.
    body = re.sub(r"<p>((?:(?!</p>).)*?)</p>(\s*<(?:pre|table|figure|div|ul|ol))",
                  lambda m: f'<p class="lead">{m.group(1)}</p>{m.group(2)}'
                  if m.group(1).rstrip().endswith(":") or
                  m.group(1).startswith("<strong>Table") or
                  re.fullmatch(r"<strong>[^<]*</strong>(?: \(<code>[^<]*</code>\))?",
                               m.group(1).strip()) or
                  len(re.sub(r"<[^>]+>", "", m.group(1))) < 160
                  else m.group(0),
                  body, flags=re.S)

    # Long identifiers in running text may break anywhere, so that
    # justified lines are not stretched around them.
    body = re.sub(r"<code>([^<]{26,})</code>",
                  r'<code class="long">\1</code>', body)

    # Coverage symbols (Table 1) in a font that draws them clearly.
    body = re.sub(r"([●◐○])", r'<span class="sym">\1</span>', body)

    # The closing "Cite as" line.
    body = re.sub(r"<p><em>Cite as:</em>(.*?)</p>",
                  r'<p class="cite"><em>Cite as:</em>\1</p>', body, flags=re.S)
    return body


def build(name: str, browser) -> Path:
    meta = PAPERS_META[name]
    md = (PAPERS / name).read_text(encoding="utf-8")
    title, subtitle, author, meta_lines, body_md = split_front(md)

    # Diagrams become figures: Mermaid as SVG, the layer stack as HTML.
    with tempfile.TemporaryDirectory() as tmp:
        figures = []

        def keep(figure):
            figures.append(figure)
            return f"\n\nFIGURE{len(figures) - 1}\n\n"
        body_md = re.sub(r"```mermaid\n(.*?)```",
                         lambda m: keep(mermaid_figure(m.group(1), Path(tmp))),
                         body_md, flags=re.S)
        body_md = re.sub(r"```\n(┌.*?)```",
                         lambda m: keep(stack_figure(m.group(1))),
                         body_md, flags=re.S)
        body = pandoc(body_md, "--section-divs")

    for i, figure in enumerate(figures):
        body = body.replace(f"<p>FIGURE{i}</p>", figure)

    # A figure marked "pdf: figure after list" is printed after the list
    # that follows it, so that a figure too tall for the rest of its page
    # does not leave a gap. The Markdown keeps its order.
    body = re.sub(r"<!-- pdf: figure after list -->\s*(<figure.*?</figure>)"
                  r"\s*(<ol[^>]*>.*?</ol>)", r"\2\n\1", body, flags=re.S)
    body = refine(body)

    # Abstract on the title page; the body starts on a new page.
    m = re.search(r'(<section id="abstract".*?</section>)', body, re.S)
    abstract = m.group(1) if m else ""
    body = body.replace(abstract, "", 1)
    toc = table_of_contents(body) if meta["toc"] else ""

    links = "\n".join(f'<link rel="stylesheet" href="{(FONTS / f).as_uri()}">'
                      for f in FONT_CSS)
    runhead = meta["runhead"].replace('"', '\\"')
    page_css = ('@page { @top-left { content: "%s"; } } '
                '@page :first { @top-left { content: none; } '
                '@bottom-center { content: none; } }' % runhead)
    meta_html = "".join(f"<p>{inline(ln)}</p>" for ln in meta_lines)
    doc = f"""<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8">
<title>{html.escape(meta['pdf_title'])}</title>
{links}
<link rel="stylesheet" href="{(HERE / 'paper.css').as_uri()}">
<style>{page_css}</style>
</head><body>
<header class="titlepage">
  <div class="kicker">Open Intelligence Protocol</div>
  <h1 class="title">{html.escape(title)}</h1>
  <p class="subtitle">{inline(subtitle) if subtitle else ''}</p>
  <p class="author">{html.escape(author)}</p>
  <div class="meta">{meta_html}</div>
  <hr class="title-rule">
  {abstract}
</header>
{toc}
<main class="body">
{body}
</main>
</body></html>"""

    OUT.mkdir(exist_ok=True)
    html_path = OUT / (Path(name).stem + ".html")
    html_path.write_text(doc, encoding="utf-8")
    pdf_path = OUT / (Path(name).stem + ".pdf")
    # Laid out at the printed text width, so that blocks can be measured.
    page = browser.new_page(viewport={"width": 643, "height": 1000})
    page.emulate_media(media="print")
    page.goto(html_path.as_uri(), wait_until="networkidle")
    page.evaluate("document.fonts.ready")
    page.evaluate(UNKEEP)
    page.pdf(path=str(pdf_path), format="A4", print_background=True,
             prefer_css_page_size=True, outline=True, tagged=True)
    page.close()
    if "--keep-html" not in sys.argv:
        html_path.unlink()

    # Document information for archives and search engines.
    writer = PdfWriter(clone_from=PdfReader(str(pdf_path)))
    writer.add_metadata({
        "/Title": meta["pdf_title"],
        "/Author": author,
        "/Subject": subtitle or title,
        "/Keywords": meta["keywords"],
        "/Creator": "OIP papers build (pandoc, Chromium)",
    })
    with open(pdf_path, "wb") as fh:
        writer.write(fh)
    return pdf_path


def main(names):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for name in names or PAPERS_META:
            path = build(name, browser)
            pages = len(PdfReader(str(path)).pages)
            print(f"wrote {path.relative_to(PAPERS.parent)} ({pages} pages)")
        browser.close()


if __name__ == "__main__":
    main([a for a in sys.argv[1:] if not a.startswith("--")])
