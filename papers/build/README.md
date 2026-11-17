# Typesetting the papers

`build.py` turns the Markdown papers into the PDFs in [`../pdf/`](../pdf/). Pandoc reads the Markdown as CommonMark, as GitHub renders it, and Chromium prints the resulting HTML with `paper.css`.

```
npm install                          # fonts: Source Serif 4, Inter, JetBrains Mono (pinned)
python3 build.py                     # both papers
python3 build.py 01-founding-paper.md   # or one
```

It needs pandoc 3, Mermaid CLI (`mmdc`), Python Playwright with Chromium, and pypdf.

Beyond plain conversion, the build:

- turns the title block (everything before the first `---`) into a title page with the abstract, and gives the technical paper a contents page;
- typesets the layer stack drawn with box characters as a figure, and renders Mermaid diagrams as SVG figures;
- keeps short tables and code blocks on one page unless moving one whole would leave a large gap (it measures them at the printed width), and keeps an introduction with what it introduces;
- prints a diagram marked `<!-- pdf: figure after list -->` after the list that follows it, so a tall figure does not leave a gap; the Markdown keeps its order;
- writes the title, author, subject and keywords into the PDF's document information.

After changing a paper, rebuild and look at every page before publishing a new version.
