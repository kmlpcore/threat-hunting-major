"""Render each .mmd in this folder to SVG + PNG: Mermaid (CDN) in headless Chrome -> SVG -> scaled PNG."""
import html
import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageChops

here = Path(__file__).parent
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SCALE = 3
names = {"1_architecture": "ch4_fig1_architecture", "2_cqrs": "ch4_fig2_cqrs",
         "3_dfd0": "ch4_fig3_dfd_level0", "4_dfd1": "ch4_fig4_dfd_level1",
         "5_lifecycle": "ch4_fig5_partition_lifecycle", "6_rule_sequence": "ch4_fig6_rule_sequence"}

RENDER = """<!doctype html><html><head><meta charset="utf-8">
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script></head>
<body><pre class="mermaid">{src}</pre>
<script>mermaid.initialize({{startOnLoad:true, theme:'neutral',
  flowchart:{{htmlLabels:true, curve:'basis', useMaxWidth:false}}, sequence:{{useMaxWidth:false}},
  state:{{useMaxWidth:false}}, themeVariables:{{fontSize:'16px', fontFamily:'Segoe UI, Arial, sans-serif'}}}});</script>
</body></html>"""
SHOT = """<!doctype html><html><head><meta charset="utf-8"><style>html,body{{margin:0;background:#fff}}
svg{{display:block}}</style></head><body>{svg}</body></html>"""


def run(*args):
    return subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", *args],
                          check=True, capture_output=True, timeout=180, text=True, encoding="utf-8")


for mmd in sorted(here.glob("*.mmd")):
    page = here / f"{mmd.stem}.html"
    page.write_text(RENDER.format(src=html.escape(mmd.read_text(encoding="utf-8"))), encoding="utf-8")
    dom = run("--virtual-time-budget=10000", "--dump-dom", page.as_uri()).stdout
    m = re.search(r"<svg[^>]*id=\"mermaid-[^\"]*\".*?</svg>\s*(?=</pre>)", dom, re.S) or re.search(r"<svg.*</svg>", dom, re.S)
    if not m:
        sys.exit(f"no svg for {mmd.stem}")
    svg = m.group(0).strip()
    vb = [float(x) for x in re.search(r'viewBox="([^"]+)"', svg).group(1).split()]
    w, h = vb[2], vb[3]
    head = re.match(r"<svg[^>]*>", svg).group(0)
    clean = re.sub(r'\s(width|height|style)="[^"]*"', "", head)
    body = svg[len(head):]
    base = out / names[mmd.stem]
    base.with_suffix(".svg").write_text(clean.replace("<svg", f'<svg width="{w:.0f}" height="{h:.0f}"', 1) + body,
                                        encoding="utf-8")
    shot = here / f"{mmd.stem}_shot.html"
    shot.write_text(SHOT.format(svg=clean.replace("<svg", f'<svg width="{w*SCALE:.0f}" height="{h*SCALE:.0f}"', 1)
                                + body), encoding="utf-8")
    png = base.with_suffix(".png")
    run(f"--window-size={int(w*SCALE)+40},{int(h*SCALE)+40}", f"--screenshot={png}", shot.as_uri())
    im = Image.open(png).convert("RGB")
    box = ImageChops.difference(im, Image.new("RGB", im.size, (255, 255, 255))).getbbox()
    if box:
        im = im.crop((max(box[0] - 30, 0), max(box[1] - 30, 0), min(box[2] + 30, im.width), min(box[3] + 30, im.height)))
    im.save(png, dpi=(300, 300))
    print(png.name, im.size, "svg", f"{w:.0f}x{h:.0f}")
