#!/usr/bin/env python3
"""
gen_html.py — deterministic VAPT HTML report generator (bundled into every TrashiOS ai_review package).

Turns the AI's `final_report.md` (+ the `screenshots/` next to it) into ONE self-contained
`final_report.html`: black-&-white theme, every screenshot embedded inline as base64, a Copy button on
every code/secret block, a sticky section nav, auto-filled stat cards, and a filterable triage table.

The design is FIXED and proven — do NOT hand-edit it per report. Stat counts and the nav are derived
automatically from the report, so there is nothing to tweak: just run it.

    python3 gen_html.py [BASE]      # BASE = folder containing final_report.md (default ".")

Exit codes:
    0  success — every self-check passed
    1  HARD FAILURE — a referenced screenshot was missing, a code fence/placeholder leaked through,
       or the triage table wasn't found. The HTML is still written (with visible placeholders) so you
       can inspect it, but the run fails loudly so it never silently ships a broken report.
    2  produced with warnings (e.g. Pillow not installed → images embedded full-size).

Dependencies: `markdown` (required), `Pillow` (optional — only for downscaling; degrades gracefully).
"""
from __future__ import annotations

import base64
import html as htmllib
import io
import os
import re
import sys
import textwrap

try:
    import markdown
except ImportError:
    sys.stderr.write(
        "ERROR: the 'markdown' package is required to build the HTML report.\n"
        "       pip install markdown Pillow\n"
    )
    sys.exit(1)

try:
    from PIL import Image
    _HAVE_PIL = True
except ImportError:
    _HAVE_PIL = False


# ─────────────────────────────────────────────────────────────────────────────
# Theme — verbatim from the proven recipe. Do not restyle.
# ─────────────────────────────────────────────────────────────────────────────
CSS_INLINE = r"""
:root{--ink:#111;--muted:#666;--line:#d9d9d9;--soft:#f5f5f5;--soft2:#ececec;}
*{box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{margin:0;background:#fff;color:var(--ink);
 font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
 -webkit-font-smoothing:antialiased;}
.wrap{max-width:980px;margin:0 auto;padding:0 22px 80px;}
a{color:#000;text-decoration:underline;text-underline-offset:2px;}
h1{font-size:30px;line-height:1.25;margin:30px 0 6px;letter-spacing:-.3px;}
h2{font-size:23px;margin:46px 0 14px;padding-bottom:8px;border-bottom:2px solid #000;scroll-margin-top:60px;}
h3{font-size:18px;margin:30px 0 10px;scroll-margin-top:64px;}
p{margin:10px 0;}
hr{border:0;border-top:1px solid var(--line);margin:34px 0;}
ul,ol{margin:10px 0 10px 4px;padding-left:22px;}
li{margin:4px 0;}
strong{font-weight:700;}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13.5px;
 background:var(--soft);padding:1.5px 5px;border-radius:4px;border:1px solid var(--line);}
nav.top{position:sticky;top:0;z-index:50;background:#fff;border-bottom:1px solid #000;
 display:flex;flex-wrap:wrap;gap:4px;padding:9px 22px;margin:0 0 8px;}
nav.top a{text-decoration:none;font-size:13px;font-weight:600;padding:5px 11px;border:1px solid var(--line);border-radius:20px;color:#000;}
nav.top a:hover{background:#000;color:#fff;border-color:#000;}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:18px 0;}
.stat{border:1px solid var(--line);border-top:4px solid #000;padding:12px 14px;}
.stat b{display:block;font-size:26px;line-height:1;}
.stat span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;}
table{border-collapse:collapse;width:100%;margin:16px 0;font-size:14px;}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top;}
th{background:#000;color:#fff;font-weight:600;position:sticky;top:0;}
#triage tbody tr:nth-child(even){background:var(--soft);}
#triage tbody tr:hover{background:var(--soft2);}
td:first-child{font-family:ui-monospace,Menlo,monospace;white-space:nowrap;font-weight:600;}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.4px;
 padding:2px 8px;border-radius:3px;border:1px solid #000;text-transform:uppercase;white-space:nowrap;}
.b-high{background:#000;color:#fff;}
.b-medium{background:#555;color:#fff;border-color:#555;}
.b-low{background:#fff;color:#000;}
.b-info,.b-na{background:#fff;color:#888;border-color:#bbb;}
.b-confirmed{background:#000;color:#fff;}
.b-likely{background:#fff;color:#000;border-style:dashed;}
.b-fp{background:#fff;color:#888;border-color:#bbb;border-style:dotted;}
.filters{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0;}
.filters button{font:600 13px/1 inherit;padding:7px 13px;border:1px solid #000;background:#fff;color:#000;border-radius:4px;cursor:pointer;}
.filters button.active{background:#000;color:#fff;}
.codewrap{position:relative;margin:14px 0;}
.codewrap pre{background:var(--soft);border:1px solid var(--line);border-radius:6px;
 padding:14px;overflow-x:auto;margin:0;font-size:13px;line-height:1.5;}
.codewrap pre code{background:none;border:0;padding:0;font-size:13px;white-space:pre;}
.copy{position:absolute;top:8px;right:8px;font:600 11px/1 inherit;letter-spacing:.4px;
 padding:5px 10px;border:1px solid #000;background:#fff;color:#000;border-radius:4px;cursor:pointer;text-transform:uppercase;}
.copy:hover,.copy.done{background:#000;color:#fff;}
figure{margin:16px 0;border:1px solid var(--line);padding:8px;background:var(--soft);}
figure img{display:block;max-width:100%;height:auto;margin:0 auto;border:1px solid var(--line);}
figcaption{font-size:12.5px;color:var(--muted);margin-top:8px;text-align:center;font-style:italic;}
.missingbox{border:1px dashed #888;padding:26px 14px;text-align:center;color:#888;
 font-style:italic;font-size:13px;background:#fff;}
blockquote{border-left:3px solid #000;margin:10px 0;padding:2px 14px;color:#333;}
@media(max-width:620px){.wrap{padding:0 14px 60px;}h1{font-size:24px;}nav.top{gap:3px;}}
"""

JS = r"""
// 1) grayscale badges on the triage table
(function(){
 var map={'critical':'b-high','high':'b-high','medium':'b-medium','low':'b-low','informational':'b-info',
  'confirmed':'b-confirmed','likely':'b-likely','false positive':'b-fp','actionable':'b-low',
  'non-actionable':'b-na','—':'b-na'};
 var t=document.getElementById('triage'); if(!t) return;
 var rows=t.tBodies[0].rows;
 for(var i=0;i<rows.length;i++){
   [2,3,4].forEach(function(ci){               // cols: 2=Verdict 3=Severity 4=Action
     var c=rows[i].cells[ci]; if(!c) return;
     var key=c.textContent.trim().toLowerCase();
     if(map[key]){ c.innerHTML='<span class="badge '+map[key]+'">'+c.textContent.trim()+'</span>'; }
   });
   rows[i].dataset.action=(rows[i].cells[4]?rows[i].cells[4].textContent:'').toLowerCase();
   rows[i].dataset.verdict=(rows[i].cells[2]?rows[i].cells[2].textContent:'').toLowerCase();
 }
})();
// 2) triage filters
function applyFilter(mode,btn){
 document.querySelectorAll('.filters button').forEach(function(b){b.classList.remove('active');});
 if(btn)btn.classList.add('active');
 document.querySelectorAll('#triage tbody tr').forEach(function(r){
   var a=r.dataset.action||'', v=r.dataset.verdict||'', show=true;
   if(mode==='actionable') show=a.indexOf('non-actionable')<0 && a.indexOf('actionable')>=0;
   else if(mode==='confirmed') show=v.indexOf('confirmed')>=0;
   else if(mode==='fp') show=v.indexOf('false positive')>=0;
   r.style.display=show?'':'none';
 });
}
// 3) copy buttons
document.addEventListener('click',function(e){
 if(!e.target.classList.contains('copy'))return;
 var pre=e.target.parentNode.querySelector('pre');
 navigator.clipboard.writeText(pre.innerText).then(function(){
   var b=e.target,old=b.textContent;b.textContent='Copied';b.classList.add('done');
   setTimeout(function(){b.textContent=old;b.classList.remove('done');},1200);
 });
});
"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _strip_tags(s: str) -> str:
    """Plain text of a cell/heading: drop tags, unescape entities, collapse whitespace."""
    return re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", "", s))).strip()


def _encode_image(path: str, max_w: int = 820) -> str | None:
    """Return a data: URI for the image, downscaled+JPEG if Pillow is present, else original bytes."""
    if not os.path.exists(path):
        return None
    if _HAVE_PIL:
        im = Image.open(path)
        if im.mode in ("RGBA", "P", "LA"):
            im = im.convert("RGB")
        if im.width > max_w:
            im = im.resize((max_w, int(im.height * max_w / im.width)), Image.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, format="JPEG", quality=86, optimize=True)
        return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
    data = open(path, "rb").read()
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
            "gif": "image/gif", "webp": "image/webp"}.get(ext, "image/png")
    return f"data:{mime};base64," + base64.b64encode(data).decode()


def _derive_stats(html_body: str) -> str:
    """Build the .stats card row by tallying the tagged triage table.

    Columns are fixed by TrashiOS's PROMPT triage table:
        0=ID 1=Finding 2=Verdict 3=Real Severity 4=Action 5=reason
    """
    m = re.search(r'<table id="triage">.*?</table>', html_body, re.DOTALL)
    if not m:
        return ""
    body = re.search(r"<tbody>(.*?)</tbody>", m.group(0), re.DOTALL)
    rows_html = body.group(1) if body else m.group(0)
    rows = re.findall(r"<tr>(.*?)</tr>", rows_html, re.DOTALL)

    total = crit = high = med = low = fp = info = actionable = 0
    for row in rows:
        cells = [_strip_tags(c).lower() for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.DOTALL)]
        if not cells:
            continue
        total += 1
        verdict = cells[2] if len(cells) > 2 else ""
        sev = cells[3] if len(cells) > 3 else ""
        action = cells[4] if len(cells) > 4 else ""
        if "non-actionable" not in action and "actionable" in action:
            actionable += 1
        if "critical" in sev:
            crit += 1
        elif "high" in sev:
            high += 1
        elif "medium" in sev:
            med += 1
        elif "low" in sev:
            low += 1
        if "false positive" in verdict:
            fp += 1
        if "informational" in verdict or "informational" in sev:
            info += 1

    cards = [(total, "Total findings"), (actionable, "Actionable")]
    if crit:
        cards.append((crit, "Critical"))
    cards += [(high, "High"), (med, "Medium"), (low, "Low"),
              (fp, "False positive"), (info, "Informational")]
    inner = "".join(f"<div class=\"stat\"><b>{n}</b><span>{label}</span></div>" for n, label in cards)
    return f'<div class="stats">{inner}</div>'


def _derive_nav(html_body: str) -> str:
    """Build the sticky pill nav from the actual <h2 id=...> headings the toc extension emitted."""
    pills = []
    for hid, inner in re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', html_body, re.DOTALL):
        label = _strip_tags(inner)
        if len(label) > 30:
            label = label[:29].rstrip() + "…"
        pills.append(f'<a href="#{hid}">{htmllib.escape(label)}</a>')
    return f'<nav class="top">{"".join(pills)}</nav>' if pills else ""


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "."
    md_path = os.path.join(base, "final_report.md")
    out_path = os.path.join(base, "final_report.html")
    shots_dir = os.path.join(base, "screenshots")

    if not os.path.isfile(md_path):
        sys.stderr.write(f"ERROR: {md_path} not found. Run this from (or pass) the review package folder.\n")
        return 1

    md_text = open(md_path, encoding="utf-8").read()

    # 1) PRE-EXTRACT every fenced code block FIRST (handles fences inside list items, the #1 gotcha).
    code_blocks: list[str] = []

    def grab(m: re.Match) -> str:
        code_blocks.append(textwrap.dedent(m.group("code")).rstrip("\n"))
        return "\n@@CODEBLOCK%d@@" % (len(code_blocks) - 1)

    md_text = re.sub(r"[ \t]*```[\w-]*\n(?P<code>.*?)\n[ \t]*```", grab, md_text, flags=re.DOTALL)

    # 2) Markdown -> HTML (NO fenced_code: we render code ourselves so list-nested fences survive).
    html_body = markdown.markdown(
        md_text, extensions=["tables", "sane_lists", "toc"], output_format="html5"
    )

    # 3) Embed screenshots as downscaled base64 <figure>s. Order-independent attribute parsing;
    #    a referenced-but-missing file becomes a visible placeholder AND a hard validation failure.
    img_refs = 0
    img_embedded = 0
    missing: list[str] = []

    def img_sub(m: re.Match) -> str:
        nonlocal img_refs, img_embedded
        tag = m.group(0)
        src_m = re.search(r'src="([^"]*)"', tag)
        alt_m = re.search(r'alt="([^"]*)"', tag)
        src = src_m.group(1) if src_m else ""
        alt = alt_m.group(1) if alt_m else ""
        if not src.startswith("screenshots/"):
            return tag  # leave non-evidence images untouched
        img_refs += 1
        data = _encode_image(os.path.join(shots_dir, os.path.basename(src)))
        if data is None:
            missing.append(os.path.basename(src))
            return (f'<figure class="missing"><div class="missingbox">missing screenshot: '
                    f'{htmllib.escape(os.path.basename(src))}</div>'
                    f'<figcaption>{htmllib.escape(alt)}</figcaption></figure>')
        img_embedded += 1
        return (f'<figure><img src="{data}" alt="{htmllib.escape(alt)}">'
                f'<figcaption>{htmllib.escape(alt)}</figcaption></figure>')

    html_body = re.sub(r"<img\b[^>]*>", img_sub, html_body)

    # 4) Re-insert code blocks as copy-enabled <pre> blocks (standalone + joined-in-list forms).
    def codewrap_html(code: str) -> str:
        return ('<div class="codewrap"><button class="copy" type="button">Copy</button>'
                "<pre><code>" + htmllib.escape(code) + "</code></pre></div>")

    for i, code in enumerate(code_blocks):
        block = codewrap_html(code)
        html_body = html_body.replace("<p>@@CODEBLOCK%d@@</p>" % i, block)
        html_body = html_body.replace("@@CODEBLOCK%d@@" % i, block)

    # 5) Tag the triage table (the one whose header carries Verdict + Real Severity).
    triage_found = False

    def tag_triage(m: re.Match) -> str:
        nonlocal triage_found
        t = m.group(0)
        if "Verdict" in t and "Real Severity" in t:
            triage_found = True
            return t.replace("<table>", '<table id="triage">', 1)
        return t

    html_body = re.sub(r"<table>.*?</table>", tag_triage, html_body, flags=re.DOTALL)

    # 6) Auto-derive stat cards + 7) sticky nav (no hand-edited numbers, no hardcoded anchors).
    stats = _derive_stats(html_body)
    nav = _derive_nav(html_body)
    filters = ('<div class="filters">'
               "<button class=\"active\" onclick=\"applyFilter('all',this)\">All</button>"
               "<button onclick=\"applyFilter('actionable',this)\">Actionable</button>"
               "<button onclick=\"applyFilter('confirmed',this)\">Confirmed</button>"
               "<button onclick=\"applyFilter('fp',this)\">False positives</button></div>")

    # Inject stats right after the first <h2>; filters right before the triage table.
    if stats:
        html_body = re.sub(r"(<h2\b[^>]*>.*?</h2>)", r"\1" + stats, html_body, count=1, flags=re.DOTALL)
    if triage_found:
        html_body = html_body.replace('<table id="triage">', filters + '<table id="triage">', 1)

    # 8) Wrap in the self-contained skeleton and write.
    doc = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           f"<title>VAPT Report</title><style>{CSS_INLINE}</style></head><body>"
           f'{nav}<div class="wrap">{html_body}</div><script>{JS}</script></body></html>')
    open(out_path, "w", encoding="utf-8").write(doc)

    # 9) Self-validation — print PASS/FAIL; never silently ship a broken report.
    copy_count = doc.count('class="copy"')
    stray_fences = doc.count("```")
    stray_ph = len(re.findall(r"@@CODEBLOCK\d+@@", doc))
    asset_http = len(re.findall(r'src\s*=\s*"https?://', doc)) + len(re.findall(r"url\(\s*['\"]?https?://", doc))

    checks = [
        (img_embedded == img_refs and not missing,
         f"images embedded ({img_embedded}/{img_refs})",
         ("missing: " + ", ".join(missing)) if missing else ""),
        (copy_count == len(code_blocks),
         f"copy buttons == code blocks ({copy_count}/{len(code_blocks)})", ""),
        (stray_fences == 0, f"no leftover ``` fences ({stray_fences})", ""),
        (stray_ph == 0, f"no leftover @@CODEBLOCK placeholders ({stray_ph})", ""),
        (triage_found, "triage table found + tagged", ""),
        (asset_http == 0, f"no external asset URLs ({asset_http})", ""),
    ]

    print("─" * 64)
    hard_fail = False
    for ok, label, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  — {detail}" if (detail and not ok) else ""))
        hard_fail = hard_fail or not ok
    warned = False
    if not _HAVE_PIL:
        print("  [WARN] Pillow not installed — screenshots embedded full-size (larger file). "
              "pip install Pillow")
        warned = True
    if not nav:
        print("  [WARN] no <h2> headings found — section nav is empty.")
        warned = True
    print(f"  wrote {out_path} ({os.path.getsize(out_path):,} bytes)")
    print("─" * 64)

    if hard_fail:
        return 1
    return 2 if warned else 0


if __name__ == "__main__":
    sys.exit(main())
