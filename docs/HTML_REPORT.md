# HTML Report — `gen_html.py`

Reference for the deterministic HTML-report generator bundled into every AI-review package.

> **Source of truth is the code, not this doc.** The script is
> [`core/templates/gen_html.py`](../core/templates/gen_html.py); it is copied verbatim into each
> `output/<bundle>/ai_review/` package as `gen_html.py`. If this doc and the script ever disagree,
> the script wins — update the doc.

---

## Why it exists

The AI used to **hand-write** `final_report.html` during the review. That wasted tokens on CSS/layout
reasoning and produced a slightly different-looking report every run. Now the AI writes only
`final_report.md` and runs **one command** — `python3 gen_html.py` — to turn it into the HTML. The
theme is fixed, so every report looks identical and the AI spends ~0 tokens on design.

## What it does

```
python3 gen_html.py [BASE]      # BASE = folder with final_report.md (default ".")
```

| | |
|---|---|
| **Input** | `final_report.md` — the VAPT report in Markdown. Screenshots referenced as `![caption](screenshots/<file>)`; code/secrets in fenced ```` ``` ```` blocks. The first triage table's header must contain the words **`Verdict`** and **`Real Severity`**. |
| **Input** | `screenshots/` — the PNGs the `![]()` tags point at (next to the report). |
| **Output** | `final_report.html` — one self-contained file (~0.5 MB typical). No CDN, no external CSS/JS/fonts/images; opens offline anywhere. |
| **Deps** | `markdown` (required), `Pillow` (optional — only downscales screenshots; degrades gracefully). Both are in `requirements.txt`. |

## The theme (fixed — do not restyle)

Strictly **monochrome** (`#fff` background, `#111` ink); severity is shown by badge **weight**, not
colour. System font stack, max content width 980 px. Components:

- **Sticky pill nav** (`nav.top`) — one pill per `<h2>` section.
- **Stat cards** (`.stats`) — Total / Actionable / [Critical] / High / Medium / Low / False positive /
  Informational. Counts are **auto-derived** (see below).
- **Filterable triage table** (`#triage`) — All / Actionable / Confirmed / False positives, with
  grayscale badges on the Verdict / Real Severity / Action cells, zebra striping, and hover.
- **Copy buttons** (`.codewrap .copy`) — every code/secret block; one click copies the full text.
- **Figures** — each screenshot embedded as a downscaled base64 `data:` URI with its caption.

## Pipeline (the order matters)

1. **Pre-extract every fenced code block** with a regex, `dedent`, and leave a flush-left placeholder.
   *This is the #1 gotcha:* `python-markdown`'s `fenced_code` extension silently fails on fences
   nested inside list items (e.g. PoC steps), so we handle code ourselves and **do not** use that
   extension.
2. **Markdown → HTML** with extensions `tables`, `sane_lists`, `toc`.
3. **Embed images.** The `<img …>` match is **attribute-order-independent** (pulls `src` + `alt`
   regardless of order/extra attrs). Only `screenshots/…` sources are embedded. With Pillow: downscale
   to ≤820 px wide, JPEG q86. Without Pillow: embed the original bytes (larger file) + a warning. A
   referenced-but-**missing** file becomes a visible placeholder `<figure>` (not a broken `<img>`) and
   is recorded as a validation failure. Images load **eagerly** (no `loading="lazy"`) so they render
   everywhere — including print-to-PDF and viewers without an `IntersectionObserver`.
4. **Re-insert code blocks** as `<div class="codewrap"><button class="copy">…</button><pre><code>…</code></div>`,
   HTML-escaped.
5. **Tag the triage table** — the table whose header contains `Verdict` **and** `Real Severity` gets
   `id="triage"` so the JS can badge + filter it.
6. **Auto-derive stat counts** by parsing the triage rows. Fixed column order (matches the TrashiOS
   PROMPT triage table): `0 ID · 1 Finding · 2 Verdict · 3 Real Severity · 4 Action · 5 reason`.
7. **Auto-derive the nav** from the `<h2 id="…">` headings (`toc` slugs). Labels >30 chars are
   ellipsised. No hardcoded anchors.
8. **Inject** stats after the first `<h2>`, filters before the triage table, then **wrap** in the HTML
   skeleton with inline `<style>` (the theme CSS) and `<script>` (the badge/filter/copy JS). Write
   `final_report.html`.
9. **Self-validate** (see next section).

> Because of steps 6–7, the script is **zero-edit**: there are no per-report numbers or anchors to
> tweak. Just run it.

## Self-validation & exit codes

After writing the file the script prints a `PASS`/`FAIL` summary and exits:

| Exit | Meaning |
|---|---|
| **0** | All checks passed. |
| **1** | **Hard failure** — a referenced screenshot was missing, a code fence/placeholder leaked through, or the triage table wasn't found. The HTML is still written (with a visible placeholder) so you can inspect it, but the run fails loudly so a broken report never ships silently. |
| **2** | Produced with warnings (e.g. Pillow absent → images embedded full-size; or no `<h2>` headings → empty nav). |

Checks: every referenced screenshot embedded (names any miss) · `copy buttons == code blocks` ·
`0` leftover ```` ``` ```` fences · `0` `@@CODEBLOCK` placeholders · triage table found + tagged ·
no external `http(s)://` asset URLs remain.

## How it's wired into TrashiOS

All in [`core/ai_review.py`](../core/ai_review.py):

- `_write_gen_html(pkg)` copies the script into the package; `assemble_review_package` calls it.
- The review instructions (`STARTER_PROMPT`, `_write_prompt`, `_write_claude_md`) tell the AI to run
  `python3 gen_html.py` as its **final step** — not to hand-write HTML.
- It **auto-runs end-to-end**: `run_review.sh` runs it after `final_report.md` is written, and
  `_generate_html` (called from `_announce_final`) runs it after the `--ai-review`, headless, custom-
  backend, and interactive paths — so the HTML always reflects the final report with no manual step.

## Regenerating by hand

From any review package (or a folder holding `final_report.md` + `screenshots/`):

```bash
cd output/<bundle>/ai_review
python3 gen_html.py            # writes final_report.html, prints PASS/FAIL
```
