#!/usr/bin/env python3
"""
Generator for Findings-to-Fix.pdf and Findings-to-Fix-print-source.html
(Claude Code edition).

What it does, in order:
  1. Downloads the variable source fonts (Inter, Space Grotesk, JetBrains Mono)
     into a temporary cache, instantiates static weight instances with fontTools,
     subsets them to the characters this document uses, and base64 inlines them.
     Static instances matter: Chrome rasterizes variable fonts into Type3 glyphs
     when printing, which makes the PDF text unselectable and unsearchable.
  2. Draws the three diagrams as inline SVG with coordinates computed from real
     font metrics, so no label overflows its box and no wire crosses a box.
  3. Writes a single self-contained HTML file.
  4. Prints it to PDF with headless Chrome.

Requirements: python3, fontTools, brotli, Google Chrome.
Usage: python3 build-findings-to-fix-pdf.py
"""

import base64
import io
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from fontTools.subset import Subsetter, Options

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

DOCS = Path(__file__).resolve().parent
HTML_OUT = DOCS / "Findings-to-Fix-print-source.html"
PDF_OUT = DOCS / "Findings-to-Fix.pdf"
IMAGES = DOCS / "images"
CACHE = Path(tempfile.gettempdir()) / "cx-findings-to-fix-fonts"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

TOTAL_PAGES = 8

# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------

VIOLET = "#6B34FD"
MAGENTA = "#A822BF"
ORANGE = "#F25929"
BLUE = "#006BD5"
MIDNIGHT = "#140921"

INK = MIDNIGHT
INK_SOFT = "#4A4058"
INK_FAINT = "#6E6580"
RULE = "#DCD6E6"
BOX_LINE = "#CFC7DE"
TINT = "#F7F4FE"
TINT_2 = "#FBFAFE"

# --------------------------------------------------------------------------
# Geometry. All page work is in points: 1pt = 1/72in.
# --------------------------------------------------------------------------

PAGE_W_IN = 8.5
PAGE_H_IN = 11.0
MARGIN_X_IN = 0.9
MARGIN_TOP_IN = 0.82
MARGIN_BOTTOM_IN = 0.95
CONTENT_W_IN = PAGE_W_IN - 2 * MARGIN_X_IN                # 6.7in
CONTENT_W = CONTENT_W_IN * 72.0                           # 482.4pt

# --------------------------------------------------------------------------
# Fonts
# --------------------------------------------------------------------------

FONT_SOURCES = {
    "inter": "https://raw.githubusercontent.com/google/fonts/main/ofl/inter/Inter%5Bopsz,wght%5D.ttf",
    "grotesk": "https://raw.githubusercontent.com/google/fonts/main/ofl/spacegrotesk/SpaceGrotesk%5Bwght%5D.ttf",
    "mono": "https://raw.githubusercontent.com/google/fonts/main/ofl/jetbrainsmono/JetBrainsMono%5Bwght%5D.ttf",
}

# source key -> CSS family name, static weight, axis pins
FONT_INSTANCES = [
    ("inter", "FtfSans", 400, {"wght": 400, "opsz": 14}),
    ("inter", "FtfSans", 500, {"wght": 500, "opsz": 14}),
    ("inter", "FtfSans", 600, {"wght": 600, "opsz": 14}),
    ("inter", "FtfSans", 700, {"wght": 700, "opsz": 14}),
    ("grotesk", "FtfDisplay", 500, {"wght": 500}),
    ("grotesk", "FtfDisplay", 600, {"wght": 600}),
    ("grotesk", "FtfDisplay", 700, {"wght": 700}),
    ("mono", "FtfMono", 400, {"wght": 400}),
    ("mono", "FtfMono", 700, {"wght": 700}),
]

SUBSET_UNICODES = (
    "U+0020-007E,U+00A0,U+00B0,U+00B7,U+2018-201D,U+2022,U+2026,U+2192,U+2713"
)

MIN_FONT_BYTES = 20000


def download(url, dest):
    """Fetch url to dest, accepting only a 200 response with a plausible size."""
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=120) as response:
        status = getattr(response, "status", None)
        if status != 200:
            raise RuntimeError("Download of %s returned HTTP %s" % (url, status))
        payload = response.read()
    if len(payload) < MIN_FONT_BYTES:
        raise RuntimeError("Download of %s returned %d bytes" % (url, len(payload)))
    dest.write_bytes(payload)


def fetch_sources():
    CACHE.mkdir(parents=True, exist_ok=True)
    paths = {}
    for key, url in FONT_SOURCES.items():
        dest = CACHE / ("%s.ttf" % key)
        if not dest.exists() or dest.stat().st_size < MIN_FONT_BYTES:
            print("  downloading %s" % key)
            download(url, dest)
        paths[key] = dest
    return paths


def build_fonts():
    """Return (css @font-face block, {(family, weight): Metrics})."""
    sources = fetch_sources()
    css_parts = []
    metrics = {}
    for key, family, weight, pins in FONT_INSTANCES:
        base = TTFont(str(sources[key]))
        static = instancer.instantiateVariableFont(base, pins, inplace=False, optimize=True)
        static["OS/2"].usWeightClass = weight

        # Metrics are read before subsetting so measurement covers every glyph.
        metrics[(family, weight)] = Metrics(static)

        opts = Options()
        opts.layout_features = ["kern", "liga", "clig", "calt", "ccmp", "locl", "rlig"]
        opts.name_IDs = [1, 2, 3, 4, 6]
        opts.notdef_outline = True
        opts.recalc_bounds = True
        sub = Subsetter(options=opts)
        sub.populate(unicodes=parse_unicodes(SUBSET_UNICODES))
        sub.subset(static)

        static.flavor = "woff2"
        buf = io.BytesIO()
        static.save(buf)
        data = base64.b64encode(buf.getvalue()).decode("ascii")
        css_parts.append(
            "@font-face{font-family:'%s';font-style:normal;font-weight:%d;"
            "font-display:block;src:url(data:font/woff2;base64,%s) format('woff2');}"
            % (family, weight, data)
        )
        print("  %s %d: %.1f KB subset" % (family, weight, len(buf.getvalue()) / 1024))
    return "\n".join(css_parts), metrics


def parse_unicodes(spec):
    out = []
    for part in spec.split(","):
        part = part.strip().replace("U+", "")
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a, 16), int(b, 16) + 1))
        else:
            out.append(int(part, 16))
    return out


class Metrics:
    """Advance-width measurement straight from the instantiated font."""

    def __init__(self, ttfont):
        self.upem = ttfont["head"].unitsPerEm
        self.cmap = ttfont.getBestCmap()
        self.hmtx = ttfont["hmtx"]

    def width(self, text, size):
        total = 0
        for ch in text:
            gname = self.cmap.get(ord(ch)) or self.cmap.get(0x20)
            total += self.hmtx[gname][0]
        return total * size / self.upem

    def wrap(self, text, size, max_width):
        words = text.split()
        lines, cur = [], ""
        for w in words:
            trial = w if not cur else cur + " " + w
            if self.width(trial, size) <= max_width or not cur:
                cur = trial
            else:
                lines.append(cur)
                cur = w
        if cur:
            lines.append(cur)
        return lines


# --------------------------------------------------------------------------
# SVG helpers
# --------------------------------------------------------------------------

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def svg_open(width, height):
    return (
        '<svg class="dg" viewBox="0 0 %.2f %.2f" '
        'style="width:%.4fin;height:%.4fin" xmlns="http://www.w3.org/2000/svg" '
        'role="img">' % (width, height, width / 72.0, height / 72.0)
    )


def rect(x, y, w, h, fill, stroke=None, rx=5, sw=0.7, dash=None):
    s = '<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" rx="%.1f" fill="%s"' % (
        x, y, w, h, rx, fill)
    if stroke:
        s += ' stroke="%s" stroke-width="%.2f"' % (stroke, sw)
    if dash:
        s += ' stroke-dasharray="%s"' % dash
    return s + "/>"


def text(x, y, s, size, weight=400, fill=INK, family="FtfSans", anchor="start",
         spacing=None):
    extra = ' letter-spacing="%.2f"' % spacing if spacing else ""
    return ('<text x="%.2f" y="%.2f" font-family="%s" font-size="%.2f" '
            'font-weight="%d" fill="%s" text-anchor="%s"%s>%s</text>'
            % (x, y, family, size, weight, fill, anchor, extra, esc(s)))


def arrow_h(x1, x2, y, color, head=4.0):
    """Horizontal wire with a solid triangular head at x2."""
    d = 1 if x2 > x1 else -1
    stop = x2 - d * head
    return (
        '<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="%s" stroke-width="1.1" '
        'stroke-linecap="round"/>'
        '<path d="M %.2f %.2f L %.2f %.2f L %.2f %.2f Z" fill="%s"/>'
        % (x1, y, stop, y, color, x2, y, stop, y - head * 0.62, stop, y + head * 0.62, color)
    )


def polyline_arrow(points, color, head=4.0):
    """Elbow wire through the given points, head on the final segment."""
    pts = list(points)
    (x1, y1), (x2, y2) = pts[-2], pts[-1]
    if abs(x2 - x1) > abs(y2 - y1):
        d = 1 if x2 > x1 else -1
        end = (x2 - d * head, y2)
        headpath = "M %.2f %.2f L %.2f %.2f L %.2f %.2f Z" % (
            x2, y2, end[0], y2 - head * 0.62, end[0], y2 + head * 0.62)
    else:
        d = 1 if y2 > y1 else -1
        end = (x2, y2 - d * head)
        headpath = "M %.2f %.2f L %.2f %.2f L %.2f %.2f Z" % (
            x2, y2, x2 - head * 0.62, end[1], x2 + head * 0.62, end[1])
    pts[-1] = end
    d_attr = " ".join("%s %.2f %.2f" % ("M" if i == 0 else "L", p[0], p[1])
                      for i, p in enumerate(pts))
    return ('<path d="%s" fill="none" stroke="%s" stroke-width="1.1" '
            'stroke-linecap="round" stroke-linejoin="round"/>'
            '<path d="%s" fill="%s"/>' % (d_attr, color, headpath, color))


class Box:
    """A node: coloured kicker line, then wrapped body text, auto height."""

    def __init__(self, x, w, kicker, body, accent, metrics,
                 kicker_size=6.8, body_size=7.9, pad_x=9.0, pad_top=9.0,
                 pad_bottom=9.0, lead=10.0, min_h=None):
        self.x, self.w = x, w
        self.accent = accent
        self.kicker = kicker
        self.kicker_size = kicker_size
        self.body_size = body_size
        self.pad_x, self.pad_top, self.pad_bottom, self.lead = pad_x, pad_top, pad_bottom, lead
        inner = w - 2 * pad_x
        m = metrics[("FtfSans", 400)]
        self.lines = m.wrap(body, body_size, inner) if body else []
        h = pad_top + pad_bottom + len(self.lines) * lead
        if kicker:
            h += kicker_size + 4.6
        self.h = max(h, min_h or 0)
        self.y = 0.0
        # Widest rendered line, kicker included. Used to assert nothing overflows.
        km = metrics[("FtfSans", 700)]
        widths = [m.width(ln, body_size) for ln in self.lines]
        if kicker:
            widths.append(km.width(kicker.upper(), kicker_size)
                          + 0.5 * max(len(kicker) - 1, 0))
        self.max_text_w = max(widths) if widths else 0.0

    def place(self, y):
        self.y = y
        return self

    @property
    def cx(self):
        return self.x + self.w / 2

    @property
    def right(self):
        return self.x + self.w

    @property
    def bottom(self):
        return self.y + self.h

    def check(self):
        room = self.w - 2 * self.pad_x
        if self.max_text_w > room + 0.5:
            raise RuntimeError("Box text overflows: %r needs %.1fpt, has %.1fpt"
                               % (self.kicker, self.max_text_w, room))

    def render(self, fill="#FFFFFF", stroke=BOX_LINE):
        self.check()
        out = [rect(self.x, self.y, self.w, self.h, fill, stroke)]
        out.append(rect(self.x, self.y + 5.0, 2.0, self.h - 10.0, self.accent, rx=1))
        ty = self.y + self.pad_top
        tx = self.x + self.pad_x
        if self.kicker:
            ty += self.kicker_size
            out.append(text(tx, ty, self.kicker.upper(), self.kicker_size, 700,
                            self.accent, "FtfSans", spacing=0.5))
            ty += 4.6
        for ln in self.lines:
            ty += self.body_size
            out.append(text(tx, ty, ln, self.body_size, 400, INK_SOFT))
            ty += self.lead - self.body_size
        return "".join(out)


# --------------------------------------------------------------------------
# Diagram 1: After a scan
# --------------------------------------------------------------------------

def diagram_after_scan(M):
    W = CONTENT_W
    gap1 = 22.0
    bw = (W - 2 * gap1) / 3.0
    row_gap = 34.0

    a = Box(0, bw, "Bitbucket", "A developer pushes code or opens a pull request.", VIOLET, M)
    b = Box(bw + gap1, bw, "CI/CD pipeline",
            "The pipeline starts a Checkmarx One scan.", VIOLET, M)
    c = Box(2 * (bw + gap1), bw, "Checkmarx One", "The code is scanned.", VIOLET, M)
    top_h = max(a.h, b.h, c.h)
    for box in (a, b, c):
        box.h = top_h
        box.place(0)

    gap2 = 24.0
    dw = 198.0
    ew = W - dw - gap2
    d = Box(0, dw, "Triage Assist",
            "Evaluates findings for Attackability (reachability, exploitability, "
            "code context, policy) and updates the state of those that require "
            "action to Confirmed.", MAGENTA, M)
    e = Box(dw + gap2, ew, "Remediation Assist",
            "Generates a code fix for a finding on request: the changed files as diffs, "
            "a short explanation, and unit tests.", BLUE, M)
    bot_h = max(d.h, e.h)
    y2 = top_h + row_gap
    for box in (d, e):
        box.h = bot_h
        box.place(y2)

    H = y2 + bot_h
    s = [svg_open(W, H)]
    s.append(a.render())
    s.append(b.render())
    s.append(c.render())
    s.append(d.render())
    s.append(e.render())
    s.append(arrow_h(a.right + 3.5, b.x - 3.0, top_h / 2, VIOLET))
    s.append(arrow_h(b.right + 3.5, c.x - 3.0, top_h / 2, VIOLET))
    wrap_y = top_h + row_gap / 2
    s.append(polyline_arrow([(c.cx, c.bottom + 3.0), (c.cx, wrap_y),
                             (d.cx, wrap_y), (d.cx, d.y - 3.0)], MAGENTA))
    s.append(arrow_h(d.right + 3.5, e.x - 3.0, d.y + bot_h / 2, BLUE))
    s.append("</svg>")
    return "".join(s)


# --------------------------------------------------------------------------
# Diagram 2: What the developer does
# --------------------------------------------------------------------------

def diagram_developer_strip(M):
    W = CONTENT_W
    steps = [
        ("Open the project you want to fix", VIOLET),
        ("Run /cx-findings-to-fix:fix", MAGENTA),
        ("Answer project and branch if asked", MAGENTA),
        ("Accept or reject each change", BLUE),
        ("Let Claude run the generated tests, if you want", ORANGE),
    ]
    n = len(steps)
    gap = 9.6
    cw = (W - gap * (n - 1)) / n
    size = 7.6
    lead = 9.8
    m = M[("FtfSans", 500)]
    wrapped = [m.wrap(t, size, cw - 3.0) for t, _ in steps]
    max_lines = max(len(w) for w in wrapped)

    r = 9.2
    circle_cy = r
    text_top = 2 * r + 12.0
    H = text_top + max_lines * lead + 2.0

    s = [svg_open(W, H)]
    # Connector wires first so the circles sit on top of them.
    for i in range(n - 1):
        x1 = i * (cw + gap) + cw / 2 + r + 2.5
        x2 = (i + 1) * (cw + gap) + cw / 2 - r - 2.0
        s.append(arrow_h(x1, x2, circle_cy, "#B9AFCE", head=3.4))
    for i, ((label, color), lines) in enumerate(zip(steps, wrapped)):
        cx = i * (cw + gap) + cw / 2
        s.append('<circle cx="%.2f" cy="%.2f" r="%.2f" fill="%s"/>' % (cx, circle_cy, r, color))
        s.append(text(cx, circle_cy + 3.2, str(i + 1), 9.2, 700, "#FFFFFF",
                      "FtfDisplay", "middle"))
        ty = text_top
        for ln in lines:
            ty += size
            s.append(text(cx, ty, ln, size, 500, INK_SOFT, "FtfSans", "middle"))
            ty += lead - size
    s.append("</svg>")
    return "".join(s)


# --------------------------------------------------------------------------
# Diagram 3: How a fix travels
# --------------------------------------------------------------------------

def diagram_fix_travels(M):
    W = CONTENT_W
    gap = 19.0
    widths = [104.0, 152.0, 100.0, W - 104.0 - 152.0 - 100.0 - 3 * gap]
    xs = []
    x = 0.0
    for w in widths:
        xs.append(x)
        x += w + gap

    b1 = Box(xs[0], widths[0], "Checkmarx One",
             "Remediation Assist generates the fix.", BLUE, M)
    b2 = Box(xs[1], widths[1], "The ftf tool on your machine",
             "Reads the findings, fetches the fixes, and computes each one against "
             "your current files. Writes nothing into the project on its own.", VIOLET, M)
    b3 = Box(xs[2], widths[2], "Claude Code",
             "Proposes each change as an edit.", MAGENTA, M)
    b4 = Box(xs[3], widths[3], "You", "Accept or reject each change.", ORANGE, M)
    boxes = [b1, b2, b3, b4]
    h = max(b.h for b in boxes)
    for b in boxes:
        b.h = h
        b.place(0)

    note_txt = ("Your Checkmarx One API key stays on this machine. "
                "It never enters the conversation.")
    nsize = 7.3
    nm = M[("FtfSans", 500)]
    nw = nm.width(note_txt, nsize) + 26.0
    nx = min(max(b2.cx - nw / 2, 0.0), W - nw)
    ny = h + 18.0
    nh = 20.0

    s = [svg_open(W, ny + nh)]
    for b in boxes:
        s.append(b.render())
    colors = [BLUE, VIOLET, MAGENTA]
    for i in range(3):
        s.append(arrow_h(boxes[i].right + 3.5, boxes[i + 1].x - 3.0, h / 2, colors[i]))
    s.append('<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="%s" '
             'stroke-width="0.8" stroke-dasharray="2 2"/>'
             % (b2.cx, h + 2.0, b2.cx, ny, VIOLET))
    s.append(rect(nx, ny, nw, nh, "#F4EFFE", VIOLET, rx=9.5, sw=0.7, dash="3 2"))
    s.append('<circle cx="%.2f" cy="%.2f" r="2.4" fill="%s"/>'
             % (nx + 12.0, ny + nh / 2, VIOLET))
    s.append(text(nx + 19.0, ny + nh / 2 + 2.4, note_txt, nsize, 500, MIDNIGHT))
    s.append("</svg>")
    return "".join(s)


# --------------------------------------------------------------------------
# Screenshots
# --------------------------------------------------------------------------

SHOTS = ("command.png", "findings-table.png", "edit-prompt.png", "explain.png")


def png_size(data):
    """Pixel size straight from the PNG IHDR chunk."""
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    return (int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big"))


def figure(filename, caption, src_w, src_h, display_w_in, fig_w_in=None):
    """Embed images/<filename> if it exists, otherwise a placeholder box.

    The image is placed at its own aspect ratio and is never scaled past its
    native pixel size, so print stays sharp.
    """
    path = IMAGES / filename
    if path.exists():
        raw = path.read_bytes()
        size = png_size(raw)
        if size:
            src_w, src_h = size
        width_in = min(display_w_in, src_w / 96.0)
        height_in = width_in * src_h / src_w
        data = base64.b64encode(raw).decode("ascii")
        ext = path.suffix.lstrip(".").lower()
        inner = ('<img class="shot" src="data:image/%s;base64,%s" '
                 'style="width:%.3fin;height:%.3fin" alt="%s"/>'
                 % ("jpeg" if ext in ("jpg", "jpeg") else ext, data,
                    width_in, height_in, esc(caption)))
    else:
        width_in = display_w_in
        height_in = width_in * src_h / src_w
        inner = ('<div class="shot ph" style="width:%.3fin;height:%.3fin">'
                 '<span>screenshot</span></div>' % (width_in, height_in))
    return ('<figure class="fig" style="width:%.3fin"><div class="figbox">%s</div>'
            '<figcaption>%s</figcaption></figure>'
            % (max(fig_w_in or width_in, width_in), inner, esc(caption)))


def present_images():
    return {f: (IMAGES / f).exists() for f in SHOTS}


# --------------------------------------------------------------------------
# Page content
# --------------------------------------------------------------------------

def page(n, body, kind=""):
    return ('<section class="page %s"><div class="body">%s</div>'
            '<div class="foot"><span class="foot-l">Findings-to-Fix</span>'
            '<span class="foot-r">Page %d of %d</span></div></section>'
            % (kind, body, n, TOTAL_PAGES))


def head(title, lead=None):
    out = '<h1 class="ph1">%s</h1>' % esc(title)
    if lead:
        out += '<p class="lead">%s</p>' % lead
    return out


def build_html(font_css, M):
    d1 = diagram_after_scan(M)
    d2 = diagram_developer_strip(M)
    d3 = diagram_fix_travels(M)

    # ---------------- Page 1: cover ----------------
    p1 = """
<div class="cover">
  <div class="cover-mark"></div>
  <h1 class="title">Findings-to-Fix</h1>
  <p class="subtitle">Fix confirmed Checkmarx findings from your terminal or editor
     with Claude&nbsp;Code</p>
  <div class="rule-accent"></div>
  <p class="summary">Built on Checkmarx One Triage Assist and Remediation Assist. Triage Assist
     has already evaluated the findings on the platform, using reachability, exploitability,
     code context, and policy signals, and confirmed the ones that require action.
     Findings-to-Fix takes only those, asks Remediation Assist to generate the review-ready
     fix, and shows you each change in Claude Code as a diff to accept or reject. The agent
     proposes; you approve.</p>
  <div class="cover-cols">
    <div class="panel">
      <h2 class="pnl-h">What you need</h2>
      <ul class="ticks">
        <li><b>A Checkmarx One API key</b> on your machine, in your shell profile
            or in the <code>cx</code> CLI configuration.</li>
        <li><b>Python 3 or Node</b> on your machine. Either one works.</li>
        <li><b>Claude Code</b> in a terminal, or through its VS&nbsp;Code or
            JetBrains extension.</li>
      </ul>
    </div>
    <div class="panel contents">
      <h2 class="pnl-h">Contents</h2>
      <ol class="toc">
        <li><span>How it fits together</span><i>2</i></li>
        <li><span>Getting started</span><i>3</i></li>
        <li><span>Using it</span><i>4</i></li>
        <li><span>Reviewing each change</span><i>5</i></li>
        <li><span>What happens, step by step</span><i>6</i></li>
        <li><span>Where things live and what can happen</span><i>7</i></li>
        <li><span>Rolling out to a team</span><i>8</i></li>
      </ol>
    </div>
  </div>
  <p class="cover-note">Only findings that Checkmarx Triage Assist has marked
     <b>Confirmed</b>, at critical or high severity, are fixed. Nothing is committed
     or pushed. You review, then commit as usual.</p>
</div>
"""

    # ---------------- Page 2: how it fits together ----------------
    p2 = head("How it fits together",
              "Three views of the same flow: what the platform does after a scan, "
              "what a developer does at the keyboard, and the path a single fix takes.")
    p2 += """
<div class="dgblock">
  <h2 class="dg-h"><span class="dg-n">1</span>After a scan</h2>
  %s
  <p class="dg-cap">All of this happens on the Checkmarx One platform. No developer
     action is needed for any of it.</p>
</div>
<div class="dgblock">
  <h2 class="dg-h"><span class="dg-n">2</span>What the developer does</h2>
  %s
  <p class="dg-cap">Five steps in Claude Code. Type <code>/cx-f</code> and press Tab to
     complete the command name. Adding the project and branch after it skips step 3.</p>
</div>
<div class="dgblock">
  <h2 class="dg-h"><span class="dg-n">3</span>How a fix travels</h2>
  %s
  <p class="dg-cap">Every change to code arrives as an edit that you accept or reject.
     The plugin never commits or pushes.</p>
</div>
""" % (d1, d2, d3)

    # ---------------- Page 3: getting started ----------------
    p3 = head("Getting started",
              "Three things once. After that it is one command.")
    p3 += """
<ol class="steps">
  <li>
    <h2>A Checkmarx One API key on your machine</h2>
    <p>Ask your Checkmarx admin for an API key. Then either put it in your shell profile:</p>
    <pre class="code">export CX_APIKEY=&lt;your key&gt;</pre>
    <p>or, if you already use the Checkmarx <code>cx</code> command line tool:</p>
    <pre class="code">cx configure set --prop-name cx_apikey --prop-value &lt;your key&gt;</pre>
    <p>Findings-to-Fix reads it from either place. It never shows the key to Claude.</p>
  </li>
  <li>
    <h2>Python or Node on your machine</h2>
    <p>Either one works. Most Macs and Linux machines already have Python 3. On Windows,
       if you have <code>python3</code> or <code>node</code> in a terminal, you are set.</p>
  </li>
  <li>
    <h2>Install the plugin</h2>
    <pre class="code">claude plugin marketplace add cx-israel-ogunsakin/cx-findings-to-fix-claude
claude plugin install cx-findings-to-fix@cx-findings-to-fix-claude</pre>
    <p>For a private copy of the repository, use its Git URL or a local folder path in the
       first command. Claude Code's Bash tool has to be allowed, and the first run asks you
       to permit the plugin's command.</p>
  </li>
</ol>
<div class="figrow one">%s</div>
""" % figure("command.png",
             "Type /cx-f, press Tab, and add the project and branch if you know them",
             1804, 459, CONTENT_W_IN)

    # ---------------- Page 4: using it ----------------
    p4 = head("Using it", "Open a project, run one command, then review each change.")
    p4 += """
<ol class="steps tight">
  <li><h2>Open the project you want to fix and start Claude Code</h2>
      <p>Run <code>claude</code> in a terminal in the project folder. The Claude Code
         extensions for VS&nbsp;Code and JetBrains work the same way.</p></li>
  <li><h2>Type <code class="inl">/cx-f</code>, press Tab to complete, then Enter</h2>
      <p>Add the project name and branch after the command to skip the questions:
         <code>/cx-findings-to-fix:fix CxRW-Sandbox/ProjectHub9 feat/update-routes</code></p></li>
</ol>
<h2 class="sub-h">Claude will</h2>
<ul class="dots">
  <li>work out which Checkmarx project and scan this is. If the project name does not
      match your git setup, it lists the likely projects and asks you to pick. If only one
      branch has scans (common for monorepos and zip uploads, which Checkmarx files under
      the branch name <span class="mono">.unknown</span>), it uses that and tells you. If
      several branches have scans and yours is not one of them, it lists the most recently
      scanned ones with dates and asks. It never guesses.</li>
  <li>fetch the fixes from Checkmarx: a couple of minutes the first time, seconds after that.</li>
  <li>show you a table of the confirmed findings and ask which to apply.</li>
  <li>propose each change as an edit you accept or reject, file by file.</li>
  <li>explain what each fix does and why, then offer to run the tests Checkmarx generated.</li>
</ul>
<p class="note-line">Nothing is committed or pushed. You review, then commit as usual.</p>
<div class="figrow one">%s</div>
""" % figure("findings-table.png",
             "Claude lists the confirmed findings and asks which to apply",
             1804, 710, CONTENT_W_IN)

    # ---------------- Page 5: reviewing each change ----------------
    p5 = head("Reviewing each change",
              "Each change is a diff you decide on, and Claude explains itself afterwards.")
    p5 += """
<ul class="dots">
  <li>Claude Code asks before every edit: <b>Yes</b>, <b>Yes, and don't ask again this
      session</b>, or <b>No, and tell Claude what to do differently</b>.</li>
  <li>Answering No leaves the file as it was, and you can say what you would rather have.</li>
  <li>When the edits are done, Claude explains the finding and names the tests
      Remediation Assist generated for it.</li>
</ul>
<div class="figstack">%s%s</div>
""" % (figure("edit-prompt.png",
              "Each change is shown as a diff; choose Yes to accept it or No to reject",
              1804, 752, CONTENT_W_IN),
       figure("explain.png",
              "After the edits, Claude explains what was wrong, why it matters, "
              "and how the fix works",
              1804, 836, CONTENT_W_IN))

    # ---------------- Page 6: step by step ----------------
    p6 = head("What happens, step by step",
              "The full sequence, from the command to the commit.")
    p6 += """
<ol class="seq">
  <li><b>The developer runs the command.</b> In Claude Code, <code>/cx-findings-to-fix:fix</code>,
      optionally followed by the project name and branch.</li>
  <li><b>Claude runs the tool.</b> The tool reads the project's git remote and current
      branch and looks the project up in Checkmarx One.</li>
  <li><b>The tool asks when it is unsure.</b> If the name matches no project, or the branch
      has no completed scan, Claude shows a numbered list and the developer picks.</li>
  <li><b>The tool fetches the fixes.</b> It lists the Confirmed critical and high findings
      on the latest completed scan and sends them to Remediation Assist in one request.</li>
  <li><b>Claude shows the findings</b> as a table and asks which to apply.</li>
  <li><b>The tool computes each fix against the current files</b> without writing anything,
      producing the complete new content for each changed file.</li>
  <li><b>Claude proposes each fix as an edit.</b> The change is shown as a diff the
      developer accepts or rejects, file by file.</li>
  <li><b>Files that changed since the scan are placed by hand,</b> so the developer's own
      edits stay in place.</li>
  <li><b>Claude explains each fix</b> (what, why, how) and names the tests Remediation
      Assist generated.</li>
  <li><b>Claude offers to run those tests</b> and does so only if the developer says yes.
      The developer then commits as usual. The plugin never commits or pushes.</li>
</ol>
<div class="callout">
  <h2 class="pnl-h">When a file changed since the scan</h2>
  <p>Claude reads the intended change and the current file, makes the same change where the
     code now lives, leaves the developer's other edits in place, and says plainly that this
     fix was placed by hand and deserves a closer look. Claude never overwrites a whole file
     on its own. Fresh fixes take two to three minutes. Fixes that already exist come back
     in seconds.</p>
</div>
<h2 class="sub-h">The whole run, end to end</h2>
<pre class="transcript">&gt; /cx-findings-to-fix:fix CxRW-Sandbox/ProjectHub9 feat/update-routes
  Project CxRW-Sandbox/ProjectHub9, branch feat/update-routes, scan from 2026-08-13.
  | Index | Severity | Query      | Location           | Status | Files                           |
  | 0     | CRITICAL | Stored_XSS | backend/app.py:137 | READY  | jinja_filters.py, test_utils.py |
  Apply this fix?
&gt; yes
  Edit(backend/utils/jinja_filters.py)
  Do you want to make this edit to jinja_filters.py?
  1. Yes  2. Yes, and don't ask again this session  3. No, and tell Claude what to do differently
&gt; 1
  Fixes accepted. Explanation: What ... Why ... How ...
  Checkmarx generated tests in backend/tests/test_utils.py. Run them?</pre>
"""

    # ---------------- Page 7: boundaries ----------------
    p7 = head("Where things live and what can happen",
              "Which credential is used where, and the boundaries the plugin works inside.")
    p7 += """
<h2 class="sub-h">Where the credential goes and does not go</h2>
<table class="tbl cred">
  <thead><tr><th>Credential</th><th>Lives</th><th>Used by</th><th>Never reaches</th></tr></thead>
  <tbody>
    <tr><td><b>Checkmarx One API key</b></td>
        <td>shell profile or <code>cx</code> CLI config on the workstation</td>
        <td>the <code>ftf</code> tool, which exchanges it for a short-lived token in memory</td>
        <td>the assistant's conversation, Anthropic</td></tr>
    <tr><td><b>Claude Code session</b></td>
        <td>Claude Code's sign-in</td>
        <td>Claude Code</td>
        <td>Checkmarx</td></tr>
    <tr><td><b>CI/CD credential that triggers scans</b></td>
        <td>the CI/CD system</td>
        <td>the pipeline</td>
        <td>the developer's machine</td></tr>
  </tbody>
</table>
<div class="two-col">
  <div class="panel">
    <h2 class="pnl-h">What can and cannot happen</h2>
    <ul class="dots small">
      <li>The plugin reads findings and fetches fixes. It cannot change a finding's state,
          trigger a scan, or touch Checkmarx configuration.</li>
      <li>Every change to code arrives as an edit the developer accepts. The tool writes
          nothing into the project on its own during the normal flow.</li>
      <li>The plugin never commits or pushes.</li>
      <li>Only Confirmed critical and high findings are considered. Package (SCA) fixes are
          supported and off by default.</li>
      <li>Nothing runs on a server. Nothing is installed besides the plugin folder.</li>
    </ul>
  </div>
  <div class="panel">
    <h2 class="pnl-h">Good to know</h2>
    <ul class="dots small">
      <li>It works whether your project folder is a git clone or a plain folder.</li>
      <li>Monorepos: open one service's folder rather than the whole repository and you see
          only the findings under that folder, with the project's total noted. Ask for "all
          findings" to see everything.</li>
      <li>Ask Claude to "include package fixes" when you want SCA fixes as well.</li>
      <li>Claude Code's Bash tool has to be allowed. The first run asks you to permit the
          plugin's command.</li>
      <li>If something is missing (no API key, expired key, feature not enabled on your
          tenant), Claude tells you exactly what and how to fix it.</li>
      <li>Triage Assist sets the Confirmed and Proposed Not Exploitable states on the
          platform. Nothing in the plugin changes those verdicts.</li>
    </ul>
  </div>
</div>
"""

    # ---------------- Page 8: rollout ----------------
    p8 = head("Rolling out to a team",
              "Host the plugin repository somewhere developers can reach, then let them "
              "install it in two commands.")
    p8 += """
<div class="two-col routes">
  <div class="panel">
    <div class="route-tag">Install</div>
    <h2 class="pnl-h">Each developer runs two commands</h2>
    <p>The repository can sit in GitHub, Bitbucket, or an internal Git server. Each
       developer adds it as a marketplace and installs the plugin from it, once:</p>
    <pre class="code">claude plugin marketplace add &lt;repository URL&gt;
claude plugin install cx-findings-to-fix@cx-findings-to-fix-claude</pre>
  </div>
  <div class="panel">
    <div class="route-tag">Managed settings</div>
    <h2 class="pnl-h">Pre-approve it centrally</h2>
    <p>Claude Code's managed settings can pre-approve the marketplace for everyone, so each
       developer does not have to approve the source themselves.</p>
    <p>Per developer, one time: a Checkmarx One API key, Python 3 or Node on the machine,
       and Claude Code's Bash tool allowed. The first run asks the developer to permit the
       plugin's command.</p>
  </div>
</div>
<h2 class="sub-h">What is in the plugin</h2>
<table class="tbl parts">
  <thead><tr><th>Path</th><th>What it is</th></tr></thead>
  <tbody>
    <tr><td><code>.claude-plugin/plugin.json</code></td>
        <td>Tells Claude Code this is a plugin</td></tr>
    <tr><td><code>.claude-plugin/marketplace.json</code></td>
        <td>Lets the repository be added as a marketplace</td></tr>
    <tr><td><code>commands/fix.md</code></td>
        <td>The <code>/cx-findings-to-fix:fix</code> command and its instructions</td></tr>
    <tr><td><code>agents/findings-to-fix.md</code></td>
        <td>A subagent with the same instructions</td></tr>
    <tr><td><code>skills/fix-confirmed-findings/SKILL.md</code></td>
        <td>The same instructions as a skill</td></tr>
    <tr><td><code>skills/fix-confirmed-findings/ftf.py</code>, <code>ftf.js</code></td>
        <td>The tool that talks to Checkmarx (Python and Node versions, identical)</td></tr>
    <tr><td><code>hooks/</code></td><td>The one-line "installed" note at session start</td></tr>
    <tr><td><code>docs/</code></td><td>The guide and architecture document</td></tr>
  </tbody>
</table>
<p class="note-line">Nothing runs on a server. Nothing is installed besides the plugin folder.
   A GitHub Copilot version of the same plugin exists as a separate repository,
   cx-findings-to-fix.</p>
<div class="support">
  <h2 class="pnl-h">Support</h2>
  <p>Questions and issues: open an issue in the plugin repository.</p>
</div>
"""

    pages = "".join([
        page(1, p1, "cover-page"),
        page(2, p2),
        page(3, p3),
        page(4, p4),
        page(5, p5),
        page(6, p6),
        page(7, p7),
        page(8, p8),
    ])
    return HTML_SHELL % (font_css, CSS, pages)


# --------------------------------------------------------------------------
# CSS + shell
# --------------------------------------------------------------------------

CSS = """
:root{
  --violet:%(violet)s; --magenta:%(magenta)s; --orange:%(orange)s;
  --blue:%(blue)s; --ink:%(ink)s; --ink-soft:%(inksoft)s; --ink-faint:%(inkfaint)s;
  --rule:%(rule)s; --box:%(boxline)s; --tint:%(tint)s; --tint2:%(tint2)s;
}
*{box-sizing:border-box;}
html,body{margin:0;padding:0;background:#fff;}
body{
  font-family:'FtfSans',system-ui,sans-serif; color:var(--ink);
  font-size:9.6pt; line-height:1.45;
  -webkit-font-smoothing:antialiased;
  -webkit-print-color-adjust:exact; print-color-adjust:exact;
}
.page{
  position:relative; width:%(pw)sin; height:%(ph)sin; overflow:hidden;
  padding:%(mt)sin %(mx)sin %(mb)sin %(mx)sin; background:#fff;
}
.page + .page{break-before:page;}
.body{width:%(cw)sin;}
.foot{
  position:absolute; left:%(mx)sin; right:%(mx)sin; bottom:0.52in;
  display:flex; justify-content:space-between; align-items:center;
  border-top:0.5pt solid var(--rule); padding-top:5pt;
  font-size:7.4pt; color:var(--ink-faint); letter-spacing:0.02em;
}
.foot-l{font-weight:600;color:var(--ink-soft);}

/* headings */
h1,h2,h3{margin:0;font-family:'FtfDisplay','FtfSans',sans-serif;font-weight:600;}
.ph1{font-size:20pt; line-height:1.12; letter-spacing:-0.012em; color:var(--ink);}
.ph1::after{
  content:""; display:block; width:38pt; height:2.4pt; margin-top:7pt;
  background:var(--violet); border-radius:2pt;
}
.lead{margin:9pt 0 15pt; font-size:9.8pt; color:var(--ink-soft); max-width:5.9in;}
.sub-h{font-size:10.4pt; margin:14pt 0 7pt; color:var(--ink);}
.pnl-h{font-size:9.6pt; margin:0 0 6pt; color:var(--ink);}
p{margin:0 0 6pt;}

/* cover */
.cover-page{padding-top:1.45in;}
.cover-mark{
  width:52pt; height:5pt; border-radius:3pt; margin-bottom:22pt;
  background:linear-gradient(90deg,var(--violet) 0%%,var(--magenta) 100%%);
}
.title{
  font-family:'FtfDisplay',sans-serif; font-weight:700; font-size:46pt;
  line-height:1.0; letter-spacing:-0.028em; color:var(--ink); margin-bottom:12pt;
}
.subtitle{font-size:13pt; color:var(--ink-soft); font-weight:400; margin:0 0 22pt; max-width:6.7in;}
.rule-accent{
  height:3pt; width:100%%; border-radius:2pt; margin-bottom:20pt;
  background:linear-gradient(90deg,var(--violet) 0%%,var(--magenta) 42%%,var(--blue) 74%%,var(--orange) 100%%);
}
.summary{font-size:11.6pt; line-height:1.55; color:var(--ink); max-width:5.5in; margin-bottom:30pt;}
.cover-cols{display:flex; gap:20pt; align-items:stretch;}
.cover-cols .panel{flex:1;}
.panel{
  background:var(--tint2); border:0.6pt solid var(--rule); border-radius:6pt;
  padding:12pt 13pt 12pt;
}
.contents{background:#fff;}
ul.ticks{margin:0; padding:0; list-style:none;}
ul.ticks li{position:relative; padding-left:13pt; margin-bottom:7pt; font-size:9.1pt; color:var(--ink-soft);}
ul.ticks li:last-child{margin-bottom:0;}
ul.ticks li::before{
  content:""; position:absolute; left:0; top:4.2pt; width:5pt; height:5pt;
  border-radius:1.5pt; background:var(--violet);
}
ul.ticks b{color:var(--ink); font-weight:600;}
ol.toc{margin:0; padding:0; list-style:none;}
ol.toc li{
  display:flex; align-items:baseline; gap:6pt; font-size:9.1pt;
  padding:4.6pt 0; border-bottom:0.5pt dotted var(--rule); color:var(--ink-soft);
}
ol.toc li:last-child{border-bottom:none;}
ol.toc span{flex:1;}
ol.toc i{font-style:normal; font-weight:600; color:var(--violet); font-size:8.6pt;}
.cover-note{
  margin-top:30pt; font-size:9pt; color:var(--ink-soft);
  border-left:2pt solid var(--magenta); padding-left:10pt; max-width:5.9in;
}
.cover-note b{color:var(--ink);}

/* diagrams */
.dgblock{margin-bottom:21pt;}
.dgblock:last-child{margin-bottom:0;}
.dg-h{font-size:10.6pt; margin:0 0 9pt; display:flex; align-items:center; gap:7pt;}
.dg-n{
  display:inline-flex; align-items:center; justify-content:center;
  width:14.5pt; height:14.5pt; border-radius:50%%; background:var(--ink); color:#fff;
  font-size:8.2pt; font-weight:700; font-family:'FtfDisplay',sans-serif;
}
svg.dg{display:block;}
.dg-cap{margin:9pt 0 0; font-size:8.6pt; color:var(--ink-faint); max-width:6.3in;}

/* numbered walkthroughs */
ol.steps{margin:0; padding:0; list-style:none; counter-reset:st;}
ol.steps > li{
  counter-increment:st; position:relative; padding-left:26pt; margin-bottom:13pt;
}
ol.steps > li:last-child{margin-bottom:0;}
ol.steps > li::before{
  content:counter(st); position:absolute; left:0; top:-0.5pt;
  width:17pt; height:17pt; border-radius:50%%; background:var(--violet); color:#fff;
  font-family:'FtfDisplay',sans-serif; font-weight:700; font-size:9pt;
  display:flex; align-items:center; justify-content:center;
}
ol.steps > li > h2{font-size:10.2pt; margin:1.5pt 0 5pt;}
ol.steps p{font-size:9.2pt; color:var(--ink-soft);}
ol.steps.tight > li{margin-bottom:9pt;}
ol.substeps{margin:0 0 6pt; padding-left:14pt; font-size:9.2pt; color:var(--ink-soft);}
ol.substeps li{margin-bottom:3.4pt;}
ol.substeps b{color:var(--ink);}

ul.dots{margin:0 0 6pt; padding:0; list-style:none;}
ul.dots li{position:relative; padding-left:12pt; margin-bottom:5.4pt; font-size:9.2pt; color:var(--ink-soft);}
ul.dots li::before{
  content:""; position:absolute; left:1pt; top:4.4pt; width:4pt; height:4pt;
  border-radius:50%%; background:var(--violet);
}
ul.dots.small li{font-size:8.9pt; margin-bottom:6.4pt;}
ul.dots b{color:var(--ink);}
.note-line{
  font-size:9.2pt; color:var(--ink); font-weight:500;
  border-left:2pt solid var(--orange); padding-left:9pt; margin:10pt 0 0;
}

/* sequence list */
ol.seq{margin:0; padding:0; list-style:none; counter-reset:sq;}
ol.seq li{
  counter-increment:sq; position:relative; padding-left:22pt; margin-bottom:6.2pt;
  font-size:9.1pt; color:var(--ink-soft);
}
ol.seq li::before{
  content:counter(sq); position:absolute; left:0; top:0.6pt; width:14pt;
  font-family:'FtfDisplay',sans-serif; font-weight:700; font-size:8.6pt;
  color:var(--violet); text-align:right;
}
ol.seq b{color:var(--ink); font-weight:600;}
.callout{
  margin:12pt 0 0; padding:11pt 13pt; border-radius:6pt;
  background:var(--tint); border:0.6pt solid #E2D9FA;
}
.callout p{font-size:8.9pt; color:var(--ink-soft); margin:0;}

/* code and transcript */
code,pre.code,pre.transcript{font-variant-ligatures:none; font-feature-settings:"liga" 0,"calt" 0;}
code{font-family:'FtfMono',monospace; font-size:8.4pt; color:var(--ink);
     background:#F3F0F9; padding:0.7pt 2.6pt; border-radius:2.5pt;}
code.inl{font-size:9.2pt;}
pre.code{
  font-family:'FtfMono',monospace; font-size:8.4pt; margin:5pt 0 6pt; padding:7pt 9pt;
  background:#F7F5FC; border:0.5pt solid var(--rule); border-left:2pt solid var(--violet);
  border-radius:4pt; color:var(--ink); white-space:pre-wrap; line-height:1.35;
}
.routes pre.code{font-size:7.5pt;}
pre.transcript{
  font-family:'FtfMono',monospace; font-size:7.05pt; line-height:1.5; margin:0;
  padding:10pt 12pt; background:#FAF8FE; border:0.6pt solid #E4DDF4;
  border-left:2.4pt solid var(--violet); border-radius:5pt; color:#2A2038;
  white-space:pre; overflow:hidden;
}

/* tables */
table.tbl{width:100%%; border-collapse:collapse; font-size:8.7pt;}
table.tbl th{
  text-align:left; font-family:'FtfDisplay',sans-serif; font-weight:600; font-size:8.2pt;
  color:#fff; background:var(--ink); padding:5.6pt 8pt;
}
table.tbl th:first-child{border-top-left-radius:4pt;}
table.tbl th:last-child{border-top-right-radius:4pt;}
table.tbl td{
  padding:6.4pt 8pt; border-bottom:0.5pt solid var(--rule); color:var(--ink-soft);
  vertical-align:top;
}
table.tbl tbody tr:nth-child(even){background:var(--tint2);}
table.tbl td b{color:var(--ink); font-weight:600;}
table.cred td:nth-child(1){width:23%%;}
table.cred td:nth-child(2){width:26%%;}
table.cred td:nth-child(3){width:30%%;}
table.parts td{padding:5.2pt 8pt;}
table.parts td:nth-child(1){width:42%%;}
table.parts code{background:none; padding:0; font-size:8pt;}

.two-col{display:flex; gap:16pt; margin-top:14pt; align-items:stretch;}
.two-col .panel{flex:1;}
.routes .panel{background:#fff;}
.route-tag{
  font-size:7.2pt; font-weight:700; letter-spacing:0.14em; text-transform:uppercase;
  color:var(--violet); margin-bottom:5pt;
}
.support{
  margin-top:14pt; padding:11pt 13pt; border-radius:6pt; background:var(--tint);
  border:0.6pt solid #E2D9FA;
}
.support p{margin:0; font-size:9pt; color:var(--ink-soft);}

/* figures */
.figrow{display:flex; gap:18pt; margin-top:15pt;}
.figrow.one{justify-content:flex-start;}
.figrow.two{justify-content:flex-start; align-items:flex-end;}
.figstack{display:flex; flex-direction:column; gap:13pt; margin-top:14pt;}
figure.fig{margin:0;}
.figbox{display:block;}
.shot{display:block; border-radius:4pt;}
.shot:not(.ph){border:0.6pt solid var(--box);}
.ph{
  border:1pt dashed #B9A9E8;
  background:repeating-linear-gradient(135deg,#FBF9FF 0 7pt,#F5F1FE 7pt 14pt);
  display:flex; align-items:center; justify-content:center;
}
.ph span{
  font-size:8pt; font-weight:600; letter-spacing:0.14em; text-transform:uppercase;
  color:#8C79C6;
}
figcaption{margin-top:6pt; font-size:8.1pt; color:var(--ink-faint); line-height:1.35;}
""" % {
    "violet": VIOLET, "magenta": MAGENTA, "orange": ORANGE, "blue": BLUE,
    "ink": INK, "inksoft": INK_SOFT, "inkfaint": INK_FAINT, "rule": RULE,
    "boxline": BOX_LINE, "tint": TINT, "tint2": TINT_2,
    "pw": PAGE_W_IN, "ph": PAGE_H_IN, "mx": MARGIN_X_IN, "mt": MARGIN_TOP_IN,
    "mb": MARGIN_BOTTOM_IN, "cw": CONTENT_W_IN,
}

HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Findings-to-Fix</title>
<style>
@page{size:8.5in 11in;margin:0;}
%s
%s
</style>
</head>
<body>
%s
</body>
</html>
"""


# --------------------------------------------------------------------------
# Print
# --------------------------------------------------------------------------

def print_pdf():
    if not os.path.exists(CHROME):
        sys.exit("Google Chrome not found at %s" % CHROME)
    profile = tempfile.mkdtemp(prefix="ftf-chrome-")
    try:
        cmd = [
            CHROME, "--headless=old", "--disable-gpu", "--no-sandbox",
            "--no-first-run", "--no-pdf-header-footer",
            "--disable-crash-reporter", "--disable-extensions",
            "--user-data-dir=" + profile,
            "--virtual-time-budget=20000",
            "--print-to-pdf=" + str(PDF_OUT),
            HTML_OUT.as_uri(),
        ]
        if PDF_OUT.exists():
            PDF_OUT.unlink()
        stderr = ""
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            stderr = res.stderr or ""
        except subprocess.TimeoutExpired:
            # Chrome sometimes lingers after writing the file; the file is what counts.
            stderr = "Chrome did not exit within the timeout."
        if not PDF_OUT.exists():
            sys.exit("Chrome failed to print:\n" + stderr[-3000:])
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def main():
    print("Building font subsets")
    font_css, metrics = build_fonts()
    print("Writing HTML")
    html = build_html(font_css, metrics)
    HTML_OUT.write_text(html, encoding="utf-8")
    print("  %s (%.0f KB)" % (HTML_OUT.name, HTML_OUT.stat().st_size / 1024))
    for name, present in present_images().items():
        print("  image %s: %s" % (name, "embedded" if present else "placeholder"))
    print("Printing PDF")
    print_pdf()
    print("  %s (%.0f KB)" % (PDF_OUT.name, PDF_OUT.stat().st_size / 1024))


if __name__ == "__main__":
    main()
