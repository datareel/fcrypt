#!/usr/bin/env python3
"""Write docs/security_design.html, a standalone copy of the fcrypt security
design white paper, from docs/security_design.php (the source of
https://datareel.com/fcrypt/security_design.php), for the release packages.

Run from the repository root after copying the page from the websites repo:
  cp ../websites/datareel/fcrypt/security_design.php docs/
  python3 docs/make_docs_html.py
The page's own <style> and <article> are kept; the site header, menu and
footer are left out, and site links become https://datareel.com links.
"""
import html
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(ROOT, 'security_design.php'), encoding='utf-8').read()

m_t = re.search(r"\$dr2_t = '([^']*)';", src)
m_d = re.search(r"\$dr2_d = '([^']*)';", src)
m_style = re.search(r'<style>(.*?)</style>', src, re.S)
m_art = re.search(r'<article class="dr2-doc">(.*?)</article>', src, re.S)
if not (m_t and m_d and m_style and m_art):
    sys.exit('security_design.php does not have the expected title, description, style and article')
body = m_art.group(1)
if '<?' in body:
    sys.exit('the article holds PHP code, the standalone copy would be wrong')
# Site links to the live site
body = re.sub(r'(href|src)="/', r'\1="https://datareel.com/', body)
title = html.unescape(m_t.group(1))

page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{m_d.group(1)}">
<!-- Made by docs/make_docs_html.py from docs/security_design.php
     (https://datareel.com/fcrypt/security_design.php); edit the page, not this file. -->
<style>
:root {{
  --dr2-text: #1d2430; --dr2-muted: #5b6575; --dr2-bg: #ffffff; --dr2-surface-2: #f3f5f8;
  --dr2-border-strong: #8a94a6; --dr2-accent: #2a6fdb; --dr2-accent-soft: #e3edfc;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --dr2-text: #e6e9ef; --dr2-muted: #a3acbb; --dr2-bg: #14181f; --dr2-surface-2: #1f2530;
    --dr2-border-strong: #6c7688; --dr2-accent: #7aa9f5; --dr2-accent-soft: #1d2b44;
  }}
}}
body {{ background: var(--dr2-bg); color: var(--dr2-text); margin: 0;
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }}
article {{ max-width: 920px; margin: 0 auto; padding: 24px 16px 48px; }}
a {{ color: var(--dr2-accent); }}
code {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.92em; }}
table {{ border-collapse: collapse; }}
th, td {{ border: 1px solid var(--dr2-border-strong); padding: 4px 8px; text-align: left; vertical-align: top; }}
h1 {{ font-size: 1.7em; margin-top: 0; }}
{m_style.group(1)}
</style>
</head>
<body>
<article class="dr2-doc">
<h1>{html.escape(title)}</h1>
<p>{m_d.group(1)}</p>
<p>The current copy is at <a href="https://datareel.com/fcrypt/security_design.php">https://datareel.com/fcrypt/security_design.php</a>.</p>
{body}
</article>
</body>
</html>
'''
out = os.path.join(ROOT, 'security_design.html')
open(out, 'w', encoding='utf-8').write(page)
print('wrote', os.path.relpath(out), len(page), 'bytes')
