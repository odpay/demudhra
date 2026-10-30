#!/usr/bin/env python3
"""Render the static site from site/ and data/.

Inputs: site/index.src.html (template), site/transcript.raw (raw pty output from
tools/capture_transcript.py), data/fingerprints.tsv and data/certs.json.
site/og.png is rendered from site/og.html with headless Chrome:
  cd site && google-chrome --headless=new --window-size=1200,630 --screenshot=og.png og.html
"""
import html
import json
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE = ROOT / 'site'
E = lambda s: html.escape(s, quote=True)  # noqa: E731
STATIC = ('style.css', 'favicon.svg', 'og.png')
# Cookieless PostHog page analytics for the HTML pages only. /run, the scripts
# and the fingerprint data never load or send anything to it.
ANALYTICS = """<script>
!function(t,e){var o,n,p,r;e.__SV||(window.posthog&&window.posthog.__loaded)||(window.posthog=e,e._i=[],e.init=function(i,s,a){function g(t,e){var o=e.split(".");2==o.length&&(t=t[o[0]],e=o[1]),t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}}(p=t.createElement("script")).type="text/javascript",p.crossOrigin="anonymous",p.async=!0,p.src=s.api_host+"/static/array.js",(r=t.getElementsByTagName("script")[0]).parentNode.insertBefore(p,r);var u=e;for(void 0!==a?u=e[a]=[]:a="posthog",u.people=u.people||[],u.toString=function(t){var e="posthog";return"posthog"!==a&&(e+="."+a),t||(e+=" (stub)"),e},u.people.toString=function(){return u.toString(1)+".people (stub)"},o="init capture register register_once unregister opt_out_capturing has_opted_out_capturing opt_in_capturing reset get_distinct_id get_session_id".split(" "),n=0;n<o.length;n++)g(u,o[n]);e._i.push([i,s,a])},e.__SV=1)}(document,window.posthog||[]);
posthog.init('phc_yQWJrGSbLL4Jhmz3soBsPVdXyXTJHiNCxzFBsQwnS8LQ', {
  api_host: 'https://hp.demudhra.sh',
  ui_host: 'https://us.posthog.com',
  persistence: 'memory',
  disable_session_recording: true,
  autocapture: false,
  capture_pageview: true,
  capture_pageleave: true,
  disable_surveys: true,
  advanced_disable_flags: true
});
</script>
"""


def with_analytics(page):
    if page.count('</head>') != 1:
        raise ValueError('page needs exactly one </head> for the analytics snippet')
    return page.replace('</head>', ANALYTICS + '</head>')

GROUPS = [
    ('default-root', 'default: root', 'Removed by default. The root the TLS intermediates chain to.'),
    ('default-intermediate', 'default: intermediates',
     'Removed by default. The eight weak keys, each as issued by eMudhra and as cross-signed by Sectigo.'),
    ('all-emudhra-root', '--all-emudhra',
     'Only with <code>--all-emudhra</code>. Other eMudhra roots and their cross-certificates, G1 included.'),
    ('opt-in-cross-sign', '--include-aaa', 'Only with <code>--include-aaa</code>. Sectigo\'s root, not eMudhra\'s.'),
]

# Lines kept from the raw capture, in order. Everything else is dropped and each
# dropped run is marked with a dim '...' line, so nothing disappears silently.
KEEP = [
    lambda l: l.startswith('Active set:'),
    lambda l: l.startswith('OS trust store:'),
    lambda l: l.startswith('  /etc/ssl/certs/ca-certificates.crt'),
    lambda l: l.startswith('  /usr/share/ca-certificates/mozilla/emSign'),
    lambda l: l.startswith('Java:'),
    lambda l: l.startswith('Firefox/Chrome NSS:'),
    lambda l: l.startswith('Python:'),
    lambda l: l.startswith('  /home/dev/.pyenv/'),
    lambda l: l.startswith('  /home/dev/.venv/'),
    lambda l: l.startswith('  /home/dev/miniconda3/'),
    lambda l: l.startswith('  /usr/lib/python3/'),
    lambda l: l.startswith('Node:'),
    lambda l: l.startswith('Other:'),
    lambda l: l.startswith('  /opt/acme-agent/'),
    lambda l: l.startswith('Summary:') and 'removed=0' in l,
    lambda l: l.startswith('found ') and '[y/N]' in l,
    lambda l: l.startswith('Backup directory:'),
    lambda l: l.startswith('Undo after closing applications:'),
    lambda l: l.startswith('REMOVED 1 certificate(s) from /etc/ssl/certs/ca-certificates.crt'),
    lambda l: l.startswith('REMOVED 3 certificate(s) from /opt/acme-agent/'),
    lambda l: l.startswith('Regenerating native system trust'),
    lambda l: l.startswith('Summary:') and 'failed=0' in l and 'removed=0' not in l,
]


def rows():
    out = []
    for line in (ROOT / 'data/fingerprints.tsv').read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        sha, group, subject, source = line.split('\t')
        if not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError(f'bad fingerprint {sha}')
        out.append(dict(sha=sha, group=group, subject=subject, source=source))
    return out


def counts(table):
    n = {g: sum(r['group'] == g for r in table) for g, *_ in GROUPS}
    default = n['default-root'] + n['default-intermediate']
    return dict(N_DEFAULT=default, N_INTERMEDIATE=n['default-intermediate'], N_MORE=n['all-emudhra-root'],
                N_ALL=default + n['all-emudhra-root'], N_AAA=n['opt-in-cross-sign'], N_TOTAL=len(table))


def cn(dn):
    m = re.search(r'(?:^|,)CN=([^,]+)', dn)
    return m.group(1) if m else dn


def org(dn):
    m = re.search(r'(?:^|,)O=([^,]+)', dn)
    return m.group(1) if m else ''


def transcript():
    raw = (SITE / 'transcript.raw').read_text().replace('\r', '').replace('\x1b[K', '')
    lines = raw.split('\n')
    picked, last, i = [], -1, 0
    for pred in KEEP:
        j = next(k for k in range(i, len(lines)) if pred(lines[k]))
        if j - last > 1 and picked:
            picked.append(('gap', '...'))
        picked.append(('line', lines[j]))
        last, i = j, j + 1

    def render(kind, text):
        e = html.escape(text)
        if kind == 'gap':
            return f'<span class="dim">{e}</span>'
        if text.startswith('found ') and '[y/N]' in text:
            a, b = e.rsplit('[y/N] ', 1)
            return f'<span class="ask">{a}[y/N]</span> <span class="you">{b}</span>'
        if text.startswith('REMOVED'):
            return '<span class="ok">REMOVED</span>' + e[len('REMOVED'):]
        if text.startswith('  /'):
            return f'<span class="path">{e}</span>'
        if text.startswith('Undo after'):
            return f'<span class="undo">{e}</span>'
        return e
    body = ['<span class="prompt">$</span> curl -fsSL https://demudhra.sh/run | sh'] + [render(*x) for x in picked]
    return ''.join(f'<span class="l">{x}</span>' for x in body)


def home(version, table):
    root, = (r for r in table if r['group'] == 'default-root')
    values = dict(counts(table), ROOT_NAME=E(cn(root['subject'])), VERSION=E(version), TRANSCRIPT=transcript())
    page = (SITE / 'index.src.html').read_text()
    for key, value in values.items():
        page = page.replace('{{' + key + '}}', str(value))
    left = re.findall(r'\{\{[A-Z_]+\}\}', page)
    if left:
        raise ValueError(f'unfilled template keys: {left}')
    return page


def certs_page(table):
    meta = {c['sha256']: c for c in json.loads((ROOT / 'data/certs.json').read_text())}
    if set(meta) != {r['sha'] for r in table}:
        raise ValueError('data/fingerprints.tsv and data/certs.json disagree')

    def src(s):
        url, _, note = s.partition(' ')
        if not url.startswith('https://'):
            raise ValueError(url)
        host = re.sub(r'^www\.', '', url.split('/')[2])
        label = {'bugzilla.mozilla.org': 'mozilla bug', 'ccadb.my.salesforce-sites.com': 'ccadb',
                 'support.apple.com': 'apple'}.get(host, host)
        note = note.strip('()').replace('bug description', 'description').replace('comment ', 'c')
        note = note.replace(': Mozilla emergency removal', '').replace('record ', '')
        return f'<a href="{E(url)}">{E(label)}{(" " + E(note)) if note else ""}</a>'

    parts = []
    for group, title, blurb in GROUPS:
        body = []
        selected = [r for r in table if r['group'] == group]
        for r in selected:
            m = meta[r['sha']]
            if m['subject'] != r['subject'] or m['group'] != group:
                raise ValueError(f'metadata mismatch for {r["sha"]}')
            links = [src(r['source'])]
            crt = next((u for u in m['source_urls'] if u.startswith('https://crt.sh/')), None)
            if crt:
                links.append(f'<a href="{E(crt.split(" ")[0])}">crt.sh</a>')
            issued = 'self-signed' if m['issuer'] == r['subject'] else 'from ' + E(cn(m['issuer']))
            body.append(f'<tr><td>{E(cn(r["subject"]))}<span class="issuer">{E(org(r["subject"]))} · {issued}</span></td>'
                        f'<td class="fp">{r["sha"]}</td><td class="src">{" · ".join(links)}</td></tr>')
        parts.append(f'<h2>{E(title)} ({len(selected)})</h2>\n<p>{blurb}</p>\n'
                     '<table><colgroup><col class="c1"><col class="c2"><col class="c3"></colgroup>'
                     '<thead><tr><th>certificate</th><th>sha-256 of DER</th><th>source</th></tr></thead><tbody>\n'
                     + '\n'.join(body) + '\n</tbody></table>')
    n = counts(table)
    desc = 'Every certificate demudhra can remove, by SHA-256 fingerprint, with a source for each.'
    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>certs · demudhra</title>
<meta name="description" content="{desc}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/style.css">
<link rel="canonical" href="https://demudhra.sh/certs/">
<meta property="og:type" content="website">
<meta property="og:url" content="https://demudhra.sh/certs/">
<meta property="og:title" content="demudhra cert list">
<meta property="og:description" content="{desc}">
<meta property="og:image" content="https://demudhra.sh/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="https://demudhra.sh/og.png">
</head>
<body class="list">
<main class="list">
<a class="back" href="/">&larr; back</a>
<h1>demudhra/certs</h1>
<p class="intro">demudhra matches on the SHA-256 of each certificate's DER bytes, never on its name.
The list has {n['N_TOTAL']} certificates. A default run removes {n['N_DEFAULT']}.
<code>--all-emudhra</code> adds {n['N_MORE']} more, for {n['N_ALL']} eMudhra certificates.
<code>--include-aaa</code> adds Sectigo's AAA root on top of either.
Generated from <code>data/fingerprints.tsv</code>, the same file the script reads.</p>
{chr(10).join(parts)}
<footer><p>by <a href="https://github.com/odpay">odpay</a> · {n['N_TOTAL']} certificates · the site uses cookieless PostHog analytics; the script sends nothing</p>
<!-- repo link, add once odpay/demudhra is public:
<p><a href="https://github.com/odpay/demudhra/blob/master/data/fingerprints.tsv">fingerprints.tsv on github</a></p>
--></footer>
</main>
</body>
</html>
'''
    found = re.findall(r'<td class="fp">([0-9a-f]{64})</td>', page)
    if sorted(found) != sorted(r['sha'] for r in table) or len(found) != len(set(found)):
        raise ValueError('certificate page does not list every fingerprint exactly once')
    return page


def build_site(out, version):
    table = rows()
    out.mkdir(parents=True, exist_ok=True)
    (out / 'index.html').write_text(with_analytics(home(version, table)))
    (out / 'certs').mkdir(exist_ok=True)
    (out / 'certs/index.html').write_text(with_analytics(certs_page(table)))
    (out / '404.html').write_text(with_analytics((SITE / '404.html').read_text()))
    for name in STATIC:
        shutil.copyfile(SITE / name, out / name)
    shutil.copytree(SITE / 'fonts', out / 'fonts', dirs_exist_ok=True)
    (out / 'data').mkdir(exist_ok=True)
    shutil.copyfile(ROOT / 'data/certs.json', out / 'data/certs.json')
