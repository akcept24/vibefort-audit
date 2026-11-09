"""ShipAudit Lab — shared branded HTML email template.

One template function renders every client-facing email (brief
confirmation, Deep Scan delivery, monitoring alerts) so the whole
mail stream looks like one firm. The design mirrors the site
(deploy-repo/style.css): paper #faf9f6, ink #141310, line #e4e1d8,
accent red #d92b1f, muted #66645e; serif display headlines (Fraunces
on the site, Georgia fallback in mail), sans body (Archivo -> Arial),
mono uppercase labels (IBM Plex Mono -> Courier). The dark header and
footer bands mirror the site footer's ink treatment.

Email-safe by construction: table layout only, inline styles only,
no external images, max-width 600px. All interpolated values pass
through esc(). Stdlib only.

Every HTML mail is sent alongside its original plain-text body
(multipart) — the text part is unchanged and reads on its own.
"""

import html as _html

INK = "#141310"
PAPER = "#faf9f6"
PAGE_BG = "#eceae4"
LINE = "#e4e1d8"
RED = "#d92b1f"
MUTED = "#66645e"
BODY_INK = "#3c3a35"
TINT = "#f2f0ea"
FOOTER_MUTED = "#bdbbb4"

SERIF = "Georgia, 'Times New Roman', Times, serif"
SANS = "Arial, Helvetica, sans-serif"
MONO = "'Courier New', Courier, monospace"

SEV_COLORS = {
    "CRITICAL": "#d92b1f",
    "HIGH": "#b4561a",
    "MEDIUM": "#866128",
    "LOW": "#6b675e",
    "INFO": "#526751",
}

_EYE = (f"font-family:{MONO};font-size:11px;letter-spacing:2px;"
        f"text-transform:uppercase;")
_P = (f"font-family:{SANS};font-size:15px;line-height:1.65;"
      f"color:{BODY_INK};margin:0 0 16px 0;")


def esc(s):
    return _html.escape(str(s), quote=True)


def para(text):
    return f'<p style="{_P}">{esc(text)}</p>'


def details_table(pairs):
    """(label, value) rows — the neat definition table used for
    order #, target, tier, status."""
    rows = []
    for label, value in pairs:
        rows.append(
            '<tr>'
            f'<td style="font-family:{MONO};font-size:11px;'
            f'letter-spacing:1px;text-transform:uppercase;'
            f'color:{MUTED};padding:9px 16px 9px 0;white-space:nowrap;'
            f'border-bottom:1px solid {LINE};vertical-align:top;">'
            f'{esc(label)}</td>'
            f'<td style="font-family:{SANS};font-size:14px;'
            f'color:{INK};padding:9px 0;border-bottom:1px solid '
            f'{LINE};word-break:break-word;">{esc(value)}</td>'
            '</tr>')
    return ('<table role="presentation" cellpadding="0" cellspacing="0" '
            'border="0" width="100%" style="border-collapse:collapse;'
            'margin:6px 0 22px 0;">' + "".join(rows) + '</table>')


def steps(items):
    """Numbered next-steps, red mono numerals like the site's
    method section. items = [(title, text), ...]."""
    rows = []
    for i, (title, text) in enumerate(items, 1):
        rows.append(
            '<tr>'
            f'<td style="font-family:{MONO};font-size:13px;'
            f'color:{RED};padding:10px 14px 10px 0;vertical-align:top;'
            f'border-bottom:1px solid {LINE};">{i:02d}</td>'
            f'<td style="font-family:{SANS};font-size:14px;'
            f'line-height:1.6;color:{BODY_INK};padding:10px 0;'
            f'border-bottom:1px solid {LINE};">'
            f'<strong style="color:{INK};">{esc(title)}</strong> '
            f'{esc(text)}</td></tr>')
    return ('<table role="presentation" cellpadding="0" cellspacing="0" '
            'border="0" width="100%" style="border-collapse:collapse;'
            'margin:2px 0 22px 0;">' + "".join(rows) + '</table>')


def notice_box(text, label="Please read"):
    """Bordered honesty-notice box with a red rule — used for the
    Deep Scan automated-scan disclosure."""
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0" '
        'border="0" width="100%" style="border-collapse:collapse;'
        f'background:{TINT};margin:4px 0 22px 0;"><tr>'
        f'<td style="width:3px;background:{RED};font-size:0;'
        'line-height:0;">&nbsp;</td>'
        '<td style="padding:16px 20px 6px 20px;">'
        f'<div style="{_EYE}color:{RED};margin:0 0 8px 0;">'
        f'{esc(label)}</div>'
        f'<p style="font-family:{SANS};font-size:13.5px;line-height:1.65;'
        f'color:{BODY_INK};margin:0 0 12px 0;">{esc(text)}</p>'
        '</td></tr></table>')


def result_block(text):
    """The one-line scan result, set as a bordered summary block."""
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0" '
        'border="0" width="100%" style="border-collapse:collapse;'
        f'border:1px solid {INK};margin:4px 0 22px 0;"><tr>'
        '<td style="padding:16px 20px;">'
        f'<div style="{_EYE}color:{RED};margin:0 0 8px 0;">Result</div>'
        f'<p style="font-family:{SANS};font-size:15px;line-height:1.6;'
        f'color:{INK};margin:0;">{esc(text)}</p>'
        '</td></tr></table>')


def severity_counts(counts):
    """Four-cell severity strip, mirroring the report cover.
    counts = [(label, n), ...] with site severity colors."""
    cells = []
    for label, n in counts:
        color = SEV_COLORS.get(str(label).upper(), INK)
        cells.append(
            f'<td style="padding:14px 10px 12px 0;">'
            f'<div style="font-family:{MONO};font-size:26px;'
            f'color:{color};line-height:1;">{int(n)}</div>'
            f'<div style="{_EYE}font-size:9px;color:{MUTED};'
            f'margin-top:6px;">{esc(label)}</div></td>')
    return ('<table role="presentation" cellpadding="0" cellspacing="0" '
            'border="0" width="100%" style="border-collapse:collapse;'
            f'border-top:1px solid {INK};border-bottom:1px solid '
            f'{LINE};margin:0 0 22px 0;"><tr>' + "".join(cells) +
            '</tr></table>')


def severity_list(items, empty="none"):
    """Monitoring change list. items = [(severity, title), ...]."""
    if not items:
        return (f'<p style="font-family:{SANS};font-size:14px;'
                f'color:{MUTED};margin:0 0 18px 0;">— {esc(empty)}</p>')
    rows = []
    for sev, title in items:
        color = SEV_COLORS.get(str(sev).upper(), MUTED)
        rows.append(
            '<tr>'
            f'<td style="padding:8px 12px 8px 0;white-space:nowrap;'
            f'border-bottom:1px solid {LINE};vertical-align:top;">'
            f'<span style="font-family:{MONO};font-size:10px;'
            f'letter-spacing:1px;color:{color};border:1px solid '
            f'{color};padding:3px 6px;">{esc(str(sev).upper())}</span>'
            '</td>'
            f'<td style="font-family:{SANS};font-size:14px;'
            f'color:{BODY_INK};line-height:1.55;padding:8px 0;'
            f'border-bottom:1px solid {LINE};">{esc(title)}</td></tr>')
    return ('<table role="presentation" cellpadding="0" cellspacing="0" '
            'border="0" width="100%" style="border-collapse:collapse;'
            'margin:0 0 20px 0;">' + "".join(rows) + '</table>')


def list_heading(text):
    return (f'<div style="{_EYE}color:{INK};margin:20px 0 6px 0;">'
            f'{esc(text)}</div>')


def grade_block(grade, score):
    """Big mono grade + score, like the site scan result title."""
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0" '
        'border="0" style="border-collapse:collapse;'
        'margin:2px 0 20px 0;"><tr>'
        f'<td style="font-family:{MONO};font-size:52px;line-height:1;'
        f'color:{INK};padding:0 18px 0 0;">{esc(grade)}</td>'
        f'<td style="font-family:{MONO};font-size:13px;'
        f'color:{MUTED};vertical-align:bottom;padding-bottom:6px;">'
        f'{esc(score)} / 100<br>current grade</td>'
        '</tr></table>')


def render_email(*, eyebrow, headline, body_html, reason):
    """The full branded document. body_html is composed by the
    caller from the block helpers above."""
    return f"""<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light">
<title>ShipAudit Lab</title>
</head>
<body style="margin:0;padding:0;background:{PAGE_BG};">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:{PAGE_BG};">
<tr><td align="center" style="padding:32px 12px 40px 12px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:600px;max-width:100%;border-collapse:collapse;">
<tr><td bgcolor="{INK}" style="background:{INK};padding:26px 36px 22px 36px;">
<div style="font-family:{SERIF};font-size:27px;font-weight:bold;color:{PAPER};letter-spacing:-0.5px;">ShipAudit Lab<span style="color:{RED};">&#9632;</span></div>
<div style="{_EYE}font-size:9px;color:{FOOTER_MUTED};margin-top:8px;">Security for what you shipped</div>
</td></tr>
<tr><td style="background:{RED};height:3px;font-size:0;line-height:0;">&nbsp;</td></tr>
<tr><td bgcolor="{PAPER}" style="background:{PAPER};padding:34px 36px 30px 36px;border-left:1px solid {LINE};border-right:1px solid {LINE};">
<div style="{_EYE}color:{RED};margin:0 0 14px 0;">{esc(eyebrow)}</div>
<div style="font-family:{SERIF};font-size:29px;line-height:1.2;font-weight:bold;color:{INK};margin:0 0 20px 0;">{esc(headline)}</div>
{body_html}
<p style="{_P}margin-bottom:0;">— ShipAudit Lab</p>
</td></tr>
<tr><td bgcolor="{INK}" style="background:{INK};padding:22px 36px 24px 36px;">
<div style="font-family:{SANS};font-size:12px;line-height:1.7;color:{FOOTER_MUTED};">
ShipAudit Lab — a Probcapital LLC company.<br>
&copy; 2026 Probcapital LLC. All rights reserved.<br>
Probcapital LLC is an American financial technology holding company, registered in the State of Delaware, United States.<br>
Questions? <a href="mailto:security@shipauditlab.com" style="color:{PAPER};text-decoration:underline;">security@shipauditlab.com</a> — or just reply to this email.<br>
{esc(reason)}
</div>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""
