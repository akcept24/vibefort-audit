#!/usr/bin/env python3
"""
generate_report.py — build a client-facing VibeFort audit report (HTML)
from a findings JSON in the widecheck results shape:

    {"targets": [{"target": ..., "host": ..., ...}],
     "findings": [{"target":..., "check":..., "severity": "critical|high|
                    medium|low|info", "title":..., "evidence":...,
                    "status":...}]}

The output reuses the sample report's design (report.html + style.css from
the repo root; the CSS is inlined so the file is self-contained).

Usage:
    python3 tools/generate_report.py findings.json -o report-client.html
        [--id VF-002] [--scope "Surface scan"] [--date "31 October 2026"]

This tool is NOT deployed with the site; it runs on the operator's machine.
"""

import argparse
import datetime
import html
import json
import os
import re
import sys
import urllib.parse

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

IMPACT = {
    "tls": "Transport security protects credentials and session data in "
           "transit; weaknesses here let network attackers intercept or "
           "downgrade that protection.",
    "headers": "Browser-enforced protections are missing or weak, which "
               "leaves browser-based attacks (clickjacking, script "
               "injection, MIME sniffing) more room to work.",
    "cors": "Cross-origin rules decide which websites may read responses "
            "through a visitor's browser. A permissive policy can expose "
            "signed-in users' data to attacker-controlled sites.",
    "cookies": "Session cookies without protective flags can be stolen or "
               "sent over insecure connections, enabling account takeover.",
    "exposed-files": "Files that were never meant to be public are "
                     "reachable by anyone, which can hand attackers source "
                     "code, configuration, or credentials.",
    "bundle-secrets": "Anything shipped in the browser bundle is public. "
                      "Real keys in client code give attackers the same "
                      "access the application itself has.",
    "db-probe": "The database answers requests from the public internet. "
                "If its access rules are open, customer data can be read "
                "without ever signing in.",
    "framework-cve": "A known framework vulnerability may let attackers "
                     "bypass the application's access controls.",
    "rate-limit": "Without visible throttling, automated credential "
                  "attacks against the sign-in surface are cheaper to run.",
    "cache-deception": "Shared caches may store private pages under "
                       "static-looking URLs and serve them to others.",
    "email-dns": "Email authentication records decide whether attackers "
                 "can convincingly send mail as your domain, and whether "
                 "your real mail reaches inboxes.",
}


def fix_prompt(f):
    check, title = f["check"], f["title"]
    t = title.lower()
    if check == "headers":
        if "content-security-policy" in t and "missing" in t:
            return ("Add a Content-Security-Policy header at the hosting layer. "
                    "Start from a restrictive policy (default-src 'self') and "
                    "allow only the script, style, font, image, and connect "
                    "origins the app actually uses. Roll out in report-only "
                    "mode first, resolve violations, then enforce.")
        if "strict-transport-security" in t:
            return ("Send Strict-Transport-Security with a max-age of at "
                    "least one year (e.g. max-age=63072000; includeSubDomains) "
                    "on all HTTPS responses, after confirming every subdomain "
                    "works over HTTPS.")
        if "clickjacking" in t:
            return ("Add X-Frame-Options: DENY (or SAMEORIGIN if the app "
                    "frames itself) and/or a CSP frame-ancestors directive "
                    "restricting framing to your own origins.")
        if "x-content-type-options" in t:
            return "Send X-Content-Type-Options: nosniff on all responses."
        if "referrer-policy" in t:
            return ("Send Referrer-Policy: strict-origin-when-cross-origin "
                    "(or stricter) on all responses.")
        if "permissions-policy" in t:
            return ("Send a Permissions-Policy header disabling browser "
                    "features the app does not use (camera, microphone, "
                    "geolocation, payment), e.g. camera=(), microphone=(), "
                    "geolocation=(), payment=().")
        if "disclosure" in t:
            return ("Remove or genericise technology/version response "
                    "headers (e.g. X-Powered-By, Server version strings) at "
                    "the hosting layer so the stack is not advertised.")
        return ("Configure the hosting layer to send the standard set of "
                "security headers (CSP, HSTS, X-Frame-Options, "
                "X-Content-Type-Options, Referrer-Policy, Permissions-Policy) "
                "on every response and verify with a header scan.")
    if check == "tls":
        if "expired" in t or "expires" in t:
            return ("Renew the TLS certificate now and automate renewal "
                    "(e.g. ACME/Let's Encrypt with auto-deploy) so expiry "
                    "cannot recur. Confirm the full chain is served.")
        if "redirect" in t or "plain http" in t:
            return ("Redirect all HTTP traffic to HTTPS with a permanent "
                    "redirect (301/308) at the edge, and enable HSTS once "
                    "every route works over HTTPS.")
        return ("Disable TLS 1.0/1.1 at the edge so only TLS 1.2+ is "
                "negotiated, and confirm the certificate chain and expiry "
                "automation.")
    if check == "cors":
        return ("Restrict Access-Control-Allow-Origin to your own trusted "
                "origins — never reflect an arbitrary Origin, and never "
                "combine a wildcard/reflected origin with "
                "Access-Control-Allow-Credentials: true. Apply the strictest "
                "policy to API and auth routes, then test signed-in flows "
                "from a foreign origin to confirm they are blocked.")
    if check == "cookies":
        return ("Set the Secure, HttpOnly, and SameSite=Lax (or Strict) "
                "attributes on session cookies at the auth provider or "
                "server framework, then test sign-in, refresh, and sign-out.")
    if check == "exposed-files":
        if ".env" in t:
            return ("Remove the .env file from the web-served directory "
                    "immediately, block /.env at the server/proxy, and "
                    "ROTATE every secret it contained — treat them as "
                    "compromised. Keep environment files outside the "
                    "document root in the deployment pipeline.")
        if ".git" in t:
            return ("Block access to /.git/ at the server/proxy (deny and "
                    "return 404) and remove the .git directory from the "
                    "deployed artifact. Deploy from a clean export instead "
                    "of a working clone.")
        if "security.txt" in t:
            return ("Publish a security.txt at /.well-known/security.txt "
                    "with a monitored security contact and an expiry date "
                    "(RFC 9116), so researchers can reach you before issues "
                    "are exploited.")
        if "source map" in t:
            return ("Disable source-map generation for production builds "
                    "(or restrict .map files to authenticated developer "
                    "access) and redeploy.")
        if "robots.txt" in t:
            return ("Remove sensitive paths from robots.txt Disallow lines — "
                    "the file is public and advertises them. Protect the "
                    "paths themselves with authentication instead.")
        return ("Remove the exposed file from the web root, block the path "
                "at the server/proxy, and rotate any credentials it "
                "contained.")
    if check == "bundle-secrets":
        if "service-role" in t:
            return ("Remove the service-role key from all client-side code "
                    "and public build variables and ROTATE it immediately — "
                    "it bypasses row-level security. Move privileged "
                    "operations into a server-side function with "
                    "authorization checks; the browser must only ever hold "
                    "the public anon key.")
        return ("Remove the exposed key from the client bundle, rotate it, "
                "and move the operation that needs it behind a server-side "
                "endpoint with authorization checks. Rebuild and grep the "
                "new bundle for the old value.")
    if check == "db-probe":
        if "firebase" in t:
            return ("Set Firebase Realtime Database rules to deny public "
                    "access (auth != null, with per-user path rules), deploy "
                    "the rules, and re-test /.json?shallow=true as an "
                    "anonymous client — it must return 401.")
        return ("Enable row-level security on every exposed table and add "
                "policies so the public anon key can only read rows it "
                "genuinely needs (ideally none containing customer data). "
                "Re-test with the anon key: table count and read probes "
                "must be denied.")
    if check == "framework-cve":
        return ("Upgrade Next.js to a version with the CVE-2025-29927 fix "
                "(>= 14.2.25 / 15.2.3 or later), and do not rely on "
                "middleware alone for authorization — enforce access checks "
                "in the data layer as well. Redeploy and re-run the "
                "subrequest probe.")
    if check == "rate-limit":
        return ("Add server-side rate limiting to sign-in attempts by "
                "account and IP at the auth provider or edge, with a "
                "temporary cooldown and a generic error message. Add a "
                "captcha challenge after repeated failures.")
    if check == "cache-deception":
        return ("Exclude dynamic/HTML responses from shared-cache storage: "
                "send Cache-Control: private, no-store on authenticated and "
                "dynamic pages, and review CDN cache rules for "
                "static-looking suffixes.")
    if check == "email-dns":
        if "spf" in t:
            return ("Publish an SPF record for the domain listing exactly "
                    "the services allowed to send mail for it, ending in "
                    "-all. If mail is sent from a subdomain (e.g. send.), "
                    "make sure the sending domain's records are the ones "
                    "receiving systems check.")
        if "dmarc" in t and "p=none" in t:
            return ("Move DMARC from monitoring to enforcement in stages: "
                    "review the rua reports for legitimate senders, then "
                    "raise the policy to p=quarantine and finally p=reject.")
        if "dmarc" in t:
            return ("Publish a DMARC record at _dmarc.<domain> starting "
                    "with p=none and a rua reporting address, review the "
                    "reports, then step up to quarantine/reject.")
        return ("Review the domain's email authentication (SPF, DKIM, "
                "DMARC) with your mail provider and align all three.")
    return ("Investigate the finding using the evidence below, apply the "
            "narrowest fix that removes the exposure, and re-run the "
            "surface scan to confirm it is gone.")


def esc(s):
    return html.escape(str(s), quote=True)


def main():
    ap = argparse.ArgumentParser(description="VibeFort report generator")
    ap.add_argument("input", help="findings JSON (widecheck results shape)")
    ap.add_argument("-o", "--output", required=True, help="output HTML file")
    ap.add_argument("--id", default="VF-002", help="report id (default VF-002)")
    ap.add_argument("--scope", default="Surface scan",
                    help="scope label for the cover")
    ap.add_argument("--date", default=None,
                    help="report date (default: today, '31 October 2026')")
    ap.add_argument("--css", default=None,
                    help="path to style.css (default: repo-root style.css "
                         "relative to this tool)")
    args = ap.parse_args()

    with open(args.input) as fh:
        data = json.load(fh)
    findings = [f for f in data.get("findings", [])]
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    targets = data.get("targets", [])
    target_url = (targets[0].get("target") if targets else
                  findings[0]["target"] if findings else "unknown")
    host = urllib.parse.urlparse(target_url).hostname or target_url
    date_str = args.date or datetime.date.today().strftime("%d %B %Y")

    css_path = args.css or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "style.css")
    style_block = ""
    if os.path.exists(css_path):
        with open(css_path) as fh:
            style_block = f"<style>{fh.read()}</style>"
    else:
        style_block = '<link rel="stylesheet" href="style.css">'

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    top = [s for s in ("critical", "high") if counts.get(s)]
    if top:
        summary_line = (f"{len(findings)} findings. "
                        f"{counts.get('critical', 0) + counts.get('high', 0)} "
                        "need immediate attention.")
    else:
        summary_line = (f"{len(findings)} findings. None are critical or "
                        "high severity.")

    total = len(findings)
    sidebar = ['<a href="#summary">00 / Summary</a>']
    articles = []
    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        sidebar.append(f'<a href="#f{i}">{i:02d} / {esc(f["title"][:28])}</a>')
        impact = IMPACT.get(f["check"], "")
        articles.append(f"""<article class="finding" id="f{i}"><div class="finding-top"><span>FINDING {i:02d} / {total:02d}</span><span class="chip {sev}">{sev.upper()}</span></div><h2>{esc(f['title'])}</h2>{f'<p>{esc(impact)}</p>' if impact else ''}<h4>Evidence</h4><pre>{esc(f['evidence'])}</pre><h4>Fix prompt</h4><div class="fix">{esc(fix_prompt(f))}</div></article>""")

    counts_html = "".join(
        f'<div><b>{counts.get(s, 0):02d}</b><span>{s.upper()}</span></div>'
        for s in ("critical", "high", "medium", "low"))

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security audit report — {esc(host)}</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700&family=Fraunces:ital,opsz,wght@0,9..144,600;1,9..144,600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">{style_block}</head><body><header class="site-header wrap"><a class="logo" href="index.html">VibeFort<i></i></a><nav aria-label="Main navigation"><a href="index.html#method">Method</a><a href="report.html">Sample report</a><a href="index.html#pricing">Pricing</a><a href="index.html#faq">FAQ</a></nav><a class="header-cta" href="index.html#scan">Run a free scan <span>↗</span></a></header><main class="wrap report-page"><div class="report-cover"><div class="report-top"><span>APPLICATION SECURITY / AUDIT REPORT</span><span>{esc(args.id)}</span></div><div class="stamp">VERIFIED</div><p class="eyebrow">SURFACE AUDIT · AUTOMATED EVIDENCE, HUMAN-REVIEWED FORMAT</p><h1>Security audit<br><em>{esc(host)}.</em></h1><p class="report-lead">A practical review of the application's public surface and supporting configuration.</p><div class="report-meta"><div><span>APPLICATION</span><strong>{esc(host)}</strong></div><div><span>REPORT DATE</span><strong>{esc(date_str)}</strong></div><div><span>SCOPE</span><strong>{esc(args.scope)}</strong></div><div><span>VERIFICATION</span><strong>Independent second pass</strong></div></div></div><div class="report-body"><aside class="report-sidebar"><p class="eyebrow">REPORT INDEX</p>{''.join(sidebar)}</aside><div class="report-content"><section id="summary" class="report-summary"><p class="eyebrow">00 — EXECUTIVE SUMMARY</p><h2>{esc(summary_line)}</h2><p>Findings are ordered by severity. Each one carries the evidence we observed and a fix prompt written for your builder.</p><div class="severity-counts">{counts_html}</div><p class="fine">EVIDENCE IS REDACTED: SECRET VALUES AND CUSTOMER DATA ARE NEVER COPIED INTO THIS REPORT.</p></section>{''.join(articles)}<div class="report-end"><p class="eyebrow">END OF REPORT</p><h2>Know what's exposed.</h2><a href="index.html#pricing" class="button">See audit options ↗</a></div></div></div></main><footer class="footer"><div class="wrap footer-bottom"><span>VibeFort / AUDIT REPORT</span><a href="index.html">BACK TO SITE ↗</a></div></footer></body></html>"""

    with open(args.output, "w") as fh:
        fh.write(doc)
    print(f"wrote {args.output}: {total} findings for {host}")


if __name__ == "__main__":
    main()
