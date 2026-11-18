// Site configuration.
const BRAND = 'ShipAudit Lab';
const CONTACT_EMAIL = 'security@shipauditlab.com';
const CHECKOUT_URLS = { 'Free scan': '#', 'Deep Scan': 'https://buy.stripe.com/8x2aEY3HTbe171xe3hdjO00', 'Quick Audit': 'https://buy.stripe.com/cNi6oI1zLci571xe3hdjO01', 'Full Audit': 'https://buy.stripe.com/8x28wQa6h2HvgC77ETdjO02', 'Deep Audit': 'https://buy.stripe.com/6oU28sa6hbe1fy34sHdjO03', 'Monitoring': 'https://buy.stripe.com/bJeaEYfqB6XL71xgbpdjO04' };
document.querySelectorAll('[data-brand]').forEach(el => el.textContent = BRAND);
document.querySelectorAll('[data-contact]').forEach(el => { el.textContent = CONTACT_EMAIL; el.href = `mailto:${CONTACT_EMAIL}`; });
if (!document.title.includes(BRAND)) document.title = document.title + ' — ' + BRAND;
const scanForm = document.querySelector('#scan-form');
const output = document.querySelector('#scan-output');
const checks = ['TLS configuration', 'Security headers', 'CORS policy', 'Exposed files', 'JavaScript bundle secrets', 'Public database probes', 'Email records'];
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
// Funnel analytics: fire-and-forget event sink. Only the event name,
// the page path and the sanitized utm_source ever leave the browser —
// never the scanned URL or any finding. Every failure is swallowed:
// analytics must never break the scan flow.
function trackEvent(name) {
  try {
    const payload = JSON.stringify({ event: name, page: location.pathname, source: (new URLSearchParams(location.search).get('utm_source') || '').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 32) });
    let sent = false;
    if (navigator.sendBeacon) sent = navigator.sendBeacon('/api/event', new Blob([payload], { type: 'application/json' }));
    if (!sent) fetch('/api/event', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload, keepalive: true }).catch(() => {});
  } catch (e) { /* analytics is best-effort only */ }
}
async function runScan(url, consent) {
  // Real backend scan: POST /api/scan runs the surface checks server-side.
  // The checklist animates while the request is in flight; the results are
  // whatever the server actually found — or an honest error.
  let i = 0;
  const timer = setInterval(() => {
    if (i >= checks.length) { clearInterval(timer); return; }
    const row = document.querySelector(`[data-check="${i}"]`);
    if (row) { row.classList.add('done'); row.querySelector('b').textContent = 'DONE'; }
    i++;
  }, 1200);
  try {
    const resp = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url, consent }) });
    const result = await resp.json();
    if (!resp.ok || !result.ok) throw new Error(result.error || 'scan failed');
    trackEvent('scan_started');
    return result;
  } catch (e) {
    trackEvent('scan_failed');
    throw e;
  } finally {
    clearInterval(timer);
    document.querySelectorAll('[data-check] b').forEach(b => { b.textContent = 'DONE'; });
  }
}
if (scanForm) scanForm.addEventListener('submit', async event => {
  trackEvent('scan_submit_clicked');
  event.preventDefault();
  const urlInput = document.querySelector('#scan-url'); const consentBox = scanForm.querySelector('.check input'); const button = scanForm.querySelector('button'); const scanError = document.querySelector('#scan-error');
  const showScanError = msg => { if (scanError) { scanError.textContent = msg; scanError.hidden = false; } };
  if (scanError) { scanError.hidden = true; scanError.textContent = ''; }
  // Accept the address the way people type it: a bare domain is normal.
  // Normalize here — never let native form validation wall off the scan.
  let rawUrl = urlInput.value.trim();
  if (rawUrl.startsWith('//')) rawUrl = rawUrl.slice(2);
  if (rawUrl && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(rawUrl)) rawUrl = 'https://' + rawUrl;
  let parsedUrl = null;
  try { parsedUrl = new URL(rawUrl); } catch (e) { parsedUrl = null; }
  if (!parsedUrl || !parsedUrl.hostname || !parsedUrl.hostname.includes('.')) { trackEvent('scan_validation_failed'); showScanError("Enter your app's address — for example yourapp.com"); urlInput.focus(); return; }
  if (!consentBox.checked) { trackEvent('scan_authorization_missing'); showScanError('Tick the box to confirm this is your site, then run the scan.'); consentBox.focus(); return; }
  const url = rawUrl; const consent = consentBox.checked; button.disabled = true;
  output.innerHTML = `<div class="scan-panel"><div class="scan-panel-head"><span>SURFACE CHECK / CHECKLIST</span><span>IN PROGRESS</span></div><div class="checklist">${checks.map((c,i)=>`<div data-check="${i}"><span>${String(i+1).padStart(2,'0')} / ${c}</span><b>WAITING</b></div>`).join('')}</div></div>`;
  try {
    const result = await runScan(url, consent);
    const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const findings = Array.isArray(result.findings) ? result.findings : [];
    const top = findings.slice(0, 3);
    const rest = findings.slice(3);
    const rowHtml = f => `<tr><td data-l="Severity"><span class="chip ${f.severity.toLowerCase()}">${f.severity}</span></td><td data-l="Finding">${esc(f.finding)}</td><td data-l="Evidence">${esc(f.evidence)}</td><td data-l="Status">${f.status}</td></tr>`;
    const topHtml = top.length ? `<div class="top-findings"><p class="top-findings-head">Top findings from this scan</p>${top.map(f=>`<div class="top-finding"><span class="chip ${f.severity.toLowerCase()}">${f.severity}</span><div><strong>${esc(f.finding)}</strong><code>${esc(f.evidence)}</code></div></div>`).join('')}</div>` : '';
    const moreLine = rest.length ? `<p class="more-findings">+ ${rest.length} more finding${rest.length === 1 ? '' : 's'} from this free scan — full list below.</p>` : '';
    const zeroHtml = findings.length ? '' : `<div class="passed-checks"><p class="passed-line">No issues found on the public surface.</p><ul>${checks.map(c=>`<li><span>${c}</span><b>CHECKED</b></li>`).join('')}</ul><p class="fine">The scan ran these checks against your live site just now and reported no findings.</p></div>`;
    const deepCta = `<div class="deep-cta"><div><h4>Go deeper: the Deep Scan</h4><p>This free scan reads the homepage surface. The Deep Scan checks the whole public surface — every public table probed, a secrets scan of all scripts — and delivers a PDF report with a re-scan within 14 days.</p></div><button class="button scan-deep-cta" type="button">Get the Deep Scan — $29 <svg class="arr" viewBox="0 0 10 10" aria-hidden="true" focusable="false"><path d="M2.2 7.8 7.8 2.2M7.8 2.2H3.4M7.8 2.2v4.4" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/></svg></button><form class="deep-mini-form" novalidate><input class="deep-mini-email" type="email" autocomplete="email" placeholder="Your email for the report" aria-label="Your email for the report" required><p class="field-error deep-mini-error" hidden></p><label class="check"><input class="deep-mini-authorized" type="checkbox" required> <span>I confirm I own this application or have written authorization to have it tested.</span></label><button class="button" type="submit">Run automated Deep Scan — $29</button><p class="fine deep-mini-alt">Questions first? <a href="#" class="deep-mini-brief">Send a brief instead</a></p></form></div>`;
    const restHtml = rest.length ? `<p class="also-head">Also from this free scan</p><table class="findings-table"><thead><tr><th>SEVERITY</th><th>FINDING</th><th>EVIDENCE</th><th>STATUS</th></tr></thead><tbody>${rest.map(rowHtml).join('')}</tbody></table>` : '';
    output.innerHTML = `<div class="scan-panel results"><div class="scan-panel-head"><span>SURFACE CHECK / RESULTS</span><span>COMPLETE</span></div><div class="result-title"><div><span class="eyebrow">SURFACE SCORE</span><h3>${result.grade}<small>${result.score} / 100</small></h3></div><div class="stamp">Live scan</div></div><p class="fine">Real checks against your live site, run just now. Paid audits add a second, independent verification pass to every finding.</p>${topHtml}${moreLine}${zeroHtml}${deepCta}${restHtml}</div>`;
    const cta = output.querySelector('.scan-deep-cta');
    const miniForm = output.querySelector('.deep-mini-form');
    const miniEmail = output.querySelector('.deep-mini-email');
    // Money path: the result-panel Deep Scan button no longer opens
    // the brief dialog — it takes the visitor straight to the inline
    // mini-form (email + authorization) rendered in the same block.
    // The dialog stays one click away via the "Send a brief instead"
    // link and every other tier's trigger.
    if (cta && miniEmail) cta.addEventListener('click', () => { miniEmail.scrollIntoView({ behavior: 'smooth', block: 'center' }); miniEmail.focus({ preventScroll: true }); });
    const miniBrief = output.querySelector('.deep-mini-brief');
    if (miniBrief) miniBrief.addEventListener('click', event => { event.preventDefault(); const trigger = document.querySelector('.brief-trigger[data-tier="Deep Scan"]'); if (trigger) trigger.click(); });
    if (miniForm && miniEmail) miniForm.addEventListener('submit', async event => {
      event.preventDefault();
      const email = miniEmail.value.trim();
      const authorizedBox = miniForm.querySelector('.deep-mini-authorized');
      const miniError = miniForm.querySelector('.deep-mini-error');
      const showMiniError = msg => { miniError.textContent = msg; miniError.hidden = false; };
      miniError.hidden = true; miniError.textContent = '';
      if (!email || !miniEmail.checkValidity()) { showMiniError('Enter a valid work email.'); miniEmail.focus(); return; }
      if (!authorizedBox.checked) { showMiniError('Please confirm you own this application or have written authorization to test it.'); authorizedBox.focus(); return; }
      const btn = miniForm.querySelector('button[type=submit]'); btn.disabled = true;
      try {
        const resp = await fetch('/api/brief', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: '', email, url, tier: 'Deep Scan', notes: '', authorized: true, source: 'scan_result' }) });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || !data.ok) throw new Error('brief rejected');
        trackEvent('deep_scan_checkout_started');
        window.location.href = CHECKOUT_URLS['Deep Scan'] + '?prefilled_email=' + encodeURIComponent(email);
      } catch (e) {
        showMiniError('Something went wrong sending your brief. Please try again, or email us directly at ' + CONTACT_EMAIL + '.');
        btn.disabled = false;
      }
    });
    trackEvent('scan_completed');
  } catch (err) {
    const mailtoFail = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent('Free scan request')}&body=${encodeURIComponent('Please run a free scan for: ' + url)}`;
    output.innerHTML = `<div class="scan-panel"><div class="scan-panel-head"><span>SURFACE CHECK / ERROR</span><span>NOT COMPLETED</span></div><p class="scan-notice">We couldn't complete the scan. Check that the address is a public site starting with https:// and try again — or send us the URL by email and we'll run it for you.</p><p><a class="button outline" href="${mailtoFail}">Email us this address — we'll run it and send the results</a></p></div>`;
  }
  button.disabled = false;
});
// Funnel: form visibility + first URL entry (each fires once per load).
if (scanForm) {
  if ('IntersectionObserver' in window) {
    const formObserver = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) { trackEvent('scan_form_viewed'); formObserver.unobserve(scanForm); }
    }, { threshold: 0.3 });
    formObserver.observe(scanForm);
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => trackEvent('scan_form_viewed'));
  } else {
    trackEvent('scan_form_viewed');
  }
}
const scanUrlInput = document.querySelector('#scan-url');
if (scanUrlInput) {
  let urlEnteredFired = false;
  scanUrlInput.addEventListener('input', () => {
    if (!urlEnteredFired && scanUrlInput.value.trim()) { urlEnteredFired = true; trackEvent('scan_url_entered'); }
  });
}
// Human fallback under the scan form: keep the mailto's body in sync with
// whatever address is currently typed, so a stuck visitor's address reaches
// us without retyping. An empty field still sends the plain prefilled body.
const scanMailto = document.querySelector('#scan-mailto');
if (scanForm && scanMailto) {
  const scanUrlField = document.querySelector('#scan-url');
  const buildScanMailto = addr => `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent('Free scan request')}&body=${encodeURIComponent('Please run a free scan for: ' + addr)}`;
  const refreshScanMailto = () => { scanMailto.href = buildScanMailto(scanUrlField.value.trim()); };
  scanUrlField.addEventListener('input', refreshScanMailto);
  scanMailto.addEventListener('click', refreshScanMailto);
  refreshScanMailto();
}
const dialog = document.querySelector('#brief-dialog');
if (dialog) {
  const form = document.querySelector('#brief-form');
  const labels = {name:'Enter your name.',email:'Enter a valid work email.',url:'Enter a valid app URL starting with http:// or https://.',tier:'Select an audit tier.'};
  for (const field of ['name','email','url','tier']) { const input=form.elements[field]; const error=document.createElement('span'); error.className='field-error'; error.id=`error-${field}`; error.hidden=true; input.setAttribute('aria-describedby',error.id); input.after(error); input.addEventListener('input',()=>validate(input)); input.addEventListener('change',()=>validate(input)); }
  function validate(input) { let valid=input.checkValidity(); if (input.name==='name') valid=!!input.value.trim(); if (input.name==='url' && valid) { try { valid=['http:','https:'].includes(new URL(input.value).protocol); } catch { valid=false; } } const error=document.querySelector(`#error-${input.name}`); error.textContent=valid?'':labels[input.name]; error.hidden=valid; input.setAttribute('aria-invalid',String(!valid)); return valid; }
  document.querySelectorAll('.brief-trigger').forEach(button => button.addEventListener('click', () => { form.reset(); form.elements.tier.value = button.dataset.tier; form.dataset.checkoutUrl = CHECKOUT_URLS[button.dataset.tier]; form.querySelectorAll('.field-error').forEach(e=>{e.hidden=true;e.textContent='';}); form.querySelectorAll('[aria-invalid]').forEach(e=>e.removeAttribute('aria-invalid')); document.querySelector('#brief-content').hidden = false; document.querySelector('#brief-success').hidden = true; dialog.showModal(); }));
  form.elements.tier.addEventListener('change',()=>{form.dataset.checkoutUrl=CHECKOUT_URLS[form.elements.tier.value] || '#';});
  dialog.querySelector('.close').addEventListener('click', () => dialog.close());
  dialog.querySelector('.close-success').addEventListener('click', () => dialog.close());
  form.addEventListener('submit', async event => { event.preventDefault(); const fields=['name','email','url','tier'].map(n=>form.elements[n]); const valid=fields.map(validate); if(valid.includes(false)){fields[valid.indexOf(false)].focus();return;} const errBox=document.querySelector('#brief-error'); if(!form.elements.authorized.checked){errBox.textContent='Please confirm you own this application or have written authorization to test it.';errBox.hidden=false;form.elements.authorized.focus();return;} errBox.hidden=true; const btn=form.querySelector('button[type=submit]'); btn.disabled=true;
    try {
      const resp = await fetch('/api/brief', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: form.elements.name.value.trim(), email: form.elements.email.value.trim(), url: form.elements.url.value.trim(), tier: form.elements.tier.value, notes: form.elements.notes.value.trim(), authorized: form.elements.authorized.checked, company_website: form.elements.company_website ? form.elements.company_website.value : '' }) });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok || !data.ok) throw new Error('brief rejected');
      document.querySelector('#brief-content').hidden = true; document.querySelector('#brief-success').hidden = false; const payBtn = document.querySelector('#brief-pay'); if (payBtn) { const u = form.dataset.checkoutUrl; if (u && u !== '#') { payBtn.href = u; payBtn.hidden = false; } else { payBtn.hidden = true; } } if (data.confirmation === 'failed') { const m = document.querySelector('#brief-success-mail'); if (m) m.textContent = 'Your brief is in — but the confirmation email could not be sent. We have your brief on file and will reply within one business day.'; }
    } catch (e) {
      errBox.textContent = 'Something went wrong sending your brief. Please try again, or email us directly at ' + CONTACT_EMAIL + '.';
      errBox.hidden = false;
    }
    btn.disabled = false; });
}
