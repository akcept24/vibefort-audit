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
    return result;
  } finally {
    clearInterval(timer);
    document.querySelectorAll('[data-check] b').forEach(b => { b.textContent = 'DONE'; });
  }
}
if (scanForm) scanForm.addEventListener('submit', async event => {
  event.preventDefault(); if (!scanForm.reportValidity()) return;
  const url = document.querySelector('#scan-url').value; const consent = scanForm.querySelector('.check input').checked; const button = scanForm.querySelector('button'); button.disabled = true;
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
    const deepCta = `<div class="deep-cta"><div><h4>Go deeper: the Deep Scan</h4><p>This free scan reads the homepage surface. The Deep Scan checks the whole public surface — every public table probed, a secrets scan of all scripts — and delivers a PDF report with a re-scan within 14 days.</p></div><button class="button scan-deep-cta" type="button">Get the Deep Scan — $29 <svg class="arr" viewBox="0 0 10 10" aria-hidden="true" focusable="false"><path d="M2.2 7.8 7.8 2.2M7.8 2.2H3.4M7.8 2.2v4.4" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/></svg></button></div>`;
    const restHtml = rest.length ? `<p class="also-head">Also from this free scan</p><table class="findings-table"><thead><tr><th>SEVERITY</th><th>FINDING</th><th>EVIDENCE</th><th>STATUS</th></tr></thead><tbody>${rest.map(rowHtml).join('')}</tbody></table>` : '';
    output.innerHTML = `<div class="scan-panel results"><div class="scan-panel-head"><span>SURFACE CHECK / RESULTS</span><span>COMPLETE</span></div><div class="result-title"><div><span class="eyebrow">SURFACE SCORE</span><h3>${result.grade}<small>${result.score} / 100</small></h3></div><div class="stamp">Live scan</div></div><p class="fine">Real checks against your live site, run just now. Paid audits add a second, independent verification pass to every finding.</p>${topHtml}${moreLine}${zeroHtml}${deepCta}${restHtml}</div>`;
    const cta = output.querySelector('.scan-deep-cta');
    if (cta) cta.addEventListener('click', () => { const trigger = document.querySelector('.brief-trigger[data-tier="Deep Scan"]'); if (trigger) trigger.click(); });
  } catch (err) {
    output.innerHTML = `<div class="scan-panel"><div class="scan-panel-head"><span>SURFACE CHECK / ERROR</span><span>NOT COMPLETED</span></div><p class="scan-notice">We couldn't complete the scan. Check that the address is a public site starting with https:// and try again — or send us the URL by email and we'll run it for you.</p></div>`;
  }
  button.disabled = false;
});
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
