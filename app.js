// Site configuration. Run `node sync-config.js` after changing the contact address.
const BRAND = 'VibeFort';
const CONTACT_EMAIL = 'security@probcapital.com';
const CHECKOUT_URLS = { 'Free scan': '#', 'Quick Audit': '#', 'Full Audit': '#', 'Deep Audit': '#', 'Monitoring': '#' };
document.querySelectorAll('[data-brand]').forEach(el => el.textContent = BRAND);
document.querySelectorAll('[data-contact]').forEach(el => { el.textContent = CONTACT_EMAIL; el.href = `mailto:${CONTACT_EMAIL}`; });
document.title = document.title + ' — ' + BRAND;
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
    output.innerHTML = `<div class="scan-panel results"><div class="scan-panel-head"><span>SURFACE CHECK / RESULTS</span><span>COMPLETE</span></div><div class="result-title"><div><span class="eyebrow">SURFACE SCORE</span><h3>${result.grade}<small>${result.score} / 100</small></h3></div><div class="stamp">Live scan</div></div><p class="fine">Real checks against your live site, run just now. Paid audits add a second, independent verification pass to every finding.</p><table class="findings-table"><thead><tr><th>SEVERITY</th><th>FINDING</th><th>EVIDENCE</th><th>STATUS</th></tr></thead><tbody>${result.findings.map(f=>`<tr><td data-l="Severity"><span class="chip ${f.severity.toLowerCase()}">${f.severity}</span></td><td data-l="Finding">${esc(f.finding)}</td><td data-l="Evidence">${esc(f.evidence)}</td><td data-l="Status">${f.status}</td></tr>`).join('')}</tbody></table></div>`;
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
  form.addEventListener('submit', async event => { event.preventDefault(); const fields=['name','email','url','tier'].map(n=>form.elements[n]); const valid=fields.map(validate); if(valid.includes(false)){fields[valid.indexOf(false)].focus();return;} const errBox=document.querySelector('#brief-error'); errBox.hidden=true; const btn=form.querySelector('button[type=submit]'); btn.disabled=true;
    try {
      const resp = await fetch('/api/brief', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: form.elements.name.value.trim(), email: form.elements.email.value.trim(), url: form.elements.url.value.trim(), tier: form.elements.tier.value, notes: form.elements.notes.value.trim(), company_website: form.elements.company_website ? form.elements.company_website.value : '' }) });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok || !data.ok) throw new Error('brief rejected');
      document.querySelector('#brief-content').hidden = true; document.querySelector('#brief-success').hidden = false;
    } catch (e) {
      errBox.textContent = 'Something went wrong sending your brief. Please try again, or email us directly at ' + CONTACT_EMAIL + '.';
      errBox.hidden = false;
    }
    btn.disabled = false; });
}
