// Site configuration. Run `node sync-config.js` after changing the contact address.
const BRAND = 'VibeFort';
const CONTACT_EMAIL = 'security@probcapital.com';
const CHECKOUT_URLS = { 'Free scan': '#', 'Quick Audit': '#', 'Full Audit': '#', 'Deep Audit': '#', 'Monitoring': '#' };
const SCAN_RESULT = { grade: 'C', score: 68, findings: [
  { severity: 'HIGH', finding: 'Public database endpoint responds', evidence: 'Public probe returned a response; access rules need review.', status: 'VERIFIED' },
  { severity: 'MEDIUM', finding: 'Content Security Policy missing', evidence: 'No Content-Security-Policy header in sample response.', status: 'VERIFIED' },
  { severity: 'LOW', finding: 'Email policy incomplete', evidence: 'Sample DMARC policy is set to monitoring only.', status: 'VERIFIED' },
  { severity: 'INFO', finding: 'TLS available', evidence: 'Sample endpoint accepts HTTPS connections.', status: 'PASS' }
]};
document.querySelectorAll('[data-brand]').forEach(el => el.textContent = BRAND);
document.querySelectorAll('[data-contact]').forEach(el => { el.textContent = CONTACT_EMAIL; el.href = `mailto:${CONTACT_EMAIL}`; });
document.title = document.title + ' — ' + BRAND;
const scanForm = document.querySelector('#scan-form');
const output = document.querySelector('#scan-output');
const checks = ['TLS configuration', 'Security headers', 'CORS policy', 'Exposed files', 'JavaScript bundle secrets', 'Public database probes', 'Email records'];
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function runScan(url) {
  // TODO: integrate POST /api/scan. Send the URL and permission confirmation to a trusted backend and return validated findings.
  for (let i = 0; i < checks.length; i++) { await delay(950); const row = document.querySelector(`[data-check="${i}"]`); if (row) { row.classList.add('done'); row.querySelector('b').textContent = 'DONE'; } }
  return SCAN_RESULT;
}
if (scanForm) scanForm.addEventListener('submit', async event => {
  event.preventDefault(); if (!scanForm.reportValidity()) return;
  const url = document.querySelector('#scan-url').value; const button = scanForm.querySelector('button'); button.disabled = true;
  output.innerHTML = `<div class="scan-panel"><div class="scan-panel-head"><span>SURFACE CHECK / CHECKLIST</span><span>IN PROGRESS</span></div><div class="checklist">${checks.map((c,i)=>`<div data-check="${i}"><span>${String(i+1).padStart(2,'0')} / ${c}</span><b>WAITING</b></div>`).join('')}</div></div>`;
  const result = await runScan(url);
  output.innerHTML = `<div class="scan-panel results"><div class="scan-panel-head"><span>SURFACE CHECK / RESULTS</span><span>COMPLETE</span></div><div class="result-title"><div><span class="eyebrow">SURFACE SCORE</span><h3>${result.grade}<small>${result.score} / 100</small></h3></div><div class="stamp">Verified</div></div><p class="fine">Sample data — the live scanner plugs in at launch.</p><table class="findings-table"><thead><tr><th>SEVERITY</th><th>FINDING</th><th>EVIDENCE</th><th>STATUS</th></tr></thead><tbody>${result.findings.map(f=>`<tr><td data-l="Severity"><span class="chip ${f.severity.toLowerCase()}">${f.severity}</span></td><td data-l="Finding">${f.finding}</td><td data-l="Evidence">${f.evidence}</td><td data-l="Status">${f.status}</td></tr>`).join('')}</tbody></table></div>`;
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
  form.addEventListener('submit', event => { event.preventDefault(); const fields=['name','email','url','tier'].map(n=>form.elements[n]); const valid=fields.map(validate); if(valid.includes(false)){fields[valid.indexOf(false)].focus();return;} const body=`Name: ${form.elements.name.value.trim()}\nWork email: ${form.elements.email.value}\nApp URL: ${form.elements.url.value}\nTier: ${form.elements.tier.value}\nNotes: ${form.elements.notes.value}\nCheckout: ${form.dataset.checkoutUrl}`; const link=document.createElement('a'); link.href=`mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent('Security audit brief: '+form.elements.tier.value)}&body=${encodeURIComponent(body)}`; link.click(); document.querySelector('#brief-content').hidden = true; document.querySelector('#brief-success').hidden = false; });
}
