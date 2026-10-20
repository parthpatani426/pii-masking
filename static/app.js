const form = document.getElementById('mask-form');
const input = document.getElementById('file-input');
const zone = document.getElementById('dropzone');
const label = document.getElementById('file-label');
const chip = document.getElementById('file-chip');
const result = document.getElementById('result');
const button = document.getElementById('submit-btn');
function showFile(file){ if(!file)return; label.textContent=file.name; chip.hidden=false; chip.textContent=`${(file.size/1024/1024).toFixed(2)} MB`; }
input.addEventListener('change',()=>showFile(input.files[0]));
['dragenter','dragover'].forEach(e=>zone.addEventListener(e,ev=>{ev.preventDefault();zone.classList.add('drag')}));
['dragleave','drop'].forEach(e=>zone.addEventListener(e,ev=>{ev.preventDefault();zone.classList.remove('drag')}));
zone.addEventListener('drop',ev=>{const f=ev.dataTransfer.files[0];if(f){const dt=new DataTransfer();dt.items.add(f);input.files=dt.files;showFile(f)}});
form.addEventListener('submit',async ev=>{
 ev.preventDefault(); if(!input.files.length)return;
 const types=[...form.querySelectorAll('input[name="types"]:checked')];
 if(!types.length){result.hidden=false;result.innerHTML='<h3>Select at least one detection rule</h3>';return}
 button.disabled=true;button.innerHTML='⏳ Processing file…';result.hidden=true;
 const fd=new FormData(form);
 try{
  const response=await fetch('/api/mask',{method:'POST',body:fd});
  const data=await response.json();result.hidden=false;
  if(!response.ok)throw new Error(data.error||'Processing failed');
  result.innerHTML=`<h3>✓ Masking complete</h3><p><b>${escapeHtml(data.filename)}</b> · ${data.detected_count} detections across ${(data.detected_types||[]).map(escapeHtml).join(', ')||'no matched PII patterns'}.</p><a href="${data.download_url}">Download masked file ↓</a><p>${escapeHtml(data.note||'')}</p><p>${data.storage_saved?'Masked output uploaded to Supabase Storage.':'Masked output was not saved to Supabase Storage.'} ${data.metadata_saved?'Job metadata saved to Supabase.':'Job metadata not saved to Supabase.'}</p>${data.storage_error?`<p class="warning">Storage: ${escapeHtml(data.storage_error)}</p>`:''}${data.database_error?`<p class="warning">Database: ${escapeHtml(data.database_error)}</p>`:''}`;
 }catch(err){result.hidden=false;result.innerHTML=`<h3>Could not process file</h3><p class="warning">${escapeHtml(err.message)}</p>`}
 finally{button.disabled=false;button.innerHTML='<span>✦</span> Detect &amp; mask file <span class="arrow">→</span>'}
});
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
