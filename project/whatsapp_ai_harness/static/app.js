const $=id=>document.getElementById(id);
const state={database:null,history:[],running:false};
const escapeHtml=value=>String(value??'').replace(/[&<>'"]/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const formatNumber=value=>typeof value==='number'?new Intl.NumberFormat().format(value):String(value??'—');
const humanize=value=>String(value??'').replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase());
const concise=value=>{if(value===null||value===undefined)return '—';if(typeof value==='object')return JSON.stringify(value);return formatNumber(value)};

function setView(name){
  $('investigate-view').hidden=name!=='investigate';$('history-view').hidden=name!=='history';
  document.querySelectorAll('.nav-item').forEach(button=>button.classList.toggle('active',button.dataset.view===name));
}
function renderDatabase(db){
  state.database=db;$('database-meta').textContent=`Revision ${db.current_revision} • ${db.quality_status} quality • ${db.contract_version}`;
  $('metric-captures').textContent=formatNumber(db.ready_upload_count||0);$('metric-packets').textContent=formatNumber(db.packet_count||0);
  $('metric-flows').textContent=formatNumber(db.flow_count||0);$('metric-parties').textContent=formatNumber(db.party_count||0);$('metric-calls').textContent=formatNumber(db.session_count||0);
  $('empty-warning').hidden=(db.ready_upload_count||0)>0||(db.no_match_upload_count||0)>0;
}
function renderHealth(health){
  const model=health.ollama?.models?.[0],ok=health.status==='ok'&&health.ollama?.available;
  $('health').textContent=ok?'Systems operational':'Attention required';$('health').className=`health-pill ${ok?'ok':'bad'}`;
  $('model-card').innerHTML=`<small>LOCAL MODEL</small><strong>${escapeHtml(model||'Ollama unavailable')}</strong>`;
}
function renderHistory(items){
  state.history=items;
  $('history-preview').innerHTML=items.slice(0,5).map(item=>`<button class="history-item" data-trace="${escapeHtml(item.trace_id)}"><strong>${escapeHtml(item.question)}</strong><span>Route ${escapeHtml(item.route)} • revision ${escapeHtml(item.analysis_revision??'—')} • ${escapeHtml(item.status)}</span></button>`).join('')||'<div class="pipeline-empty">No investigations recorded.</div>';
  $('history').innerHTML=items.map(item=>`<div class="history-row" data-trace="${escapeHtml(item.trace_id)}"><small>${escapeHtml((item.created_at_utc||'').replace('T',' ').slice(0,19))}</small><strong>Route ${escapeHtml(item.route)}</strong><span>${escapeHtml(item.question)}</span><small>Revision ${escapeHtml(item.analysis_revision??'—')}</small><small>${escapeHtml(item.status)}</small></div>`).join('')||'<div class="pipeline-empty">No investigations recorded.</div>';
  document.querySelectorAll('[data-trace]').forEach(element=>element.onclick=()=>openInvestigation(element.dataset.trace));
}
async function loadRuntime(){
  const [dbResponse,healthResponse,historyResponse]=await Promise.all([fetch('/api/v1/database'),fetch('/api/v1/health'),fetch('/api/v1/investigations')]);
  const db=await dbResponse.json(),health=await healthResponse.json(),history=await historyResponse.json();if(!dbResponse.ok)throw new Error(db.error||'Database unavailable');
  renderDatabase(db);renderHealth(health);renderHistory(history.investigations||[]);
}
function renderPipeline(result){
  const plan=result.validated_plan||[],steps=[{operator:'Question routed',detail:`Route ${result.route}`},...plan.map(step=>({operator:humanize(step.operator),detail:step.input_refs?.length?`Uses ${step.input_refs.join(', ')}`:'Verified database operator'})),{operator:'Evidence verified',detail:`Revision ${result.analysis_revision}`},{operator:'Answer packaged',detail:`${result.citations?.length||0} citation(s)`}];
  $('pipeline').innerHTML=steps.map(step=>`<div class="pipeline-step done"><span class="step-dot">✓</span><strong>${escapeHtml(step.operator)}</strong><small>${escapeHtml(step.detail)}</small></div>`).join('');$('pipeline-state').textContent=result.status==='success'?'Verified':humanize(result.status);
}
function renderWorkingPipeline(){$('pipeline-state').textContent='Running';$('pipeline').innerHTML=`<div class="pipeline-step active"><span class="step-dot">1</span><strong>Interpreting question</strong><small>Routing against the forensic catalog</small></div><div class="pipeline-step"><span class="step-dot">2</span><strong>Validated execution</strong><small>Waiting for an approved plan</small></div><div class="pipeline-step"><span class="step-dot">3</span><strong>Evidence verification</strong><small>No claim is displayed before verification</small></div>`}
function renderFacts(facts){const useful=(facts||[]).filter(f=>['string','number','boolean'].includes(typeof f.value)).slice(0,6);$('fact-cards').innerHTML=useful.map(f=>`<div class="fact-card"><strong>${escapeHtml(concise(f.value))}</strong><span>${escapeHtml(f.unit||f.derivation)}</span></div>`).join('')}
function renderTables(tables){
  const populated=(tables||[]).filter(table=>Array.isArray(table.rows)&&table.rows.length);$('table-section').hidden=!populated.length;$('row-summary').textContent=`${populated.reduce((n,t)=>n+t.rows.length,0)} row(s)`;
  $('tables').innerHTML=populated.map(table=>{const columns=[...new Set(table.rows.flatMap(row=>Object.keys(row)))],header=columns.map(column=>`<th>${escapeHtml(humanize(column))}</th>`).join(''),body=table.rows.map(row=>`<tr>${columns.map(column=>`<td>${escapeHtml(concise(row[column]))}</td>`).join('')}</tr>`).join('');return `<div class="table-label">${escapeHtml(humanize(table.operator))}</div><div class="table-wrap"><table><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table></div>`}).join('');
}
function renderCitations(citations){$('citation-count').textContent=`${citations?.length||0} immutable reference(s)`;$('citations').innerHTML=(citations||[]).map(c=>`<button class="citation-card" data-citation="${escapeHtml(c.citation_id)}"><strong>${escapeHtml(c.view_name)}</strong><span>${escapeHtml(c.primary_id)} • ${escapeHtml(c.citation_id)}</span></button>`).join('')||'<div class="pipeline-empty">No row citation was produced for this response.</div>';document.querySelectorAll('[data-citation]').forEach(button=>button.onclick=()=>openCitation(button.dataset.citation))}
function renderResult(result){
  $('answer-panel').hidden=false;$('answer').textContent=result.answer;$('answer').classList.toggle('error-copy',result.status!=='success');$('route').textContent=`Route ${result.route} • revision ${result.analysis_revision}`;$('latency').textContent=result.elapsed_ms?`${(result.elapsed_ms/1000).toFixed(1)}s`:'Saved';
  $('limitations').innerHTML=(result.limitations||[]).map(text=>`<div class="warning">${escapeHtml(text)}</div>`).join('');renderFacts(result.facts);renderTables(result.tables);renderCitations(result.citations);renderPipeline(result);
  $('exports').innerHTML=result.trace_id?['json','csv','pdf'].map(format=>`<a href="/api/v1/investigations/${encodeURIComponent(result.trace_id)}/export?format=${format}">Export ${format.toUpperCase()}</a>`).join(''):'';$('answer-panel').scrollIntoView({behavior:'smooth',block:'start'});
}
async function openCitation(id){const response=await fetch('/api/v1/evidence/'+encodeURIComponent(id)),data=await response.json();if(!response.ok){$('status').textContent=data.error||'Citation unavailable';return}$('evidence-reference').innerHTML=Object.entries(data.reference||{}).filter(([,value])=>value!==null).map(([key,value])=>`<div><small>${escapeHtml(humanize(key))}</small><strong>${escapeHtml(value)}</strong></div>`).join('');$('evidence-record').textContent=JSON.stringify(data.record,null,2);$('evidence-dialog').showModal()}
async function openInvestigation(traceId){
  const response=await fetch('/api/v1/investigations/'+encodeURIComponent(traceId)),record=await response.json();if(!response.ok)return;const pkg=record.answer_package||{},plan=(record.plan?.ordered_steps||[]).map((step,index)=>({step:index+1,...step}));
  renderResult({trace_id:record.trace_id,status:record.status,route:record.route,answer:record.displayed_answer,analysis_revision:record.analysis_revision,facts:pkg.facts||[],tables:pkg.tables||[],citations:pkg.citations||[],limitations:pkg.limitations||[],validated_plan:plan,elapsed_ms:null});setView('investigate');
}
async function streamQuery(payload){
  const response=await fetch('/api/v1/query/stream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});if(!response.ok)throw new Error((await response.json()).error||'Query failed');const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='';
  while(true){const {value,done}=await reader.read();buffer+=decoder.decode(value||new Uint8Array(),{stream:!done});const blocks=buffer.split('\n\n');buffer=blocks.pop();for(const block of blocks){let event='message',data='';for(const line of block.split('\n')){if(line.startsWith('event:'))event=line.slice(6).trim();if(line.startsWith('data:'))data+=line.slice(5).trim()}if(!data)continue;const message=JSON.parse(data);if(event==='status')$('status').textContent=message.message;if(event==='error')throw new Error(message.error||'Query failed');if(event==='result')return message}if(done)break}throw new Error('The investigation ended without a result');
}
async function runQuery(){
  if(state.running)return;const question=$('question').value.trim();if(!question){$('status').textContent='Enter a forensic question first.';$('question').focus();return}const split=id=>$(id).value.split(',').map(value=>value.trim()).filter(Boolean),scope={upload_ids:split('upload-ids'),batch_ids:split('batch-ids'),endpoint_filters:split('endpoint-ips')};
  if($('call-type').value)scope.call_type=$('call-type').value;if($('start-time').value)scope.start_time=new Date($('start-time').value).getTime()/1000;if($('end-time').value)scope.end_time=new Date($('end-time').value).getTime()/1000;
  state.running=true;$('ask').disabled=true;$('ask').querySelector('span').textContent='Analyzing…';$('status').textContent='Routing and validating the investigation…';renderWorkingPipeline();
  try{const result=await streamQuery({question,scope});renderResult(result);$('status').textContent=result.status==='success'?'Investigation completed and evidence verified.':'The request stopped safely.';await loadRuntime()}catch(error){$('status').textContent=error.message;$('pipeline-state').textContent='Failed'}finally{state.running=false;$('ask').disabled=false;$('ask').querySelector('span').textContent='Run investigation'}
}
document.querySelectorAll('.suggestion').forEach(button=>button.onclick=()=>{$('question').value=button.textContent;$('question').dispatchEvent(new Event('input'));$('question').focus()});document.querySelectorAll('.nav-item').forEach(button=>button.onclick=()=>setView(button.dataset.view));
$('view-all-history').onclick=()=>setView('history');$('back-investigate').onclick=()=>setView('investigate');$('refresh').onclick=()=>loadRuntime().catch(showStartupError);$('ask').onclick=runQuery;$('question').oninput=()=>{$('question-count').textContent=`${$('question').value.length} / 4000`};$('question').onkeydown=event=>{if(event.ctrlKey&&event.key==='Enter'){event.preventDefault();runQuery()}};$('close-dialog').onclick=()=>$('evidence-dialog').close();
function showStartupError(error){$('health').textContent='Connection failed';$('health').className='health-pill bad';$('database-meta').textContent=error.message}loadRuntime().catch(showStartupError);
