const state={edr:'crowdstrike',hosts:[],selected:new Set(),profile:'triage',profileConfirmed:false,pushStarted:false,health:null,jobs:[],currentPushId:null,pushed:new Set(),endpointTab:'all',velociraptor:null};
function normalizeOs(v){const x=String(v||'').toLowerCase();if(x.includes('win'))return 'windows';if(x.includes('mac')||x.includes('darwin')||x.includes('osx'))return 'macos';if(x.includes('linux')||x.includes('ubuntu')||x.includes('debian'))return 'linux';return 'unknown'}

function collectorReadyForSelection(){
  if(!state.selected.size || !state.velociraptor)return false;
  return [...state.selected].every(id=>{const h=state.hosts.find(x=>x.device_id===id);if(!h)return false;const os=normalizeOs(h.os_family||h.platform);return Boolean(state.velociraptor.collectors?.[os]?.[state.profile]?.available)});
}
function updateCollectorStatusContext(){
  const main=$('#collectorStatusText'),dot=$('#collectorStatusDot'),box=$('#collectorStatus');if(!main||!dot||!box)return;
  if(!state.selected.size){main.innerHTML='<strong>Velociraptor</strong> · Select endpoints to check collector readiness';dot.className='collector-status-dot';return}
  if(collectorReadyForSelection()){main.innerHTML='<strong>Velociraptor ready</strong> · Offline collector available for all selected endpoints';dot.className='collector-status-dot good'}
  else{main.innerHTML='<strong>Velociraptor collector missing</strong> · Build or update the required collector in Settings';dot.className='collector-status-dot warn'}
}
function updateDeployButton(){const button=$('#run');if(!button)return;const enabled=state.selected.size>0&&!state.pushStarted&&collectorReadyForSelection();button.disabled=!enabled;button.setAttribute('aria-disabled',String(!enabled));button.title=enabled?'Ready to collect evidence':'A Velociraptor collector must be available for every selected endpoint and profile'}

const $=s=>document.querySelector(s);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function loadVelociraptorStatus(){try{const x=await api('/api/velociraptor/status');state.velociraptor=x;const s=$('#velociraptorServerSetting'),v=$('#velociraptorVersionSetting'),l=$('#velociraptorLinuxSetting'),m=$('#velociraptorMacSetting'),w=$('#velociraptorWindowsSetting');if(s)s.textContent=x.server_url||'Configured by server';if(v)v.textContent=x.version||'Configured by server';if(l)l.textContent=Object.values(x.collectors?.linux||{}).filter(c=>c.available).length+' / '+Object.keys(x.collectors?.linux||{}).length+' ready';if(m)m.textContent=Object.values(x.collectors?.macos||{}).filter(c=>c.available).length+' / '+Object.keys(x.collectors?.macos||{}).length+' ready';if(w)w.textContent=Object.values(x.collectors?.windows||{}).filter(c=>c.available).length+' / '+Object.keys(x.collectors?.windows||{}).length+' ready';updateCollectorStatusContext();updateDeployButton()}catch(e){}}
async function api(url,opts={}){const r=await fetch(url,{credentials:'same-origin',...opts});if(r.status===401){throw new Error('Application login required.')}if(r.status===503){toast('Cloudflare Access verification is not configured.');throw new Error('Cloudflare Access verification is not configured')}if(!r.ok){let t=await r.text();try{t=JSON.parse(t).detail||t}catch{}throw new Error(t)}return r.headers.get('content-type')?.includes('application/json')?r.json():r}
const themeStore={get(){try{return window.localStorage.getItem('kfc-theme')}catch{return null}},set(v){try{window.localStorage.setItem('kfc-theme',v)}catch{}}};
function applyTheme(mode){document.documentElement.dataset.theme=mode==='auto'?'':mode;themeStore.set(mode)}
function initTheme(){const saved=themeStore.get()||'auto';applyTheme(saved);document.querySelectorAll('.theme-buttons [data-theme]').forEach(b=>b.addEventListener('click',()=>{applyTheme(b.dataset.theme);toast(`Theme: ${b.dataset.theme==='auto'?'browser setting':b.dataset.theme}`)}))}
const coverageState={assets:[],filter:'all',query:'',loaded:false};
let workspace='dfir';
let dfirView='console';
function coverageBadge(present,label){return `<span class="coverage-source ${present?'present':'missing'}">${present?'Present':'Missing'}</span>`}
function renderCoverage(data){
  const assets=data.assets||[];coverageState.assets=assets;coverageState.loaded=true;
  $('#coverageTotal').textContent=data.counts?.total ?? assets.length;$('#coverageCs').textContent=data.counts?.crowdstrike ?? 0;$('#coverageS1').textContent=data.counts?.sentinelone ?? 0;$('#coverageTen').textContent=data.counts?.tenable ?? 0;
  const syncText=$('#coverageSyncStatus');if(syncText)syncText.textContent=`Last sync: ${data.last_sync||'Not yet synchronized'} · ${data.sync_status==='running'?'Syncing':'Idle'}`;const notice=$('#coverageSourceNotice');const errors=Object.entries(data.errors||{});if(notice){notice.classList.toggle('hidden',!errors.length);notice.textContent=errors.length?`Source warnings: ${errors.map(([k,v])=>`${k}: ${v}`).join(' · ')}`:'';}
  const body=$('#coverageTable');if(!body)return;if(!assets.length){body.innerHTML='<tr><td colspan="6" class="state-msg">No assets match this view.</td></tr>';return}
  body.innerHTML=assets.map(a=>{const src=a.sources||[];const names=Object.values(a.source_records||{}).map(x=>x.hostname).filter(Boolean);const displayIp=(a.ips||[])[0]||'—';return `<tr><td><strong>${esc(a.hostname||'Unknown')}</strong><div class="job-meta">${esc(names.slice(0,3).join(' · '))}</div></td><td><code>${esc(displayIp)}</code></td><td>${coverageBadge(!!a.coverage?.crowdstrike,'CrowdStrike')}</td><td>${coverageBadge(!!a.coverage?.sentinelone,'SentinelOne')}</td><td>${coverageBadge(!!a.coverage?.tenable,'Tenable')}</td><td><span class="match-confidence">${a.sources.length}/3 sources</span></td></tr>`}).join('')
}
async function loadAssetCoverage(){
  try{const params=new URLSearchParams();params.set('missing',coverageState.filter);if(coverageState.query)params.set('q',coverageState.query);const data=await api('/api/asset-coverage?'+params.toString());renderCoverage(data)}catch(e){const body=$('#coverageTable');if(body)body.innerHTML=`<tr><td colspan="6" class="state-msg danger">${esc(e.message)}</td></tr>`}
}
async function requestAssetSync(){try{await api('/api/asset-coverage/sync',{method:'POST'});toast('Asset inventory sync started')}catch(e){toast(e.message)}}
function showAssetCoverage(){coverageState.filter=$('#coverageMissing')?.value||'all';coverageState.query=$('#coverageSearch')?.value.trim()||'';loadAssetCoverage()}


function csvCell(value){
  const s=String(value??'');
  return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s;
}
function exportAssetCoverage(){
  const assets=coverageState.assets||[];
  const header=['Hostname','IP','CrowdStrike','SentinelOne','Tenable','Sources','CrowdStrike ID','SentinelOne ID','Tenable ID'];
  const rows=assets.map(a=>[
    a.hostname,(a.ips||[])[0]||'',
    a.coverage?.crowdstrike?'Present':'Missing',
    a.coverage?.sentinelone?'Present':'Missing',
    a.coverage?.tenable?'Present':'Missing',
    (a.sources||[]).join('; '),
    a.source_records?.crowdstrike?.id||'',
    a.source_records?.sentinelone?.id||'',
    a.source_records?.tenable?.id||''
  ]);
  const csv=[header,...rows].map(r=>r.map(csvCell).join(',')).join('\r\n');
  const blob=new Blob([csv],{type:'text/csv;charset=utf-8;'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=`asset-coverage-${new Date().toISOString().slice(0,10)}.csv`;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  if(typeof toast==='function')toast(`Exported ${assets.length} assets`);
}


const vulnState={rows:[],view:'exec',weight:.60,newDays:3,severity:'all',newOnly:false,separateMs:true,os:'all',query:'',source:'Tenable API',loaded:false};

function vulnOsOf(r){
  const s=[r.operating_system||r.os||'',r.family||'',r.plugin_name||''].join(' ').toLowerCase();
  if(/windows|microsoft|win(dows)?/.test(s))return'windows';
  if(/linux|ubuntu|debian|rhel|red hat|centos|suse/.test(s))return'linux';
  if(/macos|os x|darwin|apple/.test(s))return'macos';
  return'other';
}
function vulnTs(v){if(v==null)return null;if(typeof v==='number')return v<1e12?v*1000:v;const d=Date.parse(v);return Number.isNaN(d)?null:d}
function vulnAge(v){const ts=vulnTs(v);return ts==null?null:Math.max(0,Math.floor((Date.now()-ts)/86400000))}
function vulnScore(r){const v=Number(r.vpr),c=Number(r.cvss3);if(Number.isFinite(v)&&Number.isFinite(c))return vulnState.weight*v+(1-vulnState.weight)*c;if(Number.isFinite(v))return v;if(Number.isFinite(c))return c;return({critical:9.5,high:7.5,medium:5,low:2.5,info:.5}[r.severity]||0)}
function vulnSeverityRank(s){return({critical:4,high:3,medium:2,low:1,info:0}[String(s).toLowerCase()]??-1)}
function vulnIsMs(r){const n=String(r.plugin_name||'').toLowerCase(),f=String(r.family||'').toLowerCase();return f.includes('microsoft bulletins')||/\bkb\d{6,}\b/.test(n)||(/security update|cumulative update|security monthly quality rollup|security-only|monthly rollup/.test(n)&&/microsoft|windows|office|edge|sql server|exchange|sharepoint|visual studio|\.net/.test(n))}
function vulnDecorate(rows){
  return rows.map(r=>({...r, _os:vulnOsOf(r), _score:vulnScore(r), _firstAge:vulnAge(r.first_found), _lastAge:vulnAge(r.last_found), _new:vulnAge(r.first_found)!=null&&vulnAge(r.first_found)<=vulnState.newDays, _active:vulnAge(r.last_found)!=null&&vulnAge(r.last_found)<=vulnState.newDays, _ms:vulnIsMs(r)}));
}
function vulnFiltered(){
  const sev=vulnState.severity==='all'?null:new Set(vulnState.severity.split(','));
  const q=vulnState.query.trim().toLowerCase();
  return vulnDecorate(vulnState.rows).filter(r=>{
    if(vulnState.separateMs&&r._ms&&vulnState.view!=='patch')return false;
    if(sev&&!sev.has(String(r.severity).toLowerCase()))return false;
    if(vulnState.newOnly&&!r._new)return false;
    if(vulnState.os!=='all'&&r._os!==vulnState.os)return false;
    if(q){const hay=[r.host,r.plugin_name,r.family,(r.cve||[]).join(' ')].join(' ').toLowerCase();if(!hay.includes(q))return false}
    return true;
  });
}
function vulnSetText(id,text){const e=$('#'+id);if(e)e.textContent=text}
function vulnBadge(sev){return `<span class="vuln-sev sev-${esc(sev)}">${esc(String(sev).toUpperCase())}</span>`}
function renderVulnKpis(rows){
  const hosts=new Set(rows.map(r=>r.host)).size;
  const critical=rows.filter(r=>r.severity==='critical').length;
  const newCritical=rows.filter(r=>r.severity==='critical'&&r._new).length;
  const recurring=rows.filter(r=>r.severity==='critical'&&!r._new).length;
  const c=$('#vulnKpis');if(!c)return;
  c.innerHTML=[
    ['Hosts in scope',hosts,'with open findings'],['Open findings',rows.length,'current Tenable findings'],
    ['Critical',critical,'severity = critical'],['New critical',newCritical,`first seen ≤ ${vulnState.newDays}d`],
    ['Recurring critical',recurring,'older, still open']
  ].map((x,i)=>`<article class="kpi ${i===3?'kpi-primary':''}"><div class="k-label">${x[0]}</div><div class="k-num">${x[1]}</div><div class="k-foot">${x[2]}</div></article>`).join('');
}
function renderVulnNewCritical(rows){
  const list=rows.filter(r=>r.severity==='critical'&&r._new).sort((a,b)=>b._score-a._score).slice(0,8);
  vulnSetText('vulnNewCritCount',`${list.length} shown`);
  const box=$('#vulnNewCrit');if(!box)return;
  if(!list.length){box.innerHTML='<div class="state-msg">No new critical findings in the selected window.</div>';return}
  box.innerHTML=list.map(r=>`<div class="vuln-list-row"><div><strong>${esc(r.host)}</strong><div class="job-meta">${esc(r.plugin_name)}</div></div><div>${vulnBadge(r.severity)}</div><div class="vuln-score">${r._score.toFixed(1)}</div></div>`).join('');
}
function renderVulnHostRisk(rows){
  const map=new Map();rows.forEach(r=>map.set(r.host,(map.get(r.host)||0)+r._score));
  const items=[...map.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8),max=items[0]?.[1]||1;const box=$('#vulnHostRisk');if(!box)return;
  box.innerHTML=items.length?items.map(([host,score],i)=>`<div class="vuln-host-row"><div class="vuln-host-name">${esc(host)}</div><div class="vuln-risk-track"><span style="width:${Math.max(2,score/max*100)}%"></span></div><div class="vuln-score">${score.toFixed(1)}</div></div>`).join(''):'<div class="state-msg">No findings.</div>';
}
function renderVulnSeverity(rows){
  const counts={critical:0,high:0,medium:0,low:0,info:0};rows.forEach(r=>counts[r.severity]=(counts[r.severity]||0)+1);const max=Math.max(1,...Object.values(counts));const box=$('#vulnSeverityChart');if(!box)return;
  box.innerHTML=Object.entries(counts).map(([k,n])=>`<div class="vuln-bar-row"><span>${k}</span><div class="vuln-risk-track"><span class="sev-${k}" style="width:${n/max*100}%"></span></div><b>${n}</b></div>`).join('');
}
function renderVulnMatrix(rows){
  const buckets=[0,7,30,90,365],labels=['≤7d','8–30d','31–90d','91–365d','365d+'];const matrix={critical:[0,0,0,0,0],high:[0,0,0,0,0],medium:[0,0,0,0,0],low:[0,0,0,0,0]};
  rows.forEach(r=>{const age=r._firstAge??9999;let i=age<=7?0:age<=30?1:age<=90?2:age<=365?3:4;if(matrix[r.severity])matrix[r.severity][i]++});
  const head=labels.map(x=>`<th>${x}</th>`).join('');const body=['critical','high','medium','low'].map(s=>`<tr><th>${s}</th>${matrix[s].map(n=>`<td>${n}</td>`).join('')}</tr>`).join('');
  const box=$('#vulnAgeMatrix');if(box)box.innerHTML=`<table class="mini-matrix"><thead><tr><th>Severity</th>${head}</tr></thead><tbody>${body}</tbody></table>`;
}
function renderVulnFindings(){
  const rows=vulnFiltered().sort((a,b)=>b._score-a._score);vulnSetText('vulnFindingsCount',`${rows.length} findings`);
  const body=$('#vulnFindingsTable');if(!body)return;
  if(!rows.length){body.innerHTML='<tr><td colspan="8" class="state-msg">No findings match the selected filters.</td></tr>';return}
  body.innerHTML=rows.map(r=>`<tr><td><strong>${esc(r.plugin_name||'Unknown')}</strong><div class="job-meta">${esc((r.cve||[]).join(', '))}</div></td><td><strong>${esc(r.host)}</strong><div class="job-meta">${esc(r.operating_system||'OS unknown')}</div></td><td>${vulnBadge(r.severity)}</td><td class="tabular">${Number.isFinite(Number(r.vpr))?Number(r.vpr).toFixed(1):'—'}</td><td class="tabular">${Number.isFinite(Number(r.cvss3))?Number(r.cvss3).toFixed(1):'—'}</td><td class="tabular">${esc(String(r.first_found||'').slice(0,10)||'—')}</td><td class="tabular">${esc(String(r.last_found||'').slice(0,10)||'—')}</td><td>${esc(String(r.state||'open').toUpperCase())}</td></tr>`).join('');
}
function renderVulnPatch(){
  const rows=vulnDecorate(vulnState.rows).filter(r=>r._ms).sort((a,b)=>b._score-a._score);const box=$('#vulnPatchList');if(!box)return;
  box.innerHTML=rows.length?rows.slice(0,20).map(r=>`<div class="vuln-list-row"><div><strong>${esc(r.host)}</strong><div class="job-meta">${esc(r.plugin_name)}</div></div>${vulnBadge(r.severity)}<div class="vuln-score">${r._score.toFixed(1)}</div></div>`).join(''):'<div class="state-msg">No Microsoft update findings in the current data.</div>';
}
function renderVulnLinux(){
  const distro=$('#vulnLinuxDistro')?.value||'all';let rows=vulnDecorate(vulnState.rows).filter(r=>r._os==='linux');if(distro!=='all')rows=rows.filter(r=>{const os=String(r.operating_system||'').toLowerCase();if(distro==='rhel')return os.includes('red hat')||os.includes('rhel');if(distro==='almalinux')return os.includes('alma');if(distro==='oraclelinux')return os.includes('oracle linux');return os.includes(distro)});
  const box=$('#vulnLinuxList');if(!box)return;
  box.innerHTML=rows.length?rows.slice(0,20).map(r=>`<div class="vuln-list-row"><div><strong>${esc(r.host)}</strong><div class="job-meta">${esc(r.plugin_name)} · ${esc(r.operating_system||'Unknown OS')}</div></div>${vulnBadge(r.severity)}<div class="vuln-score">${r._score.toFixed(1)}</div></div>`).join(''):'<div class="state-msg">No Linux findings in the current data.</div>';
}
function setVulnView(view){
  vulnState.view=view;
  document.querySelectorAll('.vuln-link').forEach(b=>b.classList.toggle('active',b.dataset.vulnView===view));
  document.querySelectorAll('.vuln-page').forEach(p=>p.classList.toggle('hidden',p.dataset.vulnPanel!==view));
  if(view==='findings')renderVulnFindings();if(view==='patch')renderVulnPatch();if(view==='linux')renderVulnLinux();if(view==='exec')renderVulnExecutive();
}
function renderVulnExecutive(){
  const rows=vulnFiltered();renderVulnKpis(rows);renderVulnNewCritical(rows);renderVulnHostRisk(rows);renderVulnSeverity(rows);renderVulnMatrix(rows);
}
function renderVulnAll(){renderVulnExecutive();if(vulnState.view==='findings')renderVulnFindings();if(vulnState.view==='patch')renderVulnPatch();if(vulnState.view==='linux')renderVulnLinux();}

async function loadVulnerabilities(){
  try{
    const days=$('#vulnHistory')?.value||'';
    const url='/api/vulns'+(days?`?since_days=${encodeURIComponent(days)}`:'');
    const data=await api(url);
    vulnState.rows=data.vulnerabilities||[];
    vulnState.loaded=true;
    vulnState.source=data.source||'Tenable API';
    const src=$('#vulnSourceStatus');if(src)src.textContent=`Source: ${vulnState.source}`;
    renderVulnAll();
  }catch(e){const box=$('#vulnNewCrit');if(box)box.innerHTML=`<div class="state-msg danger">${esc(e.message)}</div>`}
}

function wireVulnerabilityUi(){
  document.querySelectorAll('.vuln-link').forEach(b=>b.addEventListener('click',()=>setVulnView(b.dataset.vulnView)));
  $('#refreshVuln')?.addEventListener('click',loadVulnerabilities);
  $('#vulnHistory')?.addEventListener('change',loadVulnerabilities);
  $('#vulnWeight')?.addEventListener('input',e=>{vulnState.weight=Number(e.target.value)/100;vulnSetText('vulnWeightReadout',`VPR ${vulnState.weight.toFixed(2)} · CVSS ${(1-vulnState.weight).toFixed(2)}`);renderVulnAll()});
  $('#vulnNewDays')?.addEventListener('input',e=>{vulnState.newDays=Number(e.target.value)||3;renderVulnAll()});
  $('#vulnSeverity')?.addEventListener('change',e=>{vulnState.severity=e.target.value;renderVulnAll()});
  $('#vulnNewOnly')?.addEventListener('change',e=>{vulnState.newOnly=e.target.checked;renderVulnAll()});
  $('#vulnSeparateMs')?.addEventListener('change',e=>{vulnState.separateMs=e.target.checked;renderVulnAll()});
  $('#vulnOs')?.addEventListener('change',e=>{vulnState.os=e.target.value;renderVulnFindings()});
  $('#vulnSearch')?.addEventListener('input',e=>{vulnState.query=e.target.value;renderVulnFindings()});
  $('#vulnLinuxDistro')?.addEventListener('change',renderVulnLinux);
}
wireVulnerabilityUi();



const authState={user:null,authenticated:false};
const workspaceLabels={dfir:'DFIR Evidence Collection',assets:'Asset Coverage',vuln:'Vulnerability Management'};
function workspaceAllowed(name){return Boolean(authState.user?.admin || authState.user?.permissions?.includes(name))}
function showAuthScreen(){document.getElementById('authScreen')?.classList.remove('hidden');document.getElementById('appShell')?.classList.add('auth-locked');document.getElementById('loginUsername')?.focus()}
function hideAuthScreen(){document.getElementById('authScreen')?.classList.add('hidden');document.getElementById('appShell')?.classList.remove('auth-locked')}
async function loadCurrentUser(){try{const r=await fetch('/api/auth/me',{credentials:'same-origin'});if(!r.ok)throw new Error('unauthenticated');const body=await r.json();authState.user=body.user;authState.authenticated=true;hideAuthScreen();renderUserContext();applyWorkspaceAccess();loadAdminUsers();if(!workspaceAllowed(workspace))workspace=['dfir','assets','vuln'].find(workspaceAllowed)||'dfir';return true}catch{authState.user=null;authState.authenticated=false;showAuthScreen();return false}}
function renderUserContext(){const el=$('#authUserLabel');if(el&&authState.user)el.textContent=authState.user.username+(authState.user.admin?' · Admin':'')}
function applyWorkspaceAccess(){document.querySelectorAll('.workspace-tab').forEach(btn=>{const allowed=workspaceAllowed(btn.dataset.workspace);btn.hidden=!allowed;btn.disabled=!allowed});const settings=$('#settingsGlobal');if(settings)settings.hidden=!authState.user?.admin}
function updateWorkspaceBranding(){
  const assets=workspace==='assets',vuln=workspace==='vuln',settings=workspace==='settings';
  const set=(id,text)=>{const el=document.getElementById(id);if(el)el.textContent=text};
  set('pageKicker',settings?'Application Configuration':vuln?'Vulnerability Management':assets?'Security Asset Visibility':'Digital Forensics & Incident Response · Evidence Collection');
  set('pageTitle',settings?'Settings':vuln?'Vulnerability Management':assets?'Asset Coverage':'DFIR Evidence Collection Console');
  set('pageTagline',settings?'Collector configuration and web application administration.':vuln?'Tenable findings prioritized by VPR, CVSSv3, severity, age, and host risk.':assets?'Deduplicated asset inventory across CrowdStrike, SentinelOne, and Tenable.':document.getElementById('pageTagline')?.textContent||'');
  set('pageFooterBrand',settings?'USC Office of Cybersecurity · Settings':vuln?'USC Office of Cybersecurity · Vulnerability Management':assets?'USC Office of Cybersecurity · Asset Coverage':'USC Office of Cybersecurity · DFIR Evidence Collection Console');
}

function showView(view){dfirView=view;workspace=view==='settings'?'settings':'dfir';applyWorkspaceLayout();if(view==='jobs')renderJobs();if(view==='audit')renderAudit();if(view==='console')renderWorkflow();}
function openSettings(){workspace='settings';applyWorkspaceLayout();}

let adminEditingUser=null;

function renderAdminUsers(users){
  const box=$('#adminUserTable');if(!box)return;
  if(!users?.length){box.innerHTML='<div class="state-msg">No application users found.</div>';return}
  box.innerHTML=users.map((u,i)=>{
    const perms=(u.permissions||[]).map(p=>`<span class="permission-pill granted">${esc(workspaceLabels[p]||p)}</span>`).join('');
    const identity=u.identity_email||'No Cloudflare identity';
    const role=u.role==='admin'?'Administrator':'Operator';
    return `<div class="admin-user-row">
      <div><strong>${esc(u.username)}</strong></div>
      <div><div>${esc(role)}</div><div class="job-meta">${esc(identity)}</div></div>
      <div class="admin-perms">${perms||'<span class="job-meta">No workspace access</span>'}</div>
      <div><span class="permission-pill ${u.enabled?'granted':''}">${u.enabled?'Enabled':'Disabled'}</span></div>
      <div class="admin-user-actions"><button class="btn btn-secondary btn-small" type="button" data-admin-edit="${i}">Edit</button><button class="btn btn-danger btn-small" type="button" data-admin-delete="${i}" ${u.username===authState.user?.username?'disabled':''}>Delete</button></div>
    </div>`
  }).join('');
  box.querySelectorAll('[data-admin-edit]').forEach(b=>b.addEventListener('click',()=>editAdminUser(users[Number(b.dataset.adminEdit)])));
  box.querySelectorAll('[data-admin-delete]').forEach(b=>b.addEventListener('click',()=>deleteAdminUser(users[Number(b.dataset.adminDelete)])));
}

async function loadAdminUsers(){
  const box=$('#adminUserTable');if(!box||!authState.user?.admin)return;
  try{const users=await api('/api/admin/users');renderAdminUsers(users)}catch(e){box.innerHTML=`<div class="state-msg danger">${esc(e.message)}</div>`}
}

function editAdminUser(u){
  adminEditingUser=u.username;
  $('#adminFormTitle').textContent='Edit application user';
  $('#adminUsername').value=u.username;$('#adminUsername').disabled=true;
  $('#adminPassword').value='';$('#adminIdentityEmail').value=u.identity_email||'';
  $('#adminRole').value=u.role;$('#adminEnabled').checked=!!u.enabled;
  ['dfir','assets','vuln'].forEach(x=>$('#perm_'+x).checked=(u.permissions||[]).includes(x));
}

function resetAdminUserForm(){
  adminEditingUser=null;$('#adminFormTitle').textContent='Add application user';
  $('#adminUsername').disabled=false;$('#adminUsername').value='';$('#adminPassword').value='';
  $('#adminIdentityEmail').value='';$('#adminRole').value='operator';$('#adminEnabled').checked=true;
  ['dfir','assets','vuln'].forEach(x=>$('#perm_'+x).checked=false);
}

async function saveAdminUser(e){
  e.preventDefault();
  const username=$('#adminUsername').value.trim(),role=$('#adminRole').value;
  const permissions=['dfir','assets','vuln'].filter(x=>$('#perm_'+x).checked);
  const body={username,password:$('#adminPassword').value||null,role,permissions,identity_email:$('#adminIdentityEmail').value.trim()||null,enabled:$('#adminEnabled').checked};
  try{
    if(adminEditingUser){await api('/api/admin/users/'+encodeURIComponent(adminEditingUser),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})}
    else{await api('/api/admin/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})}
    toast(adminEditingUser?'User updated':'User created');resetAdminUserForm();await loadAdminUsers();
  }catch(e){toast(e.message)}
}

async function deleteAdminUser(u){
  if(!u||u.username===authState.user?.username)return;
  if(!window.confirm(`Delete application user "${u.username}"?`))return;
  try{await api('/api/admin/users/'+encodeURIComponent(u.username),{method:'DELETE'});toast('User deleted');await loadAdminUsers()}catch(e){toast(e.message)}
}


$('#adminUserForm')?.addEventListener('submit',saveAdminUser);
$('#adminCancelEdit')?.addEventListener('click',resetAdminUserForm);
document.querySelectorAll('.admin-only').forEach(x=>x.hidden=!authState.user?.admin);


