/* PID Facilities Management server: authentication, sessions, shared persistence. */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const nodemailer = require('nodemailer');

const ROOT = __dirname;
/* Load local deployment settings without adding a runtime dependency. */
const ENV_FILE = path.join(ROOT, '.env');
if (fs.existsSync(ENV_FILE)) {
  for (const line of fs.readFileSync(ENV_FILE, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2];
  }
}
/* In Azure App Service set DATA_DIR=/home/pid-facilities-data. The deployment
   package may be mounted read-only, while /home remains durable storage. */
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const DATA_FILE = path.join(DATA_DIR, 'state.json');
const PORT = Number(process.env.PORT || 8080);
const SECRET = process.env.SESSION_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ROLES = new Set(['superadmin', 'admin', 'hq', 'centre', 'technician', 'intern', 'viewer', 'auditor']);
const PASSWORD_MIN_LENGTH = 12;
const DOC_LIBRARY_CAPACITY_BYTES = 2_000_000_000_000;

function fail(message) { console.error(message); process.exit(1); }
if (!SECRET || SECRET.length < 32) fail('SESSION_SECRET must be at least 32 characters.');
if (!ADMIN_EMAIL || !ADMIN_PASSWORD) fail('Set ADMIN_EMAIL and ADMIN_PASSWORD before first start.');
fs.mkdirSync(DATA_DIR, { recursive:true });

function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash:crypto.scryptSync(password, salt, 64).toString('hex') };
}
function passwordMatches(password, user) {
  const candidate = crypto.scryptSync(password, user.salt, 64).toString('hex');
  const storedHash = user.passwordHash || user.hash; // accepts the initial v1 state too
  return !!storedHash && crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(storedHash, 'hex'));
}
function syncBootstrapAdmin(state) {
  if (!state || !Array.isArray(state.users)) return false;
  const canonicalEmail = ADMIN_EMAIL.toLowerCase();
  const nextHash = passwordHash(ADMIN_PASSWORD);
  let target = state.users.find(user => user.email && user.email.toLowerCase() === canonicalEmail);
  if (!target) {
    target = state.users.find(user => user.role === 'superadmin' || user.id === 'admin-1' || user.id === 'USR-0001') || state.users[0];
  }
  if (!target) {
    target = { id:'admin-1', email:canonicalEmail, name:'Administrator', role:'superadmin' };
    state.users.push(target);
  }

  const emailChanged = !!target.email && target.email.toLowerCase() !== canonicalEmail;
  const passwordChanged = target.salt !== nextHash.salt || (target.passwordHash || target.hash) !== nextHash.hash;
  const roleChanged = target.role !== 'superadmin';
  const accessChanged = target.suspended || target.mustChangePassword;
  const changed = emailChanged || passwordChanged || roleChanged || accessChanged;

  target.email = canonicalEmail;
  target.name = target.name || 'Administrator';
  target.role = 'superadmin';
  target.salt = nextHash.salt;
  target.passwordHash = nextHash.hash;
  delete target.hash;
  target.mustChangePassword = false;
  target.suspended = false;
  if (emailChanged || passwordChanged || roleChanged) target.sessionVersion = (target.sessionVersion || 0) + 1;

  const uniqueUsers = [];
  const seenEmails = new Set();
  for (const user of state.users) {
    if (!user || !user.email) continue;
    const normalized = user.email.toLowerCase();
    if (seenEmails.has(normalized)) continue;
    seenEmails.add(normalized);
    uniqueUsers.push(user);
  }
  state.users = uniqueUsers;

  if (!state.storage || typeof state.storage !== 'object') state.storage = {};
  const storedAppDataText = state.storage['pid-fms-data-v2'];
  if (storedAppDataText) {
    try {
      const storedAppData = JSON.parse(storedAppDataText);
      const adminUsers = Array.isArray(storedAppData.users) ? storedAppData.users : [];
      let storedAdmin = adminUsers.find(user => user.email && user.email.toLowerCase() === canonicalEmail)
        || adminUsers.find(user => user.role === 'superadmin' || user.id === 'USR-0001' || user.id === 'admin-1');
      if (!storedAdmin) {
        storedAdmin = { id:'USR-0001', name:'Administrator', role:'superadmin', centreId:'', email:canonicalEmail, phone:'' };
        adminUsers.push(storedAdmin);
      }
      storedAdmin.email = canonicalEmail;
      storedAdmin.name = storedAdmin.name || 'Administrator';
      storedAdmin.role = 'superadmin';
      storedAppData.users = adminUsers.filter((user, index, list) => {
        if (!user || !user.email) return true;
        return list.findIndex(candidate => candidate && candidate.email && candidate.email.toLowerCase() === user.email.toLowerCase()) === index;
      });
      state.storage['pid-fms-data-v2'] = JSON.stringify(storedAppData);
    } catch {
      // Keep any existing storage value intact if it is malformed; the login state remains authoritative.
    }
  }
  return changed;
}
function load() {
  let state;
  if (fs.existsSync(DATA_FILE)) state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if (!state) {
    const hash = passwordHash(ADMIN_PASSWORD);
    const appData = {
      orgName:'', msEmail:'', waNumber:'', requireMsAuthForAdmin:false, sharepointFolder:'PID Facilities Reports', sharepointSiteId:'', theme:'default',
      centres:[], users:[{ id:'USR-0001', name:'Administrator', role:'superadmin', centreId:'', email:ADMIN_EMAIL, phone:'' }],
      assets:[], workOrders:[], pmTasks:[], projects:[], incidents:[], inspections:[], assetReports:[], doodleLinks:[], documents:[], internChecklists:{},
      seq:{asset:0,wo:0,pm:0,proj:0,inc:0,insp:0,centre:0,user:1,ar:0,dl:0,doc:0}
    };
    state = { users:[{ id:'admin-1', email:ADMIN_EMAIL, name:'Administrator', role:'superadmin', ...hash }], storage:{ 'pid-fms-data-v2':JSON.stringify(appData) } };
  }
  const changed = syncBootstrapAdmin(state);
  if (changed) save(state);
  return state;
}
function save(state) {
  const temp = DATA_FILE + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(state, null, 2), { mode:0o600 });
  fs.renameSync(temp, DATA_FILE);
}
function tokenFor(user) {
  const payload = Buffer.from(JSON.stringify({ id:user.id, version:user.sessionVersion||0, exp:Date.now() + 8*60*60*1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return payload + '.' + signature;
}
function sessionCookieOptions(req, token = '', clear = false) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '');
  const secure = !!(req.socket && req.socket.encrypted) || forwardedProto.split(',').map(part => part.trim().toLowerCase()).includes('https');
  const sameSite = secure ? 'None' : 'Lax';
  const secureSuffix = secure ? '; Secure' : '';
  return `pid_session=${clear ? '' : token}; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=${clear ? 0 : 28800}${secureSuffix}`;
}
function sessionTokenFromRequest(req) {
  const authHeader = String(req.headers.authorization || '').trim();
  if (authHeader.toLowerCase().startsWith('bearer ')) return authHeader.slice(7).trim();
  const headerToken = String(req.headers['x-session-token'] || '').trim();
  if (headerToken) return headerToken;
  const cookie = (req.headers.cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith('pid_session='));
  if (!cookie) return null;
  return cookie.slice('pid_session='.length).trim();
}
function userFor(req, state) {
  const token = sessionTokenFromRequest(req);
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const session=JSON.parse(Buffer.from(payload, 'base64url'));
    const user=state.users.find(u=>u.id===session.id);
    const expired=user && user.accountExpiresAt && Date.parse(user.accountExpiresAt)<Date.now();
    return session.exp>Date.now() && user && !user.suspended && !expired ? user : null;
  } catch { return null; }
}
function publicUser(user) {
  return { id:user.id, name:user.name, email:user.email, role:user.role, suspended:!!user.suspended,
    mustChangePassword:!!user.mustChangePassword, accountExpiresAt:user.accountExpiresAt||null,
    lastLoginAt:user.lastLoginAt||null, loginHistory:user.loginHistory||[] };
}
function requireAdmin(req, res, state) {
  const user=requireUser(req,res,state);
  if(user && user.role!=='admin' && user.role!=='superadmin'){ respond(res,403,{error:'Administrator access required'}); return null; }
  return user;
}
function generatedPassword() {
  const groups=['ABCDEFGHJKLMNPQRSTUVWXYZ','abcdefghijkmnopqrstuvwxyz','23456789','!@#$%^&*-_'];
  const alphabet=groups.join('');
  const characters=groups.map(group=>group[crypto.randomInt(group.length)]);
  while(characters.length<24) characters.push(alphabet[crypto.randomInt(alphabet.length)]);
  for(let position=characters.length-1;position>0;position--){
    const swapIndex=crypto.randomInt(position+1);
    [characters[position],characters[swapIndex]]=[characters[swapIndex],characters[position]];
  }
  return characters.join('');
}
function passwordPolicy(state) {
  let settings={};
  try{ settings=JSON.parse(state.storage['pid-fms-data-v2']||'{}').adminSettings||{}; }catch{}
  return { minLength:Math.max(PASSWORD_MIN_LENGTH,Math.min(128,Number(settings.passwordMinimumLength)||PASSWORD_MIN_LENGTH)),
    uppercase:!!settings.passwordRequireUppercase, number:!!settings.passwordRequireNumber, symbol:!!settings.passwordRequireSymbol };
}
function passwordPolicyError(password, state) {
  const policy=passwordPolicy(state);
  if(password.length<policy.minLength) return `Password must be at least ${policy.minLength} characters.`;
  if(policy.uppercase && !/[A-Z]/.test(password)) return 'Password must include an uppercase letter.';
  if(policy.number && !/[0-9]/.test(password)) return 'Password must include a number.';
  if(policy.symbol && !/[^A-Za-z0-9]/.test(password)) return 'Password must include a symbol.';
  return '';
}
function writeAudit(state, actor, action, target, req) {
  if(!Array.isArray(state.auditLog)) state.auditLog=[];
  state.auditLog.push({ at:new Date().toISOString(), actor:actor.email, action, target,
    where:req.socket.remoteAddress||'unknown' });
  if(state.auditLog.length>1000) state.auditLog.splice(0,state.auditLog.length-1000);
}
function auditAppDataChanges(state, actor, beforeValue, nextValue, req) {
  try{
    const before=JSON.parse(beforeValue||'{}'); const next=JSON.parse(nextValue||'{}'); const changed=[];
    for(const [field,resource] of Object.entries(APP_DATA_RESOURCES)){
      const oldRows=before[field]||[]; const newRows=next[field]||[];
      if(JSON.stringify(oldRows)===JSON.stringify(newRows)) continue;
      const oldItems=Array.isArray(oldRows)?oldRows.map((row,index)=>[String(row.id||index),row]):Object.entries(oldRows);
      const newItems=Array.isArray(newRows)?newRows.map((row,index)=>[String(row.id||index),row]):Object.entries(newRows);
      const oldMap=new Map(oldItems); const newMap=new Map(newItems);
      const ids=new Set([...oldMap.keys(),...newMap.keys()]);
      for(const id of ids) if(JSON.stringify(oldMap.get(id))!==JSON.stringify(newMap.get(id))) changed.push(`${resource}: ${id}`);
    }
    const beforeSettings=before.adminSettings||{}; const nextSettings=next.adminSettings||{};
    const changedSettings=Array.from(new Set([...Object.keys(beforeSettings),...Object.keys(nextSettings)]))
      .filter(key=>JSON.stringify(beforeSettings[key])!==JSON.stringify(nextSettings[key]));
    if(changedSettings.length){
      const permissionsChanged=changedSettings.some(key=>key==='permissionMatrix'||key==='permissionMatrixEnforced');
      writeAudit(state,actor,permissionsChanged?'permissions.updated':'settings.updated',changedSettings.join(', '),req);
    }
    if(changed.length) writeAudit(state,actor,'records.updated',changed.slice(0,30).join('; '),req);
  }catch(error){ /* Ignore audit serialization errors; the data write is validated separately. */ }
}
const APP_DATA_RESOURCES={centres:'Centres',assets:'Assets',assetReports:'Assets',workOrders:'Work Orders',pmTasks:'Maintenance',projects:'Projects',documents:'Documents',incidents:'OHSA',inspections:'OHSA',internChecklists:'Users',doodleLinks:'Documents'};
function filterAppDataForUser(user, data) {
  if(user.role==='admin' || user.role==='superadmin' || !data.adminSettings?.permissionMatrixEnforced) return data;
  const rules=data.adminSettings.permissionMatrix&&data.adminSettings.permissionMatrix[user.role]||{};
  for(const [field,resource] of Object.entries(APP_DATA_RESOURCES)) if(!rules[resource]||rules[resource].view!==true) data[field]=Array.isArray(data[field])?[]:{};
  return data;
}
function preserveHiddenAppData(user, beforeValue, nextValue) {
  if(user.role==='admin' || user.role==='superadmin') return nextValue;
  const before=JSON.parse(beforeValue||'{}'); const next=JSON.parse(nextValue||'{}');
  if(!before.adminSettings?.permissionMatrixEnforced) return nextValue;
  const rules=before.adminSettings.permissionMatrix&&before.adminSettings.permissionMatrix[user.role]||{};
  for(const [field,resource] of Object.entries(APP_DATA_RESOURCES)) if(!rules[resource]||rules[resource].view!==true) next[field]=before[field]|| (field==='internChecklists'?{}:[]);
  return JSON.stringify(next);
}
function appDataPermissionError(user, beforeValue, nextValue) {
  if(user.role==='admin' || user.role==='superadmin') return null;
  try{
    const before=JSON.parse(beforeValue||'{}'); const next=JSON.parse(nextValue||'{}');
    const settings=before.adminSettings||{};
    if(!settings.permissionMatrixEnforced) return null;
    const protectedKeys=['users','adminSettings','orgName','msEmail','waNumber','requireMsAuthForAdmin','sharepointFolder','sharepointSiteId'];
    if(protectedKeys.some(key=>JSON.stringify(before[key])!==JSON.stringify(next[key]))) return 'Administrator permission required for user and system settings.';
    for(const [key,resource] of Object.entries(APP_DATA_RESOURCES)){
      const oldRows=before[key]||[]; const newRows=next[key]||[];
      if(JSON.stringify(oldRows)===JSON.stringify(newRows)) continue;
      const roleRules=settings.permissionMatrix&&settings.permissionMatrix[user.role];
      const rules=roleRules&&roleRules[resource];
      if(!rules||rules.view!==true) return `View permission denied for ${resource}.`;
      const oldMap=new Map((Array.isArray(oldRows)?oldRows:[]).map((row,index)=>[String(row.id||index),row]));
      const newMap=new Map((Array.isArray(newRows)?newRows:[]).map((row,index)=>[String(row.id||index),row]));
      for(const [id,row] of newMap){
        const previous=oldMap.get(id);
        if(!previous){ if(rules.create!==true) return `Create permission denied for ${resource}.`; continue; }
        if(JSON.stringify(previous)!==JSON.stringify(row)){
          const approving=resource==='Work Orders'&&previous.status==='pending_approval'&&['open','denied'].includes(row.status);
          const action=approving?'approve':'edit';
          if(rules[action]!==true) return `${action[0].toUpperCase()+action.slice(1)} permission denied for ${resource}.`;
        }
      }
      for(const id of oldMap.keys()) if(!newMap.has(id)&&rules.delete!==true) return `Delete permission denied for ${resource}.`;
    }
  }catch(error){ return 'Invalid application data.'; }
  return null;
}
function corsHeaders(req) {
  const origin = req.headers.origin;
  const allowed = !origin || origin === 'null' || origin === 'http://localhost:4310' || origin === 'https://pidmms.azurewebsites.net' || origin === 'https://pid-ftf6dmerh7fmfkga.southafricanorth-01.azurewebsites.net';
  return allowed && origin ? { 'Access-Control-Allow-Origin':origin, 'Access-Control-Allow-Credentials':'true', 'Access-Control-Allow-Headers':'Content-Type, Accept', 'Access-Control-Allow-Methods':'GET, POST, PUT, DELETE, OPTIONS' } : {};
}
function respond(res, status, data, headers={}) { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', ...headers }); res.end(JSON.stringify(data)); }
function readJson(req) { return new Promise((resolve, reject) => { let body=''; req.on('data', c=>{ body+=c; if(body.length>2_000_000) req.destroy(); }); req.on('end', ()=>{ try{ resolve(body ? JSON.parse(body) : {}); }catch{ reject(new Error('Invalid JSON')); } }); }); }
function serveFile(req, res) {
  const requestPath = req.url === '/' ? '/index.html' : decodeURIComponent(req.url.split('?')[0]);
  const file = path.resolve(ROOT, '.' + requestPath);
  const relativePath = path.relative(ROOT, file);
  const segments = relativePath.split(path.sep);
  const publicTypes = new Map([
    ['.html','text/html; charset=utf-8'], ['.css','text/css; charset=utf-8'],
    ['.js','text/javascript; charset=utf-8'], ['.mjs','text/javascript; charset=utf-8'],
    ['.svg','image/svg+xml'], ['.png','image/png'], ['.jpg','image/jpeg'],
    ['.jpeg','image/jpeg'], ['.gif','image/gif'], ['.webp','image/webp'],
    ['.ico','image/x-icon'], ['.woff','font/woff'], ['.woff2','font/woff2']
  ]);
  const mime = publicTypes.get(path.extname(file).toLowerCase());
  const inDataDir = file === DATA_DIR || file.startsWith(DATA_DIR + path.sep);
  if (!relativePath || relativePath.startsWith('..' + path.sep) || path.isAbsolute(relativePath) ||
      segments.some(segment => segment.startsWith('.')) || inDataDir || !mime ||
      !fs.existsSync(file) || fs.statSync(file).isDirectory()) return respond(res, 404, {error:'Not found'});
  res.writeHead(200, { 'Content-Type':mime, 'X-Content-Type-Options':'nosniff' }); fs.createReadStream(file).pipe(res);
}
function requireUser(req, res, state) { const user=userFor(req,state); if(!user){ respond(res,401,{error:'Sign in required'}); return null; } return user; }
function workflowDraft(description, assetName='') {
  const text = `${description} ${assetName}`.toLowerCase();
  const critical = /fire|smoke|shock|flood|gas leak|security breach|unsafe|injur|life safety/.test(text);
  const high = /leak|burst|power|electric|outage|broken|failure|blocked|urgent|down/.test(text);
  const preventive = /inspect|service|maintain|replace|clean|test|scheduled/.test(text);
  const priority = critical ? 'critical' : high ? 'high' : preventive ? 'medium' : 'low';
  const type = preventive && !high ? 'preventive' : 'corrective';
  const slaHours = critical ? 2 : high ? 8 : priority === 'medium' ? 48 : 120;
  const due = new Date(Date.now() + slaHours * 60 * 60 * 1000).toISOString().slice(0,10);
  const nextSteps = critical
    ? ['Make the area safe and isolate the hazard.', 'Notify the centre manager and safety lead.', 'Capture photos and log the incident before repair.']
    : high
      ? ['Inspect the affected equipment and isolate it if needed.', 'Confirm parts, access requirements and responsible technician.', 'Record the repair outcome and test before handover.']
      : ['Inspect the asset and confirm the root cause.', 'Gather parts and access requirements.', 'Complete the work and record the verification check.'];
  const title = `${critical ? 'Urgent safety response' : high ? 'Priority maintenance response' : 'Facilities task'}${assetName ? ` - ${assetName}` : ''}`;
  return { title, type, priority, dueDate:due, summary:`${priority[0].toUpperCase()+priority.slice(1)} ${type} workflow`, nextSteps, slaHours };
}
async function azureOpenAIHeaders(){
  const apiKey=String(process.env.AZURE_OPENAI_API_KEY||'').trim();
  if(apiKey) return {'api-key':apiKey};
  const identityEndpoint=process.env.IDENTITY_ENDPOINT; const identityHeader=process.env.IDENTITY_HEADER;
  if(!identityEndpoint||!identityHeader) throw new Error('Managed identity is unavailable.');
  const tokenUrl=new URL(identityEndpoint);
  tokenUrl.searchParams.set('resource','https://cognitiveservices.azure.com/');
  tokenUrl.searchParams.set('api-version','2019-08-01');
  const response=await fetch(tokenUrl,{headers:{'X-IDENTITY-HEADER':identityHeader},signal:AbortSignal.timeout(10000)});
  if(!response.ok) throw new Error('Managed identity token request failed.');
  const token=await response.json();
  if(!token.access_token) throw new Error('Managed identity returned no access token.');
  return {Authorization:`Bearer ${token.access_token}`};
}

function xmlEscape(value){
  return String(value||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');
}
function wordParagraph(text,style='Normal'){
  const content=xmlEscape(text);
  return `<w:p><w:pPr><w:pStyle w:val="${style}"/></w:pPr><w:r><w:t xml:space="preserve">${content}</w:t></w:r></w:p>`;
}
function crc32(buffer){
  let crc=0xffffffff;
  for(const byte of buffer){crc^=byte;for(let bit=0;bit<8;bit++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}
  return (crc^0xffffffff)>>>0;
}
function zipStore(entries){
  const local=[],central=[];let offset=0;
  for(const [name,value] of entries){
    const filename=Buffer.from(name,'utf8'),data=Buffer.from(value,'utf8'),crc=crc32(data);
    const localHeader=Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50,0);localHeader.writeUInt16LE(20,4);localHeader.writeUInt16LE(0x0800,6);localHeader.writeUInt16LE(0,8);
    localHeader.writeUInt32LE(crc,14);localHeader.writeUInt32LE(data.length,18);localHeader.writeUInt32LE(data.length,22);localHeader.writeUInt16LE(filename.length,26);
    local.push(localHeader,filename,data);
    const centralHeader=Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50,0);centralHeader.writeUInt16LE(20,4);centralHeader.writeUInt16LE(20,6);centralHeader.writeUInt16LE(0x0800,8);centralHeader.writeUInt16LE(0,10);
    centralHeader.writeUInt32LE(crc,16);centralHeader.writeUInt32LE(data.length,20);centralHeader.writeUInt32LE(data.length,24);centralHeader.writeUInt16LE(filename.length,28);
    centralHeader.writeUInt32LE(offset,42);central.push(centralHeader,filename);
    offset+=localHeader.length+filename.length+data.length;
  }
  const centralSize=central.reduce((sum,part)=>sum+part.length,0),end=Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(centralSize,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([...local,...central,end]);
}
function pidReportDocx(report,generatedAt){
  const intro='OAU-PID has initiated a programme aimed at assessing, refurbishing and advancing all 45 UNISA facilities located across the various regions. The programme seeks to improve the condition, functionality, safety and technological capability of the facilities to provide students, learners, educators and staff with suitable environments that support teaching, learning and operational activities.';
  const order=['Executive Summary','Introduction','Previous Report Comparison','Current Report','Issues','Recommendations','Conclusion'];
  const paragraphs=[wordParagraph('PID Report','Title'),wordParagraph('OAU-PID Facilities Programme','Subtitle'),wordParagraph('Generated: '+generatedAt,'Normal')];
  for(const section of order){
    if(typeof report[section]!=='string')continue;
    paragraphs.push(wordParagraph(section,'Heading1'));
    for(const line of report[section].split(/\r?\n/)){
      const trimmed=line.trim();
      if(!trimmed)continue;
      paragraphs.push(wordParagraph(trimmed,'Normal'));
    }
  }
  if(!report.Introduction.startsWith(intro))throw new Error('The required programme introduction is missing.');
  const document=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${paragraphs.join('')}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr></w:body></w:document>`;
  const types='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>';
  const rels='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
  const styles='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial"/><w:sz w:val="22"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="36"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="64748B"/><w:sz w:val="24"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:rPr><w:b/><w:color w:val="1E3A5F"/><w:sz w:val="28"/></w:rPr></w:style></w:styles>';
  return zipStore([['[Content_Types].xml',types],['_rels/.rels',rels],['word/document.xml',document],['word/styles.xml',styles]]);
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost'); const state=load();
  if (req.method==='OPTIONS' && url.pathname.startsWith('/api/')) { res.writeHead(204, corsHeaders(req)); return res.end(); }
  const apiHeaders = corsHeaders(req);
  for (const [name, value] of Object.entries(apiHeaders)) res.setHeader(name, value);
  if (req.method==='GET' && url.pathname==='/api/health') return respond(res,200,{ok:true,authenticated:!!userFor(req,state)},apiHeaders);
  if (req.method==='GET' && url.pathname==='/api/auth/me') { const user=userFor(req,state); return user ? respond(res,200,{user:publicUser(user)},apiHeaders) : respond(res,401,{error:'Not signed in'},apiHeaders); }
  if (req.method==='POST' && url.pathname==='/api/auth/login') {
    const {email='',password=''}=await readJson(req); const user=state.users.find(u=>u.email===String(email).trim().toLowerCase());
    if(!user || user.suspended || (user.accountExpiresAt && Date.parse(user.accountExpiresAt)<Date.now()) || !passwordMatches(String(password),user)) return respond(res,401,{error:'Invalid credentials'},apiHeaders);
    user.lastLoginAt=new Date().toISOString();
    if(!Array.isArray(user.loginHistory)) user.loginHistory=[];
    user.loginHistory.push({ at:user.lastLoginAt, where:req.socket.remoteAddress||'unknown' });
    if(user.loginHistory.length>50) user.loginHistory.shift();
    save(state);
    const sessionToken = tokenFor(user);
    return respond(res,200,{user:publicUser(user), sessionToken},{...apiHeaders,'Set-Cookie':sessionCookieOptions(req, sessionToken)});
  }
  if (req.method==='POST' && url.pathname==='/api/auth/logout') {
    const user=userFor(req,state);
    if(user){ user.sessionVersion=(user.sessionVersion||0)+1; writeAudit(state,user,'user.logout',user.email,req); save(state); }
    return respond(res,200,{ok:true},{...apiHeaders,'Set-Cookie':sessionCookieOptions(req, '', true)});
  }
  if (req.method==='POST' && url.pathname==='/api/auth/change-password') {
    const user=requireUser(req,res,state); if(!user) return;
    const body=await readJson(req); const current=String(body.currentPassword||''); const next=String(body.newPassword||'');
    if(next.length>256) return respond(res,400,{error:'Password must be 256 characters or fewer.'},apiHeaders);
    const policyError=passwordPolicyError(next,state); if(policyError) return respond(res,400,{error:policyError},apiHeaders);
    if(!user.mustChangePassword && !passwordMatches(current,user)) return respond(res,400,{error:'Current password is incorrect.'},apiHeaders);
    const hash=passwordHash(next); user.salt=hash.salt; user.passwordHash=hash.hash; delete user.hash;
    user.mustChangePassword=false; user.sessionVersion=(user.sessionVersion||0)+1;
    writeAudit(state,user,'password.changed',user.email,req); save(state);
    return respond(res,200,{ok:true,message:'Password changed. Sign in with your new password.'},{...apiHeaders,'Set-Cookie':sessionCookieOptions(req, '', true)});
  }
  if (url.pathname==='/api/admin/users' && req.method==='GET') {
    const actor=requireAdmin(req,res,state); if(!actor) return;
    return respond(res,200,{users:state.users.map(publicUser)});
  }
  if (url.pathname==='/api/admin/users' && req.method==='POST') {
    const actor=requireAdmin(req,res,state); if(!actor) return;
    const body=await readJson(req); const email=String(body.email||'').trim().toLowerCase();
    const name=String(body.name||'').trim(); const role=String(body.role||'technician');
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !name || !ROLES.has(role)) return respond(res,400,{error:'A valid email, name, and role are required.'},apiHeaders);
    if(role==='superadmin' && actor.role!=='superadmin') return respond(res,403,{error:'Only a Super Administrator can assign that role.'},apiHeaders);
    if(state.users.some(user=>user.email===email)) return respond(res,409,{error:'An account with that email already exists.'},apiHeaders);
    const accountExpiresAt=body.accountExpiresAt||null;
    if(accountExpiresAt&&!Number.isFinite(Date.parse(accountExpiresAt))) return respond(res,400,{error:'Invalid account expiry date.'},apiHeaders);
    const temporaryPassword=generatedPassword(); const hash=passwordHash(temporaryPassword);
    const user={id:crypto.randomUUID(),email,name,role,...hash,mustChangePassword:body.mustChangePassword===undefined?true:!!body.mustChangePassword,accountExpiresAt,loginHistory:[]};
    state.users.push(user); writeAudit(state,actor,'user.created',email,req); save(state);
    return respond(res,201,{user:publicUser(user),temporaryPassword});
  }
  if (url.pathname.startsWith('/api/admin/users/')) {
    const actor=requireAdmin(req,res,state); if(!actor) return;
    const parts=url.pathname.split('/').filter(Boolean); const userId=decodeURIComponent(parts[3]||'');
    const target=state.users.find(user=>user.id===userId);
    if(!target) return respond(res,404,{error:'User not found.'},apiHeaders);
    if(target.role==='superadmin' && actor.role!=='superadmin') return respond(res,403,{error:'Only a Super Administrator can manage that account.'},apiHeaders);
    if(parts[4]==='reset-password' && req.method==='POST') {
      const temporaryPassword=generatedPassword(); const hash=passwordHash(temporaryPassword);
      target.salt=hash.salt; target.passwordHash=hash.hash; delete target.hash;
      target.mustChangePassword=true; target.sessionVersion=(target.sessionVersion||0)+1;
      writeAudit(state,actor,'user.password_reset',target.email,req); save(state);
      return respond(res,200,{user:publicUser(target),temporaryPassword});
    }
    if(parts.length===4 && req.method==='PATCH') {
      const body=await readJson(req);
      if(body.role!==undefined && !ROLES.has(String(body.role))) return respond(res,400,{error:'Invalid role.'},apiHeaders);
      if(body.role==='superadmin' && actor.role!=='superadmin') return respond(res,403,{error:'Only a Super Administrator can assign that role.'},apiHeaders);
      if(body.name!==undefined && !String(body.name).trim()) return respond(res,400,{error:'Name cannot be empty.'},apiHeaders);
      if(body.accountExpiresAt && !Number.isFinite(Date.parse(body.accountExpiresAt))) return respond(res,400,{error:'Invalid account expiry date.'},apiHeaders);
      if(target.id===actor.id && (body.role && body.role!=='admin' || body.suspended===true)) return respond(res,400,{error:'You cannot remove your own administrator access.'},apiHeaders);
      const revokeSessions=(body.role!==undefined && String(body.role)!==target.role) ||
        (body.suspended!==undefined && !!body.suspended!==!!target.suspended) ||
        (body.accountExpiresAt!==undefined && (body.accountExpiresAt||null)!==(target.accountExpiresAt||null)) ||
        (body.mustChangePassword!==undefined && !!body.mustChangePassword!==!!target.mustChangePassword);
      if(body.name!==undefined) target.name=String(body.name).trim();
      if(body.role!==undefined) target.role=String(body.role);
      if(body.suspended!==undefined) target.suspended=!!body.suspended;
      if(body.accountExpiresAt!==undefined) target.accountExpiresAt=body.accountExpiresAt||null;
      if(body.mustChangePassword!==undefined) target.mustChangePassword=!!body.mustChangePassword;
      if(revokeSessions) target.sessionVersion=(target.sessionVersion||0)+1;
      writeAudit(state,actor,'user.updated',target.email,req); save(state);
      return respond(res,200,{user:publicUser(target)});
    }
    if(parts.length===4 && req.method==='DELETE') {
      if(target.id===actor.id) return respond(res,400,{error:'You cannot remove your own administrator account.'},apiHeaders);
      state.users=state.users.filter(user=>user.id!==target.id);
      writeAudit(state,actor,'user.deleted',target.email,req); save(state);
      return respond(res,200,{ok:true});
    }
  }
  if (req.method==='GET' && url.pathname==='/api/admin/audit') {
    const actor=requireAdmin(req,res,state); if(!actor) return;
    return respond(res,200,{entries:(state.auditLog||[]).slice().reverse()});
  }
  if (req.method==='POST' && url.pathname==='/api/ai/workflow') {
    const user=requireUser(req,res,state); if(!user) return;
    const body=await readJson(req); const description=String(body.description||'').trim(); const assetName=String(body.assetName||'').trim();
    if(description.length<10 || description.length>2000) return respond(res,400,{error:'Describe the issue in 10 to 2000 characters.'},apiHeaders);
    return respond(res,200,{workflow:workflowDraft(description,assetName),description,assetName},apiHeaders);
  }
  if(req.method==='POST' && url.pathname==='/api/ai/programme-report'){
    const user=requireUser(req,res,state);if(!user)return;
    const body=await readJson(req),source=String(body.source||'').trim();
    if(source.length<10||source.length>12000)return respond(res,400,{error:'Provide current report notes between 10 and 12,000 characters.'},apiHeaders);
    const intro='OAU-PID has initiated a programme aimed at assessing, refurbishing and advancing all 45 UNISA facilities located across the various regions. The programme seeks to improve the condition, functionality, safety and technological capability of the facilities to provide students, learners, educators and staff with suitable environments that support teaching, learning and operational activities.';
    const candidate=body.previousReport&&typeof body.previousReport==='object'?body.previousReport:null;
    const previousDate=candidate?Date.parse(candidate.generatedAt||''):NaN;
    const previousReport=Number.isFinite(previousDate)&&previousDate<Date.now()&&candidate.report&&typeof candidate.report==='object'?candidate:null;
    const previousText=previousReport?JSON.stringify(previousReport.report).slice(0,16000):'';
    const endpoint=String(process.env.AZURE_OPENAI_ENDPOINT||'').trim();
    const deployment=String(process.env.AZURE_OPENAI_DEPLOYMENT||'gpt-4.1-mini').trim();
    if(!endpoint||!deployment)return respond(res,503,{error:'PID Report generation is not configured on this host.'},apiHeaders);
    let requestUrl;
    try{
      requestUrl=new URL(endpoint);
      if(requestUrl.protocol!=='https:')return respond(res,503,{error:'AI report endpoint must use HTTPS.'},apiHeaders);
      requestUrl.pathname=requestUrl.pathname.replace(/\/$/,'')+`/openai/deployments/${encodeURIComponent(deployment)}/chat/completions`;
      requestUrl.searchParams.set('api-version',String(process.env.AZURE_OPENAI_API_VERSION||'2024-10-21'));
    }catch(error){return respond(res,503,{error:'AI report endpoint configuration is invalid.'},apiHeaders);}
    const sections=['Executive Summary','Introduction',...(previousReport?['Previous Report Comparison']:[]),'Current Report','Issues','Recommendations','Conclusion'];
    const systemPrompt=`You are the OAU-PID programme's PID Report writer. Return one valid JSON object with exactly these string keys: ${sections.join(', ')}. Write a complete, polished, evidence-led management report with clear paragraphs and concrete detail. Executive Summary: about 180-250 words, state purpose, scope, evidence available, key findings, priority issues and decisions/actions required. Introduction must be exactly this paragraph with no text before it: "${intro}" Current Report: about 400-600 words, explain the reported review period and material, programme scope, work and findings actually supplied, and operational implications. Where dates, progress, regional breakdowns, inspections, costs or outcome measures were not provided, clearly mark them as not supplied; never fabricate them. Issues: about 150-250 words, describe only evidence-backed issues and identify material evidence gaps. Recommendations: give 6-8 numbered, practical actions; for each, state a responsible role, sequencing or timeframe, and a measurable record or completion check, while labeling these as proposed actions. Conclusion: about 120-180 words, synthesize what the evidence supports, outstanding decisions and the next reporting step. Use only evidence in the current report material and supplied earlier report. Never invent site visits, condition scores, budgets, completed work, dates, regional findings, stakeholder comments, outcomes or changes. If current information is thin, produce a transparent complete report that identifies missing evidence rather than filling gaps with assumptions. ${previousReport?'Previous Report Comparison: about 200-300 words comparing the most recent earlier generated PID Report with the current material. Separate supported changes, continuing issues and items that cannot be compared. If no current evidence can confirm progress, state that clearly; do not claim progress without evidence.':'There is no earlier generated PID Report. Omit Previous Report Comparison entirely.'}`;
    try{
      const authHeaders=await azureOpenAIHeaders();
      const response=await fetch(requestUrl,{method:'POST',headers:{...authHeaders,'Content-Type':'application/json'},body:JSON.stringify({
        model:deployment,temperature:0.2,max_tokens:5000,response_format:{type:'json_object'},
        messages:[{role:'system',content:systemPrompt},{role:'user',content:JSON.stringify({currentReportMaterial:source,previousReport:previousText||null})}]
      }),signal:AbortSignal.timeout(60000)});
      if(!response.ok)return respond(res,502,{error:`PID Report provider returned ${response.status}. Check the deployment and model access.`},apiHeaders);
      const result=await response.json(),content=result.choices?.[0]?.message?.content;
      let report;try{report=JSON.parse(content);}catch(error){return respond(res,502,{error:'AI report provider returned invalid structured content.'},apiHeaders);}
      if(!report||sections.some(section=>typeof report[section]!=='string'||!report[section].trim()))return respond(res,502,{error:'PID Report is missing one or more required sections.'},apiHeaders);
      report.Introduction=intro;
      return respond(res,200,{report,model:deployment,comparedTo:previousReport?previousReport.generatedAt:null},apiHeaders);
    }catch(error){return respond(res,502,{error:'PID Report generation failed. Check model access and managed identity configuration.'},apiHeaders);}
  }
  if(req.method==='POST' && url.pathname==='/api/reports/pid-report/docx'){
    const user=requireUser(req,res,state);if(!user)return;
    const body=await readJson(req),report=body.report;
    const required=['Executive Summary','Introduction','Current Report','Issues','Recommendations','Conclusion'];
    if(!report||typeof report!=='object'||required.some(section=>typeof report[section]!=='string'||!report[section].trim()))return respond(res,400,{error:'The PID Report is incomplete and cannot be exported.'},apiHeaders);
    if(Object.values(report).some(value=>typeof value!=='string'||value.length>24000))return respond(res,400,{error:'One or more report sections exceed the document limit.'},apiHeaders);
    const generatedAt=String(body.generatedAt||new Date().toISOString());
    try{
      const docx=pidReportDocx(report,generatedAt);
      res.writeHead(200,{'Content-Type':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','Content-Disposition':'attachment; filename="PID-Report.docx"','Cache-Control':'no-store',...apiHeaders});
      return res.end(docx);
    }catch(error){return respond(res,400,{error:error.message||'Could not create the Word document.'},apiHeaders);}
  }
  if(req.method==='POST' && url.pathname==='/api/notifications/email'){
    const actor=requireUser(req,res,state);if(!actor)return;
    if(!['admin','superadmin','hq'].includes(String(actor.role||'').toLowerCase()))return respond(res,403,{error:'Only HQ/admin can send assignment notifications.'},apiHeaders);
    const host=String(process.env.SMTP_HOST||'').trim(),user=String(process.env.SMTP_USER||'').trim(),pass=String(process.env.SMTP_PASS||'');
    const port=Number(process.env.SMTP_PORT||587),from=String(process.env.SMTP_FROM||user).trim();
    if(!host||!user||!pass||!from)return respond(res,503,{error:'Email automation is not configured on this host.'},apiHeaders);
    const body=await readJson(req),to=String(body.to||'').trim(),subject=String(body.subject||'').trim().slice(0,250),text=String(body.text||'').trim().slice(0,10000);
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)||!subject||!text)return respond(res,400,{error:'A valid recipient, subject and message are required.'},apiHeaders);
    try{
      const transporter=nodemailer.createTransport({host,port,secure:port===465,auth:{user,pass}});
      await transporter.sendMail({from,to,subject,text});
      return respond(res,200,{ok:true});
    }catch(error){return respond(res,502,{error:'Email provider could not send the notification. Check SMTP settings.'},apiHeaders);}
  }
  if(req.method==='POST' && url.pathname==='/api/notifications/whatsapp'){
    const actor=requireUser(req,res,state); if(!actor) return;
    const phoneNumberId=String(process.env.WHATSAPP_PHONE_NUMBER_ID||'').trim();
    const accessToken=String(process.env.WHATSAPP_ACCESS_TOKEN||'').trim();
    const template=String(process.env.WHATSAPP_ASSIGNMENT_TEMPLATE||process.env.WHATSAPP_TEMPLATE_NAME||'').trim();
    const version=String(process.env.WHATSAPP_GRAPH_API_VERSION||process.env.WHATSAPP_GRAPH_VERSION||'v23.0').trim();
    const language=String(process.env.WHATSAPP_TEMPLATE_LANGUAGE||'en').trim();
    if(!phoneNumberId||!accessToken||!template) return respond(res,503,{error:'WhatsApp automation is not configured on this host.'},apiHeaders);
    if(!/^\d+$/.test(phoneNumberId)||!/^v\d+\.\d+$/.test(version)) return respond(res,503,{error:'WhatsApp provider configuration is invalid.'},apiHeaders);
    const body=await readJson(req); let recipient=String(body.recipient||'').replace(/\D/g,'');
    if(recipient.length===10&&recipient.startsWith('0')) recipient='27'+recipient.slice(1);
    if(!/^[1-9]\d{7,14}$/.test(recipient)) return respond(res,400,{error:'A valid international assignee number is required.'},apiHeaders);
    const fields=['workOrderId','title','asset','priority','dueDate'].map(key=>String(body[key]||'').trim().slice(0,500));
    if(!fields[0]||!fields[1]) return respond(res,400,{error:'Work order ID and title are required.'},apiHeaders);
    const payload={messaging_product:'whatsapp',to:recipient,type:'template',template:{name:template,language:{code:language},components:[{type:'body',parameters:fields.map(text=>({type:'text',text:text||'Not specified'}))}]}};
    try{
      const response=await fetch(`https://graph.facebook.com/${version}/${phoneNumberId}/messages`,{method:'POST',headers:{Authorization:`Bearer ${accessToken}`,'Content-Type':'application/json'},body:JSON.stringify(payload),signal:AbortSignal.timeout(10000)});
      if(!response.ok) return respond(res,502,{error:`WhatsApp provider rejected the notification (${response.status}). Check the approved template and recipient.`},apiHeaders);
      return respond(res,200,{ok:true});
    }catch(error){ return respond(res,502,{error:'WhatsApp provider could not be reached.'},apiHeaders); }
  }
  if (url.pathname.startsWith('/api/storage')) {
    const user=requireUser(req,res,state); if(!user) return;
    const suffix=url.pathname.slice('/api/storage'.length).replace(/^\//,'');
    if (!suffix && req.method==='GET') { const prefix=url.searchParams.get('prefix')||''; return respond(res,200,{keys:Object.keys(state.storage).filter(k=>k.startsWith(prefix))}); }
    const key=decodeURIComponent(suffix); if(!key || key.includes('..')) return respond(res,400,{error:'Invalid key'});
    if(req.method==='GET') {
      if(!Object.hasOwn(state.storage,key)) return respond(res,404,{error:'Not found'});
      if(key==='pid-fms-data-v2'){
        try{ return respond(res,200,{value:JSON.stringify(filterAppDataForUser(user,JSON.parse(state.storage[key])))}); }
        catch(error){ return respond(res,500,{error:'Stored application data is invalid.'}); }
      }
      return respond(res,200,{value:state.storage[key]});
    }
    if(req.method==='PUT') {
      const {value}=await readJson(req); if(typeof value!=='string') return respond(res,400,{error:'value must be a string'});
      let storedValue=value;
      if(key==='pid-fms-data-v2'){
        try{
          const before=JSON.parse(state.storage[key]||'{}'); const after=JSON.parse(value);
          if(!['admin','superadmin'].includes(user.role) && JSON.stringify(before.coordinationApps||[])!==JSON.stringify(after.coordinationApps||[])) return respond(res,403,{error:'Administrator access required to manage coordination apps.'});
          const documentBytes=(Array.isArray(after.documents)?after.documents:[]).reduce((sum,doc)=>sum+Math.max(0,Number(doc.sizeBytes)||Number(doc.sizeKB||0)*1024),0);
          if(documentBytes>DOC_LIBRARY_CAPACITY_BYTES) return respond(res,413,{error:'The 2 TB document library limit would be exceeded.'});
          const beforeSettings=before.adminSettings||{}; const afterSettings=after.adminSettings||{};
          const systemKeys=['systemEnvironment','systemApiKeys','systemIntegrations','systemWebhooks','systemFileStorage','systemDatabase','systemMapsGps','systemQrService','systemSmsWhatsApp'];
          if(user.role!=='superadmin' && systemKeys.some(setting=>JSON.stringify(beforeSettings[setting])!==JSON.stringify(afterSettings[setting]))) return respond(res,403,{error:'Super Administrator access required for system configuration.'});
          storedValue=preserveHiddenAppData(user,state.storage[key],value);
          const permissionError=appDataPermissionError(user,state.storage[key],storedValue);
          if(permissionError) return respond(res,403,{error:permissionError});
        }catch(error){ return respond(res,400,{error:'Invalid application settings data.'}); }
      }
      if(key==='pid-fms-data-v2') auditAppDataChanges(state,user,state.storage[key],storedValue,req);
      state.storage[key]=storedValue; save(state); return respond(res,200,{ok:true});
    }
    if(req.method==='DELETE') {
      if(user.role!=='admin'&&user.role!=='superadmin') return respond(res,403,{error:'Administrator access required.'});
      delete state.storage[key]; save(state); return respond(res,200,{ok:true});
    }
  }
  if (url.pathname.startsWith('/api/')) return respond(res,404,{error:'Not found'});
  return serveFile(req,res);
}

if(process.argv[2]==='reset-password') {
  const email=String(process.argv[3]||'').trim().toLowerCase();
  if(!email) fail('Usage: node server.js reset-password email');
  const state=load(); const user=state.users.find(account=>account.email===email);
  if(!user) fail('No login account exists for that email.');
  const temporaryPassword=generatedPassword(); const hash=passwordHash(temporaryPassword);
  user.salt=hash.salt; user.passwordHash=hash.hash; delete user.hash;
  user.mustChangePassword=true; user.sessionVersion=(user.sessionVersion||0)+1;
  if(!Array.isArray(state.auditLog)) state.auditLog=[];
  state.auditLog.push({at:new Date().toISOString(),actor:'Local server operator',action:'user.password_recovery',target:email,where:'CLI'});
  save(state);
  console.log(JSON.stringify({email,temporaryPassword})); process.exit(0);
}
if(process.argv[2]==='promote-superadmin') {
  const email=String(process.argv[3]||'').trim().toLowerCase();
  if(!email) fail('Usage: node server.js promote-superadmin email');
  const state=load(); const user=state.users.find(account=>account.email===email);
  if(!user) fail('No login account exists for that email.');
  user.role='superadmin'; user.suspended=false; user.sessionVersion=(user.sessionVersion||0)+1; save(state);
  console.log('Super Administrator role assigned. Sign in again to apply it.'); process.exit(0);
}
if(process.argv[2]==='create-user') {
  const [, , , email, password, role='technician', ...nameParts]=process.argv;
  if(!email || !password || !ROLES.has(role)) fail('Usage: node server.js create-user email password role [name]');
  const state=load(); if(state.users.some(u=>u.email===email.toLowerCase())) fail('That email already exists.');
  const hash=passwordHash(password); state.users.push({id:crypto.randomUUID(),email:email.toLowerCase(),name:nameParts.join(' ')||email,role,...hash}); save(state); console.log('User created.'); process.exit(0);
}
const server = http.createServer((req,res)=>handle(req,res).catch(err=>{ console.error(err); respond(res,500,{error:'Server error'}); }));
server.on('error', err => { console.error(`Could not start server on port ${PORT}: ${err.message}`); process.exitCode = 1; });
server.listen(PORT, '0.0.0.0', ()=>console.log(`PID Facilities is running at http://0.0.0.0:${PORT}`));
