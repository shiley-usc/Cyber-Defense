import base64
import hashlib
import hmac
import json
import re
import os
import secrets
import shutil
import sqlite3
import struct
import subprocess
import threading
import time
import uuid
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urljoin

from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .providers import FalconProvider, SentinelOneProvider, TenableProvider

BASE = Path(__file__).resolve().parent.parent
UPLOADS = BASE / 'uploads'
UPLOADS.mkdir(exist_ok=True)

PROFILES = {
    'triage': {'name':'Endpoint Triage','description':'Fast, cross-platform evidence collection for initial compromise assessment.','estimated':'2-5 min'},
    'core_dfir': {'name':'Core DFIR','description':'System, execution, authentication, and persistence evidence.','estimated':'5-15 min'},
    'browser': {'name':'Browser','description':'Browser artifacts and related user activity evidence.','estimated':'2-10 min'},
    'persistence': {'name':'Persistence','description':'Startup and persistence locations by operating system.','estimated':'2-10 min'},
}

STAGES = [
    'Queued',
    'Connecting',
    'Waiting for Online',
    'Deploying Collector',
    'Verifying',
    'Collecting',
    'Packaging',
    'Retrieving',
    'Verifying Evidence',
    'Encrypting',
    'Cleanup',
    'Complete',
]

def load_dotenv():
    env_file = BASE / '.env'
    if not env_file.exists():
        return
    for raw in env_file.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

load_dotenv()
EDR_DEFAULT = os.getenv('EDR_PROVIDER', 'crowdstrike').lower().strip()
DB_PATH = BASE / os.getenv('COLLECTOR_DB_PATH', 'evidence-collector.db')
APP_SECRET = os.getenv('APP_SECRET', '')
EVIDENCE_KEY = os.getenv('EVIDENCE_ENCRYPTION_KEY', '')
RETENTION_DAYS = int(os.getenv('EVIDENCE_RETENTION_DAYS', '30'))
MAX_WORKERS = max(1, int(os.getenv('JOB_WORKERS', '2')))
ONLINE_POLL_INTERVAL_SECONDS = max(60, int(os.getenv('ONLINE_POLL_INTERVAL_SECONDS', '300')))
ONLINE_WAIT_TIMEOUT_SECONDS = max(300, int(os.getenv('ONLINE_WAIT_TIMEOUT_SECONDS', '86400')))
ASSET_SYNC_HOURS = (0, 6, 12, 18)
ASSET_SYNC_CHUNK_SIZE = max(1000, int(os.getenv('ASSET_SYNC_CHUNK_SIZE', '5000')))
ASSET_SYNC_LOCK = threading.Lock()
ASSET_SYNC_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix='asset-sync')
VELOCIRAPTOR_COLLECTOR_ROOT = BASE / os.getenv('VELOCIRAPTOR_COLLECTOR_ROOT', './velociraptor/collectors')
if not VELOCIRAPTOR_COLLECTOR_ROOT.is_absolute(): VELOCIRAPTOR_COLLECTOR_ROOT = (BASE / VELOCIRAPTOR_COLLECTOR_ROOT).resolve()
VELOCIRAPTOR_VERSION = os.getenv('VELOCIRAPTOR_VERSION', '0.77.1')
VELOCIRAPTOR_SERVER_URL = os.getenv('VELOCIRAPTOR_SERVER_URL', 'https://127.0.0.1:8889').rstrip('/')
VELOCIRAPTOR_UPDATE_COMMAND = os.getenv('VELOCIRAPTOR_UPDATE_COMMAND', '').strip()
S1_SCRIPT_ID_WINDOWS = os.getenv('S1_REMOTE_SCRIPT_ID_WINDOWS', os.getenv('S1_REMOTE_SCRIPT_ID', '')).strip()
S1_SCRIPT_ID_LINUX = os.getenv('S1_REMOTE_SCRIPT_ID_LINUX', '').strip()
S1_SCRIPT_ID_MACOS = os.getenv('S1_REMOTE_SCRIPT_ID_MACOS', '').strip()
EVIDENCE = Path(os.getenv('EVIDENCE_DIR', './uploads/collections'))
EVIDENCE = EVIDENCE if EVIDENCE.is_absolute() else BASE / EVIDENCE
EVIDENCE.mkdir(parents=True, exist_ok=True)
AUTH_SESSION_COOKIE='usc_oc_session'
SESSION_TTL_SECONDS=int(os.getenv('SESSION_TTL_SECONDS','28800'))
COOKIE_SECURE=os.getenv('COOKIE_SECURE','true').lower()=='true'
CLOUDFLARE_ACCESS_REQUIRED=os.getenv('CLOUDFLARE_ACCESS_REQUIRED','true').lower()=='true'
BOOTSTRAP_ADMIN_USERNAME=os.getenv('BOOTSTRAP_ADMIN_USERNAME','').strip()
BOOTSTRAP_ADMIN_PASSWORD=os.getenv('BOOTSTRAP_ADMIN_PASSWORD','')
WORKSPACE_PERMISSIONS=('dfir','assets','vuln')

if not APP_SECRET or len(APP_SECRET) < 32:
    raise RuntimeError('APP_SECRET must be set to a high-entropy value of at least 32 characters.')
if not EVIDENCE_KEY:
    raise RuntimeError('EVIDENCE_ENCRYPTION_KEY must be set. Use scripts/generate_secrets.py.')

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _key = base64.urlsafe_b64decode(EVIDENCE_KEY.encode())
    if len(_key) not in (16, 24, 32):
        raise ValueError('EVIDENCE_ENCRYPTION_KEY must decode to 16, 24, or 32 bytes.')
except Exception as exc:
    raise RuntimeError(f'Invalid EVIDENCE_ENCRYPTION_KEY: {exc}')

app = FastAPI(title='USC Office of Cybersecurity Security Operations Console')
app.mount('/static', StaticFiles(directory=BASE / 'app' / 'static'), name='static')
DB_LOCK = threading.Lock()
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix='collector-job')
WAIT_EXECUTOR = ThreadPoolExecutor(max_workers=max(4, MAX_WORKERS * 2), thread_name_prefix='online-wait')

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def db_init():
    with DB_LOCK, db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          device_id TEXT NOT NULL, hostname TEXT NOT NULL, profile TEXT NOT NULL,
          deploy INTEGER NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, object_id TEXT, detail TEXT NOT NULL
        );        CREATE TABLE IF NOT EXISTS pushes (
          id TEXT PRIMARY KEY, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
          edr_provider TEXT NOT NULL, profile TEXT NOT NULL, endpoint_count INTEGER NOT NULL,
          s1_fetch_password_enc TEXT, s1_fetch_password_sha256 TEXT
        );
        CREATE TABLE IF NOT EXISTS package_links (
          token_hash TEXT PRIMARY KEY, path TEXT NOT NULL, expires_at REAL NOT NULL,
          max_uses INTEGER NOT NULL, used_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS asset_inventory (
          asset_id TEXT PRIMARY KEY, hostname TEXT, ips_json TEXT NOT NULL,
          aliases_json TEXT NOT NULL, sources_json TEXT NOT NULL, coverage_json TEXT NOT NULL,
          payload_json TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_asset_inventory_hostname ON asset_inventory(hostname);
        CREATE TABLE IF NOT EXISTS asset_inventory_sync (
          source TEXT PRIMARY KEY, status TEXT NOT NULL, started_at TEXT, completed_at TEXT,
          record_count INTEGER NOT NULL DEFAULT 0, error TEXT, last_asset_update TEXT
        );
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'operator',
          permissions_json TEXT NOT NULL, identity_email TEXT, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created_at TEXT NOT NULL, expires_at REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at);
        ''')
        # Persisted jobs that were active when the process stopped are safely re-queued.        conn.execute("UPDATE jobs SET status='queued', updated_at=? WHERE status='running'", (now(),))
        # Older jobs already queued remain queued for startup recovery.

db_init()

def _password_hash(password,salt=None):
    if not password or len(password)<12: raise ValueError('Passwords must be at least 12 characters.')
    salt=salt or secrets.token_bytes(16); digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
    return f'scrypt$16384$8$1${salt.hex()}${digest.hex()}'

def _password_verify(password,encoded):
    try:
        alg,n,r,p,salt_hex,digest_hex=encoded.split('$',5)
        if alg!='scrypt': return False
        digest=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt_hex),n=int(n),r=int(r),p=int(p),dklen=32)
        return hmac.compare_digest(digest.hex(),digest_hex)
    except Exception:return False

def _user_row(username):
    with DB_LOCK,db() as conn:return conn.execute('SELECT * FROM users WHERE username=? AND enabled=1',(username,)).fetchone()

def _public_user(row):
    return {'username':row['username'],'role':row['role'],'admin':row['role']=='admin','permissions':json.loads(row['permissions_json'] or '[]'),'identity_email':row['identity_email']}

def _bootstrap_admin():
    if not BOOTSTRAP_ADMIN_USERNAME or not BOOTSTRAP_ADMIN_PASSWORD:return
    with DB_LOCK,db() as conn:
        if conn.execute('SELECT 1 FROM users LIMIT 1').fetchone():return
        conn.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?,?)',(BOOTSTRAP_ADMIN_USERNAME,_password_hash(BOOTSTRAP_ADMIN_PASSWORD),'admin',json.dumps(list(WORKSPACE_PERMISSIONS)),None,1,now(),now()))
_bootstrap_admin()

def _session_user(request):
    token=request.cookies.get(AUTH_SESSION_COOKIE)
    if not token:return None
    digest=hashlib.sha256(token.encode()).hexdigest()
    with DB_LOCK,db() as conn:row=conn.execute('SELECT username,expires_at FROM auth_sessions WHERE token_hash=?',(digest,)).fetchone()
    if not row or float(row['expires_at'])<time.time():return None
    return _user_row(row['username'])

def _require_cloudflare_if_configured(request):
    cfg=configure_cloudflare()
    if cfg['team_domain'] and cfg['audience']:
        return verify_cloudflare_jwt(request)
    if CLOUDFLARE_ACCESS_REQUIRED:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,'Cloudflare Access verification is not configured.')
    return None

def require_auth(request):
    row=_session_user(request)
    if not row:raise HTTPException(status.HTTP_401_UNAUTHORIZED,'Application login required.')
    cf_identity=_require_cloudflare_if_configured(request)
    if cf_identity and row['identity_email'] and row['identity_email'].lower()!=cf_identity.lower():
        raise HTTPException(status.HTTP_403_FORBIDDEN,'Application account is not assigned to this Cloudflare identity.')
    return _public_user(row)

def require_permission(request,workspace):
    u=require_auth(request)
    if u['admin'] or workspace in u['permissions']:return u
    raise HTTPException(status.HTTP_403_FORBIDDEN,f'Permission denied for {workspace}.')

def require_admin(request):
    u=require_auth(request)
    if not u['admin']:raise HTTPException(status.HTTP_403_FORBIDDEN,'Administrator permission required.')
    return u

def actor(request):
    u=require_auth(request);cf=request.headers.get('CF-Access-Authenticated-User-Email') or request.headers.get('cf-access-authenticated-user-email')
    return cf or u.get('identity_email') or u['username']

def audit(actor, action, object_id=None, **detail):
    with DB_LOCK, db() as conn:
        conn.execute(
            'INSERT INTO audit_log(at,actor,action,object_id,detail) VALUES (?,?,?,?,?)',
            (now(), actor, action, object_id, json.dumps(detail, sort_keys=True)),
        )

def save_job(job):
    job['updated_at'] = now()
    payload = json.dumps(job)
    with DB_LOCK, db() as conn:
        conn.execute(
            '''INSERT INTO jobs(id,created_at,updated_at,device_id,hostname,profile,deploy,status,payload)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,
               status=excluded.status,payload=excluded.payload''',
            (
                job['id'], job['created_at'], job['updated_at'], job['device_id'], job['hostname'],
                job['profile'], 1 if job['deploy'] else 0, job['status'], payload,
            ),
        )

def get_job(job_id):
    with DB_LOCK, db() as conn:
        row = conn.execute('SELECT payload FROM jobs WHERE id=?', (job_id,)).fetchone()
    return json.loads(row['payload']) if row else None

def list_jobs():
    with DB_LOCK, db() as conn:
        rows = conn.execute('SELECT payload FROM jobs ORDER BY created_at DESC').fetchall()
    return [json.loads(r['payload']) for r in rows]

def get_push(push_id):
    with DB_LOCK, db() as conn:
        row = conn.execute('SELECT * FROM pushes WHERE id=?', (push_id,)).fetchone()
    return dict(row) if row else None

def sha256(path: Path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def normalize_os_family(platform_value):
    value = str(platform_value or '').lower()
    if any(x in value for x in ('windows', 'win32', 'win64')):
        return 'windows'
    if any(x in value for x in ('macos', 'mac os', 'darwin', 'osx')):
        return 'macos'
    if any(x in value for x in ('linux', 'ubuntu', 'debian', 'rhel', 'centos', 'red hat', 'suse')):
        return 'linux'
    return 'unknown'

def collector_for_os(os_family):
    return 'velociraptor' if os_family in ('windows','linux','macos') else 'unsupported'


def velociraptor_collector_path(os_family, profile):
    if os_family not in ('windows','linux','macos') or profile not in PROFILES:
        raise RuntimeError(f'No Velociraptor collector is defined for {os_family}/{profile}.')
    os_label = {'windows':'Windows','linux':'Linux','macos':'MacOS'}[os_family]
    path = VELOCIRAPTOR_COLLECTOR_ROOT / f'Collector_{os_label}_{profile}'
    if not path.exists():
        raise RuntimeError(f'Velociraptor collector is not built for {os_family}/{profile}. Run scripts/build_velociraptor_collectors.sh on the collector server.')
    return path


def latest_velociraptor_release():
    req=urllib.request.Request('https://api.github.com/repos/Velocidex/velociraptor/releases/latest',headers={'Accept':'application/vnd.github+json','User-Agent':'USC-Evidence-Collector'})
    with urllib.request.urlopen(req,timeout=15) as resp:
        body=json.loads(resp.read().decode('utf-8'))
    version=str(body.get('tag_name','')).lstrip('v')
    if not version: raise RuntimeError('Latest Velociraptor release did not include a version tag.')
    return {'version':version,'html_url':body.get('html_url')}

def velociraptor_status():
    rows={}
    for os_family in ('windows','linux','macos'):
        rows[os_family]={}
        for profile in PROFILES:
            try:
                p=velociraptor_collector_path(os_family, profile)
                rows[os_family][profile]={'available':True,'filename':p.name,'sha256':sha256(p),'size':p.stat().st_size}
            except Exception:
                rows[os_family][profile]={'available':False,'filename':None}
    result={'version':VELOCIRAPTOR_VERSION,'server_url':VELOCIRAPTOR_SERVER_URL,'collectors':rows}
    try:
        latest=latest_velociraptor_release()
        result['latest_version']=latest['version']
        result['update_available']=latest['version'] != VELOCIRAPTOR_VERSION
    except Exception as exc:
        result['latest_version']=None; result['update_available']=False; result['update_check_error']=str(exc)
    return result

def s1_script_id_for_os(os_family):
    return {
        'windows': S1_SCRIPT_ID_WINDOWS,
        'linux': S1_SCRIPT_ID_LINUX,
        'macos': S1_SCRIPT_ID_MACOS,
    }.get(os_family, '')


def response_dict(response):
    if hasattr(response, 'data') and isinstance(response.data, dict):
        return response.data
    if isinstance(response, dict):
        body = response.get('body', response)
        return body if isinstance(body, dict) else {}
    return {}

def resources(response):
    body = response_dict(response)
    return body.get('resources', []) if isinstance(body, dict) else []

def session_id_from(response):
    items = resources(response)
    if not items or not items[0].get('session_id'):
        raise RuntimeError(f'Falcon RTR session response missing session_id: {response_dict(response)}')
    return items[0]['session_id']

class RTRClient:
    def __init__(self):
        self.poll_interval = float(os.getenv('RTR_POLL_INTERVAL', '2'))
        self.command_timeout = int(os.getenv('RTR_COMMAND_TIMEOUT', '900'))
        self.client_id = os.getenv('FALCON_CLIENT_ID')
        self.client_secret = os.getenv('FALCON_CLIENT_SECRET')
        self.cloud = os.getenv('FALCON_CLOUD', 'us-1')
        self._api = None
        if self.client_id and self.client_secret:
            from falconpy import RealTimeResponse
            self._api = RealTimeResponse(client_id=self.client_id, client_secret=self.client_secret, cloud_region=self.cloud, pythonic=True)

    def _require_api(self):
        if self._api is None:
            raise RuntimeError('Falcon RTR credentials are not configured on the server.')

    def init_session(self, device_id):
        self._require_api()
        return self._api.init_session(device_id=device_id)

    def close_session(self, session_id):
        self._require_api()
        try:
            return self._api.delete_session(session_id=session_id)
        except Exception:
            return None

    def run_active(self, device_id, session_id, base_command, command_string):
        self._require_api()
        return self._api.execute_command(device_id=device_id, session_id=session_id, base_command=base_command, command_string=command_string)

    def run_admin(self, device_id, session_id, base_command, command_string):
        self._require_api()
        return self._api.execute_admin_command(device_id=device_id, session_id=session_id, base_command=base_command, command_string=command_string)

    def run_active_and_wait(self, device_id, session_id, base_command, command_string):
        result = self.run_active(device_id, session_id, base_command, command_string)
        items = resources(result)
        req = items[0].get('cloud_request_id') if items else None
        if not req:
            return response_dict(result)
        return self.wait_command(req)

    def wait_command(self, cloud_request_id):
        self._require_api()
        deadline = time.time() + self.command_timeout
        while time.time() < deadline:
            result = self._api.get_command_status(cloud_request_id=cloud_request_id)
            body = response_dict(result)
            rows = body.get('resources', []) if isinstance(body, dict) else []
            if rows:
                item = rows[0]
                state = str(item.get('complete', '')).lower()
                if item.get('complete') is True or state == 'true':
                    return item
            time.sleep(self.poll_interval)
        raise TimeoutError(f'Falcon RTR command {cloud_request_id} timed out.')

    def create_put_file(self, path: Path):
        self._require_api()
        with path.open('rb') as f:
            return self._api.put_file_create(name=path.name, file=f.read())

    def list_downloads(self, session_id):
        self._require_api()
        return response_dict(self._api.get_file(session_id=session_id)).get('resources', [])

    def download_file(self, session_id, sha256_value, filename):
        self._require_api()
        result = self._api.get_file(session_id=session_id, sha256=sha256_value, name=filename)
        body = response_dict(result)
        return body.get('resources', [{}])[0].get('contents', b'')

falcon_provider = FalconProvider()
sentinelone_provider = SentinelOneProvider()
tenable_provider = TenableProvider()
rtr = RTRClient()
if EDR_DEFAULT not in ('crowdstrike', 'sentinelone'):
    EDR_DEFAULT = 'crowdstrike'
edr_provider = EDR_DEFAULT

def endpoint_is_online(provider_name, device_id):
    provider = falcon_provider if provider_name == 'crowdstrike' else sentinelone_provider
    try:
        inventory = provider.list_hosts('')
        for host in inventory:
            if str(host.get('device_id')) == str(device_id):
                status = str(host.get('status','')).lower()
                rtr_state = str(host.get('rtr','')).lower()
                return status in ('online','normal','connected','healthy') and rtr_state in ('ready','remote_shell','remote_script')
    except Exception:
        return False
    return False

def provider_label():
    return 'CrowdStrike' if edr_provider == 'crowdstrike' else 'SentinelOne'

def active_provider():
    return falcon_provider if edr_provider == 'crowdstrike' else sentinelone_provider


def build_asset_coverage(records_by_source):
    groups=[]
    index={}
    for source, records in records_by_source.items():
        for record in records:
            keys=_coverage_keys(record)
            matches=set()
            for key in keys:
                if key in index:
                    matches.add(index[key])
            if not matches:
                group={'id':'asset-'+uuid.uuid4().hex[:10],'hostname':record.get('hostname') or record.get('device_id'),'sources':{},'aliases':set(),'ips':set(),'os_family':record.get('os_family'),'platforms':set(),'status':set(),'last_seen':None,'match_keys':[]}
                groups.append(group); group_idx=len(groups)-1
            else:
                group_idx=min(matches)
                # Merge other groups into this one if multiple keys converged.
                for other in sorted(matches):
                    if other == group_idx: continue
                    src_group=groups[other]
                    groups[group_idx]['sources'].update(src_group['sources'])
                    groups[group_idx]['aliases'].update(src_group['aliases'])
                    groups[group_idx]['ips'].update(src_group['ips'])
                    groups[group_idx]['platforms'].update(src_group['platforms'])
                    groups[group_idx]['status'].update(src_group['status'])
                    for k,v in list(index.items()):
                        if v == other: index[k]=group_idx
                    groups[other]=None
            group=groups[group_idx]
            group['sources'][source]=record
            group['aliases'].update([record.get('hostname'), *record.get('hostnames',[]), *record.get('fqdns',[])])
            group['ips'].update([record.get('local_ip'), *record.get('ipv4s',[])])
            group['platforms'].add(record.get('platform'))
            group['status'].add(record.get('status'))
            group['os_family']=group['os_family'] or record.get('os_family')
            for key in keys:
                index[key]=group_idx
            group['match_keys'].extend(keys)
    groups=[g for g in groups if g]
    output=[]
    for g in groups:
        present=set(g['sources'])
        output.append({
            'id':g['id'],
            'hostname':next((g['sources'].get(s,{}).get('hostname') for s in ('crowdstrike','sentinelone','tenable') if g['sources'].get(s,{}).get('hostname')), 'Unknown asset'),
            'sources':sorted(present),
            'source_records':{k:{'id':v.get('device_id') or v.get('tenable_id'),'ip':v.get('local_ip'),'hostname':v.get('hostname'),'platform':v.get('platform')} for k,v in g['sources'].items()},
            'ips':sorted(x for x in g['ips'] if x),
            'aliases':sorted(x for x in g['aliases'] if x),
            'os_family':g['os_family'] or 'unknown',
            'platforms':sorted(x for x in g['platforms'] if x),
            'coverage':{'crowdstrike':'crowdstrike' in present,'sentinelone':'sentinelone' in present,'tenable':'tenable' in present},
            'missing':[x for x in ('crowdstrike','sentinelone','tenable') if x not in present],
        })
    output.sort(key=lambda x:x['hostname'].lower())
    return output

def configure_cloudflare():
    return {
        'team_domain': os.getenv('CLOUDFLARE_ACCESS_TEAM_DOMAIN', '').strip().rstrip('/'),
        'audience': os.getenv('CLOUDFLARE_ACCESS_AUDIENCE', '').strip(),
        'issuer': os.getenv('CLOUDFLARE_ACCESS_ISSUER', '').strip(),
    }

def verify_cloudflare_jwt(request: Request):
    token = request.headers.get('CF-Access-Jwt-Assertion') or request.headers.get('cf-access-jwt-assertion')
    cfg = configure_cloudflare()
    if not token or not cfg['team_domain'] or not cfg['audience']:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, 'Cloudflare Access verification is not configured.')
    try:
        import jwt
        jwks_url = urljoin(cfg['team_domain'] + '/', 'cdn-cgi/access/certs')
        jwk_client = jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300)
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        options = {'require': ['exp', 'iat', 'aud']}
        kwargs = {'algorithms': ['RS256'], 'audience': cfg['audience'], 'options': options}
        if cfg['issuer']:
            kwargs['issuer'] = cfg['issuer']
        claims = jwt.decode(token, signing_key, **kwargs)
        email = claims.get('email') or claims.get('preferred_username') or claims.get('sub')
        if not email:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'Cloudflare Access token does not identify a user.')
        return str(email)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f'Cloudflare Access authentication failed: {exc}')


def stage(job, name, status='running', **extra):
    item = next((x for x in job['steps'] if x['name'] == name), None)
    if item is None:
        item = {'at': now(), 'name': name, 'status': status}
        job['steps'].append(item)
    else:
        item['at'] = now()
        item['status'] = status
    item.update(extra)
    job['current_stage'] = name
    save_job(job)
    if status in ('ok', 'failed') and name in {'Deploying Collector','Collecting','Retrieving','Verifying Evidence','Encrypting','Cleanup'}:
        audit(job.get('created_by','system'), 'collection_stage', job.get('id'), stage=name, status=status, detail=str(extra.get('detail',''))[:240], push_id=job.get('push_id'))
    return item

def init_job_steps(job):
    job['steps'] = [{'at': now(), 'name': s, 'status': 'pending'} for s in STAGES]
    job['steps'][0]['status'] = 'queued'
    job['current_stage'] = 'Queued'

def encrypt_file(src: Path, dst: Path):
    aes = AESGCM(_key)
    chunk_size = 4 * 1024 * 1024
    with src.open('rb') as fin, dst.open('wb') as fout:
        fout.write(b'KFC1')
        fout.write(struct.pack('>I', chunk_size))
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            nonce = secrets.token_bytes(12)
            cipher = aes.encrypt(nonce, chunk, None)
            fout.write(nonce)
            fout.write(struct.pack('>I', len(cipher)))
            fout.write(cipher)

def decrypt_stream(src: Path):
    aes = AESGCM(_key)
    with src.open('rb') as f:
        if f.read(4) != b'KFC1':
            raise RuntimeError('Invalid evidence container')
        _ = struct.unpack('>I', f.read(4))[0]
        while True:
            nonce = f.read(12)
            if not nonce:
                break
            raw_len = f.read(4)
            if len(raw_len) != 4:
                raise RuntimeError('Corrupt evidence container')
            n = struct.unpack('>I', raw_len)[0]
            cipher = f.read(n)
            if len(cipher) != n:
                raise RuntimeError('Corrupt evidence container')
            yield aes.decrypt(nonce, cipher, None)

def encrypt_secret_text(value: str) -> str:
    aes = AESGCM(_key)
    nonce = secrets.token_bytes(12)
    cipher = aes.encrypt(nonce, value.encode('utf-8'), None)
    return base64.urlsafe_b64encode(nonce + cipher).decode('ascii')

def decrypt_secret_text(value: str) -> str:
    raw = base64.urlsafe_b64decode(value.encode('ascii'))
    aes = AESGCM(_key)
    return aes.decrypt(raw[:12], raw[12:], None).decode('utf-8')

def normalize_crowdstrike_transport(data: bytes, expected_filename: str, output_path: Path) -> Path:
    """Extract CrowdStrike RTR's password-protected 7z wrapper and recover the
    original Velociraptor archive without exposing the RTR password to callers."""
    transport = output_path.with_suffix(output_path.suffix + '.crowdstrike.7z')
    transport.write_bytes(data)
    extract_dir = output_path.parent / (output_path.stem + '.cs-extract')
    extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        try:
            import py7zr
        except ImportError as exc:
            raise RuntimeError('py7zr is required to normalize CrowdStrike RTR downloads.') from exc
        password = os.getenv('CROWDSTRIKE_RTR_ARCHIVE_PASSWORD', 'infected')
        with py7zr.SevenZipFile(transport, mode='r', password=password) as archive:
            archive.extractall(path=extract_dir)
        expected = expected_filename.lower()
        files = [p for p in extract_dir.rglob('*') if p.is_file()]
        match = next((p for p in files if p.name.lower() == expected), None)
        if match is None:
            zips = [p for p in files if p.suffix.lower() in {'.zip', '.7z'}]
            if len(zips) == 1:
                match = zips[0]
        if match is None:
            raise RuntimeError(f'CrowdStrike RTR archive did not contain the expected Velociraptor archive {expected_filename}.')
        shutil.copyfile(match, output_path)
        return output_path
    finally:
        transport.unlink(missing_ok=True)
        shutil.rmtree(extract_dir, ignore_errors=True)

def generate_s1_password() -> str:
    uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    lowercase = 'abcdefghijkmnopqrstuvwxyz'
    digits = '23456789'
    symbols = '!@#$%^&*-_=+'
    alphabet = uppercase + lowercase + digits + symbols
    while True:
        chars = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(symbols),
        ]
        chars.extend(secrets.choice(alphabet) for _ in range(28))
        secrets.SystemRandom().shuffle(chars)
        candidate = ''.join(chars)
        if len(candidate) == 32 and all([any(c in uppercase for c in candidate), any(c in lowercase for c in candidate), any(c in digits for c in candidate), any(c in symbols for c in candidate)]):
            return candidate

def public_job(job):
    safe = dict(job)
    safe.pop('s1_fetch_password_enc', None)
    safe.pop('s1_fetch_password_sha256', None)
    safe.pop('push_password', None)
    return safe

def create_package_token(path: Path, max_uses: int):
    token = secrets.token_urlsafe(32)
    digest = hmac.new(APP_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
    with DB_LOCK, db() as conn:
        conn.execute('INSERT INTO package_links(token_hash,path,expires_at,max_uses,used_count) VALUES(?,?,?,?,0)', (digest, str(path.resolve()), time.time() + 900, max_uses))
    return token

def consume_package_token(token: str):
    digest = hmac.new(APP_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
    with DB_LOCK, db() as conn:
        row = conn.execute('SELECT * FROM package_links WHERE token_hash=?', (digest,)).fetchone()
        if not row or row['expires_at'] < time.time() or row['used_count'] >= row['max_uses']:
            return None
        conn.execute('UPDATE package_links SET used_count=used_count+1 WHERE token_hash=?', (digest,))
        return dict(row)

def finalize_evidence(job, plain: Path, remote_sha=None, extra=None):
    stage(job, 'Verifying Evidence', 'running')
    verified_hash = sha256(plain)
    if remote_sha and verified_hash.lower() != remote_sha.lower():
        raise RuntimeError('Evidence SHA-256 verification failed after retrieval.')
    job['evidence_sha256'] = verified_hash
    stage(job, 'Verifying Evidence', 'ok', sha256=verified_hash)
    stage(job, 'Encrypting', 'running')
    enc = plain.with_suffix('.kfc')
    encrypt_file(plain, enc)
    plain.unlink(missing_ok=True)
    evidence = {
        'filename': enc.name,
        'path': str(enc.relative_to(BASE)),
        'remote_sha256': remote_sha,
        'retrieved_sha256': verified_hash,
        'encrypted': True,
        'size_encrypted': enc.stat().st_size,
        'verified': True,
        'collection_started_at': job.get('collection_started_at'),
        'collection_completed_at': job.get('collection_completed_at'),
        'retrieved_at': now(),
        'profile': job['profile'],
        'hostname': job['hostname'],
        'device_id': job['device_id'],
        'edr_provider': job['edr_provider'],
        'job_id': job['id'],
    }
    if extra:
        evidence.update(extra)
    job['evidence'] = evidence
    job['download_url'] = f'/api/jobs/{job["id"]}/download'
    stage(job, 'Encrypting', 'ok', encrypted_filename=enc.name)
    save_job(job)
    return enc

def cleanup_s1(job, host_root):
    stage(job, 'Cleanup', 'running', detail='Removing Velociraptor collector temporary files')
    params = ' '.join(['-CleanupOnly', '-DeployRoot', f'"{host_root}"'])
    result = sentinelone_provider.execute(job, params, f'DFIR collector cleanup {job["id"]}', timeout=600, script_id=s1_script_id_for_os(job.get('os_family') or normalize_os_family(job.get('platform'))))
    stage(job, 'Cleanup', 'ok', detail='Endpoint temporary files removed', parent_task_id=result['parent_task_id'])

def run_crowdstrike_velociraptor_job(job, session_id, os_family):
    collector = velociraptor_collector_path(os_family, job['profile'])
    collector_hash = sha256(collector)
    if os_family == 'windows':
        remote_root = r'C:\ProgramData\VelociraptorCollector'
        remote_dir = f'{remote_root}\\{job["id"]}'
        remote_file = f'{remote_dir}\\{collector.name}.exe'
        mkdir_cmd = f'mkdir "{remote_dir}"'
    else:
        remote_root = '/tmp/VelociraptorCollector' if os_family == 'linux' else '/private/tmp/VelociraptorCollector'
        remote_dir = f'{remote_root}/{job["id"]}'
        remote_file = f'{remote_dir}/{collector.name}'
        mkdir_cmd = f'mkdir -p "{remote_dir}"'
    stage(job,'Deploying Collector','running',detail=f'Velociraptor {os_family} offline collector via Falcon RTR',package_sha256=collector_hash)
    result=rtr.run_admin(job['device_id'],session_id,'mkdir',mkdir_cmd)
    items=resources(result); req=items[0].get('cloud_request_id') if items else None
    if req:
        done=rtr.wait_command(req)
        if done.get('stderr'): raise RuntimeError(done['stderr'])
    result=rtr.run_admin(job['device_id'],session_id,'cd',f'cd "{remote_dir}"')
    items=resources(result); req=items[0].get('cloud_request_id') if items else None
    if req:
        done=rtr.wait_command(req)
        if done.get('stderr'): raise RuntimeError(done['stderr'])
    put=rtr.create_put_file(collector); put_id=put['id']
    result=rtr.run_admin(job['device_id'],session_id,'put',f'put {put_id}')
    items=resources(result); req=items[0].get('cloud_request_id') if items else None
    if req:
        done=rtr.wait_command(req)
        if done.get('stderr'): raise RuntimeError(done['stderr'])
    if os_family == 'windows':
        invoke=f'run "{remote_file}"'
    else:
        chmod=f'chmod 700 "{remote_file}"'
        result=rtr.run_admin(job['device_id'],session_id,'runscript',f'runscript -Raw=```{chmod}```')
        items=resources(result); req=items[0].get('cloud_request_id') if items else None
        if req:
            done=rtr.wait_command(req)
            if done.get('stderr'): raise RuntimeError(done['stderr'])
        invoke=f'run "{remote_file}"'
    result=rtr.run_admin(job['device_id'],session_id,'run',invoke)
    items=resources(result); req=items[0].get('cloud_request_id') if items else None
    if req:
        done=rtr.wait_command(req)
        if done.get('stderr'): raise RuntimeError(done['stderr'])
    stage(job,'Deploying Collector','ok',detail=f'Velociraptor {os_family} collector executed',package_sha256=collector_hash)
    stage(job,'Verifying','ok',detail='Velociraptor collector completed its embedded artifact plan')
    job['collection_completed_at']=now()
    stage(job,'Collecting','ok',detail=f'Predefined profile {PROFILES[job["profile"]]["name"]} completed')
    stage(job,'Packaging','running',detail='Velociraptor collection container created')
    if os_family == 'windows':
        found=rtr.run_active_and_wait(job['device_id'],session_id,'cmd',f'dir /b /o-d "{remote_dir}\\Collection-*.zip"')
        archive_name=str(found.get('stdout','')).strip().splitlines()[0] if str(found.get('stdout','')).strip() else ''
        archive=f'{remote_dir}\\{archive_name}'
    else:
        found=rtr.run_active_and_wait(job['device_id'],session_id,'bash',f'cd "{remote_dir}" && ls -1t Collection-*.zip 2>/dev/null | head -n 1')
        archive_name=str(found.get('stdout','')).strip().splitlines()[0] if str(found.get('stdout','')).strip() else ''
        archive=f'{remote_dir}/{archive_name}'
    if not archive_name: raise RuntimeError('Velociraptor collector did not produce a collection ZIP.')
    stage(job,'Packaging','ok',detail=f'Velociraptor collection archive created: {archive_name}')
    stage(job,'Retrieving','running',detail='Retrieving Velociraptor collection container through Falcon RTR')
    gr=rtr.run_active(job['device_id'],session_id,'get',f'get "{archive}"'); gi=resources(gr)
    if not gi or not gi[0].get('cloud_request_id'): raise RuntimeError(f'RTR get failed: {response_dict(gr)}')
    req=gi[0]['cloud_request_id']; done=rtr.wait_command(req)
    if done.get('stderr'): raise RuntimeError(done['stderr'])
    dl=next((x for x in rtr.list_downloads(session_id) if x.get('cloud_request_id')==req and x.get('complete')),None)
    if not dl: raise RuntimeError('RTR completed the get but no downloadable Velociraptor archive was returned.')
    data=rtr.download_file(session_id,dl.get('sha256'),Path(archive_name).name)
    evidence_dir=EVIDENCE/job['id']; evidence_dir.mkdir(parents=True,exist_ok=True)
    temp=evidence_dir/f'{job["hostname"]}_{job["id"]}.zip'
    normalize_crowdstrike_transport(data,Path(archive_name).name,temp)
    with zipfile.ZipFile(temp) as zf:
        if zf.testzip(): raise RuntimeError('Normalized Velociraptor collection ZIP failed integrity validation.')
    stage(job,'Retrieving','ok',detail='Velociraptor collection container retrieved')
    finalize_evidence(job,temp,remote_sha=None,extra={'collector':'velociraptor','transport':'crowdstrike-rtr','os_family':os_family,'velociraptor_version':VELOCIRAPTOR_VERSION,'collector_sha256':collector_hash})
    cleanup = f'rmdir /s /q "{remote_dir}"' if os_family=='windows' else f'rm -rf "{remote_dir}"'
    base = 'cmd' if os_family=='windows' else 'runscript'
    command = cleanup if os_family=='windows' else f'runscript -Raw=```{cleanup}```'
    result=rtr.run_admin(job['device_id'],session_id,base,command)
    items=resources(result); req=items[0].get('cloud_request_id') if items else None
    if req:
        done=rtr.wait_command(req)
        if done.get('stderr'): raise RuntimeError(done['stderr'])
    stage(job,'Cleanup','ok',detail='Endpoint Velociraptor collector artifacts removed')

def run_s1_job(job, host_root: str):
    provider=sentinelone_provider
    os_family=job.get('os_family') or normalize_os_family(job.get('platform'))
    script_id=s1_script_id_for_os(os_family)
    if not script_id: raise RuntimeError(f'SentinelOne has no approved Velociraptor Remote Script configured for {os_family}.')
    if not provider.public_base: raise RuntimeError('S1_PACKAGE_BASE_URL must point to this collector server and be reachable by the endpoint.')
    push=get_push(job['push_id'])
    if not push or not push.get('s1_fetch_password_enc'): raise RuntimeError('SentinelOne push password is unavailable.')
    password=decrypt_secret_text(push['s1_fetch_password_enc'])
    evidence_dir=EVIDENCE/job['id']; evidence_dir.mkdir(parents=True,exist_ok=True)
    collector=velociraptor_collector_path(os_family, job['profile'])
    token=create_package_token(collector,max_uses=3)
    url=f'{provider.public_base}/api/s1/collector/{os_family}/{job["profile"]}/{token}'
    params=' '.join(['-CollectorUrl',f'"{url}"','-CollectorSha256',f'"{sha256(collector)}"','-CollectionId',f'"{job["id"]}"','-DeployRoot',f'"{host_root}"'])
    manifest_remote=(f'{host_root}\\{job["id"]}.manifest.txt' if os_family=='windows' else f'{host_root}/{job["id"]}.manifest.txt')
    stage(job,'Deploying Collector','running',detail=f'Executing approved SentinelOne Velociraptor collector script for {os_family}')
    result=provider.execute(job,params,f'Velociraptor collector {job["id"]}',timeout=provider.script_timeout,script_id=script_id)
    stage(job,'Deploying Collector','ok',detail='SentinelOne Remote Script completed',parent_task_id=result['parent_task_id'])
    stage(job,'Verifying','ok',detail='Velociraptor collector verified')
    job['collection_completed_at']=now()
    stage(job,'Collecting','ok',detail=f'Predefined profile {PROFILES[job["profile"]]["name"]} completed')
    stage(job,'Packaging','ok',detail='Velociraptor evidence split into SentinelOne-compatible pieces')
    ml=evidence_dir/f'{job["id"]}.manifest.txt'
    stage(job,'Retrieving','running',detail='Fetching manifest and evidence parts through SentinelOne Fetch Files')
    provider.retrieve_file_via_fetch(job['device_id'],manifest_remote,ml,password=password)
    parts=[x.strip() for x in ml.read_text(encoding='utf-8-sig',errors='replace').splitlines() if x.strip()]
    ml.unlink(missing_ok=True)
    if not parts: raise RuntimeError('SentinelOne manifest contained no evidence parts.')
    rebuilt=evidence_dir/f'{job["hostname"]}_{job["id"]}.zip'
    with rebuilt.open('wb') as out:
        for i,part in enumerate(parts,1):
            pf=evidence_dir/f'{job["id"]}.part{i:04d}'
            provider.retrieve_file_via_fetch(job['device_id'],part,pf,password=password)
            with pf.open('rb') as src: shutil.copyfileobj(src,out)
            pf.unlink(missing_ok=True)
            job['steps'][STAGES.index('Retrieving')].update(progress=round(i/len(parts)*100,1),fetched_parts=i,total_parts=len(parts),at=now()); save_job(job)
    with zipfile.ZipFile(rebuilt) as zf:
        if zf.testzip(): raise RuntimeError('Reconstructed Velociraptor evidence archive failed ZIP integrity validation.')
    stage(job,'Retrieving','ok',detail=f'Retrieved {len(parts)} Fetch Files parts')
    finalize_evidence(job,rebuilt,extra={'s1_fetch_parts':len(parts),'push_id':job['push_id'],'collector':'velociraptor','os_family':os_family,'velociraptor_version':VELOCIRAPTOR_VERSION,'collector_sha256':sha256(collector)})
    cleanup_s1(job,host_root)

def wait_for_endpoint_online(job_id):
    job=get_job(job_id)
    if not job or job.get('status')!='waiting': return
    deadline=float(job.get('wait_deadline') or (time.time()+ONLINE_WAIT_TIMEOUT_SECONDS))
    provider_name=job.get('edr_provider','crowdstrike')
    try:
        while time.time() < deadline:
            fresh=get_job(job_id)
            if not fresh or fresh.get('status')!='waiting': return
            if endpoint_is_online(provider_name,job['device_id']):
                stage(fresh,'Waiting for Online','ok',detail='Endpoint is online and ready; collection dispatched')
                fresh['status']='queued'
                fresh['wait_completed_at']=now()
                save_job(fresh)
                audit(fresh['created_by'],'endpoint_online',job_id,hostname=fresh['hostname'],edr_provider=provider_name)
                EXECUTOR.submit(worker,job_id)
                return
            remaining=max(1,int(deadline-time.time()))
            save_job(fresh)
            time.sleep(min(ONLINE_POLL_INTERVAL_SECONDS, remaining))
        fresh=get_job(job_id)
        if fresh and fresh.get('status')=='waiting':
            stage(fresh,'Waiting for Online','failed',error='Online wait timeout expired')
            fresh['status']='failed'; fresh['error']='Endpoint did not become online before the wait timeout.'; fresh['failed_at']=now(); save_job(fresh)
            audit(fresh['created_by'],'online_wait_timeout',job_id,hostname=fresh['hostname'],edr_provider=provider_name)
    except Exception as exc:
        fresh=get_job(job_id)
        if fresh and fresh.get('status')=='waiting':
            stage(fresh,'Waiting for Online','failed',error=str(exc))
            fresh['status']='failed'; fresh['error']=str(exc); fresh['failed_at']=now(); save_job(fresh)
            audit(fresh['created_by'],'online_wait_failed',job_id,hostname=fresh['hostname'],edr_provider=provider_name,error=str(exc))

def worker(job_id):
    job=get_job(job_id)
    if not job: return
    session_id=None
    host_root=(r'C:\ProgramData\VelociraptorCollector' if (job.get('os_family') or normalize_os_family(job.get('platform')))=='windows' else ('/tmp/VelociraptorCollector' if (job.get('os_family') or normalize_os_family(job.get('platform')))=='linux' else '/private/tmp/VelociraptorCollector'))
    try:
        job['status']='running'; job['collection_started_at']=now(); stage(job,'Queued','ok',detail='Job accepted by background worker'); save_job(job)
        os_family=job.get('os_family') or normalize_os_family(job.get('platform'))
        provider_name=job.get('edr_provider','crowdstrike'); collector=collector_for_os(os_family)
        stage(job,'Connecting','running',provider=provider_name,os_family=os_family)
        if provider_name=='sentinelone':
            stage(job,'Connecting','ok',detail='SentinelOne Management API reachable'); run_s1_job(job,host_root)
        else:
            stage(job,'Connecting','running',detail='Opening Falcon RTR session'); session_id=session_id_from(rtr.init_session(job['device_id'])); stage(job,'Connecting','ok',detail='Falcon RTR session initialized')
            run_crowdstrike_velociraptor_job(job,session_id,os_family)
        stage(job,'Complete','ok',detail='Collection completed successfully'); job['status']='completed'; job['completed_at']=now(); save_job(job); audit(job['created_by'],'job_completed',job['id'],hostname=job['hostname'],edr_provider=provider_name,collector=collector,os_family=os_family)
    except Exception as exc:
        current=job.get('current_stage')
        if current and current in STAGES and current!='Complete': stage(job,current,'failed',error=str(exc))
        stage(job,'Complete','failed',detail='Collection failed'); job['status']='failed'; job['error']=str(exc); job['failed_at']=now(); save_job(job); audit(job['created_by'],'job_failed',job['id'],error=str(exc),stage=current,hostname=job.get('hostname'))
    finally:
        if session_id: rtr.close_session(session_id)


class LinuxValidationRequest(BaseModel):
    distro: str
    findings: list[dict] = Field(default_factory=list)

@app.post('/api/linux/validate')
def linux_validate(request: Request, body: LinuxValidationRequest):
    require_permission(request,'vuln')
    user=actor(request)
    if body.distro not in ('debian','ubuntu','rhel','almalinux','oraclelinux'):
        raise HTTPException(400,'unsupported distro for authoritative automatic validation')
    try:
        results=tenable_provider.linux_validate(body.findings,body.distro)
        audit(request.headers.get('CF-Access-Authenticated-User-Email','unknown'),'linux_tracker_validation',None,distro=body.distro,finding_count=len(body.findings),result_count=len(results))
        sources={'debian':'Debian Security Tracker','ubuntu':'Ubuntu Security API','rhel':'Red Hat Security Data','almalinux':'AlmaLinux Errata/OVAL','oraclelinux':'Oracle Linux OVAL/Errata'}
        return {'source':'live · '+sources[body.distro],'generated_at':now(),'results':results}
    except Exception as exc:
        raise HTTPException(502,f'Linux tracker enrichment failed: {exc}')

class PushRequest(BaseModel):
    device_ids: list[str] = Field(min_length=1)
    profile: str
    deploy: bool = True
    wait_for_online: bool = False

@app.get('/', response_class=HTMLResponse)
def index():
    return (BASE / 'app/static/index.html').read_text(encoding='utf-8')

@app.post('/api/auth/login')
def login(request: Request,username:str=Form(...),password:str=Form(...)):
    _require_cloudflare_if_configured(request)
    row=_user_row(username.strip())
    if not row or not _password_verify(password,row['password_hash']):raise HTTPException(status.HTTP_401_UNAUTHORIZED,'Invalid username or password.')
    token=secrets.token_urlsafe(48);digest=hashlib.sha256(token.encode()).hexdigest()
    with DB_LOCK,db() as conn:
        conn.execute('INSERT INTO auth_sessions VALUES(?,?,?,?)',(digest,row['username'],now(),time.time()+SESSION_TTL_SECONDS));conn.execute('DELETE FROM auth_sessions WHERE expires_at<?',(time.time(),))
    audit(row['username'],'login',None,identity_email=request.headers.get('CF-Access-Authenticated-User-Email'))
    from fastapi.responses import JSONResponse
    out=JSONResponse({'authenticated':True,'user':_public_user(row)});out.set_cookie(AUTH_SESSION_COOKIE,token,max_age=SESSION_TTL_SECONDS,httponly=True,secure=COOKIE_SECURE,samesite='lax',path='/');return out
@app.post('/api/auth/logout')
def logout(request: Request):
    token=request.cookies.get(AUTH_SESSION_COOKIE)
    if token:
        digest=hashlib.sha256(token.encode()).hexdigest()
        with DB_LOCK,db() as conn:conn.execute('DELETE FROM auth_sessions WHERE token_hash=?',(digest,))
    from fastapi.responses import JSONResponse
    out=JSONResponse({'authenticated':False});out.delete_cookie(AUTH_SESSION_COOKIE,path='/');return out

@app.get('/api/auth/me')
def me(request: Request):
    return {'authenticated':True,'user':require_auth(request)}

@app.get('/api/admin/users')
def admin_users(request:Request):
    require_admin(request)
    with DB_LOCK,db() as conn:rows=conn.execute('SELECT username,role,permissions_json,identity_email,enabled,created_at,updated_at FROM users ORDER BY username').fetchall()
    return [{**dict(r),'permissions':json.loads(r['permissions_json'] or '[]')} for r in rows]
class AdminUserRequest(BaseModel):
    username:str; password:str|None=None; role:str='operator'; permissions:list[str]=Field(default_factory=list); identity_email:str|None=None; enabled:bool=True
@app.post('/api/admin/users')
def admin_create_user(request:Request,body:AdminUserRequest):
    admin=require_admin(request);u=body.username.strip()
    if not re.fullmatch(r'[A-Za-z0-9._-]{3,80}',u):raise HTTPException(400,'Invalid username.')
    if body.role not in ('admin','operator'):raise HTTPException(400,'Invalid role.')
    perms=sorted(set(body.permissions).intersection(WORKSPACE_PERMISSIONS));perms=list(WORKSPACE_PERMISSIONS) if body.role=='admin' else perms
    if body.role=='operator' and not perms:raise HTTPException(400,'Select at least one workspace permission.')
    if not body.password or len(body.password)<12:raise HTTPException(400,'Password must be at least 12 characters.')
    with DB_LOCK,db() as conn:
        if conn.execute('SELECT 1 FROM users WHERE username=?',(u,)).fetchone():raise HTTPException(409,'Username already exists.')
        conn.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?,?)',(u,_password_hash(body.password),body.role,json.dumps(perms),body.identity_email,1 if body.enabled else 0,now(),now()))
    audit(admin['username'],'admin_user_created',u,permissions=perms,role=body.role);return {'ok':True}
@app.patch('/api/admin/users/{username}')
def admin_update_user(request:Request,username:str,body:AdminUserRequest):
    admin=require_admin(request);perms=sorted(set(body.permissions).intersection(WORKSPACE_PERMISSIONS));perms=list(WORKSPACE_PERMISSIONS) if body.role=='admin' else perms
    if body.role not in ('admin','operator'):raise HTTPException(400,'Invalid role.')
    if body.role=='operator' and not perms:raise HTTPException(400,'Select at least one workspace permission.')
    with DB_LOCK,db() as conn:
        if not conn.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():raise HTTPException(404,'User not found.')
        fields=['role=?','permissions_json=?','identity_email=?','enabled=?','updated_at=?'];vals=[body.role,json.dumps(perms),body.identity_email,1 if body.enabled else 0,now()]
        if body.password:fields.insert(0,'password_hash=?');vals.insert(0,_password_hash(body.password))
        vals.append(username);conn.execute('UPDATE users SET '+','.join(fields)+' WHERE username=?',vals)
    audit(admin['username'],'admin_user_updated',username,permissions=perms,role=body.role);return {'ok':True}
@app.delete('/api/admin/users/{username}')
def admin_delete_user(request:Request,username:str):
    admin=require_admin(request)
    if username==admin['username']:raise HTTPException(400,'You cannot delete yourself.')
    with DB_LOCK,db() as conn:
        if conn.execute('DELETE FROM users WHERE username=?',(username,)).rowcount==0:raise HTTPException(404,'User not found.')
        conn.execute('DELETE FROM auth_sessions WHERE username=?',(username,))
    audit(admin['username'],'admin_user_deleted',username);return {'ok':True}

@app.get('/api/config')
def config(request: Request):
    actor(request)
    provider = active_provider()
    live_available = provider.configured()
    return {
        'edr_provider': edr_provider,
        'edr_label': provider_label(),
                'evidence_encrypted': True,
        'retention_days': RETENTION_DAYS,
        'job_workers': MAX_WORKERS,
        'provider_configured': live_available,
        'sentinelone_execution_mode': sentinelone_provider.execution_mode,
        'sentinelone_script_configured': any(s1_script_id_for_os(x) for x in ('windows','linux','macos')),
                'collector_profiles': {k: {'name': v['name'], 'description': v['description'], 'estimated': v['estimated']} for k, v in PROFILES.items()},
        's1_scripts_configured': {os_name: bool(s1_script_id_for_os(os_name)) for os_name in ('windows','linux','macos')},
        'velociraptor': velociraptor_status(),
        'cloudflare_identity': 'Cloudflare Access',
        'tenable_configured': tenable_provider.configured(),
    }

@app.get('/api/connectivity')
def connectivity(request: Request):
    actor(request)
    return {
        'crowdstrike': falcon_provider.connectivity(),
        'sentinelone': sentinelone_provider.connectivity(),
        'tenable': tenable_provider.connectivity(),
    }

@app.post('/api/config/edr')
def set_edr(request: Request, edr: str = Form(...)):
    require_admin(request)
    global edr_provider
    user = actor(request)
    edr = edr.lower().strip()
    if edr not in ('crowdstrike', 'sentinelone'):
        raise HTTPException(400, 'EDR must be crowdstrike or sentinelone')
    if any(j.get('status') in ('running', 'queued') for j in list_jobs()):
        raise HTTPException(409, 'Cannot switch EDR while collection jobs are queued or running.')
    edr_provider = edr
    audit(user, 'edr_changed', None, edr_provider=edr)
    return {'edr_provider': edr_provider, 'edr_label': provider_label(), 'provider_configured': active_provider().configured()}


@app.get('/api/hosts')
def hosts(request: Request, q: str = '', edr: str = ''):
    require_permission(request,'dfir')
    actor(request)
    provider_name = (edr or edr_provider).lower().strip()
    if provider_name not in ('crowdstrike', 'sentinelone', 'all'):
        raise HTTPException(400, 'EDR must be crowdstrike, sentinelone, or all.')
    names = ['crowdstrike', 'sentinelone'] if provider_name == 'all' else [provider_name]
    results = []
    for name in names:
        provider = falcon_provider if name == 'crowdstrike' else sentinelone_provider
        try:
            hs = provider.list_hosts(q)
        except Exception as exc:
            if provider_name == 'all':
                audit(request.headers.get('CF-Access-Authenticated-User-Email', 'unknown'), 'inventory_query_failed', None, edr_provider=name, error=str(exc)[:300])
                continue
            raise HTTPException(502, f'Unable to query {provider.label} hosts: {exc}')
        for h in hs:
            item = dict(h); item['edr_provider'] = name; item['os_family'] = item.get('os_family') or normalize_os_family(item.get('platform')); item['network_contained'] = bool(item.get('network_contained', False)); results.append(item)
    return results

@app.get('/api/profiles')
def profiles(request: Request):
    require_permission(request,'dfir')
    actor(request)
    return PROFILES



@app.get('/api/vulns')
def vulnerabilities(request: Request, since_days: int | None = None):
    require_permission(request,'vuln')
    actor(request)
    if since_days is not None and (since_days < 1 or since_days > 3650):
        raise HTTPException(400,'since_days must be between 1 and 3650.')
    if not tenable_provider.configured():
        raise HTTPException(503,'Tenable Vulnerability Management is not configured.')
    try:
        raw=tenable_provider.list_vulnerabilities(since_days=since_days)
        rows=[tenable_provider.normalize_vulnerability(v) for v in raw]
    except Exception as exc:
        raise HTTPException(502,f'Unable to retrieve Tenable vulnerability data: {exc}')
    return {'generated_at':now(),'count':len(rows),'vulnerabilities':rows,'source':'Tenable API'}

class PushRequest(BaseModel):
    device_ids: list[str] = Field(min_length=1)
    profile: str
    deploy: bool = True
    wait_for_online: bool = False

@app.post('/api/pushes')
def create_push(request: Request, body: PushRequest):
    require_permission(request,'dfir')
    user=actor(request)
    if body.profile not in PROFILES: raise HTTPException(400,'Unknown collection profile')
    if len(body.device_ids)>100: raise HTTPException(400,'A single push may target at most 100 endpoints.')
    all_hosts=hosts(request,q='',edr=edr_provider)
    by_id={h['device_id']:h for h in all_hosts}
    selected=[by_id.get(device_id) for device_id in body.device_ids]
    if any(h is None for h in selected): raise HTTPException(404,'One or more selected endpoints were not found.')
    for host in selected:
        os_family=host.get('os_family') or normalize_os_family(host.get('platform'))
        if os_family not in ('windows','linux','macos'):
            raise HTTPException(409,f'Endpoint {host["hostname"]} has an unsupported operating system.')
        velociraptor_collector_path(os_family, body.profile)
        online = str(host.get('status','')).lower() in ('online','normal','connected','healthy') and str(host.get('rtr','')).lower() in ('ready','remote_shell','remote_script')
        if not online and not body.wait_for_online:
            raise HTTPException(409,f'Endpoint {host["hostname"]} is offline or not ready. Enable "Wait for online" to queue it for automatic polling.')
    push_id='push-'+uuid.uuid4().hex[:10]
    s1_password=generate_s1_password() if edr_provider=='sentinelone' else None
    password_enc=encrypt_secret_text(s1_password) if s1_password else None
    password_hash=hashlib.sha256(s1_password.encode()).hexdigest() if s1_password else None
    with DB_LOCK, db() as conn:
        conn.execute('INSERT INTO pushes(id,created_at,created_by,edr_provider,profile,endpoint_count,s1_fetch_password_enc,s1_fetch_password_sha256) VALUES(?,?,?,?,?,?,?,?)',
                     (push_id,now(),user,edr_provider,body.profile,len(selected),password_enc,password_hash))
    audit(user,'push_created',push_id,edr_provider=edr_provider,profile=body.profile,endpoint_count=len(selected),wait_for_online=body.wait_for_online)
    response_jobs=[]
    for host in selected:
        os_family=host.get('os_family') or normalize_os_family(host.get('platform'))
        online = str(host.get('status','')).lower() in ('online','normal','connected','healthy') and str(host.get('rtr','')).lower() in ('ready','remote_shell','remote_script')
        status='queued' if online else 'waiting'
        job={'id':'job-'+uuid.uuid4().hex[:10],'push_id':push_id,'created_at':now(),'device_id':host['device_id'],'hostname':host['hostname'],
             'profile':body.profile,'status':status,'deploy':body.deploy,'wait_for_online':(not online and body.wait_for_online),
             'wait_started_at':now() if (not online and body.wait_for_online) else None,
             'wait_deadline':time.time()+ONLINE_WAIT_TIMEOUT_SECONDS if (not online and body.wait_for_online) else None,
             'steps':[],'evidence':None,'download_url':None,'created_by':user,'edr_provider':edr_provider,
             'platform':host.get('platform'),'os_family':os_family,'collector':'velociraptor'}
        init_job_steps(job)
        if status=='waiting':
            stage(job,'Waiting for Online','running',detail=f'Polling {edr_provider} every {ONLINE_POLL_INTERVAL_SECONDS // 60} minutes')
        save_job(job)
        audit(user,'job_created',job['id'],push_id=push_id,device_id=host['device_id'],hostname=host['hostname'],profile=body.profile,edr_provider=edr_provider,status=status,wait_for_online=job['wait_for_online'])
        response_jobs.append(public_job(job))
    for job in response_jobs:
        if job['status']=='waiting':
            WAIT_EXECUTOR.submit(wait_for_endpoint_online,job['id'])
            audit(user,'job_waiting_for_online',job['id'],push_id=push_id,poll_interval_seconds=ONLINE_POLL_INTERVAL_SECONDS)
        else:
            EXECUTOR.submit(worker,job['id'])
            audit(user,'job_queued',job['id'],push_id=push_id)
    return {'push_id':push_id,'jobs':response_jobs,'endpoint_count':len(response_jobs),'edr_provider':edr_provider,'wait_for_online':body.wait_for_online,'poll_interval_seconds':ONLINE_POLL_INTERVAL_SECONDS}


@app.get('/api/jobs')
def jobs(request: Request):
    require_permission(request,'dfir')
    actor(request); return [public_job(x) for x in list_jobs()]

@app.get('/api/jobs/{job_id}')
def job(request: Request, job_id: str):
    require_permission(request,'dfir')
    actor(request); item=get_job(job_id)
    if not item: raise HTTPException(404,'Job not found')
    return public_job(item)

@app.get('/api/jobs/{job_id}/download')
def download_job(request: Request, job_id: str):
    require_permission(request,'dfir'); user=actor(request); item=get_job(job_id)
    if not item or not item.get('evidence'): raise HTTPException(404,'Evidence is not available for this job.')
    path=(BASE/item['evidence']['path']).resolve()
    if not path.exists() or BASE not in path.parents: raise HTTPException(404,'Evidence file is missing.')
    audit(user,'evidence_download',job_id,filename=item['evidence']['filename'])
    def stream():
        for chunk in decrypt_stream(path): yield chunk
    return StreamingResponse(stream(),media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="{item["hostname"]}_{job_id}_evidence.zip"'})

@app.get('/api/audit')
def audit_api(request: Request, limit: int = 200):
    require_permission(request,'dfir')
    actor(request)
    with DB_LOCK, db() as conn:
        rows=conn.execute('SELECT at,actor,action,object_id,detail FROM audit_log ORDER BY id DESC LIMIT ?',(min(limit,500),)).fetchall()
    return [dict(r) for r in rows]

@app.get('/api/velociraptor/status')
def velociraptor_status_route(request: Request):
    require_permission(request,'dfir')
    actor(request)
    return velociraptor_status()


@app.post('/api/velociraptor/update')
def velociraptor_update(request: Request):
    require_admin(request)
    user=actor(request)
    latest=latest_velociraptor_release()
    if latest['version']==VELOCIRAPTOR_VERSION:
        audit(user,'velociraptor_update_check',None,status='current',version=VELOCIRAPTOR_VERSION)
        return {'status':'current','version':VELOCIRAPTOR_VERSION}
    command=VELOCIRAPTOR_UPDATE_COMMAND
    if not command:
        raise HTTPException(409, f'Velociraptor {latest["version"]} is available, but VELOCIRAPTOR_UPDATE_COMMAND is not configured on the server.')
    env=os.environ.copy(); env['VELOCIRAPTOR_LATEST_VERSION']=latest['version']
    completed=subprocess.run(command,shell=True,cwd=BASE,env=env,capture_output=True,text=True,timeout=1800)
    if completed.returncode:
        audit(user,'velociraptor_update_failed',None,target_version=latest['version'],error=completed.stderr[-1000:])
        raise HTTPException(502,'Velociraptor update command failed. See server logs.')
    audit(user,'velociraptor_updated',None,previous_version=VELOCIRAPTOR_VERSION,target_version=latest['version'])
    return {'status':'updated','previous_version':VELOCIRAPTOR_VERSION,'target_version':latest['version'],'restart_required':True}

def _serve_velociraptor_token(token: str):
    path=consume_package_token(token)
    if not path:
        raise HTTPException(404,'Collector link is invalid or expired.')
    p=Path(path).resolve()
    try:
        p.relative_to(VELOCIRAPTOR_COLLECTOR_ROOT.resolve())
    except ValueError:
        raise HTTPException(403,'Invalid collector path.')
    if not p.exists() or not p.is_file():
        raise HTTPException(404,'Collector is no longer available.')
    return FileResponse(p, filename=p.name, media_type='application/octet-stream')

@app.get('/api/s1/collector/{os_family}/{profile}/{token}')
def s1_velociraptor_collector(os_family: str, profile: str, token: str):
    return _serve_velociraptor_token(token)

@app.get('/api/health')
def health():
    return {
        'ok': True,
        'edr_provider': edr_provider,
        'crowdstrike_configured': falcon_provider.configured(),
        'sentinelone_configured': sentinelone_provider.configured(),
        'sentinelone_execution_configured': sentinelone_provider.can_execute(),
        'database': str(DB_PATH.name),
        'evidence_encrypted': True,
                'collector_profiles': {k: {'name': v['name'], 'description': v['description'], 'estimated': v['estimated']} for k, v in PROFILES.items()},
        's1_scripts_configured': {os_name: bool(s1_script_id_for_os(os_name)) for os_name in ('windows','linux','macos')},
    }

def purge_expired_evidence():
    cutoff = time.time() - RETENTION_DAYS * 86400
    for job in list_jobs():
        evidence = job.get('evidence') or {}
        rel = evidence.get('path')
        if not rel:
            continue
        path = (BASE / rel).resolve()
        try:
            if path.exists() and path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
                job['evidence']['expired_at'] = now()
                job['download_url'] = None
                save_job(job)
                audit('system', 'evidence_retention_purge', job['id'], filename=evidence.get('filename'))
        except Exception:
            pass

@app.on_event('startup')
def startup_asset_sync():
    ASSET_SYNC_EXECUTOR.submit(sync_asset_inventory)
    threading.Thread(target=asset_sync_loop, name='asset-inventory-scheduler', daemon=True).start()

@app.on_event('startup')
def startup_requeue():
    purge_expired_evidence()
    for job in list_jobs():
        if job['status'] == 'queued':
            EXECUTOR.submit(worker, job['id'])
        elif job['status'] == 'waiting' and job.get('wait_for_online'):
            WAIT_EXECUTOR.submit(wait_for_endpoint_online, job['id'])



def _coverage_query_match(asset, query):
    q=str(query or '').strip().lower()
    if not q:
        return True
    values=[asset.get('hostname',''), *asset.get('aliases',[]), *asset.get('ips',[])]
    return q in ' '.join(str(v) for v in values).lower()

def write_asset_inventory(coverage, source_counts, errors, started_at):
    with DB_LOCK, db() as conn:
        conn.execute('DELETE FROM asset_inventory')
        for asset in coverage:
            conn.execute(
                """INSERT INTO asset_inventory(asset_id,hostname,ips_json,aliases_json,sources_json,coverage_json,payload_json,updated_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (asset['id'], asset['hostname'], json.dumps(asset.get('ips',[])),
                 json.dumps(asset.get('aliases',[])), json.dumps(asset.get('sources',[])),
                 json.dumps(asset.get('coverage',{})), json.dumps(asset), now())
            )
        for source in ('crowdstrike','sentinelone','tenable'):
            status='error' if source in errors else 'ok'
            conn.execute(
                """INSERT INTO asset_inventory_sync(source,status,started_at,completed_at,record_count,error,last_asset_update)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(source) DO UPDATE SET status=excluded.status,started_at=excluded.started_at,
                   completed_at=excluded.completed_at,record_count=excluded.record_count,error=excluded.error,
                   last_asset_update=excluded.last_asset_update""",
                (source,status,started_at,now(),source_counts.get(source,0),errors.get(source),now()))

def sync_asset_inventory():
    if not ASSET_SYNC_LOCK.acquire(blocking=False):
        return {'status':'already_running'}
    started=now()
    try:
        records={}; errors={}
        for source,provider in (('crowdstrike',falcon_provider),('sentinelone',sentinelone_provider),('tenable',tenable_provider)):
                if not provider.configured():
                    records[source]=[]; errors[source]='Not configured'; continue
                try:
                    records[source]=provider.list_hosts('')
                except Exception as exc:
                    records[source]=[]; errors[source]=str(exc)[:240]
        coverage=build_asset_coverage(records)
        write_asset_inventory(coverage,{k:len(v) for k,v in records.items()},errors,started)
        audit('system','asset_inventory_sync',None,source_counts={k:len(v) for k,v in records.items()},canonical_count=len(coverage),errors=errors)
        return {'status':'completed','canonical_count':len(coverage),'source_counts':{k:len(v) for k,v in records.items()},'errors':errors,'completed_at':now()}
    finally:
        ASSET_SYNC_LOCK.release()

def seconds_until_next_asset_sync():
    current=datetime.now().astimezone()
    for hour in ASSET_SYNC_HOURS:
        candidate=current.replace(hour=hour,minute=0,second=0,microsecond=0)
        if candidate > current:
            return max(1,(candidate-current).total_seconds())
    tomorrow=(current + timedelta(days=1)).replace(hour=0,minute=0,second=0,microsecond=0)
    return max(1,(tomorrow-current).total_seconds())

def asset_sync_loop():
    while True:
        time.sleep(seconds_until_next_asset_sync())
        try:
            sync_asset_inventory()
        except Exception as exc:
            audit('system','asset_inventory_sync_failed',None,error=str(exc)[:240])


@app.get('/api/asset-coverage/status')
def asset_coverage_status(request: Request):
    require_permission(request,'assets')
    actor(request)
    with DB_LOCK, db() as conn:
        rows=conn.execute('SELECT source,status,started_at,completed_at,record_count,error,last_asset_update FROM asset_inventory_sync ORDER BY source').fetchall()
        total=conn.execute('SELECT COUNT(*) AS n FROM asset_inventory').fetchone()['n']
    return {'status':'running' if ASSET_SYNC_LOCK.locked() else 'idle',
            'schedule_hours':list(ASSET_SYNC_HOURS),'schedule':'00:00, 06:00, 12:00, 18:00 local server time','total_assets':total,
            'sources':{r['source']:dict(r) for r in rows}}

@app.post('/api/asset-coverage/sync')
def asset_coverage_sync(request: Request):
    require_permission(request,'assets')
    user=actor(request)
    if ASSET_SYNC_LOCK.locked():
        return {'status':'already_running'}
    ASSET_SYNC_EXECUTOR.submit(sync_asset_inventory)
    audit(user,'asset_inventory_sync_requested')
    return {'status':'started'}

@app.get('/api/asset-coverage')
def asset_coverage(request: Request, missing: str = 'all', q: str = ''):
    require_permission(request,'assets')
    actor(request)
    with DB_LOCK, db() as conn:
        rows=conn.execute('SELECT payload_json FROM asset_inventory ORDER BY hostname COLLATE NOCASE').fetchall()
        sync_rows=conn.execute('SELECT source,status,completed_at,record_count,error FROM asset_inventory_sync ORDER BY source').fetchall()
    coverage=[json.loads(r['payload_json']) for r in rows]
    if q: coverage=[a for a in coverage if _coverage_query_match(a,q)]
    if missing in ('crowdstrike','sentinelone','tenable'):
        coverage=[a for a in coverage if not a['coverage'][missing]]
    elif missing=='any':
        coverage=[a for a in coverage if a['missing']]
    elif missing=='none':
        coverage=[a for a in coverage if not a['missing']]
    source_counts={r['source']:r['record_count'] for r in sync_rows}
    errors={r['source']:r['error'] for r in sync_rows if r['error']}
    last_sync=max((r['completed_at'] for r in sync_rows if r['completed_at']),default=None)
    return {'assets':coverage,
            'counts':{'total':len(coverage),
                      'crowdstrike':sum(bool(a['coverage']['crowdstrike']) for a in coverage),
                      'sentinelone':sum(bool(a['coverage']['sentinelone']) for a in coverage),
                      'tenable':sum(bool(a['coverage']['tenable']) for a in coverage)},
            'errors':errors,'source_counts':source_counts,'last_sync':last_sync,
            'sync_status':'running' if ASSET_SYNC_LOCK.locked() else 'idle'}

