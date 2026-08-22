import json
import os
import shutil
import zipfile
import time
import urllib.parse
from pathlib import Path


def normalize_platform(value):
    value = str(value or '').lower()
    if any(x in value for x in ('windows', 'win32', 'win64')):
        return 'windows'
    if any(x in value for x in ('macos', 'mac os', 'darwin', 'osx')):
        return 'macos'
    if 'linux' in value or any(x in value for x in ('ubuntu','debian','rhel','centos','red hat','suse')):
        return 'linux'
    return 'unknown'


def _json_body(response):
    if isinstance(response, dict):
        body = response.get('body', response)
        return body if isinstance(body, dict) else {}
    return {}


class ProviderBase:
    name = 'base'
    label = 'Provider'

    def configured(self):
        return False

    def connectivity(self):
        return {'connected': False, 'detail': 'Not configured'}

    def list_hosts(self, query=''):
        raise NotImplementedError


class FalconProvider(ProviderBase):
    name = 'crowdstrike'
    label = 'CrowdStrike'

    def __init__(self):
        self.client_id = os.getenv('FALCON_CLIENT_ID')
        self.client_secret = os.getenv('FALCON_CLIENT_SECRET')
        self.cloud = os.getenv('FALCON_CLOUD', 'us-1')
        self._hosts = None
        self._rtr = None

    def configured(self):
        return bool(self.client_id and self.client_secret)

    def _ensure_hosts(self):
        if self._hosts is None:
            from falconpy import Hosts
            self._hosts = Hosts(client_id=self.client_id, client_secret=self.client_secret,
                                cloud_region=self.cloud, pythonic=True)
        return self._hosts

    def connectivity(self):
        if not self.configured():
            return {'connected': False, 'detail': 'API client not configured'}
        try:
            self._ensure_hosts().query_devices_by_filter_combined(
                limit=1, filter=None, fields='device_id,hostname,status')
            return {'connected': True, 'detail': f'Falcon {self.cloud} API reachable'}
        except Exception as exc:
            return {'connected': False, 'detail': str(exc)[:180]}

    def list_hosts(self, query=''):
        if not self.configured():
            return []
        hosts_api=self._ensure_hosts()
        offset=None
        out=[]
        while True:
            kwargs={'limit':10000,'filter':query or None,'fields':'device_id,hostname,platform_name,status,last_seen,local_ip,agent_version'}
            if offset:
                kwargs['offset']=offset
            result=hosts_api.query_devices_by_filter_scroll(**kwargs)
            body=_json_body(result)
            resources=body.get('resources',[])
            out.extend(resources)
            offset=body.get('meta',{}).get('pagination',{}).get('offset')
            if not offset or not resources:
                break
        return [{
            'device_id': item.get('device_id'),
            'hostname': item.get('hostname') or item.get('device_id'),
            'platform': item.get('platform_name') or item.get('platform'),
            'os_family': normalize_platform(item.get('platform_name') or item.get('platform')),
            'status': item.get('status', 'unknown'),
            'network_contained': item.get('status') in ('contained', 'containment_pending'),
            'rtr': 'ready' if item.get('status') == 'normal' else 'unknown',
            'local_ip': item.get('local_ip'),
            'agent_version': item.get('agent_version'),
            'last_seen': item.get('last_seen'),
        } for item in out]


class SentinelOneProvider(ProviderBase):
    name = 'sentinelone'
    label = 'SentinelOne'

    def __init__(self):
        self.base_url = os.getenv('SENTINELONE_BASE_URL', '').rstrip('/')
        self.token = os.getenv('SENTINELONE_API_TOKEN', '')
        self.timeout = int(os.getenv('SENTINELONE_HTTP_TIMEOUT', '60'))
        self.execution_mode = os.getenv('S1_EXECUTION_MODE', 'remote_script').strip().lower()
        self.remote_script_id = os.getenv('S1_REMOTE_SCRIPT_ID', '').strip()
        self.remote_script_ids={'windows':os.getenv('S1_REMOTE_SCRIPT_ID_WINDOWS',self.remote_script_id).strip(),'linux':os.getenv('S1_REMOTE_SCRIPT_ID_LINUX','').strip(),'macos':os.getenv('S1_REMOTE_SCRIPT_ID_MACOS','').strip()}
        self.script_timeout = int(os.getenv('S1_REMOTE_SCRIPT_TIMEOUT', '1800'))
        self.fetch_timeout = int(os.getenv('S1_FETCH_TIMEOUT', '900'))
        self.public_base = os.getenv('S1_PACKAGE_BASE_URL', '').rstrip('/')

    def configured(self):
        return bool(self.base_url and self.token)

    def can_execute(self, os_family=None):
        return self.execution_mode == 'remote_script' and bool(self.remote_script_ids.get(os_family or 'windows',self.remote_script_id))

    def connectivity(self):
        if not self.configured():
            return {'connected': False, 'detail': 'API token/base URL not configured'}
        try:
            resp = self._request('GET', '/web/api/v2.1/agents', params={'limit': 1})
            resp.raise_for_status()
            return {'connected': True, 'detail': 'SentinelOne Management API reachable'}
        except Exception as exc:
            return {'connected': False, 'detail': str(exc)[:180]}

    def _request(self, method, path, **kwargs):
        import requests
        url = self.base_url + (path if path.startswith('/') else '/' + path)
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = 'ApiToken ' + self.token
        headers.setdefault('Accept', 'application/json')
        headers.setdefault('Content-Type', 'application/json')
        return requests.request(method, url, headers=headers, timeout=self.timeout, **kwargs)

    def list_hosts(self, query=''):
        if not self.configured():
            return []
        params = {'limit': 1000}
        if query:
            params['computerName__contains'] = query
        cursor = None
        out = []
        while True:
            if cursor:
                params['cursor'] = cursor
            resp = self._request('GET', '/web/api/v2.1/agents', params=params)
            resp.raise_for_status()
            body = resp.json()
            for item in body.get('data', []):
                realtime = item.get('agentRealtimeInfo', {})
                network = realtime.get('networkStatus') or item.get('networkStatus')
                active = item.get('isActive') if 'isActive' in item else realtime.get('isActive')
                online = network in ('connected', 'connecting') or active is True
                out.append({
                    'device_id': str(item.get('id') or item.get('uuid') or ''),
                    'hostname': item.get('computerName') or item.get('computerNameNormalized') or str(item.get('id') or ''),
                    'platform': item.get('osType') or item.get('osName') or 'unknown',
                    'os_family': normalize_platform(item.get('osType') or item.get('osName')),
                    'status': 'online' if online else 'offline',
                    'rtr': 'ready' if self.can_execute(normalize_platform(item.get('osType') or item.get('osName'))) and online else ('remote_script' if online else 'not_ready'),
                    'local_ip': item.get('localIp') or item.get('externalIp'),
                    'agent_version': item.get('agentVersion') or item.get('agentVersionFull'),
                    'site_name': item.get('siteName') or (item.get('site') or {}).get('name'),
                    'group_name': item.get('groupName') or (item.get('group') or {}).get('name'),
                    'network_contained': bool(
                        item.get('networkQuarantine') is True
                        or item.get('networkQuarantineStatus') in ('enabled', 'connected', 'disconnected', 'contained')
                        or item.get('networkQuarantined') is True
                        or realtime.get('networkQuarantine') is True
                        or realtime.get('networkQuarantineStatus') in ('enabled', 'connected', 'disconnected', 'contained')
                        or realtime.get('networkQuarantined') is True
                    ),
                })
            cursor = (body.get('pagination') or {}).get('nextCursor')
            if not cursor:
                break
        return out

    def execute_remote_script(self, agent_id, input_params, task_description, timeout=None, script_id=None):
        script_id = script_id or self.remote_script_id
        if not (self.execution_mode == 'remote_script' and script_id):
            raise RuntimeError('SentinelOne Remote Script execution is not configured for the requested platform.')
        timeout = timeout or self.script_timeout
        data = {
            'filter': {'ids': [str(agent_id)]},
            'scriptId': script_id,
            'taskDescription': task_description,
            'outputDestination': 'None',
            'filterMap': {
                'inputParams': input_params,
                'scriptRuntimeTimeoutSeconds': timeout,
            },
        }
        resp = self._request('POST', '/web/api/v2.1/remote-scripts/execute', json={'data': data})
        if resp.status_code in (400, 422):
            # Some S1 console versions expose the remote-script fields one level up under data.
            fallback = {
                'filter': {'ids': [str(agent_id)]},
                'scriptId': script_id,
                'taskDescription': task_description,
                'outputDestination': 'None',
                'inputParams': input_params,
                'scriptRuntimeTimeoutSeconds': timeout,
            }
            resp = self._request('POST', '/web/api/v2.1/remote-scripts/execute', json={'data': fallback})
        resp.raise_for_status()
        return resp.json()

    def wait_remote_script(self, parent_task_id, timeout=None):
        deadline = time.time() + (timeout or self.script_timeout) + 60
        last = None
        while time.time() < deadline:
            resp = self._request('GET', '/web/api/v2.1/remote-scripts/status',
                                 params={'parentTaskId': str(parent_task_id), 'limit': 100})
            resp.raise_for_status()
            body = resp.json()
            rows = body.get('data', [])
            if rows:
                last = rows
                states = {str(row.get('status', '')).lower() for row in rows}
                if states and states.issubset({'completed', 'failed', 'expired', 'canceled', 'partially_completed'}):
                    if 'failed' in states or 'expired' in states or 'canceled' in states:
                        raise RuntimeError(json.dumps(rows[-1], sort_keys=True))
                    if 'partially_completed' in states:
                        raise RuntimeError(json.dumps(rows[-1], sort_keys=True))
                    return rows
            time.sleep(2)
        raise TimeoutError(f'SentinelOne remote script task {parent_task_id} timed out; last={last}')

    @staticmethod
    def _extract_parent_task_id(body):
        data = body.get('data', []) if isinstance(body, dict) else []
        if isinstance(data, dict):
            data = [data]
        for item in data:
            for key in ('parentTaskId', 'parent_task_id', 'taskId', 'id'):
                if item.get(key):
                    return item[key]
        if isinstance(body, dict):
            for key in ('parentTaskId', 'parent_task_id', 'taskId', 'id'):
                if body.get(key):
                    return body[key]
        return None

    def execute(self, job, input_params, task_description, timeout=None, script_id=None):
        result = self.execute_remote_script(job['device_id'], input_params, task_description, timeout=timeout, script_id=script_id)
        parent_task_id = self._extract_parent_task_id(result)
        if not parent_task_id:
            raise RuntimeError(f'SentinelOne execute response missing parentTaskId: {result}')
        self.wait_remote_script(parent_task_id, timeout=timeout)
        return {'parent_task_id': parent_task_id, 'result': result}

    def file_fetch(self, agent_id, remote_files, password):
        payload = {'data': {'files': remote_files, 'password': password}}
        resp = self._request('POST', f'/web/api/v2.1/agents/{urllib.parse.quote(str(agent_id), safe="")}/actions/fetch-files', json=payload)
        resp.raise_for_status()
        body = resp.json()
        if not body.get('data', {}).get('success', True):
            raise RuntimeError(f'SentinelOne file fetch request failed: {body}')
        return body

    def download_fetch(self, download_url, destination: Path):
        import requests
        url = download_url if download_url.startswith(('http://', 'https://')) else self.base_url + '/web/api/v2.1' + download_url
        with requests.get(url, headers={'Authorization': 'ApiToken ' + self.token}, timeout=self.timeout, stream=True) as resp:
            resp.raise_for_status()
            with destination.open('wb') as out:
                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        out.write(chunk)

    def retrieve_file_via_fetch(self, agent_id, remote_path, destination: Path, password):
        # SentinelOne Fetch Files creates a password-protected archive in Management.
        requested = self.file_fetch(agent_id, [remote_path], password)
        command_batch_uuid = None
        data = requested.get('data') or {}
        if isinstance(data, dict):
            command_batch_uuid = data.get('commandBatchUuid') or data.get('command_batch_uuid')
        deadline = time.time() + self.fetch_timeout
        destination.parent.mkdir(parents=True, exist_ok=True)
        wrapper = destination.with_suffix(destination.suffix + '.s1fetch.zip')
        try:
            while time.time() < deadline:
                params = {'limit': 100, 'sortBy': 'createdAt', 'sortOrder': 'desc', 'agentIds': str(agent_id)}
                resp = self._request('GET', '/web/api/v2.1/activities', params=params)
                resp.raise_for_status()
                for item in resp.json().get('data', []):
                    text = json.dumps(item)
                    if remote_path not in text and (command_batch_uuid and command_batch_uuid not in text):
                        continue
                    data_obj = item.get('data') or {}
                    url = data_obj.get('downloadUrl') or item.get('downloadUrl') or data_obj.get('fileFetch', {}).get('downloadUrl')
                    if not url:
                        continue
                    self.download_fetch(url, wrapper)
                    expected_name = Path(remote_path).name.lower()
                    with zipfile.ZipFile(wrapper, 'r') as zf:
                        zf.setpassword(password.encode())
                        members = zf.namelist()
                        member = next((m for m in members if Path(m).name.lower() == expected_name), None)
                        if not member:
                            raise RuntimeError(f'SentinelOne fetch archive did not contain {expected_name}: {members}')
                        with zf.open(member, 'r') as src, destination.open('wb') as dst:
                            shutil.copyfileobj(src, dst, length=1024*1024)
                    return item
                time.sleep(5)
            raise TimeoutError('SentinelOne file fetch timed out waiting for the archive download URL.')
        finally:
            wrapper.unlink(missing_ok=True)


class TenableProvider(ProviderBase):
    name = 'tenable'
    label = 'Tenable'

    def __init__(self):
        self.base_url = os.getenv('TENABLE_BASE_URL', 'https://cloud.tenable.com').rstrip('/')
        self.access_key = os.getenv('TENABLE_ACCESS_KEY', '')
        self.secret_key = os.getenv('TENABLE_SECRET_KEY', '')
        self.timeout = int(os.getenv('TENABLE_HTTP_TIMEOUT', '60'))
        self.max_assets = int(os.getenv('TENABLE_ASSET_LIST_LIMIT', '5000'))

    def configured(self):
        return bool(self.base_url and self.access_key and self.secret_key)

    def _request(self, method, path, **kwargs):
        import requests
        url = self.base_url + (path if path.startswith('/') else '/' + path)
        headers = kwargs.pop('headers', {})
        headers['X-ApiKeys'] = f'accessKey={self.access_key}; secretKey={self.secret_key}'
        headers.setdefault('Accept', 'application/json')
        headers.setdefault('Content-Type', 'application/json')
        return requests.request(method, url, headers=headers, timeout=self.timeout, **kwargs)

    def connectivity(self):
        if not self.configured():
            return {'connected': False, 'detail': 'API keys/base URL not configured'}
        try:
            resp = self._request('GET', '/assets')
            resp.raise_for_status()
            return {'connected': True, 'detail': 'Tenable Vulnerability Management API reachable'}
        except Exception as exc:
            return {'connected': False, 'detail': str(exc)[:180]}

    @staticmethod
    def _as_list(value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _normalize_asset(self, item):
        network = item.get('network') or {}
        scan = item.get('scan') or {}
        timestamps = item.get('timestamps') or {}
        hostnames = self._as_list(item.get('hostname') or item.get('hostnames') or item.get('netbios_name') or network.get('hostname') or network.get('hostnames'))
        fqdns = self._as_list(item.get('fqdn') or item.get('fqdns') or network.get('fqdn') or network.get('fqdns'))
        ipv4s = self._as_list(item.get('ipv4') or item.get('ipv4_addresses') or network.get('ipv4s') or network.get('ipv4'))
        macs = self._as_list(item.get('mac_address') or item.get('mac_addresses') or network.get('mac_addresses') or network.get('macs'))
        os_name = item.get('operating_system') or item.get('os') or item.get('operatingSystem')
        label = next((str(x) for x in hostnames + fqdns if x), str(item.get('id') or item.get('uuid') or ''))
        return {
            'device_id': str(item.get('id') or item.get('uuid') or item.get('tenable_uuid') or ''),
            'tenable_id': str(item.get('id') or item.get('uuid') or item.get('tenable_uuid') or ''),
            'hostname': label,
            'hostnames': [str(x) for x in hostnames if x],
            'fqdns': [str(x) for x in fqdns if x],
            'platform': str(os_name or 'unknown'),
            'os_family': normalize_platform(os_name),
            'local_ip': next((str(x) for x in ipv4s if x), None),
            'ipv4s': [str(x) for x in ipv4s if x],
            'macs': [str(x).lower() for x in macs if x],
            'status': 'active' if not item.get('deleted_at') and not item.get('terminated_at') else 'inactive',
            'source_last_seen': item.get('last_seen') or scan.get('last_scan_time') or timestamps.get('updated_at'),
        }

    def _filter_query(self, rows, query):
        q = str(query or '').lower().strip()
        if not q:
            return rows
        out=[]
        for row in rows:
            searchable=' '.join([row.get('hostname',''), *row.get('hostnames',[]), *row.get('fqdns',[]), *row.get('ipv4s',[]), *row.get('macs',[]), row.get('platform','')]).lower()
            if q in searchable:
                out.append(row)
        return out

    def _export_assets(self):
        resp=self._request('POST','/assets/v2/export',json={'chunk_size':5000,'filters':{'types':['host']}})
        resp.raise_for_status()
        body=resp.json()
        export_uuid=body.get('export_uuid') or body.get('exportId') or body.get('id')
        if not export_uuid:
            raise RuntimeError(f'Tenable asset export did not return an export UUID: {body}')
        deadline=time.time()+180
        status_body={}
        chunks=[]
        while time.time()<deadline:
            status_resp=self._request('GET',f'/assets/export/{export_uuid}/status')
            status_resp.raise_for_status()
            status_body=status_resp.json()
            state=str(status_body.get('status') or status_body.get('state') or '').lower()
            raw_chunks=status_body.get('chunks') or status_body.get('completed_chunks') or status_body.get('available_chunks') or []
            if isinstance(raw_chunks,dict): raw_chunks=list(raw_chunks.values())
            chunks=[]
            for c in raw_chunks:
                cid=c.get('id') if isinstance(c,dict) else c
                if isinstance(c,dict) and cid is None: cid=c.get('chunk_id')
                try: chunks.append(int(cid))
                except (TypeError,ValueError): pass
            if state in {'finished','completed','complete','ready'} and chunks:
                break
            if state in {'error','failed','canceled','cancelled'}:
                raise RuntimeError(f'Tenable asset export failed: {status_body}')
            time.sleep(2)
        if not chunks:
            raise TimeoutError(f'Tenable asset export did not finish within 180 seconds: {status_body}')
        rows=[]
        for cid in sorted(set(chunks)):
            chunk=self._request('GET',f'/assets/export/{export_uuid}/chunks/{cid}')
            chunk.raise_for_status()
            body=chunk.json()
            items=body.get('assets') or body.get('data') or body.get('items') or []
            if isinstance(items,dict): items=items.get('assets') or items.get('items') or []
            rows.extend(items)
        return rows



    _tracker_cache = {'debian': (0, None), 'ubuntu': {}}

    @staticmethod
    def _dpkg_compare(a, b):
        import re
        def split(v):
            v=str(v or '').strip(); epoch=0
            m=re.match(r'^(\d+):(.*)$',v)
            if m: epoch=int(m.group(1)); v=m.group(2)
            i=v.rfind('-')
            return epoch, (v[:i] if i>=0 else v), (v[i+1:] if i>=0 else '')
        def ordc(c):
            if c=='~': return -1
            if c=='': return 0
            if c.isalpha(): return ord(c)
            return ord(c)+256
        def cmp_part(x,y):
            i=j=0
            while i<len(x) or j<len(y):
                xa=''; ya=''
                while i<len(x) and not x[i].isdigit(): xa+=x[i]; i+=1
                while j<len(y) and not y[j].isdigit(): ya+=y[j]; j+=1
                for k in range(max(len(xa),len(ya))):
                    ox=ordc(xa[k] if k<len(xa) else ''); oy=ordc(ya[k] if k<len(ya) else '')
                    if ox!=oy: return -1 if ox<oy else 1
                xd=''; yd=''
                while i<len(x) and x[i].isdigit(): xd+=x[i]; i+=1
                while j<len(y) and y[j].isdigit(): yd+=y[j]; j+=1
                nx=int(xd or '0'); ny=int(yd or '0')
                if nx!=ny: return -1 if nx<ny else 1
            return 0
        ae,au,ar=split(a); be,bu,br=split(b)
        if ae!=be: return -1 if ae<be else 1
        return cmp_part(au,bu) or cmp_part(ar,br)

    @staticmethod
    def _deb_sec(v):
        import re
        m=re.search(r'[+~-]deb(\d+)u(\d+)',str(v or ''),re.I)
        if m: return int(m.group(1)), int(m.group(2))
        m=re.search(r'[+~-]deb(\d+)\b',str(v or ''),re.I)
        return (int(m.group(1)),0) if m else None

    @classmethod
    def _deb_verdict_compare(cls, installed, fixed):
        if not installed or not fixed: return None
        iv=str(installed).lstrip('0123456789:') if str(installed).startswith(tuple(f'{i}:' for i in range(10))) else str(installed)
        fv=str(fixed).lstrip('0123456789:') if str(fixed).startswith(tuple(f'{i}:' for i in range(10))) else str(fixed)
        if iv == fv or fv in iv: return 1
        si,sf=cls._deb_sec(iv),cls._deb_sec(fv)
        if si and sf and si[0]==sf[0]:
            if si[1]!=sf[1]: return -1 if si[1]<sf[1] else 1
            return 0
        return cls._dpkg_compare(iv,fv)

    @staticmethod
    def _parse_packages(output):
        import re
        if not output: return []
        inst=re.findall(r'(?:remote package installed|installed package|installed version)\s*:\s*(\S+)',str(output),re.I)
        fix=re.findall(r'(?:should be|fixed package|fixed version|remote fixed version)\s*:\s*(\S+)',str(output),re.I)
        out=[]
        for i in range(min(len(inst),len(fix))):
            a,b=inst[i],fix[i]
            pn,iv=(a.split('_',1)+[''])[:2] if '_' in a else ('',a)
            pn2,fv=(b.split('_',1)+[''])[:2] if '_' in b else ('',b)
            out.append({'pkg':pn or pn2 or 'package','installed':iv,'fixed':fv})
        return out

    @staticmethod
    def _debian_release(os_name):
        import re
        m=re.search(r'debian[^\d]*(\d+)',str(os_name or ''),re.I)
        return {14:'forky',13:'trixie',12:'bookworm',11:'bullseye',10:'buster',9:'stretch',8:'jessie'}.get(int(m.group(1))) if m else None

    @staticmethod
    def _ubuntu_release(os_name):
        import re
        m=re.search(r'ubuntu[^\d]*(\d\d\.\d\d)',str(os_name or ''),re.I)
        return {'14.04':'trusty','16.04':'xenial','18.04':'bionic','20.04':'focal','22.04':'jammy','24.04':'noble','24.10':'oracular','25.04':'plucky','25.10':'questing'}.get(m.group(1)) if m else None

    def _debian_index(self):
        import time, requests
        ts,data=self._tracker_cache['debian']
        ttl=12*3600
        if data is not None and time.time()-ts<ttl: return data
        resp=requests.get('https://security-tracker.debian.org/tracker/data/json',timeout=60,headers={'Accept':'application/json','User-Agent':'USC-Office-of-Cybersecurity-Vulnerability-Management/1.0'})
        resp.raise_for_status(); raw=resp.json(); idx={}
        for pkg,cves in (raw or {}).items():
            if not isinstance(cves,dict): continue
            for cve,info in cves.items():
                rels=(info or {}).get('releases') or {}
                for rel,ri in rels.items():
                    idx.setdefault(cve,{}).setdefault(pkg,{})[rel]={'status':(ri or {}).get('status'),'fixed_version':(ri or {}).get('fixed_version')}
        self._tracker_cache['debian']=(time.time(),idx); return idx

    def _ubuntu_cve(self,cve):
        import time, requests
        cache=self._tracker_cache.setdefault('ubuntu',{})
        hit=cache.get(cve)
        if hit and time.time()-hit[0]<12*3600: return hit[1]
        resp=requests.get(f'https://ubuntu.com/security/cves/{cve}.json',timeout=30,headers={'Accept':'application/json','User-Agent':'USC-Office-of-Cybersecurity-Vulnerability-Management/1.0'})
        if resp.status_code==404:
            data={}
        else:
            resp.raise_for_status(); data=resp.json()
        pkgs={}
        for pkg in data.get('packages',[]) or []:
            name=pkg.get('name'); rel={}
            for st in pkg.get('statuses',[]) or []:
                code=st.get('release_codename') or st.get('release'); status=st.get('status'); desc=st.get('description') or ''
                if not code: continue
                if status=='released': rel[code]={'status':'resolved','fixed_version':desc or None}
                elif status in ('needed','pending','deferred','needs-triage'): rel[code]={'status':'open','fixed_version':None}
                elif status in ('not-affected','DNE','ignored'): rel[code]={'status':'resolved','fixed_version':None}
            if rel: pkgs[name]=rel
        cache[cve]=(time.time(),pkgs); return pkgs


    @staticmethod
    def _rpm_release(os_name, distro):
        import re
        s=str(os_name or '').lower()
        if distro=='rhel':
            m=re.search(r'(?:red hat enterprise linux|rhel)[^0-9]*(\d+)',s)
        elif distro=='almalinux':
            m=re.search(r'alma(?:linux)?[^0-9]*(\d+)',s)
        else:
            m=re.search(r'oracle linux[^0-9]*(\d+)',s)
        return m.group(1) if m else None

    def _redhat_cve(self,cve):
        import requests
        resp=requests.get(f'https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json',
                          timeout=30,headers={'Accept':'application/json','User-Agent':'USC-Office-of-Cybersecurity-Vulnerability-Management/1.0'})
        if resp.status_code==404: return {}
        resp.raise_for_status(); return resp.json() or {}

    def _alma_errata(self,major):
        import requests,time
        cache=self._tracker_cache.setdefault('almalinux',{})
        hit=cache.get(major)
        if hit and time.time()-hit[0]<12*3600:return hit[1]
        url=f'https://errata.almalinux.org/{major}/errata.full.json'
        resp=requests.get(url,timeout=60,headers={'Accept':'application/json','User-Agent':'USC-Office-of-Cybersecurity-Vulnerability-Management/1.0'})
        resp.raise_for_status();data=resp.json()
        cache[major]=(time.time(),data);return data

    def _oracle_oval(self,major):
        # Oracle's official OVAL is authoritative, but parsing package tests safely is
        # intentionally conservative: if package/version evidence cannot be tied to the
        # finding, the caller returns needs-data rather than guessing.
        import requests,time,bz2
        cache=self._tracker_cache.setdefault('oraclelinux',{})
        hit=cache.get(major)
        if hit and time.time()-hit[0]<12*3600:return hit[1]
        urls=[
          f'https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2',
          f'https://linux.oracle.com/security/oval/com.oracle.elsa-{major}.xml.bz2'
        ]
        last=None
        for url in urls:
            try:
                r=requests.get(url,timeout=90,headers={'User-Agent':'USC-Office-of-Cybersecurity-Vulnerability-Management/1.0'})
                r.raise_for_status();raw=bz2.decompress(r.content).decode('utf-8','replace');cache[major]=(time.time(),raw);return raw
            except Exception as exc:last=exc
        raise last or RuntimeError('Oracle Linux OVAL unavailable')

    def _validate_rpm_vendor(self,r,distro):
        import re
        cves=[str(c) for c in (r.get('cve') or []) if str(c).startswith('CVE-')]
        major=self._rpm_release(r.get('operating_system') or r.get('os'),distro)
        output=str(r.get('output') or '')
        if not cves or not major:
            return {'host':r.get('host'),'plugin_id':r.get('plugin_id'),'plugin_name':r.get('plugin_name'),'distro':distro,'overall':'needs-data','results':[]}
        results=[]
        if distro=='rhel':
            for cve in cves:
                data=self._redhat_cve(cve)
                # Red Hat exposes affected/released package states, but we do not assert
                # fixed/vulnerable unless the Tenable output supplies a package/version
                # that can be tied to the vendor data.
                affected=data.get('affected_release') or []
                matching=[x for x in affected if f'Red Hat Enterprise Linux {major}' in str(x.get('product_name') or '')]
                if not matching:
                    results.append({'cve':cve,'verdict':'not-affected'})
                elif not output:
                    results.append({'cve':cve,'verdict':'needs-package-data'})
                else:
                    # A released RHSA proves a vendor fix exists, but without reliable
                    # RPM NEVRA extraction/comparison we deliberately do not guess host state.
                    results.append({'cve':cve,'verdict':'needs-package-data','advisories':[x.get('advisory') for x in matching if x.get('advisory')]})
        elif distro=='almalinux':
            data=self._alma_errata(major)
            advisories=data.get('data') if isinstance(data,dict) else data
            advisories=advisories or []
            for cve in cves:
                hits=[]
                for adv in advisories:
                    refs=adv.get('references') or adv.get('cves') or []
                    if cve in str(refs): hits.append(adv)
                if not hits: results.append({'cve':cve,'verdict':'not-tracked'})
                elif not output: results.append({'cve':cve,'verdict':'needs-package-data'})
                else: results.append({'cve':cve,'verdict':'needs-package-data','advisories':[x.get('id') or x.get('updateinfo_id') for x in hits]})
        else:
            oval=self._oracle_oval(major)
            for cve in cves:
                if cve not in oval: results.append({'cve':cve,'verdict':'not-tracked'})
                elif not output: results.append({'cve':cve,'verdict':'needs-package-data'})
                else: results.append({'cve':cve,'verdict':'needs-package-data'})
        # Strict confidence policy: only vendor-explicit not-affected is decisive here.
        overall='not-affected' if results and all(x['verdict']=='not-affected' for x in results) else 'needs-data'
        return {'host':r.get('host'),'plugin_id':r.get('plugin_id'),'plugin_name':r.get('plugin_name'),'distro':distro,'overall':overall,'results':results}

    def linux_validate(self, rows, distro):
        distro=str(distro or '').lower(); out=[]
        if distro not in ('debian','ubuntu','rhel','almalinux','oraclelinux'): return out
        if distro in ('rhel','almalinux','oraclelinux'):
            return [self._validate_rpm_vendor(r,distro) for r in rows]
        for r in rows:
            cves=[c for c in (r.get('cve') or []) if str(c).startswith('CVE-')]
            os_name=r.get('operating_system') or r.get('os') or ''
            output=r.get('output') or ''
            installeds=self._parse_packages(output)
            results=[]; any_vuln=False; any_open=False; resolved=0
            if distro=='debian':
                idx=self._debian_index(); release=self._debian_release(os_name)
                for cve in cves:
                    pkgs=idx.get(cve)
                    if not pkgs: results.append({'cve':cve,'verdict':'not-tracked'}); continue
                    pkg=next((k for k in pkgs if k.lower() in (str(r.get('plugin_name',''))+' '+str(output)).lower()), next(iter(pkgs)))
                    ri=(pkgs.get(pkg) or {}).get(release) if release else None
                    if not ri: results.append({'cve':cve,'pkg':pkg,'verdict':'needs-data','note':release or 'unknown Debian release'}); continue
                    if ri.get('status')=='resolved':
                        fixed=ri.get('fixed_version'); pair=installeds[0] if installeds else None
                        if fixed and pair:
                            cmpv=self._deb_verdict_compare(pair['installed'],fixed)
                            if cmpv is not None and cmpv<0: any_vuln=True; verdict='vulnerable'
                            else: resolved+=1; verdict='fixed'
                            results.append({'cve':cve,'pkg':pkg,'fixed':fixed,'installed':pair['installed'],'verdict':verdict})
                        elif not fixed: resolved+=1; results.append({'cve':cve,'pkg':pkg,'verdict':'not-affected'})
                        else: results.append({'cve':cve,'pkg':pkg,'fixed':fixed,'verdict':'needs-package-data'})
                    else:
                        any_open=True; results.append({'cve':cve,'pkg':pkg,'verdict':'open'})
            else:
                release=self._ubuntu_release(os_name)
                for cve in cves:
                    pkgs=self._ubuntu_cve(cve); pkg=next(iter(pkgs),None); ri=(pkgs.get(pkg) or {}).get(release) if pkg and release else None
                    if not ri: results.append({'cve':cve,'verdict':'needs-data'}); continue
                    if ri.get('status')=='resolved': resolved+=1; results.append({'cve':cve,'pkg':pkg,'fixed':ri.get('fixed_version'),'verdict':'fixed'})
                    else: any_open=True; results.append({'cve':cve,'pkg':pkg,'verdict':'open'})
            overall='vulnerable' if any_vuln else ('open' if any_open else ('fixed' if resolved and resolved==len(cves) else 'needs-data'))
            out.append({'host':r.get('host'),'plugin_id':r.get('plugin_id'),'plugin_name':r.get('plugin_name'),'distro':distro,'overall':overall,'results':results})
        return out

    def list_vulnerabilities(self, since_days=None, severities=None):
        if not self.configured():
            return []
        import datetime as _dt
        filters = {
            'severity': [str(x).upper() for x in (severities or ['LOW','MEDIUM','HIGH','CRITICAL'])],
            'state': ['OPEN','REOPENED'],
        }
        if since_days is not None:
            cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=int(since_days))
            filters['since'] = int(cutoff.timestamp())
        body = {
            'num_assets': 5000,
            'include_unlicensed': False,
            'include_plugin_output': True,
            'filters': filters,
        }
        resp=self._request('POST','/vulns/export',json=body)
        resp.raise_for_status()
        export_uuid=(resp.json() or {}).get('export_uuid')
        if not export_uuid:
            raise RuntimeError('Tenable vulnerability export did not return export_uuid.')
        deadline=time.time()+int(os.getenv('TENABLE_VULN_EXPORT_TIMEOUT_SECONDS','1800'))
        downloaded=set(); records=[]
        while time.time()<deadline:
            status_resp=self._request('GET',f'/vulns/export/{export_uuid}/status')
            status_resp.raise_for_status()
            body=status_resp.json() or {}
            state=str(body.get('status') or '').upper()
            available=set(body.get('chunks_available') or [])
            for cid in sorted(available-downloaded):
                chunk=self._request('GET',f'/vulns/export/{export_uuid}/chunks/{cid}')
                chunk.raise_for_status()
                data=chunk.json()
                if isinstance(data,list):
                    records.extend(data)
                elif isinstance(data,dict):
                    records.extend(data.get('vulnerabilities') or data.get('data') or data.get('items') or [])
                downloaded.add(cid)
            if state=='FINISHED' and available.issubset(downloaded):
                return records
            if state in ('ERROR','CANCELLED','CANCELED'):
                raise RuntimeError(f'Tenable vulnerability export ended with status {state}.')
            time.sleep(3)
        raise TimeoutError('Tenable vulnerability export did not finish within 30 minutes.')

    @staticmethod
    def normalize_vulnerability(v):
        asset=v.get('asset') or {}
        plugin=v.get('plugin') or {}
        vpr=plugin.get('vpr') or {}
        os_value=asset.get('operating_system')
        if isinstance(os_value,list):
            os_value=os_value[0] if os_value else None
        return {
            'host': asset.get('hostname') or asset.get('fqdn') or asset.get('ipv4') or asset.get('uuid') or 'Unknown',
            'ipv4': asset.get('ipv4'),
            'asset_uuid': asset.get('uuid'),
            'operating_system': os_value,
            'plugin_id': plugin.get('id'),
            'plugin_name': plugin.get('name') or 'Unknown vulnerability',
            'family': plugin.get('family'),
            'cve': plugin.get('cve') or [],
            'severity': str(v.get('severity') or 'info').lower(),
            'cvss3': plugin.get('cvss3_base_score'),
            'vpr': vpr.get('score') if isinstance(vpr,dict) else None,
            'state': str(v.get('state') or 'OPEN').lower(),
            'first_found': v.get('first_found'),
            'last_found': v.get('last_found'),
            'patch_published': plugin.get('patch_publication_date'),
            'plugin_published': plugin.get('publication_date'),
            'has_patch': plugin.get('has_patch'),
            'output': v.get('output'),
        }

    def list_hosts(self, query=''):
        if not self.configured():
            return []
        try:
            raw=self._export_assets()
        except Exception:
            resp=self._request('GET','/assets')
            resp.raise_for_status()
            body=resp.json()
            raw=body.get('assets',body.get('data',[])) if isinstance(body,dict) else []
        rows=[self._normalize_asset(item) for item in raw]
        return self._filter_query(rows,query)
