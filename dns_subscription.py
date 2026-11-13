"""Public DNS subscriptions; source updates never change system DNS."""
import json, ipaddress, os, time, urllib.request, re, tempfile
from pathlib import Path
INTERVAL=86400
CACHE=Path(os.environ.get('LOCALAPPDATA',str(Path.home()))) / 'DNSSwitcher' / 'subscription.json'
SOURCES={
 'VindEi':('json',('https://raw.githubusercontent.com/VindEi/public-dns-directory/data/index.json','https://cdn.jsdelivr.net/gh/VindEi/public-dns-directory@data/index.json')),
 'AdGuard':('markdown',('https://raw.githubusercontent.com/AdguardTeam/KnowledgeBaseDNS/master/docs/general/dns-providers.md','https://cdn.jsdelivr.net/gh/AdguardTeam/KnowledgeBaseDNS@master/docs/general/dns-providers.md')),
 'Public DNS Servers':('simple',('https://raw.githubusercontent.com/denizsnet/public-dns-servers/main/dns-servers.json','https://cdn.jsdelivr.net/gh/denizsnet/public-dns-servers@main/dns-servers.json'))}
LAST_REPORT=''
def address(v):
 try:
  ip=ipaddress.IPv4Address(v)
  return str(ip) if ip.is_global else ''
 except (ValueError,TypeError):return ''
def parse(kind,payload):
 out=[]
 def add(name,a,b=''):
  a=address(a); b=address(b) if b else ''
  if a: out.append((str(name)[:180],a,b))
 if kind=='json':
  if not isinstance(payload,dict) or not isinstance(payload.get('providers'),list): raise ValueError('目录格式无效')
  for p in payload['providers']:
   if not isinstance(p,dict): continue
   for profile in p.get('profiles',[]):
    if not isinstance(profile,dict): continue
    e=profile.get('endpoints') or {}
    if isinstance(e,dict): add('[订阅] '+str(p.get('name',''))+' · '+str(profile.get('name','')),e.get('primaryDns'),e.get('secondaryDns'))
 elif kind=='simple':
  if not isinstance(payload,dict) or not isinstance(payload.get('servers'),list): raise ValueError('目录格式无效')
  for item in payload['servers']:
   if not isinstance(item,dict): continue
   ips=item.get('ipv4') or []
   if isinstance(ips,list) and ips: add('[订阅] '+str(item.get('provider',''))+' · '+str(item.get('variant','')),ips[0],ips[1] if len(ips)>1 else '')
 else:
  if not isinstance(payload,str): raise ValueError('目录格式无效')
  provider=''; variant=''
  for line in payload.splitlines():
   if line.startswith('### '): provider=line[4:].strip(); variant=''
   elif line.startswith('#### '): variant=line[5:].strip()
   elif provider and re.match(r'^\|\s*DNS, IPv4\s*\|',line):
    field=line.split('|')[2]; ips=re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',field)
    if ips: add('[订阅] '+provider+' · '+variant,ips[0],ips[1] if len(ips)>1 else '')
 if not out: raise ValueError('没有可用的公开 IPv4 地址')
 return out

def read_cache():
 try:
  data=json.loads(CACHE.read_text(encoding='utf8'))
  if 'payload' in data:return {'VindEi':{'payload':data['payload'],'checked_at':data['checked_at']}}
  return data.get('sources',{}) if isinstance(data,dict) else {}
 except (OSError,ValueError,TypeError):return {}
def collect(cache):
 rows=[]; stamps=[]
 for name,(kind,_) in SOURCES.items():
  try:
   entry=cache[name]; rows.extend(parse(kind,entry['payload'])); stamps.append(float(entry['checked_at']))
  except (ValueError,TypeError,KeyError): continue
 return rows,min(stamps) if len(stamps)==len(SOURCES) else 0

def load():return collect(read_cache())
def update():
 global LAST_REPORT
 cache=read_cache(); success=[]; failures=[]
 for name,(kind,urls) in SOURCES.items():
  errors=[]
  for url in urls:
   try:
    req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 DNS-Switcher/1.2'})
    with urllib.request.urlopen(req,timeout=10) as resp: raw=resp.read(2000001)
    if len(raw)>2000000: raise ValueError('数据过大')
    text=raw.decode('utf-8-sig'); payload=text if kind=='markdown' else json.loads(text)
    parse(kind,payload); cache[name]={'payload':payload,'checked_at':time.time()};success.append(name);break
   except Exception as e:errors.append(url.split('/')[2]+': '+str(e))
  else: failures.append(name+': '+', '.join(errors))
 if not success: raise RuntimeError('全部订阅源更新失败：\n'+'\n'.join(failures))
 CACHE.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.NamedTemporaryFile('w',encoding='utf8',dir=CACHE.parent,delete=False) as f:
  temp=f.name;json.dump({'sources':cache},f,ensure_ascii=False)
 try:os.replace(temp,CACHE)
 finally:
  if os.path.exists(temp):os.unlink(temp)
 LAST_REPORT='成功 '+str(len(success))+'/'+str(len(SOURCES))+' 源'+('；失败源使用缓存' if failures else '')
 rows,stamp=collect(cache)
 return rows,stamp

