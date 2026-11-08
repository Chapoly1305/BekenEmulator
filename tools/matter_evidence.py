"""Evidence extraction, failing closed on incomplete/mismatched responses."""
import re,struct,json
from pathlib import Path

def tlv(data):
 p=0
 def take(n):
  nonlocal p
  if p+n>len(data):raise ValueError('truncated TLV')
  v=data[p:p+n];p+=n;return v
 def item(depth=0):
  if depth>8:raise ValueError('deep TLV')
  c=take(1)[0];typ=c&31;tc=c>>5
  if tc not in (0,1):raise ValueError('unsupported tag control')
  tag=take(1)[0] if tc else None
  if typ==24:return tag,None,True
  if 0<=typ<=7:return tag,int.from_bytes(take(1<<(typ&3)),'little',signed=typ<4),False
  if typ in (8,9):return tag,typ==9,False
  if 12<=typ<=19:
   n=int.from_bytes(take(1<<(typ&3)),'little');return tag,take(n),False
  if typ in (21,22,23):
   values={}
   while True:
    k,v,end=item(depth+1)
    if end:break
    if k in values:raise ValueError('duplicate TLV tag')
    values[k]=v
   return tag,values,False
  raise ValueError('unsupported TLV element')
 tag,value,end=item()
 if tag is not None or end or p!=len(data):raise ValueError('invalid root TLV')
 return value

def session_versions(emulator_log):
 versions=[];buf=None;expected=0
 for hx in re.findall(r'\[MATTER_BRIDGE\] C2 \d+ bytes: ([0-9a-f]+)',emulator_log):
  b=bytes.fromhex(hx)
  if len(b)<2 or b[:2]==b'el':continue
  flags=b[0]
  if not flags&7:continue
  p=2+bool(flags&8) # flags, optional ack, sequence
  if flags&1:
   if p+2>len(b):raise ValueError('truncated BTP start')
   expected=int.from_bytes(b[p:p+2],'little');p+=2;buf=bytearray()
  if buf is None:raise ValueError('orphan BTP fragment')
  buf+=b[p:]
  if not flags&4:continue
  msg=bytes(buf);buf=None
  if len(msg)!=expected:raise ValueError('BTP length mismatch')
  if len(msg)<14:continue
  # Message header: flags/session/security/counter, optional node ids.
  if msg[0]>>4 or int.from_bytes(msg[1:3],'little') or msg[3]:continue
  p=8+(8 if msg[0]&4 else 0)+({0:0,1:8,2:2}.get(msg[0]&3,999))
  if p+6>len(msg):continue
  ex,opcode=msg[p:p+2];p+=4
  if ex&0x10:p+=2 # vendor id before protocol id
  if p+2>len(msg):continue
  proto=int.from_bytes(msg[p:p+2],'little');p+=2
  if ex&2:p+=4 # acknowledged message counter
  if proto!=0 or opcode!=0x21:continue
  root=tlv(msg[p:]);params=root.get(5,{})
  if 6 in params:versions.append({'value':params[6],'hex':f'0x{params[6]:08x}','source':'PBKDFParamResponse.SessionParameters.SpecificationVersion','session_parameters':params,'message_hex':msg.hex()})
 return versions

def read_results(log):
 log=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',log).replace('\r','')
 blocks=re.split(r'Command: ',log);result={}
 for name,attr,label in [('specification-version',21,'SpecificationVersion'),('software-version',9,'SoftwareVersion'),('cluster-revision',65533,'ClusterRevision')]:
  rows=[]
  for b in blocks:
   if not b.startswith(f'basicinformation read {name} 1 0 '):continue
   # Validate the received report's path, not merely the outgoing request.
   report=b.split('ReportDataMessage =',1)
   if len(report)!=2:continue
   report=report[1]
   paths=re.findall(r'AttributePathIB =.*?Endpoint = (0x[0-9a-fA-F_]+),.*?Cluster = (0x[0-9a-fA-F_]+),.*?Attribute = (0x[0-9a-fA-F_]+),',report,re.S)
   if len(paths)!=1 or tuple(int(x.replace('_',''),16) for x in paths[0])!=(0,40,attr):continue
   if re.search(r'status = 0x86 \(UNSUPPORTED_ATTRIBUTE\)',report):rows.append({'status':'UNSUPPORTED_ATTRIBUTE'})
   else:
    v=re.search(r'\b'+label+r': (\d+)\b',report)
    if v:rows.append({'status':'SUCCESS','value':int(v[1])})
  result[name]=rows[0] if len(rows)==1 else {'status':'UNRESOLVED','matching_reports':len(rows)}
 return result

def summarize(directory):
 e=(directory/'emulator.log').read_text(errors='replace');c=(directory/'chip-tool.log').read_text(errors='replace')
 return {'pase':'PASE establishment successful' in c,'full_commissioning':False,'attributes':read_results(c),'session_versions':session_versions(e),'boundary':'SDK GATT bridge; synthetic factory credentials; unmodified application'}
if __name__=='__main__':
 import sys
 print(json.dumps(summarize(Path(sys.argv[1])),indent=2))
