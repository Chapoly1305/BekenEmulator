#!/usr/bin/env python3
"""Drive the Silicon Labs host transport against the hash-pinned Beken bridge."""
import argparse,os,subprocess,time,json,uuid,hashlib
from pathlib import Path
from matter_evidence import summarize
DATASET='0e080000000000010000000300000f35060004001fffe0020811111111222222220708fd61f77bd3df233e051000112233445566778899aabbccddeeff030e4f70656e54687265616444656d6f010212340410445f2b5ca6f2a93a55ce570a70efeecb0c0402a0fff8'
def main():
 p=argparse.ArgumentParser();p.add_argument('flash',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--chip-dir',type=Path,required=True);p.add_argument('--port',type=int,default=3511);p.add_argument('--passcode',type=int,default=20202021);p.add_argument('--host-image',default='local/renode-host-tools:26q3');a=p.parse_args()
 if a.output.exists() and any(a.output.iterdir()):raise FileExistsError('use a new output directory to retain prior evidence')
 a.output.mkdir(parents=True,exist_ok=True)
 root=Path(__file__).resolve().parents[1];env=dict(os.environ,BEKEN_MATTER_BRIDGE_PORT=str(a.port))
 suffix=uuid.uuid4().hex[:10];en='beken-matter-'+suffix;cn='beken-chip-'+suffix
 el=a.output/'emulator.log';cl=a.output/'chip-tool.log';es=el.open('w');cs=cl.open('w');chip=None
 provenance={'flash_sha256':hashlib.sha256(a.flash.read_bytes()).hexdigest(),'emulator_sha256':hashlib.sha256((root/'bekensim').read_bytes()).hexdigest(),'chip_tool_sha256':hashlib.sha256((a.chip_dir/'chip-tool').read_bytes()).hexdigest(),'host_image':a.host_image,'client_passcode':a.passcode,'port':a.port}
 (a.output/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
 emu=subprocess.Popen(['docker','run','--rm','--name',en,'--network','host','-e',f'BEKEN_MATTER_BRIDGE_PORT={a.port}','--entrypoint','/emu/bekensim','-v',f'{root}:/emu:ro','-v',f'{a.flash.resolve()}:/fixture.bin:ro',a.host_image,'/fixture.bin','--chip','BK7231N','--only-uart'],env=env,stdout=es,stderr=subprocess.STDOUT)
 result={'pase':False,'full_commissioning':False,'reads_completed':False,'emulation_boundary':'SDK GATT callbacks; original BTP/PASE/IM code','factory':'synthetic test configuration'}
 try:
  deadline=time.monotonic()+60
  while time.monotonic()<deadline:
   if 'SDK callback returned' in el.read_text(errors='replace'):break
   if emu.poll() is not None:raise RuntimeError('emulator exited before readiness')
   time.sleep(.2)
  else:raise RuntimeError('firmware readiness timeout')
  chip=subprocess.Popen(['docker','run','--rm','--name',cn,'-i','--network','host','-e',f'CHIP_FAKE_BLE_PORT={a.port}','--entrypoint','/chip/chip-tool','-v',f'{a.chip_dir.resolve()}:/chip:ro',a.host_image,'interactive','start','--trace_decode','1','--storage-directory','/tmp'],stdin=subprocess.PIPE,stdout=cs,stderr=subprocess.STDOUT,text=True)
  chip.stdin.write(f'pairing ble-thread 1 hex:{DATASET} {a.passcode} 3840 --pase-only true --bypass-attestation-verifier true --trace_decode 1 --timeout 60\n');chip.stdin.flush()
  deadline=time.monotonic()+100
  while time.monotonic()<deadline:
   s=cl.read_text(errors='replace')
   if 'PASE establishment successful' in s:result['pase']=True;break
   if 'Secure Pairing Failed' in s or 'Pairing Failure:' in s:break
   if chip.poll() is not None or emu.poll() is not None:break
   time.sleep(.5)
  if result['pase']:
   for at in ['specification-version','software-version','cluster-revision']:
    chip.stdin.write(f'basicinformation read {at} 1 0 --timeout 20\n');chip.stdin.flush();time.sleep(1)
   deadline=time.monotonic()+65
   while time.monotonic()<deadline:
    if 'ClusterRevision:' in cl.read_text(errors='replace'):result['reads_completed']=True;break
    time.sleep(.5)
  if chip.poll() is None:
   chip.stdin.write('quit\n');chip.stdin.flush()
   try:chip.wait(timeout=5)
   except subprocess.TimeoutExpired:chip.terminate()
 except Exception as e:result['error']=str(e)
 finally:
  subprocess.run(['docker','rm','-f',en,cn],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  emu.terminate()
  try:emu.wait(timeout=5)
  except subprocess.TimeoutExpired:emu.kill();emu.wait()
  if chip and chip.poll() is None:chip.terminate()
  es.close();cs.close();
  try:
   evidence=summarize(a.output);(a.output/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
   result['reads_completed']=result['pase'] and all(v['status']!='UNRESOLVED' for v in evidence['attributes'].values())
  except (ValueError,KeyError) as e:
   result['reads_completed']=False;result['evidence_error']=str(e)
  (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
 return 0 if result['pase'] and result['reads_completed'] else 1
if __name__=='__main__':raise SystemExit(main())
