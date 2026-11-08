#!/usr/bin/env python3
"""Build an explicitly synthetic BK7231N test flash from the retained ELF.
No application bytes are edited. This is not a device backup.
SPAKE2+ derivation follows connectedhomeip/scripts/tools/spake2p/spake2p.py.
The factory container layout is verified against this executable's flash reader.
"""
import argparse,base64,hashlib,json,struct
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from elftools.elf.elffile import ELFFile
EXPECTED='5118823ef2e57d35e4c3128095d9fd0a6c457824057d08b289e595513b2a5a09'

def build(elf,output):
 raw=elf.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED,'unsupported executable'
 with elf.open('rb') as f:
  segments=[s for s in ELFFile(f).iter_segments() if s['p_type']=='PT_LOAD']
  assert len(segments)==1
  s=segments[0];assert s['p_vaddr']==0x10000
  app=s.data()
 flash=bytearray(b'\xff'*0x200000);flash[0x10000:0x10000+len(app)]=app
 flash[:64]=app[:64] # explicitly synthetic exception-vector routing
 pin=20202021;disc=3840;iterations=1000;salt=b'MatterEmulator01'
 order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
 ws=hashlib.pbkdf2_hmac('sha256',struct.pack('<I',pin),salt,iterations,80)
 w0=int.from_bytes(ws[:40],'big')%order;w1=int.from_bytes(ws[40:],'big')%order
 L=ec.derive_private_key(w1,ec.SECP256R1()).public_key().public_bytes(Encoding.X962,PublicFormat.UncompressedPoint)
 verifier=w0.to_bytes(32,'big')+L
 # Header: magic, header byte count, 17 offset/length pairs. Offsets relative to end of header.
 fields=[struct.pack('<H',disc),struct.pack('<I',iterations),base64.b64encode(salt),base64.b64encode(verifier),struct.pack('<I',pin),b'MatterEmulator\0',struct.pack('<H',0xfff1),b'Test fixture\0',struct.pack('<H',0x8000),b'EMU0001\0']
 header=bytearray(0x90);struct.pack_into('<II',header,0,0xf5f50001,len(header));data=bytearray()
 for i,value in enumerate(fields):struct.pack_into('<II',header,8+i*8,len(data),len(value));data+=value
 factory=header+data;flash[0x1fe000:0x1fe000+len(factory)]=factory
 assert bytes(flash[0x10000:0x10000+len(app)])==app
 output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(flash)
 manifest={'kind':'synthetic test provisioning, NOT original factory data','elf_sha256':EXPECTED,'application_sha256':hashlib.sha256(app).hexdigest(),'flash_sha256':hashlib.sha256(flash).hexdigest(),'factory_address':'0x1fe000','synthetic_vector_copy':'0x10000..0x1003f to 0..0x3f','passcode':pin,'discriminator':disc,'iteration_count':iterations,'salt_base64':base64.b64encode(salt).decode(),'verifier_base64':base64.b64encode(verifier).decode(),'factory_schema_evidence':'getter 0x35838, partition 0xa at 0x1fd000 plus 0x1000; 0x90 byte header','limitations':['No original bootloader','No attestation certificates/private key','No original calibration or factory identity','No version/revision fields supplied']}
 output.with_suffix('.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(output)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('output',type=Path);a=p.parse_args();build(a.elf,a.output)
