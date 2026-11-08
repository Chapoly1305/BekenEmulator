import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from matter_evidence import session_versions,read_results,tlv
# Recorded unencrypted PBKDFParamResponse, not an expected value supplied to guest code.
FRAME='0d00019a0001000000e061f701e1be7893328aabb5002151ae000015300120b24ad3f19bc7e1f06876edbf9b6841528f8f3c6543ef2f5befb72d2d6b152c2a3002209d111456dc6297f4acae93714e441cdb58263cf7b3612767b8c21ded719feaf32503286035042501e8033002104d6174746572456d756c61746f7230311835052501f40125022c012503a00f24041224050b2606000004012407011818'
def capture(h):return f'[MATTER_BRIDGE] C2 {len(h)//2} bytes: {h}'
class EvidenceTests(unittest.TestCase):
 def test_session(self):self.assertEqual(session_versions(capture(FRAME))[0]['value'],0x01040000)
 def test_wrong_opcode(self):
  b=bytearray.fromhex(FRAME);b[22]=0x23
  self.assertEqual(session_versions(capture(b.hex())),[])
 def test_truncated(self):
  with self.assertRaises(ValueError):session_versions(capture(FRAME[:-2]))
 def test_tlv_truncation(self):
  with self.assertRaises(ValueError):tlv(bytes.fromhex('15260600'))
 def test_duplicate_tags(self):
  with self.assertRaises(ValueError):tlv(bytes.fromhex('1524060124060218'))
 def test_no_response_not_unsupported(self):
  s='Command: basicinformation read specification-version 1 0 --timeout 20\nrequest contains 0x86 UNSUPPORTED_ATTRIBUTE'
  self.assertEqual(read_results(s)['specification-version']['status'],'UNRESOLVED')
 def test_wrong_report_path(self):
  s='Command: basicinformation read cluster-revision 1 0 --timeout 20\nReportDataMessage = AttributePathIB = Endpoint = 0x1, Cluster = 0x28, Attribute = 0xFFFD, ClusterRevision: 1'
  self.assertEqual(read_results(s)['cluster-revision']['status'],'UNRESOLVED')
 def test_read_success(self):
  s='Command: basicinformation read cluster-revision 1 0 --timeout 20\nReportDataMessage = AttributePathIB = Endpoint = 0x0, Cluster = 0x28, Attribute = 0xFFFD, ClusterRevision: 1'
  self.assertEqual(read_results(s)['cluster-revision'],{'status':'SUCCESS','value':1})
if __name__=='__main__':unittest.main()
