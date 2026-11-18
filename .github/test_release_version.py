import importlib.util,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location('release_version',Path(__file__).with_name('release_version.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Versions(unittest.TestCase):
 def test_auto_skips_existing_manual_candidates(self):self.assertEqual(m.choose('',92,['candidates/latest-1.0.191.json','candidates/latest-1.0.192.json']),'1.0.193')
 def test_failed_build_reservations_are_not_reused(self):self.assertEqual(m.choose('',93,['candidates/reserved-1.0.194.json']),'1.0.195')
 def test_explicit_reuse_or_downgrade_is_rejected(self):
  for v in ('1.0.191','1.0.192','1.0.165'):
   with self.assertRaises(ValueError):m.choose(v,92,['latest-1.0.192.json'])
  self.assertEqual(m.choose('1.0.193',92,['latest-1.0.192.json']),'1.0.193')
 def test_unrelated_paths_and_invalid_versions_cannot_inject_commands(self):
  self.assertEqual(m.choose('',92,['logs/private.log','candidates/not-a-manifest']), '1.0.192')
  for v in ('1.0.01','1.0.193/../private','$(whoami)','1.0.193\n'):
   with self.assertRaises(ValueError):m.choose(v,92,[])
if __name__=='__main__':unittest.main()
