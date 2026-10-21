"""Reject corrupted/wrong-ABI engines before installing a partial candidate."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import windows_bundle as wb


def pe(dll=False, machine=0x8664):
    b=bytearray(160);b[:2]=b'MZ';struct.pack_into('<I',b,60,64)
    b[64:68]=b'PE\0\0';struct.pack_into('<H',b,68,machine)
    struct.pack_into('<H',b,86,0x2000 if dll else 2);struct.pack_into('<H',b,88,0x20b)
    return bytes(b)


class BundleSafety(unittest.TestCase):
    def test_machine_and_dll_are_not_interchangeable(self):
        wb.inspect_pe(pe());wb.inspect_pe(pe(True),True)
        for data,dll in [(pe(machine=0xaa64),False),(pe(True),False),(pe(),True),(b'MZ',False)]:
            with self.assertRaises(ValueError): wb.inspect_pe(data,dll)

    def test_corruption_prevents_partial_install(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);desktop=root/'desktop';base=desktop/'src-tauri';base.mkdir(parents=True)
            (base/'tauri.conf.json').write_text(json.dumps({'bundle':{'externalBin':['binaries/xray']}}))
            items=[]
            for kind in ['naive','tuic']:
                p=root/(kind+'.zip');data=pe()
                with zipfile.ZipFile(p,'w') as z:z.writestr('engine.exe',data)
                raw=p.read_bytes();items.append({'protocol':kind,'name':p.name,'member':'engine.exe','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'binary_sha256':hashlib.sha256(data).hexdigest()})
            # Archive hash is valid but its claimed executable hash is not.
            items[1]['binary_sha256']='0'*64
            manifest=root/'manifest.json';manifest.write_text(json.dumps(items))
            with patch.object(wb,'MANIFEST',manifest):
                with self.assertRaisesRegex(ValueError,'Payload checksum'):wb.stage(desktop,root,root/'output')
            self.assertFalse((base/'binaries').exists())
            self.assertFalse((root/'output').exists())

    def test_archive_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'archive.zip';p.write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'Archive checksum'):
                wb.payloads({'name':p.name,'bytes':7,'sha256':'0'*64},Path(td))


if __name__=='__main__':unittest.main()
