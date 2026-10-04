import argparse
import json
import math
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import bench
import suite
from transforms.generate import VARIANTS,make_model,generate,rle,unrle
from transforms.ir import FRONTENDS,interpret,auxiliary,aux_expected
from transforms.metrics import make_pairs,pair_metrics,resource_metrics

class IRTests(unittest.TestCase):
    def test_pricing_against_independent_oracle(self):
        program=FRONTENDS['pricing']()
        for _,lines in bench.cases('pricing',731):
            for line in lines:
                answer=bench.expected('pricing',[line])[0]
                if answer=='ERR':continue
                out,_=interpret(program,list(map(int,line.split())))
                self.assertEqual(' '.join(map(str,out[8:12])),answer)

    def test_record_modes_and_boundaries(self):
        program=FRONTENDS['record']();rng=random.Random(137)
        for size in (0,1,2,127,128,255):
            for flags in range(4):
                payload=rng.randbytes(size);memory=list(payload)+[0]*(1024-size)
                out,mem=interpret(program,[15,65535,flags,size],memory)
                line=f'15 65535 {flags} '+(payload.hex() if payload else '-')
                self.assertEqual(bytes(mem[256:256+out[8]]).hex(),bench.expected('record',[line])[0])

    def test_auxiliary_computations(self):
        inputs=[0,1,255,65535,30,200,999,1000]
        for stream in range(1,16):
            out,_=interpret(auxiliary(stream),inputs)
            self.assertEqual(out[8],aux_expected(inputs,stream))

    def test_packing_roundtrip(self):
        rng=random.Random(42)
        for data in (b'',b'\0'*4096,bytes(range(256))*4,rng.randbytes(4096),b'aaabbbccdde'*100):
            self.assertEqual(unrle(rle(data)),data)
        with self.assertRaises(ValueError):unrle(b'\xff')
        with self.assertRaises(ValueError):unrle(b'\x03a')

    def test_seed_matrix_and_order(self):
        for name in bench.NAMES:
            for variant in ('interleave','decorrelate','entangle','full'):
                for streams in (2,4,8,16):
                    hashes=set()
                    for seed in range(1,6):
                        a=make_model(name,variant,streams,seed);b=make_model(name,variant,streams,seed)
                        self.assertEqual(a['rows'],b['rows'])
                        self.assertEqual(a['streams'],streams)
                        hashes.add(json.dumps(a['rows']))
                        for s,program in enumerate(a['programs']):
                            source=[p['source_instruction'] for p in a['provenance'] if p['stream']==s]
                            self.assertEqual(source,list(range(len(program.code))))
                    self.assertEqual(len(hashes),5)

    def test_distinct_transform_mechanisms(self):
        with tempfile.TemporaryDirectory() as tmp:
            sources={v:generate('pricing',v,4,7,Path(tmp))[0] for v in VARIANTS if v!='full'}
            self.assertIn('goto L0',sources['plain'])
            self.assertIn('switch(pc)',sources['cfg'])
            self.assertIn('switch(row[',sources['vm'])
            self.assertIn('volatile unsigned phase',sources['vm-strong'])
            self.assertIn('#define MOVING 1',sources['decorrelate'])
            self.assertIn('#define ENTANGLED 1',sources['entangle'])
            self.assertNotEqual(make_model('pricing','vm',4,1)['opcodes'],make_model('pricing','entangle',4,1)['opcodes'])

class MetricTests(unittest.TestCase):
    def test_pair_metrics_and_ties(self):
        labels={'a':1,'b':1,'c':0,'d':0}
        perfect=pair_metrics(labels,{'a':1.,'b':.9,'c':.1,'d':0.})
        self.assertEqual((perfect['accuracy'],perfect['f1'],perfect['roc_auc']),(1.,1.,1.))
        self.assertEqual(pair_metrics(labels,dict.fromkeys(labels,.5))['roc_auc'],.5)
        self.assertEqual(pair_metrics(labels,{'a':0.,'b':.1,'c':.9,'d':1.})['roc_auc'],0.)
        for bad in ({},{'a':float('nan'),'b':1,'c':0,'d':0},{'a':True,'b':1,'c':0,'d':0}):
            with self.assertRaises(ValueError):pair_metrics(labels,bad)

    def test_pair_labels_balanced_and_unleaked(self):
        m=make_model('record','entangle',16,9)
        pairs,labels=make_pairs(m['provenance'],9)
        self.assertEqual(sum(labels.values()),len(labels)//2)
        streams={p['operation_id']:p['stream'] for p in m['provenance']}
        for pair in pairs:
            self.assertEqual(set(pair),{'pair_id','left','right'})
            self.assertEqual(labels[pair['pair_id']],int(streams[pair['left']]==streams[pair['right']]))

    def test_resources_and_checkpoints(self):
        events=[{'elapsed_seconds':2,'tokens':100,'executions':2,'context_tokens':700,'incorrect_hypotheses':2},
                {'elapsed_seconds':8,'kind':'checkpoint','correct':False},
                {'elapsed_seconds':12,'kind':'checkpoint','correct':True,'tokens':50,'context_tokens':950},
                {'elapsed_seconds':15,'incorrect_hypotheses':3}]
        result=resource_metrics(events)
        self.assertEqual(result['tokens'],150)
        self.assertEqual(result['time_to_first_correct_seconds'],12)
        self.assertIsNone(result['traces'])
        self.assertEqual(result['context_peak_tokens'],950)
        self.assertEqual(result['incorrect_hypotheses_before_first_correct'],2)
        with self.assertRaises(ValueError):resource_metrics([{'elapsed_seconds':2},{'elapsed_seconds':1}])


@unittest.skipUnless(os.environ.get('REBENCH_NATIVE_TESTS')=='1','set REBENCH_NATIVE_TESTS=1 to compile native transformation tests')
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='re-transforms-');cls.root=Path(cls.tmp.name)
        cls.args=argparse.Namespace(streams=2,key_backend='software-test',tpm_name=None,tpm_public=None,
            cc='gcc',cxx='g++',nm='nm',strip='strip')
        cls.folders={}
        for variant in VARIANTS:
            if variant=='full' and os.name!='nt':continue
            cls.folders[variant]=suite.build_one(cls.args,variant,19,cls.root)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def test_all_native_variants_match(self):
        # Compile and run every variant; full corpus validation remains a separate command.
        samples={
            'pricing':['1250 2 0 1 2','5000 0 1 2 0','99 20 2 2 1','100001 1 0 0 0'],
            'record':['15 65535 3 aabb0011','0 256 0 -','1 0 2 ff','0 0 0 gg'],
            'session':['STATUS','HOLD 1 30','HOLD 1 1','TICK 3','BUY 1','STATUS','RESET','HOLD 2 4','TICK 4','CANCEL 2','STATUS']}
        for variant,folder in self.folders.items():
            for name,lines in samples.items():
                actual,error=bench.run([str(folder/(name+bench.EXT))],lines,20,str(folder))
                self.assertIsNone(error,(variant,name))
                self.assertEqual(actual,bench.expected(name,lines),(variant,name))

    def test_real_operation_coordinates(self):
        for variant in ('interleave','decorrelate','entangle'):
            folder=self.folders[variant]
            for name in bench.NAMES:
                public=json.loads((folder/(name+'.pairs.json')).read_text())
                offsets=[o['image_offset'] for o in public['operations']]
                self.assertEqual(len(offsets),len(set(offsets)))
                self.assertTrue(all(x>0 for x in offsets))
                # PE virtual-to-file mapping; verify bytecode records survived compilation.
                if os.name=='nt' and variant=='entangle':
                    data=(folder/(name+'.exe')).read_bytes();pe=struct.unpack_from('<I',data,60)[0]
                    count=struct.unpack_from('<H',data,pe+6)[0];opt=struct.unpack_from('<H',data,pe+20)[0]
                    truth=json.loads((folder/(name+'.truth.json')).read_text())
                    rows={p['operation_id']:p['row'] for p in truth['provenance']}
                    for op in public['operations']:
                        rva=op['image_offset'];offset=None
                        for i in range(count):
                            section=pe+24+opt+40*i
                            size,va,rawsize,raw=struct.unpack_from('<IIII',data,section+8)
                            if va<=rva<va+max(size,rawsize):offset=raw+rva-va;break
                        self.assertIsNotNone(offset)
                        row=rows[op['operation_id']]
                        self.assertEqual(data[offset:offset+64],struct.pack('<8Q',*(row[f] for f in truth['field_order'])))

    def test_larger_stream_counts(self):
        for count in (4,8,16):
            args=argparse.Namespace(**vars(self.args));args.streams=count
            folder=suite.build_one(args,'entangle',count,self.root)
            for name,lines in {'pricing':['1000 7 1 2 2'], 'record':['1 256 3 11223344'],
                               'session':['HOLD 1 5','TICK 4','STATUS']}.items():
                actual,error=bench.run([str(folder/(name+bench.EXT))],lines,20,str(folder))
                self.assertIsNone(error);self.assertEqual(actual,bench.expected(name,lines))

    @unittest.skipUnless(os.name=='nt','Windows Platform Crypto Provider')
    def test_tpm_build_fails_without_named_key(self):
        # A transient software RSA public blob exercises the real TPM build path without
        # provisioning a persistent key. Runtime must NOT fall back to software storage.
        source=self.root/'public_fixture.c';public=self.root/'fixture.blob'
        source.write_text(r'''
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
int main(int argc,char **argv){
    BCRYPT_ALG_HANDLE a=0;BCRYPT_KEY_HANDLE k=0;unsigned char blob[1024];ULONG n=0;
    if(argc!=2 || BCryptOpenAlgorithmProvider(&a,BCRYPT_RSA_ALGORITHM,0,0) ||
       BCryptGenerateKeyPair(a,&k,2048,0) || BCryptFinalizeKeyPair(k,0) ||
       BCryptExportKey(k,0,BCRYPT_RSAPUBLIC_BLOB,blob,sizeof blob,&n,0))return 2;
    FILE *f=fopen(argv[1],"wb");if(!f)return 2;int ok=fwrite(blob,1,n,f)==n;fclose(f);
    BCryptDestroyKey(k);BCryptCloseAlgorithmProvider(a,0);return ok?0:2;
}
''')
        generator=self.root/'public_fixture.exe'
        subprocess.run(['gcc',str(source),'-o',str(generator),'-lbcrypt'],check=True)
        subprocess.run([str(generator),str(public)],check=True)
        args=argparse.Namespace(**vars(self.args));args.key_backend='windows-tpm'
        import uuid
        args.tpm_name='REBenchmarkMissing-'+uuid.uuid4().hex;args.tpm_public=public
        folder=suite.build_one(args,'full',23,self.root)
        self.assertFalse(any(folder.glob('*.exe.key')))
        for name in bench.NAMES:
            self.assertEqual(bench.run([str(folder/(name+bench.EXT))],['STATUS'],5,str(folder))[1],'exit:70')

    @unittest.skipUnless(os.name=='nt','Windows CNG')
    def test_full_wrong_missing_key_and_tamper(self):
        folder=self.folders['full'];binary=folder/'pricing.exe';key=folder/'pricing.exe.key';original=key.read_bytes()
        key.unlink()
        self.assertEqual(bench.run([str(binary)],['10 1 0 0 0'],5,str(folder))[1],'exit:70')
        key.write_bytes(b'\0'*32)
        self.assertEqual(bench.run([str(binary)],['10 1 0 0 0'],5,str(folder))[1],'exit:71')
        key.write_bytes(original)
        import re
        source=(folder/'pricing.c').read_text()
        blob=bytes(map(int,re.search(r'packed_code\[\]=\{([0-9,]+)\}',source).group(1).split(',')))
        data=bytearray(binary.read_bytes());offset=data.find(blob);self.assertGreaterEqual(offset,0)
        data[offset+28]^=1;bad=folder/'tampered.exe';bad.write_bytes(data)
        shutil.copy2(key,folder/'tampered.exe.key')
        self.assertEqual(bench.run([str(bad)],['10 1 0 0 0'],5,str(folder))[1],'exit:71')

    def test_packaging_excludes_private_material(self):
        folder=self.folders['interleave'];manifest=json.loads((folder/'manifest.json').read_text())
        # This test validates the real output first, including the audit-only auxiliary oracle.
        suite.validate(argparse.Namespace(build_dir=str(folder),seed=11,timeout=20,cc='gcc',cxx='g++'))
        dest=self.root/'bundle';suite.package(argparse.Namespace(build_dir=str(folder),out=str(dest)))
        files={str(p.relative_to(dest)).replace('\\','/') for p in dest.rglob('*') if p.is_file()}
        self.assertFalse(any(f.endswith(('.c','.cpp','.truth.json','.py')) for f in files))
        self.assertFalse(any('audit-' in f for f in files))
        self.assertIn('pricing/pairs.json',files)
        submission=self.root/'pair-submission'
        for name in bench.NAMES:
            truth=json.loads((folder/(name+'.truth.json')).read_text())
            bench.save(submission/name/'pairs.json',{k:float(v) for k,v in truth['labels'].items()})
        result=self.root/'pairs-report.json'
        pair_args=argparse.Namespace(build_dir=str(folder),bundle=str(dest),submission=str(submission),out=str(result))
        suite.grade_pairs(pair_args)
        self.assertTrue(all(v['roc_auc']==1 for v in json.loads(result.read_text())['targets'].values()))
        pair_file=dest/'pricing/pairs.json';pair_file.write_text(pair_file.read_text()+'\n')
        with self.assertRaises(ValueError):suite.grade_pairs(pair_args)
        # Never allow a baseline binary to acquire a different treatment via its label.
        with self.assertRaises(ValueError):
            bench.package(argparse.Namespace(build_dir=str(folder),out=str(self.root/'wrong'),treatment='entangle'))

@unittest.skipUnless(os.name=='nt' and os.environ.get('REBENCH_TPM_NAME') and os.environ.get('REBENCH_TPM_PUBLIC'),
                     'hardware test requires explicitly provisioned Windows TPM key and public blob')
class TPMTests(unittest.TestCase):
    def test_real_tpm_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=root/'test.key';wrapped=root/'wrapped';clear=root/'unwrapped'
            key.write_bytes(os.urandom(32));helper=suite.keytool()
            subprocess.run([str(helper),'wrap',os.environ['REBENCH_TPM_PUBLIC'],str(key),str(wrapped)],check=True)
            subprocess.run([str(helper),'unwrap',os.environ['REBENCH_TPM_NAME'],str(wrapped),str(clear)],check=True)
            self.assertEqual(key.read_bytes(),clear.read_bytes())

if __name__=='__main__':unittest.main()
