"""Prepare anti-RE variants, equivalence checks and offline assessment artifacts. No model calls."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import sys

import bench
from transforms.generate import VARIANTS, generate
from transforms.metrics import make_pairs, pair_metrics, resource_metrics

ROOT=Path(__file__).resolve().parent
SUITE_VERSION='1.0'

def tool(name):
    found=shutil.which(name)
    if not found:raise RuntimeError(f'Required tool unavailable: {name}')
    return found

def keytool(cc='gcc'):
    if os.name!='nt':raise RuntimeError('Full-stack encryption and TPM backend currently require Windows CNG')
    folder=ROOT/'build/tools';folder.mkdir(parents=True,exist_ok=True)
    out=folder/'keytool.exe'
    subprocess.run([tool(cc),'-O2','-Wall','-Wextra','-Werror',str(ROOT/'transforms/keytool.c'),'-o',str(out),'-lbcrypt','-lncrypt'],check=True)
    return out

def symbols(path,nm):
    text=subprocess.check_output([nm,'-n',str(path)],text=True)
    result={}
    for line in text.splitlines():
        parts=line.split()
        if len(parts)==3 and re.fullmatch('[0-9a-fA-F]+',parts[0]):result[parts[2]]=int(parts[0],16)
    return result

def image_base(path):
    data=path.read_bytes()
    if data[:2]!=b'MZ':return 0
    pe=struct.unpack_from('<I',data,60)[0];optional=pe+24
    return struct.unpack_from('<Q' if struct.unpack_from('<H',data,optional)[0]==0x20b else '<I',data,optional+24 if struct.unpack_from('<H',data,optional)[0]==0x20b else optional+28)[0]

def build_one(args,variant,seed,base):
    level=VARIANTS[variant];count=args.streams if level>=5 else 1
    folder=base/f'{variant}-s{count}-seed{seed}'
    if folder.exists():raise RuntimeError(f'Build exists; choose a fresh output root: {folder}')
    folder.mkdir(parents=True)
    helper=keytool(args.cc) if level==8 else None
    key_path=None
    if level==8:
        if args.key_backend=='windows-tpm' and (not args.tpm_name or not args.tpm_public):
            raise ValueError('full/windows-tpm requires --tpm-name and --tpm-public; no automatic TPM provisioning')
        key_path=folder/'build-secret.key';key_path.write_bytes(secrets.token_bytes(32))
    metadata={'benchmark_version':bench.VERSION,'suite_version':SUITE_VERSION,
              'treatment':variant+('-software-test' if level==8 and args.key_backend=='software-test' else ''),
              'variant':variant,'streams':count,'build_seed':seed,'key_backend':args.key_backend if level==8 else None,
              'platform':sys.platform,'matched_control':'plain (same lowered kernels and I/O adapters)',
              'scope':'selective core protection; parsing, formatting and session map traversal stay native',
              'generator_sha256':generator_hash(),'targets':{}}
    try:
        for name in bench.NAMES:
            source,model,pack=generate(name,variant,args.streams,seed,folder,audit=True,keytool=helper,key_path=key_path,
                                      backend=args.key_backend,tpm_name=args.tpm_name,public_blob=args.tpm_public)
            cpp=name=='session';filename=name+('.cpp' if cpp else '.c')
            (folder/filename).write_text(source,encoding='utf-8')
            compiler=tool(args.cxx if cpp else args.cc);binary=folder/(name+bench.EXT)
            flags=['-O2','-std=c++17' if cpp else '-std=c11','-Wall','-Wextra','-Werror',
                   '-Wno-unused-function','-Wno-unused-variable']
            if os.name=='nt':flags+=['-static','-Wl,--no-insert-timestamp']
            libs=['-lbcrypt','-lncrypt'] if level==8 else []
            subprocess.run([compiler,*flags,filename,'-o',binary.name,*libs],cwd=folder,check=True)
            syms=symbols(binary,tool(args.nm));base_address=image_base(binary)
            operations=[]
            for item in model['provenance']:
                op={'operation_id':item['operation_id']}
                if level in (5,6):
                    label='op_'+str(item['operation_id'])
                    if label not in syms:raise RuntimeError('Missing native operation anchor: '+label)
                    op.update({'kind':'native_anchor','image_offset':syms[label]-base_address})
                elif level in (3,4,7):
                    symbol='code' if 'code' in syms else '_ZL4code'
                    if symbol not in syms:raise RuntimeError('Missing bytecode table symbol')
                    op.update({'kind':'bytecode_record','image_offset':syms[symbol]-base_address+64*item['table_index'],'size':64})
                elif level==8:
                    op.update({'kind':'decrypted_fragment_record','fragment':item['table_index']//8,
                               'offset':64*(item['table_index']%8),'size':64})
                else:continue
                operations.append(op)
            subprocess.run([tool(args.strip),str(binary)],check=True)
            assets=[]
            if level==8 and args.key_backend=='software-test':
                fixture=binary.with_name(binary.name+'.key');shutil.copy2(key_path,fixture);assets.append(fixture.name)
            public_pairs,labels=make_pairs(model['provenance'],seed)
            bench.save(folder/(name+'.pairs.json'),{'schema_version':1,'unit':'generated IR operation, not individual machine instruction',
                'address_base':'PE image-relative offset; ELF link-time virtual address',
                'binary_sha256':bench.digest(binary),'operations':operations,'pairs':public_pairs})
            bench.save(folder/(name+'.truth.json'),{'binary_sha256':bench.digest(binary),'labels':labels,
                'provenance':model['provenance'],'opcodes':model['opcodes'],'field_order':model['fields'],
                'entries':model['entries'],'immediate_mask':model['mask']})
            metadata['targets'][name]={'binary':binary.name,'sha256':bench.digest(binary),
                'binary_bytes':binary.stat().st_size,'compiler_target':subprocess.check_output([compiler,'-dumpmachine'],text=True).strip(),
                'source':filename,'source_sha256':bench.digest(folder/filename),'compiler':subprocess.check_output([compiler,'--version'],text=True).splitlines()[0],
                'flags':flags,'libraries':libs,'assets':{f:bench.digest(folder/f) for f in assets},
                'pair_file':name+'.pairs.json','pair_sha256':bench.digest(folder/(name+'.pairs.json')),
                'truth_sha256':bench.digest(folder/(name+'.truth.json')),'operation_count':len(model['rows']),**pack}
            print(f'Prepared {variant} / {name} / streams={count} / seed={seed}',flush=True)
        bench.save(folder/'manifest.json',metadata)
    finally:
        # Fixture intentionally retains a test key; TPM builds never ship the AES key.
        if key_path:key_path.unlink(missing_ok=True)
    return folder

def generator_hash():
    paths=[ROOT/'suite.py',ROOT/'bench.py',*sorted((ROOT/'transforms').glob('*.py')),*sorted((ROOT/'transforms').glob('*.in')),
           *sorted((ROOT/'transforms').glob('*.h')),*sorted((ROOT/'transforms').glob('*.c'))]
    return hashlib.sha256(b''.join(p.name.encode()+p.read_bytes() for p in paths)).hexdigest()

def build(args):
    if args.tpm_name and not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',args.tpm_name):
        raise ValueError('TPM test key name must use 1..100 ASCII letters, digits, dot, dash or underscore')
    variants=list(VARIANTS) if args.variant=='all' else [args.variant]
    if 'full' in variants and args.key_backend=='windows-tpm' and (not args.tpm_name or not args.tpm_public):
        raise ValueError('full/windows-tpm requires --tpm-name and --tpm-public; use --key-backend software-test only for fixture checks')
    for seed in args.seeds:
        for variant in variants:build_one(args,variant,seed,Path(args.out).resolve())

def load_manifest(folder):
    folder=Path(folder).resolve();manifest=json.loads((folder/'manifest.json').read_text())
    if manifest.get('suite_version')!=SUITE_VERSION:raise ValueError('Suite version mismatch')
    for name,item in manifest['targets'].items():
        for filename,checksum in [(item['binary'],item['sha256']),(item['source'],item['source_sha256']),
                                   (item['pair_file'],item['pair_sha256']),(name+'.truth.json',item['truth_sha256']),*item['assets'].items()]:
            if bench.digest(folder/filename)!=checksum:raise ValueError('Build artifact changed: '+filename)
    return folder,manifest

def validate(args):
    folder,manifest=load_manifest(args.build_dir)
    if manifest['generator_sha256']!=generator_hash():
        raise ValueError('Generator changed since build; rebuild before validation')
    results={}
    for name,item in manifest['targets'].items():
        binary=folder/item['binary']
        result=bench.evaluate(name,[str(binary)],args.seed,args.timeout,str(folder))
        if not result['full_reconstruction']:raise RuntimeError(f'Equivalence failed: {name}: {result}')
        # Independently compute every auxiliary stream's result in an author-only build.
        audit=folder/('audit-'+item['binary']);compiler=tool(args.cxx if name=='session' else args.cc)
        subprocess.run([compiler,*item['flags'],'-DRE_AUDIT',item['source'],'-o',audit.name,*item['libraries']],cwd=folder,check=True)
        fixture=folder/(item['binary']+'.key')
        if fixture.exists():shutil.copy2(fixture,audit.with_name(audit.name+'.key'))
        audit_result=bench.evaluate(name,[str(audit)],args.seed,args.timeout,str(folder))
        if not audit_result['full_reconstruction']:raise RuntimeError('Auxiliary audit failed: '+name)
        results[name]={'equivalent':True,'auxiliary_audit_passed':True,'categories':result['categories']}
        print('Validated',name,'(behavior + auxiliary computations)',flush=True)
    bench.save(folder/'validation.json',{'kind':'implementation correctness; no model benchmark',
        'manifest_sha256':bench.digest(folder/'manifest.json'),'oracle_sha256':bench.digest(ROOT/'private/oracle.py'),
        'test_seed':args.seed,'targets':results})

def package(args):
    folder,manifest=load_manifest(args.build_dir)
    if manifest['generator_sha256']!=generator_hash():raise ValueError('Generator changed; rebuild before packaging')
    validation=json.loads((folder/'validation.json').read_text())
    if validation['manifest_sha256']!=bench.digest(folder/'manifest.json') or validation['oracle_sha256']!=bench.digest(ROOT/'private/oracle.py'):
        raise ValueError('Validation is stale')
    bench.package(argparse.Namespace(out=args.out,build_dir=str(folder),treatment=None))

def grade_pairs(args):
    folder,manifest=load_manifest(args.build_dir);results={}
    public=Path(args.bundle).resolve();public_manifest=json.loads((public/'manifest.json').read_text())
    if public_manifest.get('suite_version')!=SUITE_VERSION:raise ValueError('Not a suite bundle')
    for name,item in manifest['targets'].items():
        if bench.digest(public/name/item['binary'])!=item['sha256']:raise ValueError('Pair truth/bundle mismatch')
        if bench.digest(public/name/'pairs.json')!=item['pair_sha256']:raise ValueError('Pair questions changed')
        truth=json.loads((folder/(name+'.truth.json')).read_text())
        if not truth['labels']:
            results[name]={'applicable':False,'reason':'single semantic stream; no negative pairs'};continue
        path=Path(args.submission)/name/'pairs.json'
        if not path.exists():results[name]={'applicable':True,'valid':False,'reason':'missing predictions'};continue
        try:results[name]={'applicable':True,'valid':True,**pair_metrics(truth['labels'],json.loads(path.read_text()))}
        except ValueError as exc:results[name]={'applicable':True,'valid':False,'reason':str(exc)}
    bench.save(args.out,{'treatment':manifest['treatment'],'build_seed':manifest['build_seed'],'streams':manifest['streams'],
                        'binary_hashes':{n:i['sha256'] for n,i in manifest['targets'].items()},'targets':results})

def plan(args):
    builds=[]
    for variant,level in VARIANTS.items():
        for stream in ((2,4,8,16) if level>=5 else (1,)):
            for seed in (range(1,6) if level>=5 else (1,)):
                builds.append({'variant':variant,'streams':stream,'seed':seed,
                               'key_backend':'windows-tpm' if level==8 else None})
    bench.save(args.out,{'status':'prepared only; no agent runs', 'builds':builds,'binary_count':len(builds)*3,
        'comparisons':[['vm-strong','decorrelate'],['decorrelate','entangle'],['entangle','full']],
        'tracks':{'cold':'Each seed in a fresh session; no prior solutions.',
                  'transfer':'Solve seed 1, then give its frozen analysis to seeds 2..5. Compare with cold runs at the same budget.'},
        'note':'This is a branching ablation design. Interleave is a native scheduler, not VM+strong plus interleaving. Compare matched mechanisms; do not assume every adjacent row adds one layer.'})

def grade_checkpoints(args):
    event_file=Path(args.events).resolve();events=json.loads(event_file.read_text())
    resource_metrics(events)  # Validate timestamps/counts before running submissions.
    for index,event in enumerate(events):
        if event.get('kind')!='checkpoint':continue
        if not isinstance(event.get('submission'),str):raise ValueError('Checkpoint requires a submission directory')
        submission=(event_file.parent/event['submission']).resolve()
        report_path=Path(args.out).resolve().parent/'checkpoint-reports'/f'{index:04d}.json'
        with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink):
            bench.grade(argparse.Namespace(submission=str(submission),bundle=args.bundle,out=str(report_path),
                seed=args.seed,timeout=args.timeout,run_label=f'checkpoint-{index}'))
        report=json.loads(report_path.read_text())
        event['correct']=all(r['full_reconstruction'] for r in report['targets'].values())
        event['submission_hashes']=report['submission_hashes']
    bench.save(args.out,{'resources':resource_metrics(events),'events':events,
                         'definition':'first saved checkpoint with complete reconstruction on all three targets, graded after the run'})

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    b=sub.add_parser('build');b.add_argument('--variant',choices=[*VARIANTS,'all'],default='all')
    b.add_argument('--streams',type=int,choices=[2,4,8,16],default=4);b.add_argument('--seeds',type=int,nargs='+',default=[1])
    b.add_argument('--out',default='build/transforms');b.add_argument('--key-backend',choices=['windows-tpm','software-test'],default='windows-tpm')
    b.add_argument('--tpm-name');b.add_argument('--tpm-public',type=lambda s:Path(s).resolve())
    b.add_argument('--nm',default='nm');b.add_argument('--strip',default='strip');b.set_defaults(fn=build)
    v=sub.add_parser('validate');v.add_argument('--build-dir',required=True);v.add_argument('--seed',type=int,default=20261003)
    v.add_argument('--timeout',type=float,default=20);v.set_defaults(fn=validate)
    for cmd in (b,v):cmd.add_argument('--cc',default='gcc');cmd.add_argument('--cxx',default='g++')
    k=sub.add_parser('keytool');k.add_argument('--cc',default='gcc');k.set_defaults(fn=lambda a:print(keytool(a.cc)))
    q=sub.add_parser('package');q.add_argument('--build-dir',required=True);q.add_argument('--out',required=True);q.set_defaults(fn=package)
    q=sub.add_parser('grade-pairs');q.add_argument('--build-dir',required=True);q.add_argument('--bundle',required=True)
    q.add_argument('--submission',required=True);q.add_argument('--out',required=True);q.set_defaults(fn=grade_pairs)
    q=sub.add_parser('plan');q.add_argument('--out',default='experiments/plan.json');q.set_defaults(fn=plan)
    q=sub.add_parser('resources');q.add_argument('--events',required=True);q.add_argument('--out',required=True)
    q.set_defaults(fn=lambda a:bench.save(a.out,resource_metrics(json.loads(Path(a.events).read_text()))))
    q=sub.add_parser('grade-checkpoints');q.add_argument('--events',required=True);q.add_argument('--bundle',required=True)
    q.add_argument('--out',required=True);q.add_argument('--seed',type=int,default=20261003);q.add_argument('--timeout',type=float,default=5)
    q.set_defaults(fn=grade_checkpoints)
    args=p.parse_args();args.fn(args)

if __name__=='__main__':main()
