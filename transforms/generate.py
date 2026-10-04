"""Generate matched native controls and seven explicit protection treatments."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess

from .adapters import ADAPTERS
from .ir import FRONTENDS, OPS, auxiliary

HERE = Path(__file__).resolve().parent
VARIANTS = {
    'plain': 1, 'cfg': 2, 'vm': 3, 'vm-strong': 4,
    'interleave': 5, 'decorrelate': 6, 'entangle': 7, 'full': 8,
}
FIELDS = ('op','d','a','b','c','imm','next','uid')

def stable_seed(seed, target):
    return int.from_bytes(hashlib.sha256(f'{seed}:{target}'.encode()).digest()[:8], 'little') or 1

def rle(data):
    """PackBits-like byte format: high bit = repeated byte; low 7 bits + 1 = length."""
    out=bytearray();i=0
    while i<len(data):
        j=i+1
        while j<len(data) and data[j]==data[i] and j-i<128: j+=1
        if j-i>=3: out.extend((128+j-i-1,data[i]));i=j;continue
        start=i;i=j
        while i<len(data) and i-start<128:
            n=1
            while i+n<len(data) and data[i+n]==data[i] and n<3: n+=1
            if n>=3: break
            i+=min(n,128-(i-start))
        out.append(i-start-1);out.extend(data[start:i])
    return bytes(out)

def unrle(data):
    out=bytearray();i=0
    while i<len(data):
        tag=data[i];i+=1;n=(tag&127)+1
        if tag&128:
            if i>=len(data): raise ValueError('truncated run')
            out.extend(bytes([data[i]])*n);i+=1
        else:
            if i+n>len(data): raise ValueError('truncated literal')
            out.extend(data[i:i+n]);i+=n
    return bytes(out)

def expression(op, a='a', b='b', c='c', strong=False):
    return {
        'const':'imm', 'mov':a, 'add':f'mixed_add({a},{b})' if strong else f'{a}+{b}',
        'sub':f'mixed_add({a},mixed_add(~{b},1))' if strong else f'{a}-{b}',
        'mul':f'{a}*{b}', 'div':f'({b}?{a}/{b}:0)', 'mod':f'({b}?{a}%{b}:0)',
        'and':f'{a}&{b}', 'or':f'{a}|{b}', 'xor':f'mixed_xor({a},{b})' if strong else f'{a}^{b}',
        'shl':f'{a}<<({b}&63)', 'shr':f'{a}>>({b}&63)', 'eq':f'{a}=={b}',
        'lt':f'{a}<{b}', 'le':f'{a}<={b}', 'select':f'pick({a},{b},{c})',
        'load':f'getv(STREAMS*256+(unsigned){a})',
    }[op]

def make_model(target, variant, streams, seed):
    level=VARIANTS[variant]
    if streams not in (2,4,8,16): raise ValueError('streams must be 2, 4, 8 or 16')
    count=streams if level>=5 else 1
    programs=[FRONTENDS[target]()] + [auxiliary(s) for s in range(1,count)]
    rng=random.Random(stable_seed(seed,target))
    # Randomized stable merge: retain each stream's static instruction order.
    positions=[0]*count; order=[]
    while any(positions[s]<len(p.code) for s,p in enumerate(programs)):
        choices=[s for s,p in enumerate(programs) if positions[s]<len(p.code)]
        s=rng.choice(choices);order.append((s,positions[s]));positions[s]+=1
    lookup={pair:i for i,pair in enumerate(order)}
    opcode_values=list(range(1,len(OPS)+1))
    fields=list(FIELDS)
    if level>=7:
        opcode_values=rng.sample(range(1,65535),len(OPS));rng.shuffle(fields)
    codes=dict(zip(OPS,opcode_values))
    mask=rng.getrandbits(64) if level in (4,7,8) else 0
    def ref(register, stream):
        actual=register*count+stream
        return actual+1000003*rng.randrange(1,1<<20) if level>=6 else actual
    rows=[];provenance=[]
    uids=rng.sample(range(1,1<<30),len(order))
    for index,(s,i) in enumerate(order):
        ins=programs[s].code[i];values=asdict(ins)
        values['op']=codes[ins.op]
        for f in ('d','a','b','c'):values[f]=ref(values[f],s)
        if ins.op in ('jump','branch'):values['imm']=lookup[(s,ins.imm)]
        values['imm']^=mask
        values['next']=lookup.get((s,i+1),0xffffffff)
        values['uid']=uids[index]
        rows.append([values[f] for f in fields])
        provenance.append({'operation_id':uids[index],'stream':s,'source_instruction':i,'opcode':ins.op,
                           'table_index':index,'row':values})
    return {'target':target,'variant':variant,'level':level,'streams':count,'seed':seed,
            'fields':fields,'opcodes':codes,'mask':mask,'rows':rows,'provenance':provenance,
            'entries':[lookup[(s,0)] for s in range(count)],'programs':programs}

def packed_table(model, directory, keytool, key_path, backend, tpm_name=None, public_blob=None):
    """Encrypt separately authenticated packed fragments; keep clear bytecode author-only."""
    rows=model['rows']; blobs=[];offsets=[];sizes=[]
    # Eight 64-byte operations per fragment: at most 512 bytes plaintext live at a time.
    for start in range(0,len(rows),8):
        raw=b''.join(struct.pack('<8Q',*row) for row in rows[start:start+8])
        packed=rle(raw)
        source=directory/'fragment.pack';dest=directory/'fragment.enc'
        source.write_bytes(packed)
        subprocess.run([str(keytool),'encrypt',str(key_path),str(source),str(dest)],check=True,capture_output=True)
        payload=dest.read_bytes();offsets.append(sum(map(len,blobs)));sizes.append(len(payload));blobs.append(payload)
    wrapped=b''
    if backend=='windows-tpm':
        if not tpm_name or not public_blob: raise ValueError('TPM name and public blob are required')
        subprocess.run([str(keytool),'wrap',str(public_blob),str(key_path),str(directory/'wrapped.key')],check=True,capture_output=True)
        wrapped=(directory/'wrapped.key').read_bytes()
    source.unlink(missing_ok=True);dest.unlink(missing_ok=True)
    data=b''.join(blobs)
    def arr(name,values,typ='unsigned char'): return f'static const {typ} {name}[]={{'+','.join(map(str,values))+'};\n'
    result=(HERE/'windows_crypto.h').read_text()+'\n'+arr('packed_code',data)+arr('fragment_offsets',offsets,'unsigned')+arr('fragment_sizes',sizes,'unsigned')
    if backend=='windows-tpm':
        result+=arr('wrapped_key',wrapped)
        # JSON escaping yields a safe ASCII C wide string (name validation in CLI).
        load=f'tpm_unwrap(L{json.dumps(tpm_name)},wrapped_key,sizeof wrapped_key,runtime_key)'
    else: load='test_key(runtime_key)'
    if backend=='software-test':
        result+=r'''
static int test_key(unsigned char key[32]) {
    char path[MAX_PATH];const char *override=getenv("REBENCH_TEST_KEY");
    if(override) { if(strlen(override)>=sizeof path)return 0;strcpy(path,override); }
    else { DWORD n=GetModuleFileNameA(NULL,path,sizeof path);if(!n || n>=sizeof path-5)return 0;strcat(path,".key"); }
    FILE *f=fopen(path,"rb");if(!f)return 0;
    int ok=fread(key,1,32,f)==32 && fgetc(f)==EOF;fclose(f);return ok;
}
'''
    result+=f'''
static unsigned char runtime_key[32];
static int runtime_ready(void) {{
    if(!({load})) {{ fputs("key unavailable\\n",stderr);return 0; }} return 1;
}}
'''
    result+=r'''
static uint64_t fragment_cache[8][8];
static unsigned cached_fragment=0xffffffffu;
static void forget_fragment(void) { SecureZeroMemory(fragment_cache,sizeof fragment_cache);cached_fragment=0xffffffffu; }
static void fetch(unsigned pc,uint64_t out[8]) {
    unsigned page=pc/8;
    if(page>=sizeof(fragment_offsets)/sizeof(fragment_offsets[0]))abort();
    if(page!=cached_fragment) {
        forget_fragment();
        unsigned offset=fragment_offsets[page],size=fragment_sizes[page];
        unsigned char packed[1024],tag[16];
        if(size<28 || size-28>sizeof packed)abort();
        memcpy(tag,packed_code+offset+12,16);
        if(!fragment_crypt(0,runtime_key,packed_code+offset,tag,packed_code+offset+28,size-28,packed)) {
            fputs("fragment authentication failed\n",stderr);exit(71);
        }
        unsigned i=0,n=0;unsigned char *raw=(unsigned char*)fragment_cache;
        while(i<size-28) {
            unsigned t=packed[i++],count=(t&127)+1;
            if(n+count>sizeof fragment_cache)abort();
            if(t&128) { if(i>=size-28)abort();memset(raw+n,packed[i++],count); }
            else { if(i+count>size-28)abort();memcpy(raw+n,packed+i,count);i+=count; }
            n+=count;
        }
        if(n%64)abort();
        SecureZeroMemory(packed,sizeof packed);cached_fragment=page;
    }
    memcpy(out,fragment_cache[pc%8],64);
}
'''
    return result, {'encrypted_fragments':len(blobs),'fragment_operations':8,'ciphertext_sha256':hashlib.sha256(data).hexdigest(),
                    'wrapped_key_sha256':hashlib.sha256(wrapped).hexdigest() if wrapped else None}

def generate(target,variant,streams,seed,directory,audit=False,keytool=None,key_path=None,backend='software-test',tpm_name=None,public_blob=None):
    model=make_model(target,variant,streams,seed);level=model['level'];strong=level in (4,7,8)
    fields=model['fields'];index={f:fields.index(f) for f in fields}
    rng=random.Random(stable_seed(seed,target)^0x73a9)
    table='';packed_meta={}
    if level in (3,4,7,8):
        if level==8:
            table,packed_meta=packed_table(model,directory,keytool,key_path,backend,tpm_name,public_blob)
        else:
            table='static const uint64_t code[][8]={\n'+',\n'.join('{'+','.join(str(v)+'ULL' for v in row)+'}' for row in model['rows'])+'\n};\n'
            table+='static int runtime_ready(void){return 1;}\nstatic void fetch(unsigned pc,uint64_t out[8]){memcpy(out,code[pc],64);}\n'
        if strong:
            # Flatten interpreter fetch/execute progression; volatile phase resists folding.
            phase_start='volatile unsigned phase=0;while(phase!=3){switch(phase){case 0:fetch(pc,row);phase=1;break;case 1:{'
            phase_end='phase=3;break;}default:abort();}}'
        else: phase_start='fetch(pc,row);';phase_end=''
        body=f'''static NOINLINE unsigned step(unsigned pc) {{
            uint64_t row[8]={{0}};unsigned next=0;{phase_start}
            uint64_t a=getv((unsigned)(row[{index['a']}]%1000003)),b=getv((unsigned)(row[{index['b']}]%1000003)),c=getv((unsigned)(row[{index['c']}]%1000003));
            uint64_t imm=row[{index['imm']}]^immediate_mask;
            unsigned d=(unsigned)(row[{index['d']}]%1000003);next=(unsigned)row[{index['next']}];
            switch(row[{index['op']}]) {{\n'''
        handlers=list(OPS)
        if level>=7:rng.shuffle(handlers)
        for op in handlers:
            body+=f'case {model["opcodes"][op]}:'
            if op=='halt': stmt='next=0xffffffffu;'
            elif op=='jump':stmt='next=(unsigned)imm;'
            elif op=='branch':stmt='next=(unsigned)pick(a,imm,next);'
            elif op=='store':stmt='setv(STREAMS*256+(unsigned)a,b);'
            else:stmt=f'setv(d,{expression(op,strong=strong)});'
            body+=stmt+'break;\n'
        body+='default:abort();}\n'+phase_end+'return next;}\n'
    else:
        table='static int runtime_ready(void){return 1;}\n'
        if level==1:
            table+='#define getv(id) cells[(id)]\n#define setv(id,value) ((void)(cells[(id)]=(value)))\n'
        # Plain native has direct jumps. CFG/interleaving use a central switch dispatcher.
        if level==1:body='static void execute(void){goto L0;\n'
        else:body='static NOINLINE unsigned step(unsigned pc){switch(pc){\n'
        ordering=list(enumerate(model['provenance']))
        if level!=1:rng.shuffle(ordering)
        for loc,item in ordering:
            row=item['row'];op=item['opcode'];tag=f'op_{item["operation_id"]}'
            if level==1:body+=f'L{loc}:{{\n'
            else:body+=f'case {loc}:{{\n'
            # Public address anchors only for the pair-assessment treatments.
            if level in (5,6): body+=f'__asm__ __volatile__(".global {tag}\\n{tag}: nop" ::: "memory");\n'
            def get(f):return f'getv((unsigned)({row[f]}ULL%label_mod))' if level>=6 else f'getv({row[f]})'
            body+=f'uint64_t a={get("a")},b={get("b")},c={get("c")},imm={row["imm"]}ULL;\n'
            if op=='halt':stmt='return;' if level==1 else 'return 0xffffffffu;'
            elif op=='jump':stmt=f'goto L{row["imm"]};' if level==1 else f'return {row["imm"]};'
            elif op=='branch':
                if level==1:stmt=f'if(a)goto L{row["imm"]};goto L{row["next"]};'
                elif level>=6:stmt=f'return (unsigned)pick(a,{row["imm"]},{row["next"]});'
                else:stmt=f'if(a)return {row["imm"]};return {row["next"]};'
            else:
                dest=f'(unsigned)({row["d"]}ULL%label_mod)' if level>=6 else str(row['d'])
                stmt='setv(STREAMS*256+(unsigned)a,b);' if op=='store' else f'setv({dest},{expression(op)});'
                stmt+=f'goto L{row["next"]};' if level==1 else f'return {row["next"]};'
            body+='(void)a;(void)b;(void)c;(void)imm;'+stmt+'\n'
            body+='}\n'
        body+='}\n' if level==1 else 'default:abort();}}\n'
    if level!=1:
        entries=','.join(map(str,model['entries']))
        schedule=list(range(model['streams']));rng.shuffle(schedule)
        pc_init=f'volatile unsigned pcs[STREAMS]={{{entries}}};'
        pc_read='pcs[s]'
        pc_write='pcs[s]=next;'
        if level>=6:
            pc_init=''.join(f'setv(255*STREAMS+{s},{entry});' for s,entry in enumerate(model['entries']))
            pc_read='(unsigned)getv(255*STREAMS+s)'
            pc_write='setv(255*STREAMS+s,next);'
        body+=f'''static void execute(void) {{
            {pc_init}
            static const unsigned order[STREAMS]={{{','.join(map(str,schedule))}}};
            unsigned live=STREAMS;uint64_t steps=0;
            while(live) {{
                for(unsigned j=0;j<STREAMS;j++) {{
                    unsigned s=order[j],pc={pc_read};if(pc==0xffffffffu)continue;
                    unsigned next=step(pc);{pc_write}if(next==0xffffffffu)live--;
                    if(++steps>1000000)abort();
                }}
            }}
            {'forget_fragment();' if level==8 else ''}
        }}\n'''
    template=(HERE/'runtime.c.in').read_text()
    audit_decl=''
    if audit:
        audit_decl='''#ifdef RE_AUDIT
static uint64_t aux_reference(uint64_t input[8],unsigned s){
            uint64_t value=0x9e3779b9ULL+s;
            for(unsigned i=0;i<8;i++){value=(value*(33+2*s))^(input[i]+(s+1)*(i+17));}return value;}
#endif
'''
    replacements={'STREAMS':str(model['streams']),'MOVING':str(int(level>=6)),'ENTANGLED':str(int(level>=7)),
                  'STRONG':str(int(strong)),'RNG':str(stable_seed(seed,target)),'MASK':str(model['mask']),
                  'AUDIT_DECL':audit_decl,'TABLE':table,'EXECUTE':body,'ADAPTER':ADAPTERS[target],
                  'AUX_AUDIT':'\n#ifdef RE_AUDIT\nif(v!=aux_reference(input,s)){fputs("auxiliary mismatch\\n",stderr);abort();}\n#endif\n' if audit else ''}
    for k,v in replacements.items():template=template.replace('@'+k+'@',v)
    return template,model,packed_meta
