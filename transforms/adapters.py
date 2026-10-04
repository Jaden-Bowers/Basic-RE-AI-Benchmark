"""Shared I/O adapters across all transformed and matched-control builds."""
PRICING = r'''
int main(void) {
    char line[1024], extra; long long x[5];
    if (!runtime_ready()) return 70;
    while (fgets(line, sizeof line, stdin)) {
        if (sscanf(line,"%lld %lld %lld %lld %lld %c",x,x+1,x+2,x+3,x+4,&extra)!=5 ||
            x[0]<0 || x[0]>100000 || x[1]<0 || x[1]>200 || x[2]<0 || x[2]>2 ||
            x[3]<0 || x[3]>2 || x[4]<0 || x[4]>2) { puts("ERR"); continue; }
        uint64_t input[8]={0}, output[8]={0}, memory[1024]={0};
        for(int i=0;i<5;i++) input[i]=(uint64_t)x[i];
        core(input,output,memory);
        printf("%llu %llu %llu %llu\n",(unsigned long long)output[0],(unsigned long long)output[1],
               (unsigned long long)output[2],(unsigned long long)output[3]);
    }
    return 0;
}
'''

RECORD = r'''
static int nibble(char c) {
    if(c>='0' && c<='9') return c-'0';
    if(c>='a' && c<='f') return c-'a'+10;
    if(c>='A' && c<='F') return c-'A'+10;
    return -1;
}
int main(void) {
    char line[1024], payload[600], extra; long long k,s,f;
    if (!runtime_ready()) return 70;
    while(fgets(line,sizeof line,stdin)) {
        if(sscanf(line,"%lld %lld %lld %599s %c",&k,&s,&f,payload,&extra)!=4 ||
           k<0 || k>15 || s<0 || s>65535 || f<0 || f>3) { puts("ERR"); continue; }
        int n=strcmp(payload,"-") ? (int)strlen(payload):0;
        int bad=n%2 || n>510; uint64_t memory[1024]={0};
        for(int i=0;!bad && i<n;i+=2) {
            int a=nibble(payload[i]), b=nibble(payload[i+1]);
            if(a<0 || b<0) bad=1; else memory[i/2]=(uint64_t)(16*a+b);
        }
        if(bad) { puts("ERR"); continue; }
        uint64_t input[8]={(uint64_t)k,(uint64_t)s,(uint64_t)f,(uint64_t)(n/2),0,0,0,0}, output[8]={0};
        core(input,output,memory);
        for(uint64_t i=0;i<output[0];i++) printf("%02x",(unsigned)memory[256+i]);
        putchar('\n');
    }
    return 0;
}
'''

SESSION = r'''
#include <iostream>
#include <sstream>
#include <string>
#include <map>
struct Hold { uint64_t amount, deadline; };
int main() {
    if (!runtime_ready()) return 70;
    std::map<long long,Hold> holds;
    uint64_t stock=30,sold=0,clock=0;
    std::string line;
    auto transition = [&](uint64_t op,uint64_t qty,Hold h,uint64_t delta,uint64_t *out) {
        uint64_t input[8]={op,qty,h.amount,h.deadline,stock,sold,clock,delta}, mem[1024]={0};
        core(input,out,mem); stock=out[1]; sold=out[2]; clock=out[3];
    };
    while(std::getline(std::cin,line)) {
        std::istringstream in(line); std::string op,tail; long long id,n;
        in>>op;
        if(op=="RESET" && !(in>>tail)) { stock=30;sold=0;clock=0;holds.clear();std::cout<<"OK\n"; }
        else if(op=="STATUS" && !(in>>tail)) {
            uint64_t held=0;for(const auto &h:holds) held+=h.second.amount;
            std::cout<<stock<<' '<<held<<' '<<sold<<' '<<clock<<'\n';
        } else if(op=="HOLD" && (in>>id>>n) && !(in>>tail)) {
            if(id<1 || id>999 || n<1 || n>30) { std::cout<<"ERR\n";continue; }
            auto it=holds.find(id);Hold h=it==holds.end()?Hold{0,0}:it->second;uint64_t out[8]={0};
            transition(1,(uint64_t)n,h,0,out);
            if(out[0]==0) { holds[id]={out[4],out[5]};std::cout<<"OK\n"; }
            else std::cout<<(out[0]==1?"DUP\n":"SHORT\n");
        } else if((op=="BUY" || op=="CANCEL") && (in>>id) && !(in>>tail)) {
            if(id<1 || id>999) { std::cout<<"ERR\n";continue; }
            auto it=holds.find(id);Hold h=it==holds.end()?Hold{0,0}:it->second;uint64_t out[8]={0};
            transition(op=="BUY"?2:3,0,h,0,out);
            if(out[0]==0) { holds.erase(id);std::cout<<"OK\n"; } else std::cout<<"MISSING\n";
        } else if(op=="TICK" && (in>>n) && !(in>>tail)) {
            if(n<0 || n>1000) { std::cout<<"ERR\n";continue; }
            uint64_t out[8]={0},expired=0;transition(4,0,Hold{0,0},(uint64_t)n,out);
            for(auto it=holds.begin();it!=holds.end();) {
                transition(5,0,it->second,0,out);expired+=out[6];
                if(out[6]) it=holds.erase(it); else ++it;
            }
            std::cout<<expired<<'\n';
        } else std::cout<<"ERR\n";
    }
}
'''

ADAPTERS = {'pricing': PRICING, 'record': RECORD, 'session': SESSION}
