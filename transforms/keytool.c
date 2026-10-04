/* Explicit TPM provisioning and build-time AES-GCM/RSA-OAEP helper. */
#include "windows_crypto.h"
#ifdef _WIN32
static unsigned char *read_file(const char *name,DWORD *size) {
    FILE *f=fopen(name,"rb");if(!f)return NULL;
    if(fseek(f,0,SEEK_END)!=0){fclose(f);return NULL;}
    long n=ftell(f);if(n<0 || n>16777216){fclose(f);return NULL;}rewind(f);
    unsigned char *data=(unsigned char*)malloc((size_t)n+1);
    if(!data || fread(data,1,(size_t)n,f)!=(size_t)n){free(data);fclose(f);return NULL;}
    fclose(f);*size=(DWORD)n;return data;
}
static int write_file(const char *name,const void *data,DWORD size) {
    FILE *f=fopen(name,"wb");if(!f)return 0;
    int ok=fwrite(data,1,size,f)==size;return fclose(f)==0 && ok;
}
int main(int argc,char **argv) {
    if(argc==4 && !strcmp(argv[1],"provision")) {
        wchar_t name[256];if(!MultiByteToWideChar(CP_UTF8,0,argv[2],-1,name,256))return 2;
        NCRYPT_PROV_HANDLE p=0;NCRYPT_KEY_HANDLE k=0;DWORD bits=2048,usage=NCRYPT_ALLOW_DECRYPT_FLAG,size=0;
        SECURITY_STATUS s=NCryptOpenStorageProvider(&p,MS_PLATFORM_CRYPTO_PROVIDER,0);
        /* No overwrite flag: an existing key is never replaced. */
        if(s==0)s=NCryptCreatePersistedKey(p,&k,BCRYPT_RSA_ALGORITHM,name,0,0);
        if(s==0)s=NCryptSetProperty(k,NCRYPT_LENGTH_PROPERTY,(PBYTE)&bits,sizeof bits,0);
        if(s==0)s=NCryptSetProperty(k,NCRYPT_KEY_USAGE_PROPERTY,(PBYTE)&usage,sizeof usage,0);
        if(s==0)s=NCryptFinalizeKey(k,0);
        if(s==0)s=NCryptExportKey(k,0,BCRYPT_RSAPUBLIC_BLOB,NULL,NULL,0,&size,0);
        unsigned char *blob=(unsigned char*)malloc(size?size:1);
        if(s==0 && !blob)s=NTE_NO_MEMORY;
        if(s==0)s=NCryptExportKey(k,0,BCRYPT_RSAPUBLIC_BLOB,NULL,blob,size,&size,0);
        int ok=s==0 && write_file(argv[3],blob,size);free(blob);
        if(k)NCryptFreeObject(k);
        if(p)NCryptFreeObject(p);
        if(!ok)fprintf(stderr,"TPM provisioning failed: 0x%lx\n",(unsigned long)s);
        return ok?0:2;
    }
    if(argc==5 && !strcmp(argv[1],"wrap")) {
        DWORD bn=0,kn=0,n=0;unsigned char *blob=read_file(argv[2],&bn),*key=read_file(argv[3],&kn);
        BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_KEY_HANDLE handle=NULL;unsigned char output[1024];NTSTATUS s=-1;
        BCRYPT_OAEP_PADDING_INFO padding={BCRYPT_SHA256_ALGORITHM,NULL,0};
        if(blob && key && kn==32)s=BCryptOpenAlgorithmProvider(&alg,BCRYPT_RSA_ALGORITHM,NULL,0);
        if(s==0)s=BCryptImportKeyPair(alg,NULL,BCRYPT_RSAPUBLIC_BLOB,&handle,blob,bn,0);
        if(s==0)s=BCryptEncrypt(handle,key,kn,&padding,NULL,0,output,sizeof output,&n,BCRYPT_PAD_OAEP);
        int ok=s==0 && write_file(argv[4],output,n);
        if(key){SecureZeroMemory(key,kn);free(key);}free(blob);
        if(handle)BCryptDestroyKey(handle);
        if(alg)BCryptCloseAlgorithmProvider(alg,0);
        return ok?0:2;
    }
    if(argc==5 && !strcmp(argv[1],"encrypt")) {
        DWORD kn=0,n=0;unsigned char *key=read_file(argv[2],&kn),*input=read_file(argv[3],&n);
        unsigned char *out=(unsigned char*)calloc(1,(size_t)n+28);int ok=0;
        if(key && kn==32 && input && out && BCryptGenRandom(NULL,out,12,BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0)
            ok=fragment_crypt(1,key,out,out+12,input,n,out+28) && write_file(argv[4],out,n+28);
        if(key){SecureZeroMemory(key,kn);free(key);}free(input);free(out);return ok?0:2;
    }
    if(argc==5 && !strcmp(argv[1],"unwrap")) {
        wchar_t name[256];DWORD n=0;unsigned char key[32];
        if(!MultiByteToWideChar(CP_UTF8,0,argv[2],-1,name,256))return 2;
        unsigned char *data=read_file(argv[3],&n);
        int ok=data && tpm_unwrap(name,data,n,key) && write_file(argv[4],key,32);
        SecureZeroMemory(key,32);free(data);return ok?0:2;
    }
    fprintf(stderr,"Usage: keytool provision NAME PUBLIC | wrap PUBLIC KEY OUT | encrypt KEY INPUT OUT | unwrap NAME WRAPPED OUT\n");
    return 2;
}
#else
#error Windows CNG and Platform Crypto Provider are required.
#endif
