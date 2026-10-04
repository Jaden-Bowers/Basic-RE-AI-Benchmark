#ifndef RE_WINDOWS_CRYPTO_H
#define RE_WINDOWS_CRYPTO_H
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* AES-256-GCM uses the OS cryptographic provider. No homemade cipher. */
static int fragment_crypt(int encrypt, const unsigned char key[32],
    const unsigned char nonce[12], unsigned char tag[16],
    const unsigned char *input, unsigned long length, unsigned char *output) {
    BCRYPT_ALG_HANDLE alg=NULL; BCRYPT_KEY_HANDLE handle=NULL;
    DWORD objlen=0, got=0, written=0; PUCHAR object=NULL; NTSTATUS status=-1;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_AES_ALGORITHM,NULL,0)!=0) goto end;
    if(BCryptSetProperty(alg,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,sizeof(BCRYPT_CHAIN_MODE_GCM),0)!=0) goto end;
    if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objlen,sizeof(objlen),&got,0)!=0) goto end;
    object=(PUCHAR)calloc(1,objlen);if(!object) goto end;
    if(BCryptGenerateSymmetricKey(alg,&handle,object,objlen,(PUCHAR)key,32,0)!=0) goto end;
    BCRYPT_INIT_AUTH_MODE_INFO(info);info.pbNonce=(PUCHAR)nonce;info.cbNonce=12;
    info.pbTag=tag;info.cbTag=16;
    if(encrypt) status=BCryptEncrypt(handle,(PUCHAR)input,length,&info,NULL,0,output,length,&written,0);
    else status=BCryptDecrypt(handle,(PUCHAR)input,length,&info,NULL,0,output,length,&written,0);
end:
    if(handle) BCryptDestroyKey(handle);
    if(object) { SecureZeroMemory(object,objlen);free(object); }
    if(alg) BCryptCloseAlgorithmProvider(alg,0);
    return status==0 && written==length;
}

static int tpm_unwrap(const wchar_t *name,const unsigned char *wrapped,DWORD size,unsigned char key[32]) {
    NCRYPT_PROV_HANDLE provider=0;NCRYPT_KEY_HANDLE handle=0;DWORD got=0;
    BCRYPT_OAEP_PADDING_INFO padding={BCRYPT_SHA256_ALGORITHM,NULL,0};
    SECURITY_STATUS status=NCryptOpenStorageProvider(&provider,MS_PLATFORM_CRYPTO_PROVIDER,0);
    if(status==ERROR_SUCCESS) status=NCryptOpenKey(provider,&handle,name,0,NCRYPT_SILENT_FLAG);
    if(status==ERROR_SUCCESS) status=NCryptDecrypt(handle,(PBYTE)wrapped,size,&padding,key,32,&got,NCRYPT_PAD_OAEP_FLAG|NCRYPT_SILENT_FLAG);
    if(handle) NCryptFreeObject(handle);
    if(provider) NCryptFreeObject(provider);
    return status==ERROR_SUCCESS && got==32;
}
#endif
#endif
