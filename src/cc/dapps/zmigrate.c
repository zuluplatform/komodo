/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include "cJSON.c"

/*
 z_migrate: the purpose of z_migrate is to make converting of all sprout outputs into sapling. the usage would be for the user to specify a sapling address and call z_migrate zsaddr, until it returns that there is nothing left to be done.
 
 its main functionality is quite similar to a z_mergetoaddress ANY_ZADDR -> onetime_taddr followed by a z_sendmany onetime_taddr -> zsaddr
 
 since the z_mergetoaddress will take time, it would just queue up an async operation. When it starts, it should see if there are any onetime_taddr with 10000.0001 funds in it, that is a signal for it to do the sapling tx and it can just do that without async as it is fast enough, especially with a taddr input. Maybe it limits itself to one,  or it does all possible taddr -> sapling as fast as it can. either is fine as it will be called over and over anyway.
 
 It might be that there is nothing to do, but some operations are pending. in that case it would return such a status. as soon as the operation finishes, there would be more work to do.
 
 the amount sent to the taddr, should be 10000.0001
 
 The GUI or user would be expected to generate a sapling address and then call z_migrate saplingaddr in a loop, until it returns that it is all done. this loop should pause for 10 seconds or so, if z_migrate is just waiting for opid to complete.
 */

bits256 zeroid;

char hexbyte(int32_t c)
{
    c &= 0xf;
    if ( c < 10 )
        return('0'+c);
    else if ( c < 16 )
        return('a'+c-10);
    else return(0);
}

int32_t _unhex(char c)
{
    if ( c >= '0' && c <= '9' )
        return(c - '0');
    else if ( c >= 'a' && c <= 'f' )
        return(c - 'a' + 10);
    else if ( c >= 'A' && c <= 'F' )
        return(c - 'A' + 10);
    return(-1);
}

int32_t is_hexstr(char *str,int32_t n)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
    {
        if ( n > 0 && i >= n )
            break;
        if ( _unhex(str[i]) < 0 )
            break;
    }
    if ( n == 0 )
        return(i);
    return(i == n);
}

int32_t unhex(char c)
{
    int32_t hex;
    if ( (hex= _unhex(c)) < 0 )
    {
        //printf("unhex: illegal hexchar.(%c)\n",c);
    }
    return(hex);
}

unsigned char _decode_hex(char *hex) { return((unhex(hex[0])<<4) | unhex(hex[1])); }

int32_t decode_hex(unsigned char *bytes,int32_t n,char *hex)
{
    int32_t adjust,i = 0;
    //printf("decode.(%s)\n",hex);
    if ( is_hexstr(hex,n) <= 0 )
    {
        memset(bytes,0,n);
        return(n);
    }
    if ( hex[n-1] == '\n' || hex[n-1] == '\r' )
        hex[--n] = 0;
    if ( hex[n-1] == '\n' || hex[n-1] == '\r' )
        hex[--n] = 0;
    if ( n == 0 || (hex[n*2+1] == 0 && hex[n*2] != 0) )
    {
        if ( n > 0 )
        {
            bytes[0] = unhex(hex[0]);
            printf("decode_hex n.%d hex[0] (%c) -> %d hex.(%s) [n*2+1: %d] [n*2: %d %c] len.%ld\n",n,hex[0],bytes[0],hex,hex[n*2+1],hex[n*2],hex[n*2],(long)strlen(hex));
        }
        bytes++;
        hex++;
        adjust = 1;
    } else adjust = 0;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
            bytes[i] = _decode_hex(&hex[i*2]);
    }
    //bytes[i] = 0;
    return(n + adjust);
}

int32_t init_hexbytes_noT(char *hexbytes,unsigned char *message,long len)
{
    int32_t i;
    if ( len <= 0 )
    {
        hexbytes[0] = 0;
        return(1);
    }
    for (i=0; i<len; i++)
    {
        hexbytes[i*2] = hexbyte((message[i]>>4) & 0xf);
        hexbytes[i*2 + 1] = hexbyte(message[i] & 0xf);
        //printf("i.%d (%02x) [%c%c]\n",i,message[i],hexbytes[i*2],hexbytes[i*2+1]);
    }
    hexbytes[len*2] = 0;
    //printf("len.%ld\n",len*2+1);
    return((int32_t)len*2+1);
}

long _stripwhite(char *buf,int accept)
{
    int32_t i,j,c;
    if ( buf == 0 || buf[0] == 0 )
        return(0);
    for (i=j=0; buf[i]!=0; i++)
    {
        buf[j] = c = buf[i];
        if ( c == accept || (c != ' ' && c != '\n' && c != '\r' && c != '\t' && c != '\b') )
            j++;
    }
    buf[j] = 0;
    return(j);
}

char *clonestr(char *str)
{
    char *clone;
    if ( str == 0 || str[0]==0)
    {
        printf("warning cloning nullstr.%p\n",str);
        //#ifdef __APPLE__
        //        while ( 1 ) sleep(1);
        //#endif
        str = (char *)"<nullstr>";
    }
    clone = (char *)malloc(strlen(str)+16);
    strcpy(clone,str);
    return(clone);
}

int32_t safecopy(char *dest,char *src,long len)
{
    int32_t i = -1;
    if ( src != 0 && dest != 0 && src != dest )
    {
        if ( dest != 0 )
            memset(dest,0,len);
        for (i=0; i<len&&src[i]!=0; i++)
            dest[i] = src[i];
        if ( i == len )
        {
            printf("safecopy: %s too long %ld\n",src,len);
            //printf("divide by zero! %d\n",1/zeroval());
#ifdef __APPLE__
            //getchar();
#endif
            return(-1);
        }
        dest[i] = 0;
    }
    return(i);
}

char *bits256_str(char hexstr[65],bits256 x)
{
    init_hexbytes_noT(hexstr,x.bytes,sizeof(x));
    return(hexstr);
}

int64_t conv_floatstr(char *numstr)
{
    double val,corr;
    val = atof(numstr);
    corr = (val < 0.) ? -0.50000000001 : 0.50000000001;
    return((int64_t)(val * SATOSHIDEN + corr));
}

char *nonportable_path(char *str)
{
    int32_t i;
    for (i=0; str[i]!=0; i++)
        if ( str[i] == '/' )
            str[i] = '\\';
    return(str);
}

char *portable_path(char *str)
{
#ifdef _WIN32
    return(nonportable_path(str));
#else
#ifdef __PNACL
    /*int32_t i,n;
     if ( str[0] == '/' )
     return(str);
     else
     {
     n = (int32_t)strlen(str);
     for (i=n; i>0; i--)
     str[i] = str[i-1];
     str[0] = '/';
     str[n+1] = 0;
     }*/
#endif
    return(str);
#endif
}

void *loadfile(char *fname,uint8_t **bufp,long *lenp,long *allocsizep)
{
    FILE *fp;
    long  filesize,buflen = *allocsizep;
    uint8_t *buf = *bufp;
    *lenp = 0;
    if ( (fp= fopen(portable_path(fname),"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        filesize = ftell(fp);
        if ( filesize == 0 )
        {
            fclose(fp);
            *lenp = 0;
            printf("loadfile null size.(%s)\n",fname);
            return(0);
        }
        if ( filesize > buflen )
        {
            *allocsizep = filesize;
            *bufp = buf = (uint8_t *)realloc(buf,(long)*allocsizep+64);
        }
        rewind(fp);
        if ( buf == 0 )
            printf("Null buf ???\n");
        else
        {
            if ( fread(buf,1,(long)filesize,fp) != (unsigned long)filesize )
                printf("error reading filesize.%ld\n",(long)filesize);
            buf[filesize] = 0;
        }
        fclose(fp);
        *lenp = filesize;
        //printf("loaded.(%s)\n",buf);
    } //else printf("OS_loadfile couldnt load.(%s)\n",fname);
    return(buf);
}

void *filestr(long *allocsizep,char *_fname)
{
    long filesize = 0; char *fname,*buf = 0; void *retptr;
    *allocsizep = 0;
    fname = malloc(strlen(_fname)+1);
    strcpy(fname,_fname);
    retptr = loadfile(fname,(uint8_t **)&buf,&filesize,allocsizep);
    free(fname);
    return(retptr);
}

char *send_curl(char *url,char *fname)
{
    long fsize; char curlstr[1024];
    sprintf(curlstr,"curl --url \"%s\" > %s",url,fname);
    system(curlstr);
    return(filestr(&fsize,fname));
}

cJSON *get_urljson(char *url,char *fname)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= send_curl(url,fname)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

//////////////////////////////////////////////
// start of dapp
//////////////////////////////////////////////

char *REFCOIN_CLI;

cJSON *get_komodocli(char *refcoin,char **retstrp,char *acname,char *method,char *arg0,char *arg1,char *arg2,char *arg3)
{
    long fsize; cJSON *retjson = 0; char cmdstr[32768],*jsonstr,fname[256];
    sprintf(fname,"/tmp/zmigrate.%s",method);
    if ( acname[0] != 0 )
    {
        if ( refcoin[0] != 0 && strcmp(refcoin,"KMD") != 0 )
            printf("unexpected: refcoin.(%s) acname.(%s)\n",refcoin,acname);
        sprintf(cmdstr,"./komodo-cli -ac_name=%s %s %s %s %s %s > %s\n",acname,method,arg0,arg1,arg2,arg3,fname);
    }
    else if ( strcmp(refcoin,"KMD") == 0 )
        sprintf(cmdstr,"./komodo-cli %s %s %s %s %s > %s\n",method,arg0,arg1,arg2,arg3,fname);
    else if ( REFCOIN_CLI != 0 && REFCOIN_CLI[0] != 0 )
    {
        sprintf(cmdstr,"%s %s %s %s %s %s > %s\n",REFCOIN_CLI,method,arg0,arg1,arg2,arg3,fname);
        //printf("ref.(%s) REFCOIN_CLI (%s)\n",refcoin,cmdstr);
    }
    system(cmdstr);
    *retstrp = 0;
    if ( (jsonstr= filestr(&fsize,fname)) != 0 )
    {
        jsonstr[strlen(jsonstr)-1]='\0';
        //fprintf(stderr,"%s -> jsonstr.(%s)\n",cmdstr,jsonstr);
        if ( (jsonstr[0] != '{' && jsonstr[0] != '[') || (retjson= cJSON_Parse(jsonstr)) == 0 )
            *retstrp = jsonstr;
        else free(jsonstr);
    }
    return(retjson);
}

bits256 komodobroadcast(char *refcoin,char *acname,cJSON *hexjson)
{
    char *hexstr,*retstr,str[65]; cJSON *retjson; bits256 txid;
    memset(txid.bytes,0,sizeof(txid));
    if ( (hexstr= jstr(hexjson,"hex")) != 0 )
    {
        if ( (retjson= get_komodocli(refcoin,&retstr,acname,"sendrawtransaction",hexstr,"","","")) != 0 )
        {
            //fprintf(stderr,"broadcast.(%s)\n",jprint(retjson,0));
            free_json(retjson);
        }
        else if ( retstr != 0 )
        {
            if ( strlen(retstr) >= 64 )
            {
                retstr[64] = 0;
                decode_hex(txid.bytes,32,retstr);
            }
            fprintf(stderr,"broadcast %s txid.(%s)\n",strlen(acname)>0?acname:refcoin,bits256_str(str,txid));
            free(retstr);
        }
    }
    return(txid);
}

bits256 sendtoaddress(char *refcoin,char *acname,char *destaddr,int64_t satoshis)
{
    char numstr[32],*retstr,str[65]; cJSON *retjson; bits256 txid;
    memset(txid.bytes,0,sizeof(txid));
    sprintf(numstr,"%.8f",(double)satoshis/SATOSHIDEN);
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"sendtoaddress",destaddr,numstr,"","")) != 0 )
    {
        fprintf(stderr,"unexpected sendrawtransaction json.(%s)\n",jprint(retjson,0));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        if ( strlen(retstr) >= 64 )
        {
            retstr[64] = 0;
            decode_hex(txid.bytes,32,retstr);
        }
        fprintf(stderr,"sendtoaddress %s %.8f txid.(%s)\n",destaddr,(double)satoshis/SATOSHIDEN,bits256_str(str,txid));
        free(retstr);
    }
    return(txid);
}

int32_t get_coinheight(char *refcoin,char *acname)
{
    cJSON *retjson; char *retstr; int32_t height=0;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"getblockchaininfo","","","","")) != 0 )
    {
        height = jint(retjson,"blocks");
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"%s get_coinheight.(%s) error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return(height);
}

bits256 get_coinblockhash(char *refcoin,char *acname,int32_t height)
{
    cJSON *retjson; char *retstr,heightstr[32]; bits256 hash;
    memset(hash.bytes,0,sizeof(hash));
    sprintf(heightstr,"%d",height);
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"getblockhash",heightstr,"","","")) != 0 )
    {
        fprintf(stderr,"unexpected blockhash json.(%s)\n",jprint(retjson,0));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        if ( strlen(retstr) >= 64 )
        {
            retstr[64] = 0;
            decode_hex(hash.bytes,32,retstr);
        }
        free(retstr);
    }
    return(hash);
}

bits256 get_coinmerkleroot(char *refcoin,char *acname,bits256 blockhash)
{
    cJSON *retjson; char *retstr,str[65]; bits256 merkleroot;
    memset(merkleroot.bytes,0,sizeof(merkleroot));
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"getblockheader",bits256_str(str,blockhash),"","","")) != 0 )
    {
        merkleroot = jbits256(retjson,"merkleroot");
        //fprintf(stderr,"got merkleroot.(%s)\n",bits256_str(str,merkleroot));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"%s %s get_coinmerkleroot error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return(merkleroot);
}

int32_t get_coinheader(char *refcoin,char *acname,bits256 *blockhashp,bits256 *merklerootp,int32_t prevheight)
{
    int32_t height = 0; char str[65];
    if ( prevheight == 0 )
        height = get_coinheight(refcoin,acname) - 20;
    else height = prevheight + 1;
    if ( height > 0 )
    {
        *blockhashp = get_coinblockhash(refcoin,acname,height);
        if ( bits256_nonz(*blockhashp) != 0 )
        {
            *merklerootp = get_coinmerkleroot(refcoin,acname,*blockhashp);
            if ( bits256_nonz(*merklerootp) != 0 )
                return(height);
        }
    }
    memset(blockhashp,0,sizeof(*blockhashp));
    memset(merklerootp,0,sizeof(*merklerootp));
    return(0);
}

cJSON *get_rawmempool(char *refcoin,char *acname)
{
    cJSON *retjson; char *retstr;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"getrawmempool","","","","")) != 0 )
    {
        //printf("mempool.(%s)\n",jprint(retjson,0));
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_rawmempool.(%s) error.(%s)\n",acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *get_addressutxos(char *refcoin,char *acname,char *coinaddr)
{
    cJSON *retjson; char *retstr,jsonbuf[256];
    if ( refcoin[0] != 0 && strcmp(refcoin,"KMD") != 0 )
        printf("warning: assumes %s has addressindex enabled\n",refcoin);
    sprintf(jsonbuf,"{\\\"addresses\\\":[\\\"%s\\\"]}",coinaddr);
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"getaddressutxos",jsonbuf,"","","")) != 0 )
    {
        //printf("addressutxos.(%s)\n",jprint(retjson,0));
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_addressutxos.(%s) error.(%s)\n",acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *get_rawtransaction(char *refcoin,char *acname,bits256 txid)
{
    cJSON *retjson; char *retstr,str[65];
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"getrawtransaction",bits256_str(str,txid),"1","","")) != 0 )
    {
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_rawtransaction.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *get_listunspent(char *refcoin,char *acname)
{
    cJSON *retjson; char *retstr,str[65];
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"listunspent","","","","")) != 0 )
    {
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_listunspent.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *z_listunspent(char *refcoin,char *acname)
{
    cJSON *retjson; char *retstr,str[65];
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"z_listunspent","","","","")) != 0 )
    {
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"z_listunspent.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *z_listoperationids(char *refcoin,char *acname)
{
    cJSON *retjson; char *retstr,str[65];
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"z_listoperationids","","","","")) != 0 )
    {
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"z_listoperationids.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *z_getoperationstatus(char *refcoin,char *acname,char *opid)
{
    cJSON *retjson; char *retstr,str[65],params[512];
    sprintf(params,"'[\"%s\"]'",opid);
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"z_getoperationstatus",params,"","","")) != 0 )
    {
        //printf("got status (%s)\n",jprint(retjson,0));
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"z_getoperationstatus.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *z_getoperationresult(char *refcoin,char *acname,char *opid)
{
    cJSON *retjson; char *retstr,str[65],params[512];
    sprintf(params,"'[\"%s\"]'",opid);
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"z_getoperationresult",params,"","","")) != 0 )
    {
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"z_getoperationresult.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return(0);
}

int32_t validateaddress(char *refcoin,char *acname,char *depositaddr, char* compare)
{
    cJSON *retjson; char *retstr; int32_t res=0;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"validateaddress",depositaddr,"","","")) != 0 )
    {
        if (is_cJSON_True(jobj(retjson,compare)) != 0 ) res=1;
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"validateaddress.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return (res);
}

int32_t z_validateaddress(char *refcoin,char *acname,char *depositaddr, char *compare)
{
    cJSON *retjson; char *retstr; int32_t res=0;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"z_validateaddress",depositaddr,"","","")) != 0 )
    {
        if (is_cJSON_True(jobj(retjson,compare)) != 0 )
            res=1;
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"z_validateaddress.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
    return (res);
}

int64_t z_getbalance(char *refcoin,char *acname,char *coinaddr)
{
    cJSON *retjson; char *retstr,cmpstr[64]; int64_t amount=0;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"z_getbalance",coinaddr,"","","")) != 0 )
    {
        fprintf(stderr,"z_getbalance.(%s) %s returned json!\n",refcoin,acname);
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        amount = atof(retstr) * SATOSHIDEN;
        sprintf(cmpstr,"%.8f",dstr(amount));
        if ( strcmp(retstr,cmpstr) != 0 )
            amount++;
        //printf("retstr %s -> %.8f\n",retstr,dstr(amount));
        free(retstr);
    }
    return (amount);
}

int32_t z_exportkey(char *privkey,char *refcoin,char *acname,char *zaddr)
{
    cJSON *retjson; char *retstr,cmpstr[64]; int64_t amount=0;
    privkey[0] = 0;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"z_exportkey",zaddr,"","","")) != 0 )
    {
        fprintf(stderr,"z_exportkey.(%s) %s returned json!\n",refcoin,acname);
        free_json(retjson);
        return(-1);
    }
    else if ( retstr != 0 )
    {
        //printf("retstr %s -> %.8f\n",retstr,dstr(amount));
        strcpy(privkey,retstr);
        free(retstr);
        return(0);
    }
}

int32_t getnewaddress(char *coinaddr,char *refcoin,char *acname)
{
    cJSON *retjson; char *retstr; int64_t amount=0; int32_t retval = -1;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"getnewaddress","","","","")) != 0 )
    {
        fprintf(stderr,"getnewaddress.(%s) %s returned json!\n",refcoin,acname);
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        strcpy(coinaddr,retstr);
        free(retstr);
        retval = 0;
    }
    return(retval);
}

int32_t z_getnewaddress(char *coinaddr,char *refcoin,char *acname,char *typestr)
{
    cJSON *retjson; char *retstr; int64_t amount=0; int32_t retval = -1;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"z_getnewaddress",typestr,"","","")) != 0 )
    {
        fprintf(stderr,"z_getnewaddress.(%s) %s returned json!\n",refcoin,acname);
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        strcpy(coinaddr,retstr);
        free(retstr);
        retval = 0;
    }
    return(retval);
}

int64_t find_onetime_amount(char *coinstr,char *coinaddr)
{
    cJSON *array,*item; int32_t i,n; char *addr; int64_t amount = 0;
    coinaddr[0] = 0;
    if ( (array= get_listunspent(coinstr,"")) != 0 )
    {
        //printf("got listunspent.(%s)\n",jprint(array,0));
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if (is_cJSON_False(jobj(item, "spendable")) != 0)
                {
                    continue;
                }
                if ( (addr= jstr(item,"address")) != 0 )
                {
                    strcpy(coinaddr,addr);
                    amount = z_getbalance(coinstr,"",coinaddr);
                    printf("found address.(%s) with amount %.8f\n",coinaddr,dstr(amount));
                    break;
                }
            }
        }
        free_json(array);
    }
    return(amount);
}

int64_t find_sprout_amount(char *coinstr,char *zcaddr)
{
    cJSON *array,*item; int32_t i,n; char *addr; int64_t amount = 0;
    zcaddr[0] = 0;
    if ( (array= z_listunspent(coinstr,"")) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (addr= jstr(item,"address")) != 0 && addr[0] == 'z' && addr[1] == 'c' )
                {
                    strcpy(zcaddr,addr);
                    amount = z_getbalance(coinstr,"",zcaddr);
                    printf("found address.(%s) with amount %.8f\n",zcaddr,dstr(amount));
                    break;
                }
            }
        }
        free_json(array);
    }
    return(amount);
}

void importaddress(char *refcoin,char *acname,char *depositaddr)
{
    cJSON *retjson; char *retstr;
    if ( (retjson= get_komodocli(refcoin,&retstr,acname,"importaddress",depositaddr,"","true","")) != 0 )
    {
        printf("importaddress.(%s)\n",jprint(retjson,0));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"importaddress.(%s) %s error.(%s)\n",refcoin,acname,retstr);
        free(retstr);
    }
}

int32_t z_sendmany(char *opidstr,char *coinstr,char *acname,char *srcaddr,char *destaddr,int64_t amount)
{
    cJSON *retjson; char *retstr,params[1024],addr[128]; int32_t retval = -1;
    sprintf(params,"'[{\"address\":\"%s\",\"amount\":%.8f}]'",destaddr,dstr(amount));
    sprintf(addr,"\"%s\"",srcaddr);
    printf("z_sendmany from.(%s) -> %s\n",srcaddr,params);
    if ( (retjson= get_komodocli(coinstr,&retstr,acname,"z_sendmany",addr,params,"","")) != 0 )
    {
        printf("unexpected json z_sendmany.(%s)\n",jprint(retjson,0));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"z_sendmany.(%s) -> opid.(%s)\n",coinstr,retstr);
        strcpy(opidstr,retstr);
        free(retstr);
        retval = 0;
    }
    return(retval);
}

int32_t z_mergetoaddress(char *opidstr,char *coinstr,char *acname,char *destaddr)
{
    cJSON *retjson; char *retstr,addr[128],*opstr; int32_t retval = -1;
    sprintf(addr,"[\\\"ANY_SPROUT\\\"]");
    if ( (retjson= get_komodocli(coinstr,&retstr,acname,"z_mergetoaddress",addr,destaddr,"","")) != 0 )
    {
        if ( (opstr= jstr(retjson,"opid")) != 0 )
            strcpy(opidstr,opstr);
        retval = jint(retjson,"remainingNotes");
        fprintf(stderr,"%s\n",jprint(retjson,0));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"z_mergetoaddress.(%s) -> opid.(%s)\n",coinstr,retstr);
        strcpy(opidstr,retstr);
        free(retstr);
    }
    return(retval);
}

int32_t empty_mempool(char *coinstr,char *acname)
{
    cJSON *array; int32_t n;
    if ( (array= get_rawmempool(coinstr,acname)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
            return(0);
        free_json(array);
        return(1);
    }
    return(-1);
}

cJSON *getinputarray(int64_t *totalp,cJSON *unspents,int64_t required)
{
    cJSON *vin,*item,*vins = cJSON_CreateArray(); int32_t i,n,v; int64_t satoshis; bits256 txid;
    *totalp = 0;
    if ( (n= cJSON_GetArraySize(unspents)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(unspents,i);
            satoshis = jdouble(item,"amount") * SATOSHIDEN;
            txid = jbits256(item,"txid");
            v = jint(item,"vout");
            if ( bits256_nonz(txid) != 0 )
            {
                vin = cJSON_CreateObject();
                jaddbits256(vin,"txid",txid);
                jaddnum(vin,"vout",v);
                jaddi(vins,vin);
                *totalp += satoshis;
                if ( (*totalp) >= required )
                    break;
            }
        }
    }
    return(vins);
}

int32_t tx_has_voutaddress(char *refcoin,char *acname,bits256 txid,char *coinaddr)
{
    cJSON *txobj,*vouts,*vout,*vins,*vin,*sobj,*addresses; char *addr,str[65]; int32_t i,j,n,numarray,retval = 0, hasvout=0;
    if ( (txobj= get_rawtransaction(refcoin,acname,txid)) != 0 )
    {
        if ( (vouts= jarray(&numarray,txobj,"vout")) != 0 )
        {
            for (i=0; i<numarray; i++)
            {
                if ((vout = jitem(vouts,i)) !=0 && (sobj= jobj(vout,"scriptPubKey")) != 0 )
                {
                    if ( (addresses= jarray(&n,sobj,"addresses")) != 0 )
                    {
                        for (j=0; j<n; j++)
                        {
                            addr = jstri(addresses,j);
                            if ( strcmp(addr,coinaddr) == 0 )
                            {
                                //fprintf(stderr,"found %s in %s v%d\n",coinaddr,bits256_str(str,txid),i);
                                hasvout = 1;
                                break;
                            }
                        }
                    }
                }
                if (hasvout==1) break;
            }
        }
        // if (hasvout==1 && (vins=jarray(&numarray,txobj,"vin"))!=0)
        // {
        //     for (int i=0;i<numarray;i++)
        //     {
        //         if ((vin=jitem(vins,i))!=0 && validateaddress(refcoin,acname,jstr(vin,"address"),"ismine")!=0)
        //         {
        //             retval=1;
        //             break;
        //         }
        //     }
        // }
        free_json(txobj);
    }
    return(hasvout);
}

int32_t have_pending_opid(char *coinstr,int32_t clearresults)
{
    cJSON *array,*status,*result; int32_t i,n,j,m,pending = 0; char *statusstr;
    if ( (array= z_listoperationids(coinstr,"")) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                if ( (status= z_getoperationstatus(coinstr,"",jstri(array,i))) != 0 )
                {
                    if ( (m= cJSON_GetArraySize(status)) > 0 )
                    {
                        for (j=0; j<m; j++)
                        {
                            if ( (statusstr= jstr(jitem(status,j),"status")) != 0 )
                            {
                                if ( strcmp(statusstr,"executing") == 0 )
                                {
                                    pending++;
                                    //printf("pending.%d\n",pending);
                                }
                                else if ( clearresults != 0 )
                                {
                                    if ( (result= z_getoperationresult(coinstr,"",jstri(array,i))) != 0 )
                                    {
                                        free_json(result);
                                    }
                                }
                            }
                        }
                    }
                    free_json(status);
                }
            }
        }
        free_json(array);
    }
    return(pending);
}

int32_t main(int32_t argc,char **argv)
{
    char buf[1024],*zsaddr,*coinstr;
    if ( argc != 3 )
    {
        printf("argc needs to be 3\n");
        return(-1);
    }
    if ( strcmp(argv[1],"KMD") == 0 )
    {
        REFCOIN_CLI = "./komodo-cli";
        coinstr = clonestr("KMD");
    }
    else
    {
        sprintf(buf,"./komodo-cli -ac_name=%s",argv[1]);
        REFCOIN_CLI = clonestr(buf);
        coinstr = clonestr(argv[1]);
    }
    if ( argv[2][0] != 'z' || argv[2][1] != 's' )
    {
        printf("invalid sapling address (%s)\n",argv[2]);
        return(-2);
    }
    if ( z_validateaddress(coinstr,"",argv[2],"ismine") == 0 )
    {
        printf("invalid sapling address (%s)\n",argv[2]);
        return(-3);
    }
    zsaddr = clonestr(argv[2]);
    printf("%s: %s %s\n",REFCOIN_CLI,coinstr,zsaddr);
    uint32_t lastopid; char coinaddr[64],privkey[1024],zcaddr[128],opidstr[128]; int32_t finished; int64_t amount,stdamount,txfee;
    //stdamount = 500 * SATOSHIDEN;
    txfee = 10000;
again:
    if ( z_getnewaddress(zcaddr,coinstr,"","sprout") == 0 )
    {
        z_exportkey(privkey,coinstr,"",zcaddr);
        printf("zcaddr.(%s) -> z_exportkey.(%s)\n",zcaddr,privkey);
        while ( 1 )
        {
            if ( have_pending_opid(coinstr,0) != 0 )
            {
                sleep(10);
                continue;
            }
            if ( z_mergetoaddress(opidstr,coinstr,"",zcaddr) <= 0 )
                break;
        }
    }
    printf("start processing zmigrate\n");
    lastopid = (uint32_t)time(NULL);
    finished = 0;
    while ( 1 )
    {
        if ( have_pending_opid(coinstr,0) != 0 )
        {
            sleep(10);
            continue;
        }
        if ( (amount= find_onetime_amount(coinstr,coinaddr)) > txfee )
        {
            // find taddr with funds and send all to zsaddr
            z_sendmany(opidstr,coinstr,"",coinaddr,zsaddr,amount-txfee);
            lastopid = (uint32_t)time(NULL);
            sleep(1);
            continue;
        }
        if ( (amount= find_sprout_amount(coinstr,zcaddr)) > txfee )
        {
            // generate taddr, send max of 10000.0001
            static int64_t lastamount,lastamount2,lastamount3,lastamount4,refamount = 5000 * SATOSHIDEN;
            stdamount = refamount;
            if ( amount == lastamount && amount == lastamount2 )
            {
                stdamount /= 10;
                if ( amount == lastamount3 && amount == lastamount4 )
                    stdamount /= 10;
            }
            if ( stdamount < SATOSHIDEN )
            {
                stdamount = SATOSHIDEN;
                refamount = SATOSHIDEN * 50;
            }
            if ( stdamount < refamount )
                refamount = stdamount;
            lastamount4 = lastamount3;
            lastamount3 = lastamount2;
            lastamount2 = lastamount;
            lastamount = amount;
            if ( amount > stdamount+2*txfee )
                amount = stdamount + 2*txfee;
            if ( getnewaddress(coinaddr,coinstr,"") == 0 )
            {
                z_sendmany(opidstr,coinstr,"",zcaddr,coinaddr,amount-txfee);
                lastopid = (uint32_t)time(NULL);
            } else printf("couldnt getnewaddress!\n");
            sleep(3);
            continue;
        }
        if ( time(NULL) > lastopid+600 )
            break;
    }
    sleep(3);
    printf("%s %s ALLDONE! taddr %.8f sprout %.8f mempool empty.%d\n",coinstr,zsaddr,dstr(find_onetime_amount(coinstr,coinaddr)),dstr(find_sprout_amount(coinstr,zcaddr)),empty_mempool(coinstr,""));
    sleep(3);
    if ( find_onetime_amount(coinstr,coinaddr) == 0 && find_sprout_amount(coinstr,zcaddr) == 0 )
    {
        printf("about to purge all opid results!. ctrl-C to abort, <enter> to proceed\n");
        getchar();
        have_pending_opid(coinstr,1);
    } else goto again;
    return(0);
}
