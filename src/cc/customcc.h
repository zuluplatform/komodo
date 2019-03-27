/*
 to create a custom libcc.so:
 
 1. change "func0" and "func1" to method names that fit your custom cc. Of course, you can create more functions by adding another entry to RPC_FUNCS. there is not any practical limit to the number of methods.
 
 2. For each method make sure there is a UniValue function declaration and CUSTOM_DISPATCH has an if statement checking for it that calls the custom_func
 
 3. write the actual custom_func0, custom_func1 and custom_validate in customcc.cpp
 
 4. ./makecustom, which builds cclib.cpp with -DBUILD_CUSTOMCC and puts the libcc.so in ~/komodo/src and rebuilds komodod
 
 5. launch your chain with -ac_cclib=customcc -ac_cc=2
 
 */
 
std::string MYCCLIBNAME = (char *)"customcc";

#define EVAL_CUSTOM (EVAL_FAUCET2+1)
#define CUSTOM_TXFEE 10000

#define MYCCNAME "custom"

#define RPC_FUNCS    \
    { (char *)MYCCNAME, (char *)"chainlist", (char *)"<no args>", 0, 0, '0', EVAL_CUSTOM }, \
    { (char *)MYCCNAME, (char *)"chaininfo", (char *)"<txid>", 1, 1, '1', EVAL_CUSTOM }, \
    { (char *)MYCCNAME, (char *)"createchain", (char *)"<chain_params_JSON>", 0, 0, '2', EVAL_CUSTOM },

bool custom_validate(struct CCcontract_info *cp,int32_t height,Eval *eval,const CTransaction tx);
UniValue chainlist(struct CCcontract_info *cp,cJSON *params);
UniValue chaininfo(struct CCcontract_info *cp,cJSON *params);
UniValue createchain(struct CCcontract_info *cp,const char *params);

#define CUSTOM_DISPATCH \
if ( cp->evalcode == EVAL_CUSTOM ) \
{ \
    if ( strcmp(method,"chainlist") == 0 ) \
        return(chainlist(cp,params)); \
    else if ( strcmp(method,"chaininfo") == 0 ) \
        return(chaininfo(cp,params)); \
    else if ( strcmp(method,"createchain") == 0 ) \
        return(createchain(cp,jsonstr)); \
    else \
    { \
        result.push_back(Pair("result","error")); \
        result.push_back(Pair("error","invalid customcc method")); \
        result.push_back(Pair("method",method)); \
        return(result); \
    } \
}
