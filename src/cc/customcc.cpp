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

/*
Send burn amount to CC unspendable address with OP_RETURN containing chain params. 
 --> each txid is in a global list 
 --> min burn amount is 2000*COIN to prevent spam 
 --> doing chaininfo txid (from list) will give the chain params as a string in JSON format the same as assetchains.json. 
 */

// start of consensus code

CScript EncodeChainParams(std::string params)
{
    // self explanitory right? 
    CScript opret;
    opret << OP_RETURN << E_MARSHAL(ss << params);
    return(opret);
}

bool DecodeChainParams(const CScript &scriptPubKey, std::string &params)
{
    // self explanitory right? 
    std::vector<uint8_t> vopret;
    GetOpReturnData(scriptPubKey,vopret);
    if ( vopret.size() > 2 && E_UNMARSHAL(vopret,ss >> params) != 0 )
        return true;
    return false;
}

bool custom_validate(struct CCcontract_info *cp,int32_t height,Eval *eval,const CTransaction tx)
{
    // self explanitory right? 
    return eval->Invalid("chain vouts are unspendable");
}

// end of consensus code

UniValue custom_rawtxresult(UniValue &result,std::string rawtx,int32_t broadcastflag)
{
    CTransaction tx;
    if ( rawtx.size() > 0 )
    {
        result.push_back(Pair("hex",rawtx));
        if ( DecodeHexTx(tx,rawtx) != 0 )
        {
            if ( broadcastflag != 0 && myAddtomempool(tx) != 0 )
                RelayTransaction(tx);
            result.push_back(Pair("txid",tx.GetHash().ToString()));
            result.push_back(Pair("result","success"));
        } else result.push_back(Pair("error","decode hex"));
    } else result.push_back(Pair("error","couldnt finalize CCtx"));
    return(result);
}

std::string CreateChain(struct CCcontract_info *cp, std::string params, uint64_t supply)
{
    // Here we are taking the chain prams as a string from the RPC (not a json) and putting it into opreturn.
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    CPubKey mypk,chainpk; CScript opret;
    mypk = pubkey2pk(Mypubkey());
    chainpk = GetUnspendable(cp,0); // use the unspendable address to make 100% sure coins are always burnt! 
    if ( AddNormalinputs(mtx,mypk,supply+CUSTOM_TXFEE,64) > 0 )
    {
        mtx.vout.push_back(MakeCC1vout(EVAL_CUSTOM,supply,chainpk));
        opret = EncodeChainParams(params);
        return(FinalizeCCTx(0,cp,mtx,mypk,CUSTOM_TXFEE,opret));
    }
    return("");
}

UniValue createchain(struct CCcontract_info *cp,const char *params)
{
    UniValue result(UniValue::VOBJ);
    int32_t rawsupply; cJSON *jparams;
    uint64_t supply;
    std::string rawhex, tempstr;
    // checking if string pointer is not empty ( if it is it would crash if we tried to use it)
    if ( params != 0 )
    {
        // decode string into JSON
        if ( (jparams= cJSON_Parse(params)) != 0 )
        {
            // extract the ac_supply. 
            rawsupply = jint(jparams,(char*)"ac_supply");
            if ( rawsupply < 2000 )
            {
                // The only way to enforce that people can ONLY send greater than 2000 here is with a consensus rule 
                // that is not part of the CC, as CC validation only covers sends, so all we can do is filter any spam txns sent.
                result.push_back(Pair("error","supply is too small, min 2000 coins"));
                return result;
            }
            supply = rawsupply*COIN; // convert to sats.
        }
        tempstr.assign(params); // convert to std::string object (easier to work with)
        free_json(jparams); // free mem assigned to JSON! 
        rawhex = CreateChain(cp, tempstr, supply);
        return(custom_rawtxresult(result, rawhex, 0)); // send the tx, change 0 to 1 to make sending default behaviour. 
    } else result.push_back(Pair("error","no params entered."));
    return result;
}

UniValue chainlist(struct CCcontract_info *cp,cJSON *params)
{
    UniValue result(UniValue::VARR); std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    uint256 txid,hashBlock; CTransaction vintx; char str[65]; std::string sparams; cJSON *jparams; char *name;
    SetCCtxids(addressIndex,cp->unspendableCCaddr);
    // loop all unspents in the unspendable address
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++)
    {
        txid = it->first.txhash;
        if ( GetTransaction(txid,vintx,hashBlock,false) != 0 )
        {
            // Get the transactions that are actually elegible to create a chain only and ignore the rest! 
            int32_t numvouts = vintx.vout.size();
            if ( numvouts > 2 && numvouts < 4 && vintx.vout[0].nValue > 2000*COIN && vintx.vout[numvouts-1].scriptPubKey[0] == OP_RETURN )
            {
                if ( DecodeChainParams(vintx.vout[numvouts-1].scriptPubKey, sparams) )
                {
                    if ( (jparams= cJSON_Parse(sparams.c_str())) != 0 )
                    {
                        UniValue chain(UniValue::VOBJ);
                        name = jstr(jparams,(char*)"ac_name");
                        if ( name != 0 )
                        {
                            chain.push_back(Pair(name,uint256_str(str,txid)));
                            result.push_back(chain);
                        }
                        free_json(jparams); // free memory!
                    }
                }
            }
        }
    }
    return(result);
}

UniValue chaininfo(struct CCcontract_info *cp,cJSON *params)
{
    // This is much the same as the RPC above except it takes the txid as input and returns the entire params. 
    // Maybe we dont need this one and just return all params in the list command, although I think this is good. 
    UniValue result(UniValue::VOBJ); 
    CTransaction vintx; uint256 hashBlock,txid; std::string sparams; cJSON *jparams; char *name;
    if ( params != 0 && cJSON_GetArraySize(params) == 1 )
    {
        txid= juint256(jitem(params,0));
        if ( GetTransaction(txid,vintx,hashBlock,false) != 0 )
        {
            int32_t numvouts = vintx.vout.size();
            if ( numvouts > 2 && numvouts < 4 && vintx.vout[0].nValue > 2000*COIN && vintx.vout[numvouts-1].scriptPubKey[0] == OP_RETURN )
            {
                if ( DecodeChainParams(vintx.vout[numvouts-1].scriptPubKey, sparams) )
                {
                    if ( (jparams= cJSON_Parse(sparams.c_str())) != 0 )
                    {
                        name = jstr(jparams,(char*)"ac_name");
                        if ( name != 0 )
                            result.push_back(Pair(name,sparams));
                        else 
                            result.push_back(Pair("error","could not extract name"));
                        free_json(jparams);
                    } else result.push_back(Pair("error","chain params not valid json"));
                } else result.push_back(Pair("error","could not decode chain params"));
            } else result.push_back(Pair("error","transaction was not correct"));
        } else result.push_back(Pair("error","could not get transaction"));
    } else result.push_back(Pair("error","need txid as param"));
    return result;
}
