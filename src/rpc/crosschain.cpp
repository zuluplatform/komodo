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

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "crosschain.h"
#include "notarisationdb.h"
#include "importcoin.h"
#include "base58.h"
#include "consensus/validation.h"
#include "cc/eval.h"
#include "cc/utils.h"
#include "main.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "sync.h"
#include "util.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"

#include "key_io.h"
#include "cc/CCinclude.h"
#include "cc/CCtokens.h"

#include "merkleblock.h"

#include "cc/CCinclude.h"

#include <stdint.h>
#include <univalue.h>
#include <regex>

using namespace std;

extern std::string ASSETCHAINS_SELFIMPORT;
extern uint16_t ASSETCHAINS_CODAPORT, ASSETCHAINS_BEAMPORT;

int32_t komodo_MoM(int32_t *notarized_htp,uint256 *MoMp,uint256 *kmdtxidp,int32_t nHeight,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *kmdstartip,int32_t *kmdendip);
int32_t komodo_MoMoMdata(char *hexstr,int32_t hexsize,struct komodo_ccdataMoMoM *mdata,char *symbol,int32_t kmdheight,int32_t notarized_height);
struct komodo_ccdata_entry *komodo_allMoMs(int32_t *nump,uint256 *MoMoMp,int32_t kmdstarti,int32_t kmdendi);
uint256 komodo_calcMoM(int32_t height,int32_t MoMdepth);
extern std::string ASSETCHAINS_SELFIMPORT;
//uint256 Parseuint256(const char *hexstr);

CMutableTransaction MakeSelfImportSourceTx(CTxDestination &dest, int64_t amount);
int32_t GetSelfimportProof(const CMutableTransaction &sourceMtx, CMutableTransaction &templateMtx, ImportProof &proofNull);
std::string MakeGatewaysImportTx(uint64_t txfee, uint256 bindtxid, int32_t height, std::string refcoin, std::vector<uint8_t> proof, std::string rawburntx, int32_t ivout, uint256 burntxid);
void CheckBurnTxSource(uint256 burntxid, std::string &targetSymbol, uint32_t &targetCCid);
int32_t ensure_CCrequirements(uint8_t evalcode);
bool EnsureWalletIsAvailable(bool avoidException);

UniValue assetchainproof(const UniValue& params, bool fHelp)
{
    uint256 hash;

    // parse params and get notarisation data for tx
    if ( fHelp || params.size() != 1)
        throw runtime_error("assetchainproof needs a txid");

    hash = uint256S(params[0].get_str());
    CTransaction tx;
    auto proof = GetAssetchainProof(hash,tx);
    auto proofData = E_MARSHAL(ss << proof);
    return HexStr(proofData);
}


UniValue crosschainproof(const UniValue& params, bool fHelp)
{
    UniValue ret(UniValue::VOBJ);
    //fprintf(stderr,"crosschainproof needs to be implemented\n");
    return(ret);
}


/*UniValue height_MoM(const UniValue& params, bool fHelp)
{
    int32_t height,depth,notarized_height,MoMoMdepth,MoMoMoffset,kmdstarti,kmdendi; uint256 MoM,MoMoM,kmdtxid; uint32_t timestamp = 0; UniValue ret(UniValue::VOBJ); UniValue a(UniValue::VARR);
    if ( fHelp || params.size() != 1 )
        throw runtime_error("height_MoM height\n");
    LOCK(cs_main);
    height = atoi(params[0].get_str().c_str());
    if ( height <= 0 )
    {
        if ( chainActive.Tip() == 0 )
        {
            ret.push_back(Pair("error",(char *)"no active chain yet"));
            return(ret);
        }
        height = chainActive.Tip()->GetHeight();
    }
    //fprintf(stderr,"height_MoM height.%d\n",height);
    depth = komodo_MoM(&notarized_height,&MoM,&kmdtxid,height,&MoMoM,&MoMoMoffset,&MoMoMdepth,&kmdstarti,&kmdendi);
    ret.push_back(Pair("coin",(char *)(ASSETCHAINS_SYMBOL[0] == 0 ? "KMD" : ASSETCHAINS_SYMBOL)));
    ret.push_back(Pair("height",height));
    ret.push_back(Pair("timestamp",(uint64_t)timestamp));
    if ( depth > 0 )
    {
        ret.push_back(Pair("depth",depth));
        ret.push_back(Pair("notarized_height",notarized_height));
        ret.push_back(Pair("MoM",MoM.GetHex()));
        ret.push_back(Pair("kmdtxid",kmdtxid.GetHex()));
        if ( ASSETCHAINS_SYMBOL[0] != 0 )
        {
            ret.push_back(Pair("MoMoM",MoMoM.GetHex()));
            ret.push_back(Pair("MoMoMoffset",MoMoMoffset));
            ret.push_back(Pair("MoMoMdepth",MoMoMdepth));
            ret.push_back(Pair("kmdstarti",kmdstarti));
            ret.push_back(Pair("kmdendi",kmdendi));
        }
    } else ret.push_back(Pair("error",(char *)"no MoM for height"));
    
    return ret;
} */
int32_t komodo_notarized_height(int32_t *prevMoMheightp,uint256 *hashp,uint256 *txidp);

UniValue MoMoMdata(const UniValue& params, bool fHelp)
{
    if ( fHelp || params.size() != 3 )
        throw runtime_error("MoMoMdata symbol kmdheight ccid\n");
    UniValue ret(UniValue::VOBJ);
        
    char* symbol = (char *)params[0].get_str().c_str();
    int kmdheight = atoi(params[1].get_str().c_str());
    uint32_t ccid = atoi(params[2].get_str().c_str());
    ret.push_back(Pair("coin",symbol));
    ret.push_back(Pair("kmdheight",kmdheight));
    ret.push_back(Pair("ccid", (int) ccid));
    
    uint256 destNotarisationTxid;
    std::vector<uint256> moms;
    uint256 MoMoM = CalculateProofRoot(symbol, ccid, kmdheight, moms, destNotarisationTxid);
    UniValue valMoms(UniValue::VARR);
    for (int i=0; i<moms.size(); i++) valMoms.push_back(moms[i].GetHex());
    ret.push_back(Pair("MoMs", valMoms));
    ret.push_back(Pair("notarization_hash", destNotarisationTxid.GetHex()));
    ret.push_back(Pair("MoMoM", MoMoM.GetHex()));
    auto vmomomdata = E_MARSHAL(ss << MoMoM; ss << ((uint32_t)0));
    ret.push_back(Pair("data", HexStr(vmomomdata)));
    return ret;
}


UniValue calc_MoM(const UniValue& params, bool fHelp)
{
    int32_t height,MoMdepth; uint256 MoM; UniValue ret(UniValue::VOBJ); UniValue a(UniValue::VARR);
    if ( fHelp || params.size() != 2 )
        throw runtime_error("calc_MoM height MoMdepth\n");
    LOCK(cs_main);
    height = atoi(params[0].get_str().c_str());
    MoMdepth = atoi(params[1].get_str().c_str());
    if ( height <= 0 || MoMdepth <= 0 || MoMdepth >= height )
        throw runtime_error("calc_MoM illegal height or MoMdepth\n");
    //fprintf(stderr,"height_MoM height.%d\n",height);
    MoM = komodo_calcMoM(height,MoMdepth);
    ret.push_back(Pair("coin",(char *)(ASSETCHAINS_SYMBOL[0] == 0 ? "KMD" : ASSETCHAINS_SYMBOL)));
    ret.push_back(Pair("height",height));
    ret.push_back(Pair("MoMdepth",MoMdepth));
    ret.push_back(Pair("MoM",MoM.GetHex()));
    return ret;
}


UniValue migrate_converttoexport(const UniValue& params, bool fHelp)
{
    std::vector<uint8_t> rawproof; uint8_t *ptr; uint8_t i; uint32_t ccid = ASSETCHAINS_CC; uint64_t txfee = 10000;
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "migrate_converttoexport rawTx dest_symbol\n"
            "\nConvert a raw transaction to a cross-chain export.\n"
            "If neccesary, the transaction should be funded using fundrawtransaction.\n"
            "Finally, the transaction should be signed using signrawtransaction\n"
            "The finished export transaction, plus the payouts, should be passed to "
            "the \"migrate_createimporttransaction\" method to get the corresponding "
            "import transaction.\n"
            );

    if (ASSETCHAINS_CC < KOMODO_FIRSTFUNGIBLEID)
        throw runtime_error("-ac_cc < KOMODO_FIRSTFUNGIBLEID");

    if (ASSETCHAINS_SYMBOL[0] == 0)
        throw runtime_error("Must be called on assetchain");

    vector<uint8_t> txData(ParseHexV(params[0], "argument 1"));
    CMutableTransaction tx;
    if (!E_UNMARSHAL(txData, ss >> tx))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    string targetSymbol = params[1].get_str();
    if (targetSymbol.size() == 0 || targetSymbol.size() > 32)
        throw runtime_error("targetSymbol length must be >0 and <=32");

    if (strcmp(ASSETCHAINS_SYMBOL,targetSymbol.c_str()) == 0)
        throw runtime_error("cant send a coin to the same chain");
    
    /// Tested 44 vins p2pkh inputs as working. Set this at 25, but its a tx size limit. 
    // likely with a single RPC you can limit it by the size of tx.
    if (tx.vout.size() > 25)
        throw JSONRPCError(RPC_TYPE_ERROR, "Cannot have more than 50 vins, transaction too large.");

    CAmount burnAmount = 0;
    
    for (int i=0; i<tx.vout.size(); i++) burnAmount += tx.vout[i].nValue;
    if (burnAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Cannot export a negative or zero value.");
    // This is due to MAX MONEY in target. We set it at min 1 million coins, so you cant export more than 1 million,
    // without knowing the MAX money on the target this was the easiest solution. 
    if (burnAmount > 1000000LL*COIN)
        throw JSONRPCError(RPC_TYPE_ERROR, "Cannot export more than 1 million coins per export.");

    rawproof.resize(strlen(ASSETCHAINS_SYMBOL));
    ptr = rawproof.data();
    for (i=0; i<rawproof.size(); i++)
        ptr[i] = ASSETCHAINS_SYMBOL[i];
    CTxOut burnOut = MakeBurnOutput(burnAmount+txfee, ccid, targetSymbol, tx.vout,rawproof);
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("payouts", HexStr(E_MARSHAL(ss << tx.vout))));
    tx.vout.clear();
    tx.vout.push_back(burnOut);
    ret.push_back(Pair("exportTx", HexStr(E_MARSHAL(ss << tx))));
    return ret;
}

// creates burn tx as an alternative to 'migrate_converttoexport()'
UniValue migrate_createburntransaction(const UniValue& params, bool fHelp)
{
    UniValue ret(UniValue::VOBJ);
    //uint8_t *ptr; 
    //uint8_t i; 
    uint32_t ccid = ASSETCHAINS_CC; 
    int64_t txfee = 10000;

    if (fHelp || params.size() != 3 && params.size() != 4)
        throw runtime_error(
            "migrate_createburntransaction dest_symbol dest_addr amount [tokenid]\n"
            "\nCreates a raw burn transaction to make a cross-chain coin or non-fungible token transfer.\n"
            "The parameters:\n"
            "dest_symbol   destination chain ac_name\n"
            "dest_addr     address on the destination chain where coins are to be sent or pubkey if tokens are to be sent\n"
            "amount        amount in coins to be burned on the source chain and sent to the destination address/pubkey on the destination chain, for tokens should be equal to 1\n"
            "tokenid       token id, if tokens are transferred (optional). Only non-fungible tokens are supported\n"
            "\n"
            "The transaction should be sent using sendrawtransaction to the source chain\n"
            "The finished burn transaction and payouts should be also passed to "
            "the \"migrate_createimporttransaction\" method to get the corresponding import transaction.\n"
        );

    if (ASSETCHAINS_CC < KOMODO_FIRSTFUNGIBLEID)
        throw runtime_error("-ac_cc < KOMODO_FIRSTFUNGIBLEID");

    if (ASSETCHAINS_SYMBOL[0] == 0)
        throw runtime_error("Must be called on assetchain");

    // if -pubkey not set it sends change to null pubkey. 
    // we need a better way to return errors from this function!
    if (ensure_CCrequirements(225) < 0)
        throw runtime_error("You need to set -pubkey, or run setpukbey RPC, or imports are disabled on this chain.");

//    vector<uint8_t> txData(ParseHexV(params[0], "argument 1"));
   // CMutableTransaction tx;
//    if (!E_UNMARSHAL(txData, ss >> tx))
//        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    string targetSymbol = params[0].get_str();
    if (targetSymbol.size() == 0 || targetSymbol.size() > 32)
        throw runtime_error("targetSymbol length must be >0 and <=32");

    if (strcmp(ASSETCHAINS_SYMBOL, targetSymbol.c_str()) == 0)
        throw runtime_error("cant send a coin to the same chain");

    std::string dest_addr_or_pubkey = params[1].get_str();

    CAmount burnAmount;
    if(params.size() == 3)
        burnAmount = (CAmount)( atof(params[2].get_str().c_str()) * COIN + 0.00000000499999 );
    else
        burnAmount = atoll(params[2].get_str().c_str());

//    for (int i = 0; i<tx.vout.size(); i++) burnAmount += tx.vout[i].nValue;
    if (burnAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Cannot export a negative or zero value.");
    if (burnAmount > 1000000LL * COIN)
        throw JSONRPCError(RPC_TYPE_ERROR, "Cannot export more than 1 million coins per export.");

    uint256 tokenid = zeroid;
    if( params.size() == 4 )
        tokenid = Parseuint256(params[3].get_str().c_str());

    // check non-fungible tokens amount
    if( !tokenid.IsNull() && burnAmount != 1 )
        throw JSONRPCError(RPC_TYPE_ERROR, "For tokens amount should be equal to 1, only non-fungible tokens are supported.");

    CPubKey myPubKey = Mypubkey();
    struct CCcontract_info *cpTokens, C;
    cpTokens = CCinit(&C, EVAL_TOKENS);

    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());

    CScript scriptPubKey;
    const std::string chainSymbol(ASSETCHAINS_SYMBOL);
    std::vector<uint8_t> rawproof; //(chainSymbol.begin(), chainSymbol.end());

    if (tokenid.IsNull()) {        // coins
        int64_t inputs;
        if ((inputs = AddNormalinputs(mtx, myPubKey, burnAmount + txfee, 60)) == 0) {
            throw runtime_error("Cannot find normal inputs\n");
        }

        CTxDestination txdest = DecodeDestination(dest_addr_or_pubkey.c_str());
        scriptPubKey = GetScriptForDestination(txdest);
        if (!scriptPubKey.IsPayToPublicKeyHash()) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Incorrect destination addr.");
        }
        mtx.vout.push_back(CTxOut(burnAmount, scriptPubKey));               // 'model' vout
        ret.push_back(Pair("payouts", HexStr(E_MARSHAL(ss << mtx.vout))));  // save 'model' vout

        rawproof = E_MARSHAL(ss << chainSymbol); // add src chain name 

        CTxOut burnOut = MakeBurnOutput(burnAmount, ccid, targetSymbol, mtx.vout, rawproof);  //make opret with burned amount

        mtx.vout.clear();               // remove 'model' vout

        int64_t change = inputs - burnAmount;
        if (change != 0)
            mtx.vout.push_back(CTxOut(change, CScript() << ParseHex(HexStr(myPubKey)) << OP_CHECKSIG)); // make change here to prevent it from making in FinalizeCCtx

        mtx.vout.push_back(burnOut);    // mtx now has only burned vout (that is, amount sent to OP_RETURN making it unspendable)
        std::string exportTxHex = FinalizeCCTx(0, cpTokens, mtx, myPubKey, txfee, CScript());  // no change no opret

    }
    else {   // tokens
        CTransaction tokenbasetx;
        uint256 hashBlock;
        vscript_t vopretNonfungible;
        vscript_t vopretBurnData;
        std::vector<uint8_t> vorigpubkey, vdestpubkey;
        std::string name, description;
        std::vector<std::pair<uint8_t, vscript_t>>  oprets;

        if (!myGetTransaction(tokenid, tokenbasetx, hashBlock))
            throw runtime_error("Could not load token creation tx\n");

        // check if it is non-fungible tx and get its second evalcode from non-fungible payload
        if (tokenbasetx.vout.size() == 0)
            throw runtime_error("No vouts in token tx\n");

        if (DecodeTokenCreateOpRet(tokenbasetx.vout.back().scriptPubKey, vorigpubkey, name, description, oprets) != 'c')
            throw runtime_error("Incorrect token creation tx\n");
        GetOpretBlob(oprets, OPRETID_NONFUNGIBLEDATA, vopretNonfungible);
        if (vopretNonfungible.empty())
            throw runtime_error("No non-fungible token data\n");

        uint8_t destEvalCode = vopretNonfungible.begin()[0];
        vdestpubkey = ParseHex(dest_addr_or_pubkey);
        CPubKey destPubKey = pubkey2pk(vdestpubkey);
        if (!destPubKey.IsValid())
            throw runtime_error("Invalid destination pubkey\n");

        int64_t inputs;
        if ((inputs = AddNormalinputs(mtx, myPubKey, txfee, 1)) == 0)
            throw runtime_error("No normal input found for txfee\n");

        if (AddTokenCCInputs(cpTokens, mtx, myPubKey, tokenid, burnAmount, 1) != burnAmount)
            throw runtime_error("No non-fungible token input found for your pubkey\n");

        // destination vouts (payouts) which would create the import tx with non-fungible token:
        mtx.vout.push_back(MakeCC1vout(EVAL_TOKENS, txfee, GetUnspendable(cpTokens, NULL)));  // new marker to token cc addr, burnable and validated, vout position now changed to 0 (from 1)
        mtx.vout.push_back(MakeTokensCC1vout(destEvalCode, burnAmount, destPubKey));
        mtx.vout.push_back(CTxOut((CAmount)0, EncodeTokenCreateOpRet('c', vorigpubkey, name, description, 
            std::vector<std::pair<uint8_t, vscript_t>> {std::make_pair(OPRETID_NONFUNGIBLEDATA, vopretNonfungible)})));  // make token import opret
        ret.push_back(Pair("payouts", HexStr(E_MARSHAL(ss << mtx.vout))));  // save payouts for import tx

        rawproof = E_MARSHAL(ss << chainSymbol << tokenbasetx); // add src chain name and token creation tx

        CTxOut burnOut = MakeBurnOutput(0, ccid, targetSymbol, mtx.vout, rawproof);  //make opret with amount=0 because tokens are burned, not coins (see next vout) 

        mtx.vout.clear();  // remove payouts
        mtx.vout.push_back(MakeTokensCC1vout(destEvalCode, burnAmount, pubkey2pk(ParseHex(CC_BURNPUBKEY))));    // burn tokens
                                                                                                                
        int64_t change = inputs - txfee;
        if (change != 0)
            mtx.vout.push_back(CTxOut(change, CScript() << ParseHex(HexStr(myPubKey)) << OP_CHECKSIG));         // make change here to prevent it from making in FinalizeCCtx

        std::vector<CPubKey> voutTokenPubkeys;
        voutTokenPubkeys.push_back(pubkey2pk(ParseHex(CC_BURNPUBKEY)));  // maybe we do not need this because ccTokens has the const for burn pubkey

        GetOpReturnData(burnOut.scriptPubKey, vopretBurnData);
        mtx.vout.push_back(CTxOut(0, EncodeTokenOpRet(tokenid, voutTokenPubkeys, std::make_pair(OPRETID_BURNDATA, vopretBurnData))));  //opret
    }

    std::string burnTxHex = FinalizeCCTx(0, cpTokens, mtx, myPubKey, txfee, CScript()); //no change, no opret
    ret.push_back(Pair("BurnTxHex", burnTxHex));
    return ret;
}

// util func to check burn tx and source chain params
void CheckBurnTxSource(uint256 burntxid, UniValue &info) {

    CTransaction burnTx;
    uint256 blockHash;

    if (!GetTransaction(burntxid, burnTx, blockHash, true))
        throw std::runtime_error("Cannot find burn transaction");

    if (blockHash.IsNull())
        throw std::runtime_error("Burn tx still in mempool");

    uint256 payoutsHash;
    std::string targetSymbol;
    uint32_t targetCCid;
    std::vector<uint8_t> rawproof;

    if (!UnmarshalBurnTx(burnTx, targetSymbol, &targetCCid, payoutsHash, rawproof))
        throw std::runtime_error("Cannot unmarshal burn tx data");

    vscript_t vopret;
    std::string sourceSymbol;
    CTransaction tokenbasetx;
    uint256 tokenid = zeroid;

    if (burnTx.vout.size() > 1 && GetOpReturnData(burnTx.vout.back().scriptPubKey, vopret) && !vopret.empty())   {
        if (vopret.begin()[0] == EVAL_TOKENS) {
            if (!E_UNMARSHAL(rawproof, ss >> sourceSymbol; ss >> tokenbasetx))
                throw std::runtime_error("Cannot unmarshal rawproof for tokens");

            uint8_t evalCode;
            uint256 tokenid;
            std::vector<CPubKey> voutPubkeys;
            std::vector<std::pair<uint8_t, vscript_t>> oprets;
            if( DecodeTokenOpRet(burnTx.vout.back().scriptPubKey, evalCode, tokenid, voutPubkeys, oprets) == 0 )
                throw std::runtime_error("Cannot decode token opret in burn tx");

            if( tokenid != tokenbasetx.GetHash() )
                throw std::runtime_error("Incorrect tokenbase tx");
        }
        else {
            if (!E_UNMARSHAL(rawproof, ss >> sourceSymbol))
                throw std::runtime_error("Cannot unmarshal rawproof for coins");
        }
    }
    else {
        throw std::runtime_error("No opret in burn tx");
    }

    if (sourceSymbol != ASSETCHAINS_SYMBOL)
        throw std::runtime_error("Incorrect source chain in rawproof");

    if (targetCCid != ASSETCHAINS_CC)
        throw std::runtime_error("Incorrect CCid in burn tx");

    if (targetSymbol == ASSETCHAINS_SYMBOL)
        throw std::runtime_error("Must not be called on the destination chain");

    // fill info to return for the notary operator (if manual notarization) or user
    info.push_back(Pair("SourceSymbol", sourceSymbol));
    info.push_back(Pair("TargetSymbol", targetSymbol));
    info.push_back(Pair("TargetCCid", std::to_string(targetCCid)));
    if (!tokenid.IsNull())
        info.push_back(Pair("tokenid", tokenid.GetHex()));

}

/*
 * The process to migrate funds from a chain to chain
 *
 * 1.Create a transaction on assetchain (deprecated):
 * 1.1 generaterawtransaction
 * 1.2 migrate_converttoexport
 * 1.3 fundrawtransaction
 * 1.4 signrawtransaction
 *
 * alternatively, burn (export) transaction may be created with this new rpc call:
 * 1. migrate_createburntransaction
 *
 * next steps:
 * 2. migrate_createimporttransaction
 * 3. migrate_completeimporttransaction
 */

UniValue migrate_createimporttransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2)
        throw runtime_error("migrate_createimporttransaction burnTx payouts [notarytxid-1]..[notarytxid-N]\n\n"
                "Create an importTx given a burnTx and the corresponding payouts, hex encoded\n"
                "optional notarytxids are txids of notary operator proofs of burn tx existense (from destination chain).\n"
                "Do not make subsequent call to migrate_completeimporttransaction if notary txids are set");

    if (ASSETCHAINS_CC < KOMODO_FIRSTFUNGIBLEID)
        throw runtime_error("-ac_cc < KOMODO_FIRSTFUNGIBLEID");

    if (ASSETCHAINS_SYMBOL[0] == 0)
        throw runtime_error("Must be called on assetchain");

    vector<uint8_t> txData(ParseHexV(params[0], "argument 1"));

    CTransaction burnTx;
    if (!E_UNMARSHAL(txData, ss >> burnTx))
        throw runtime_error("Couldn't parse burnTx");

    if( burnTx.vin.size() == 0 )
        throw runtime_error("No vins in the burnTx");

    if (burnTx.vout.size() == 0)
        throw runtime_error("No vouts in the burnTx");


    vector<CTxOut> payouts;
    if (!E_UNMARSHAL(ParseHexV(params[1], "argument 2"), ss >> payouts))
        throw runtime_error("Couldn't parse payouts");

    ImportProof importProof;
    if (params.size() == 2) {  // standard MoMoM based notarization
        // get MoM import proof
        importProof = ImportProof(GetAssetchainProof(burnTx.GetHash(), burnTx));
    }
    else   {  // notarization by manual operators notary tx
        UniValue info(UniValue::VOBJ);
        CheckBurnTxSource(burnTx.GetHash(), info);

        // get notary import proof
        std::vector<uint256> notaryTxids;
        for (int i = 2; i < params.size(); i++) {
            uint256 txid = Parseuint256(params[i].get_str().c_str());
            if (txid.IsNull())
                throw runtime_error("Incorrect notary approval txid");
            notaryTxids.push_back(txid);
        }
        importProof = ImportProof(notaryTxids);
    }

    CTransaction importTx = MakeImportCoinTransaction(importProof, burnTx, payouts);

    std::string importTxHex = HexStr(E_MARSHAL(ss << importTx));
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("ImportTxHex", importTxHex));
    return ret;
}

UniValue migrate_completeimporttransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error("migrate_completeimporttransaction importTx [offset]\n\n"
                "Takes a cross chain import tx with proof generated on assetchain "
                "and extends proof to target chain proof root\n"
                "offset is optional, use it to increase the used KMD height, use when import fails.");

    if (ASSETCHAINS_SYMBOL[0] != 0)
        throw runtime_error("Must be called on KMD");

    CTransaction importTx;
    if (!E_UNMARSHAL(ParseHexV(params[0], "argument 1"), ss >> importTx))
        throw runtime_error("Couldn't parse importTx");
    
    int32_t offset = 0;
    if ( params.size() == 2 )
        offset = params[1].get_int();

    CompleteImportTransaction(importTx, offset);

    std::string importTxHex = HexStr(E_MARSHAL(ss << importTx));
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("ImportTxHex", importTxHex));
    return ret;
}

/*
* Alternate coin migration solution if MoMoM migration has failed
*
* The workflow:
* On the source chain user calls migrate_createburntransaction, sends the burn tx to the chain and sends its txid and the source chain name to the notary operators (off-chain)
* the notary operators call migrate_checkburntransactionsource on the source chain
* on the destination chain the notary operators call migrate_createnotaryapprovaltransaction and pass the burn txid and txoutproof received from the previous call, 
* the notary operators send the approval transactions to the chain and send their txids to the user (off-chain)
* on the source chain the user calls migrate_createimporttransaction and passes to it notary txids as additional parameters
* then the user sends the import transaction to the destination chain (where the notary approvals will be validated)
*/

// checks if burn tx exists and params stored in the burn tx match to the source chain
// returns txproof
// run it on the source chain
UniValue migrate_checkburntransactionsource(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("migrate_checkburntransactionsource burntxid\n\n"
            "checks if params stored in the burn tx match to its tx chain");

    if (ASSETCHAINS_SYMBOL[0] == 0)
        throw runtime_error("Must be called on asset chain");

    uint256 burntxid = Parseuint256(params[0].get_str().c_str());
    UniValue result(UniValue::VOBJ);
    CheckBurnTxSource(burntxid, result);  // check and get burn tx data

    // get tx proof for burn tx
    UniValue nextparams(UniValue::VARR);
    UniValue txids(UniValue::VARR);
    txids.push_back(burntxid.GetHex());
    nextparams.push_back(txids);
    result.push_back(Pair("TxOutProof", gettxoutproof(nextparams, false)));  // get txoutproof

    return result;
}

// creates a tx for the dest chain with txproof
// used as a momom-backup manual import solution
// run it on the dest chain
UniValue migrate_createnotaryapprovaltransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error("migrate_createnotaryapprovaltransaction burntxid txoutproof\n\n"
            "Creates a tx for destination chain with burn tx proof\n"
            "txoutproof should be retrieved by komodo-cli migrate_checkburntransactionsource call on the source chain\n" );

    if (ASSETCHAINS_SYMBOL[0] == 0)
        throw runtime_error("Must be called on asset chain");

    uint256 burntxid = Parseuint256(params[0].get_str().c_str());
    if (burntxid.IsNull())
        throw runtime_error("Couldn't parse burntxid or it is null");

    std::vector<uint8_t> proofData = ParseHex(params[1].get_str());
    CMerkleBlock merkleBlock;
    std::vector<uint256> prooftxids;
    if (!E_UNMARSHAL(proofData, ss >> merkleBlock))
        throw runtime_error("Couldn't parse txoutproof");

    merkleBlock.txn.ExtractMatches(prooftxids);
    if (std::find(prooftxids.begin(), prooftxids.end(), burntxid) == prooftxids.end())
        throw runtime_error("No burntxid in txoutproof");

    const int64_t txfee = 10000;
    struct CCcontract_info *cpDummy, C;
    cpDummy = CCinit(&C, EVAL_TOKENS);  // just for FinalizeCCtx to work 

    // creating a tx with proof:
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    if (AddNormalinputs(mtx, Mypubkey(), txfee*2, 4) == 0) 
        throw runtime_error("Cannot find normal inputs\n");
    
    mtx.vout.push_back(CTxOut(txfee, CScript() << ParseHex(HexStr(Mypubkey())) << OP_CHECKSIG));
    std::string notaryTxHex = FinalizeCCTx(0, cpDummy, mtx, Mypubkey(), txfee, CScript() << OP_RETURN << E_MARSHAL(ss << proofData;));

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("NotaryTxHex", notaryTxHex));
    return result;
}

// creates a source 'quasi-burn' tx for AC_PUBKEY
// run it on the same asset chain
UniValue selfimport(const UniValue& params, bool fHelp)
{
    UniValue result(UniValue::VOBJ);
    std::string destaddr;
    std::string source; 
    std::string sourceTxHex;
    std::string importTxHex;
    CTransaction burnTx; 
    CTxOut burnOut; 
    uint64_t burnAmount; 
    uint256 sourcetxid, blockHash; 
	std::vector<CTxOut> vouts; 
	std::vector<uint8_t> rawproof;

    if ( ASSETCHAINS_SELFIMPORT.size() == 0 )
        throw runtime_error("selfimport only works on -ac_import chains");

    if (fHelp || params.size() != 2)
        throw runtime_error("selfimport destaddr amount\n"
                  //TODO:   "or selfimport rawburntx burntxid {nvout|\"find\"} rawproof source bindtxid height} \n"
                            "\ncreates self import coin transaction");

    destaddr = params[0].get_str();
    burnAmount = atof(params[1].get_str().c_str()) * COIN + 0.00000000499999;

    source = ASSETCHAINS_SELFIMPORT;   //defaults to -ac_import=... param
    /* TODO for gateways:
    if ( params.size() >= 5 )
    {
        rawproof = ParseHex(params[4].get_str().c_str());
        if ( params.size() == 6 )
            source = params[5].get_str();
    }  */


    if (source == "BEAM")
    {
        if (ASSETCHAINS_BEAMPORT == 0)
            return(-1);
        // confirm via ASSETCHAINS_BEAMPORT that burnTx/hash is a valid BEAM burn
        // return(0);
        return -1;
    }
    else if (source == "CODA")
    {
        if (ASSETCHAINS_CODAPORT == 0)
            return(-1);
        // confirm via ASSETCHAINS_CODAPORT that burnTx/hash is a valid CODA burn
        // return(0);
        return -1;
    }
    else if (source == "PUBKEY")
    {
        ImportProof proofNull;
        CTxDestination dest = DecodeDestination(destaddr.c_str());
        CMutableTransaction sourceMtx = MakeSelfImportSourceTx(dest, burnAmount);  // make self-import source tx
        vscript_t rawProofEmpty;
        
        CMutableTransaction templateMtx;
        // prepare self-import 'quasi-burn' tx and also create vout for import tx (in mtx.vout):
        if (GetSelfimportProof(sourceMtx, templateMtx, proofNull) < 0)
            throw std::runtime_error("Failed creating selfimport template tx");

        vouts = templateMtx.vout;
        burnOut = MakeBurnOutput(burnAmount, 0xffffffff, ASSETCHAINS_SELFIMPORT, vouts, rawProofEmpty);
        templateMtx.vout.clear();
        templateMtx.vout.push_back(burnOut);	// burn tx has only opret with vouts and optional proof

        burnTx = templateMtx;					// complete the creation of 'quasi-burn' tx

        sourceTxHex = HexStr(E_MARSHAL(ss << sourceMtx));
        importTxHex = HexStr(E_MARSHAL(ss << MakeImportCoinTransaction(proofNull, burnTx, vouts)));
      
        result.push_back(Pair("SourceTxHex", sourceTxHex));
        result.push_back(Pair("ImportTxHex", importTxHex));
 
        return result;
    }
    else if (source == ASSETCHAINS_SELFIMPORT)
    {
        /////////////////////////////////////////////////
        throw std::runtime_error("not implemented yet\n");
        int32_t ivout = 0;

        //if (params.size() != 8) 
        //    throw runtime_error("use \'selfimport rawburntx burntxid nvout rawproof source bindtxid height\' to import from a coin chain\n");
       
        uint256 bindtxid = Parseuint256((char *)params[6].get_str().c_str()); 
        int32_t height = atoi((char *)params[7].get_str().c_str());

        // source is external coin is the assetchains symbol in the burnTx OP_RETURN
        // burnAmount, rawtx and rawproof should be enough for gatewaysdeposit equivalent
        importTxHex = MakeGatewaysImportTx(0, bindtxid, height, source, rawproof, sourceTxHex, ivout, sourcetxid);

        result.push_back(Pair("ImportTxHex", importTxHex));
        result.push_back(Pair("UsedRawtxVout", ivout));   // notify user about the used vout of rawtx
    }
    return result;
}

UniValue getNotarisationsForBlock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("getNotarisationsForBlock blockHash\n\n"
                "Takes a block hash and returns notarisation transactions "
                "within the block");

    uint256 blockHash = uint256S(params[0].get_str());

    NotarisationsInBlock nibs;
    GetBlockNotarisations(blockHash, nibs);
    UniValue out(UniValue::VARR);
    BOOST_FOREACH(const Notarisation& n, nibs)
    {
        UniValue item(UniValue::VARR);
        item.push_back(n.first.GetHex());
        item.push_back(HexStr(E_MARSHAL(ss << n.second)));
        out.push_back(item);
    }
    return out;
}


UniValue scanNotarisationsDB(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error("scanNotarisationsDB blockHeight symbol [blocksLimit=1440]\n\n"
                "Scans notarisationsdb backwards from height for a notarisation"
                " of given symbol");
    int height = atoi(params[0].get_str().c_str());
    std::string symbol = params[1].get_str().c_str();

    int limit = 1440;
    if (params.size() > 2) {
        limit = atoi(params[2].get_str().c_str());
    }

    if (height == 0) {
        height = chainActive.Height();
    }

    Notarisation nota;
    int matchedHeight = ScanNotarisationsDB(height, symbol, limit, nota);
    if (!matchedHeight) return NullUniValue;
    UniValue out(UniValue::VOBJ);
    out.pushKV("height", matchedHeight);
    out.pushKV("hash", nota.first.GetHex());
    out.pushKV("opreturn", HexStr(E_MARSHAL(ss << nota.second)));
    return out;
}

UniValue getimports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getimports \"hash|height\"\n"
            "\n\n"
            "\nResult:\n"
            "{\n"
            "  \"imports\" : [                  (json array)\n"
            "       \"transactionid\" : {       (json object)\n"
            "           \"value\" :             (numeric)\n"
            "           \"address\" :           (string)\n"
            "           \"export\" {                (json object)\n"
            "               \"txid\" :              (string)\n"
            "               \"value\" :             (numeric)\n"
            "               \"chain\" :             (string)\n"
            "           }\n"
            "       }"
            "  ]\n"
            "  \"TotalImported\" :              (numeric)\n"
            "  \"time\" :                       (numeric)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getimports", "\"00000000febc373a1da2bd9f887b105ad79ddc26ac26c2b28652d64e5207c5b5\"")
            + HelpExampleRpc("getimports", "\"00000000febc373a1da2bd9f887b105ad79ddc26ac26c2b28652d64e5207c5b5\"")
            + HelpExampleCli("getimports", "12800")
            + HelpExampleRpc("getimports", "12800")
        );

    LOCK(cs_main);

    std::string strHash = params[0].get_str();

    // If height is supplied, find the hash
    if (strHash.size() < (2 * sizeof(uint256))) {
        // std::stoi allows characters, whereas we want to be strict
        regex r("[[:digit:]]+");
        if (!regex_match(strHash, r)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block height parameter");
        }

        int nHeight = -1;
        try {
            nHeight = std::stoi(strHash);
        }
        catch (const std::exception &e) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block height parameter");
        }

        if (nHeight < 0 || nHeight > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
        }
        strHash = chainActive[nHeight]->GetBlockHash().GetHex();
    }

    uint256 hash(uint256S(strHash));

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");

    if(!ReadBlockFromDisk(block, pblockindex,1))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    UniValue result(UniValue::VOBJ);
    CAmount TotalImported = 0;
    UniValue imports(UniValue::VARR);
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
    {
        if(tx.IsCoinImport())
        {
            UniValue objTx(UniValue::VOBJ);
            objTx.push_back(Pair("txid",tx.GetHash().ToString()));
            ImportProof proof; CTransaction burnTx; std::vector<CTxOut> payouts; CTxDestination importaddress;
            TotalImported += tx.vout[1].nValue;
            objTx.push_back(Pair("amount", ValueFromAmount(tx.vout[1].nValue)));
            if (ExtractDestination(tx.vout[1].scriptPubKey, importaddress))
            {
                objTx.push_back(Pair("address", CBitcoinAddress(importaddress).ToString()));
            }
            UniValue objBurnTx(UniValue::VOBJ);      
            CPubKey vinPubkey;
            if (UnmarshalImportTx(tx, proof, burnTx, payouts)) 
            {
                if (burnTx.vout.size() == 0)
                    continue;
                objBurnTx.push_back(Pair("txid", burnTx.GetHash().ToString()));
                objBurnTx.push_back(Pair("amount", ValueFromAmount(burnTx.vout.back().nValue)));
                // extract op_return to get burn source chain.
                std::vector<uint8_t> burnOpret; std::string targetSymbol; uint32_t targetCCid; uint256 payoutsHash; std::vector<uint8_t>rawproof;
                if (UnmarshalBurnTx(burnTx, targetSymbol, &targetCCid, payoutsHash, rawproof))
                {
                    if (rawproof.size() > 0)
                    {
                        std::string sourceSymbol;
                        CTransaction tokenbasetx;
                        E_UNMARSHAL(rawproof,   ss >> sourceSymbol; 
                                                if (!ss.eof())
                                                    ss >> tokenbasetx );
                        objBurnTx.push_back(Pair("source", sourceSymbol));
                        if( !tokenbasetx.IsNull() )
                            objBurnTx.push_back(Pair("tokenid", tokenbasetx.GetHash().GetHex()));
                    }
                }
            }
            objTx.push_back(Pair("export", objBurnTx));
            imports.push_back(objTx);
        }
    }
    result.push_back(Pair("imports", imports));
    result.push_back(Pair("TotalImported", TotalImported > 0 ? ValueFromAmount(TotalImported) : 0 ));    
    result.push_back(Pair("time", block.GetBlockTime()));
    return result;
}

// outputs burn transactions in the wallet 
UniValue getwalletburntransactions(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getwalletburntransactions \"count\"\n\n"
            "Lists most recent wallet burn transactions up to \'count\' parameter\n"
            "parameter \'count\' is optional. If omitted, defaults to 10 burn transactions"
            "\n\n"
            "\nResult:\n"
            "[\n"
            "    {\n"
            "       \"txid\": (string)\n"
            "       \"burnedAmount\" : (numeric)\n"
            "       \"targetSymbol\" : (string)\n"
            "       \"targetCCid\" : (numeric)\n"
            "    }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletburntransactions", "100")
            + HelpExampleRpc("getwalletburntransactions", "100")
            + HelpExampleCli("getwalletburntransactions", "")
            + HelpExampleRpc("getwalletburntransactions", "")
        );

    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = "*";
    isminefilter filter = ISMINE_SPENDABLE;
    int nCount = 10;

    if (params.size() == 1)
        nCount = atoi(params[0].get_str());
    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");

    UniValue ret(UniValue::VARR);

    std::list<CAccountingEntry> acentries;
    CWallet::TxItems txOrdered = pwalletMain->OrderedTxItems(acentries, strAccount);

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
        {
            LOGSTREAM("importcoin", CCLOG_DEBUG2, stream << "pwtx iterpos=" << (int32_t)pwtx->nOrderPos << " txid=" << pwtx->GetHash().GetHex() << std::endl);
            vscript_t vopret;
            std::string targetSymbol;
            uint32_t targetCCid; uint256 payoutsHash;
            std::vector<uint8_t> rawproof;
            bool isNewBurnTx = false;

            if (pwtx->vout.size() > 0 && GetOpReturnData(pwtx->vout.back().scriptPubKey, vopret) && !vopret.empty() &&
                (isNewBurnTx = UnmarshalBurnTx(*pwtx, targetSymbol, &targetCCid, payoutsHash, rawproof)) || UnmarshalBurnTxOld(*pwtx, targetSymbol, &targetCCid, payoutsHash, rawproof)) {
                UniValue entry(UniValue::VOBJ);
                entry.push_back(Pair("txid", pwtx->GetHash().GetHex()));
                if (isNewBurnTx && vopret.begin()[0] == EVAL_TOKENS) {
                    // get burned token value
                    std::vector<std::pair<uint8_t, vscript_t>>  oprets;
                    uint256 tokenid;
                    uint8_t evalCodeInOpret;
                    std::vector<CPubKey> voutTokenPubkeys;

                    //skip token opret:
                    if (DecodeTokenOpRet(pwtx->vout.back().scriptPubKey, evalCodeInOpret, tokenid, voutTokenPubkeys, oprets) != 0) {
                        CTransaction tokenbasetx;
                        uint256 hashBlock;

                        if (myGetTransaction(tokenid, tokenbasetx, hashBlock)) {
                            std::vector<uint8_t> vorigpubkey;
                            std::string name, description;
                            std::vector<std::pair<uint8_t, vscript_t>>  oprets;
                            vscript_t vopretNonfungible;

                            if (tokenbasetx.vout.size() > 0 &&
                                DecodeTokenCreateOpRet(tokenbasetx.vout.back().scriptPubKey, vorigpubkey, name, description, oprets) == 'c' &&
                                GetOpretBlob(oprets, OPRETID_NONFUNGIBLEDATA, vopretNonfungible))
                            {
                                uint8_t destEvalCode = vopretNonfungible.begin()[0];
                                int64_t burnAmount = 0;

                                for (auto v : pwtx->vout)
                                    if (v.scriptPubKey.IsPayToCryptoCondition() &&
                                        CTxOut(v.nValue, v.scriptPubKey) == MakeTokensCC1vout(destEvalCode ? destEvalCode : EVAL_TOKENS, v.nValue, pubkey2pk(ParseHex(CC_BURNPUBKEY))))  // burned to dead pubkey
                                        burnAmount += v.nValue;

                                entry.push_back(Pair("burnedAmount", ValueFromAmount(burnAmount)));
                                entry.push_back(Pair("tokenid", tokenid.GetHex()));
                            }
                        }
                    }
                }
                else 
                    entry.push_back(Pair("burnedAmount", ValueFromAmount(pwtx->vout.back().nValue)));   // coins
                entry.push_back(Pair("targetSymbol", targetSymbol));
                entry.push_back(Pair("targetCCid", std::to_string(targetCCid)));
                if (mytxid_inmempool(pwtx->GetHash()))
                    entry.push_back(Pair("inMempool", "yes"));
                ret.push_back(entry);
            }
        } //else fprintf(stderr,"null pwtx\n
        if ((int)ret.size() >= (nCount))
            break;
    }
    // ret is newest to oldest

    if (nCount > (int)ret.size())
        nCount = ret.size();

    vector<UniValue> arrTmp = ret.getValues();

    vector<UniValue>::iterator first = arrTmp.begin();
    vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nCount);

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}