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

#include "cc/eval.h"
#include "cc/utils.h"
#include "importcoin.h"
#include "crosschain.h"
#include "primitives/transaction.h"
#include "cc/CCinclude.h"
#include "cc/CCtokens.h"

/*
 * CC Eval method for import coin.
 *
 * This method should control every parameter of the ImportCoin transaction, since it has no signature
 * to protect it from malleability.
 
 ##### 0xffffffff is a special CCid for single chain/dual daemon imports
 */

extern std::string ASSETCHAINS_SELFIMPORT;
extern uint16_t ASSETCHAINS_CODAPORT,ASSETCHAINS_BEAMPORT;
extern uint8_t ASSETCHAINS_OVERRIDE_PUBKEY33[33];

// utilities from gateways.cpp
uint256 BitcoinGetProofMerkleRoot(const std::vector<uint8_t> &proofData, std::vector<uint256> &txids);
uint256 GatewaysReverseScan(uint256 &txid, int32_t height, uint256 reforacletxid, uint256 batontxid);
int32_t GatewaysCointxidExists(struct CCcontract_info *cp, uint256 cointxid);
uint8_t DecodeGatewaysBindOpRet(char *depositaddr, const CScript &scriptPubKey, std::string &coin, uint256 &tokenid, int64_t &totalsupply, uint256 &oracletxid, uint8_t &M, uint8_t &N, std::vector<CPubKey> &pubkeys, uint8_t &taddr, uint8_t &prefix, uint8_t &prefix2);

// ac_import=chain support:
// encode opret for gateways import
CScript EncodeGatewaysImportTxOpRet(uint32_t targetCCid, std::string coin, uint256 bindtxid, std::vector<CPubKey> publishers, std::vector<uint256>txids, int32_t height, uint256 cointxid, int32_t claimvout, std::string rawburntx, std::vector<uint8_t>proof, CPubKey destpub, int64_t amount)
{
    CScript opret;
    opret << OP_RETURN << E_MARSHAL(ss << targetCCid << coin << bindtxid << publishers << txids << height << cointxid << claimvout << rawburntx << proof << destpub << amount);
    return(opret);
}

bool ImportCoinGatewaysVerify(char *refdepositaddr, uint256 oracletxid, int32_t claimvout, std::string refcoin, uint256 burntxid, const std::string rawburntx, std::vector<uint8_t>proof, uint256 merkleroot)
{
    std::vector<uint256> txids; 
    uint256 proofroot, hashBlock, foundtxid = zeroid; 
    CTransaction oracletx, burntx; 
    std::string name, description, format; 
    char destaddr[64], destpubaddr[64], claimaddr[64]; 
    int32_t i, numvouts; 
    int64_t nValue = 0;

    if (myGetTransaction(oracletxid, oracletx, hashBlock) == 0 || (numvouts = oracletx.vout.size()) <= 0)
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "ImportCoinGatewaysVerify can't find oracletxid=" << oracletxid.GetHex() << std::endl);
        return false;
    }
    if (DecodeOraclesCreateOpRet(oracletx.vout[numvouts - 1].scriptPubKey, name, description, format) != 'C' || name != refcoin)
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "ImportCoinGatewaysVerify mismatched oracle name=" << name.c_str() << " != " << refcoin.c_str() << std::endl);
        return false;
    }
    proofroot = BitcoinGetProofMerkleRoot(proof, txids);
    if (proofroot != merkleroot)
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "ImportCoinGatewaysVerify mismatched proof merkleroot=" << proofroot.GetHex() << " and oracles merkleroot=" << merkleroot.GetHex() << std::endl);
        return false;
    }

    // check the burntxid is in the proof:
    if (std::find(txids.begin(), txids.end(), burntxid) == txids.end()) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "ImportCoinGatewaysVerify invalid proof for this burntxid=" << burntxid.GetHex() << std::endl);
        return false;
    }

    /*
    if (DecodeHexTx(burntx, rawburntx) != 0)
    {
        Getscriptaddress(claimaddr, burntx.vout[claimvout].scriptPubKey);
        Getscriptaddress(destpubaddr, CScript() << ParseHex(HexStr(destpub)) << OP_CHECKSIG);
        if (strcmp(claimaddr, destpubaddr) == 0)
        {
            for (i = 0; i<numvouts; i++)
            {
                Getscriptaddress(destaddr, burntx.vout[i].scriptPubKey);
                if (strcmp(refdepositaddr, destaddr) == 0)
                {
                    foundtxid = burntx.GetHash();
                    nValue = burntx.vout[i].nValue;
                    break;
                }
            }
        }
        else fprintf(stderr, "claimaddr.(%s) != destpubaddr.(%s)\n", claimaddr, destpubaddr);
    }*/

    /*
    if (foundtxid == burntxid)   {
        LOGSTREAM("importcoin", LEV_DEBUG1, stream << "verified proof for burntxid=" << burntxid.GetHex() << " in merkleroot merkleroot" << std::endl);
        return(nValue);
    }
    else {
    LOGSTREAM("importcoin", LEV_INFO, stream << "verified proof for burntxid=" << burntxid.GetHex() << " in merkleroot merkleroot" << std::endl);

        fprintf(stderr, "(%s) != (%s) or txid %s mismatch.%d or script mismatch\n", refdepositaddr, destaddr, uint256_str(str, foundtxid), foundtxid != burntxid);
        */

    LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "verified proof for burntxid=" << burntxid.GetHex() << " in trusted merkleroot" << std::endl);
    return true;
}


// make import tx with burntx and its proof of existence
std::string MakeGatewaysImportTx(uint64_t txfee, uint256 bindtxid, int32_t height, std::string refcoin, std::vector<uint8_t>proof, std::string rawburntx, int32_t ivout, uint256 burntxid)
{
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());
    CTransaction burntx, bindtx; 
    CPubKey mypk, gatewayspk; 
    uint256 oracletxid, merkleroot, mhash, hashBlock, tokenid, txid;
    int64_t totalsupply; 
    int32_t i, m, n, numvouts; 
    uint8_t M, N, taddr, prefix, prefix2; 
    std::string coin; 
    struct CCcontract_info *cp, C;
    std::vector<CPubKey> pubkeys, publishers; 
    std::vector<uint256>txids; 
    char depositaddr[64], txidaddr[64];

    cp = CCinit(&C, EVAL_GATEWAYS);
    /*if (txfee == 0)
        txfee = 10000;
    mypk = pubkey2pk(Mypubkey());
    gatewayspk = GetUnspendable(cp, 0); */

    if (!E_UNMARSHAL(ParseHex(rawburntx), ss >> burntx))
        return std::string("");

    CAmount amount = GetCoinImportValue(burntx);  // equal to int64_t

    LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "MakeGatewaysImportTx height=" << height << " coin=" << refcoin << " amount=" << (double)amount / COIN  << " pubkeys num=" << pubkeys.size() << std::endl);

    if (GetTransaction(bindtxid, bindtx, hashBlock, false) == 0 || (numvouts = bindtx.vout.size()) <= 0)
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "MakeGatewaysImportTx cant find bindtxid=" << bindtxid.GetHex() << std::endl);
        return("");
    }
/*    if (DecodeGatewaysBindOpRet(depositaddr, bindtx.vout[numvouts - 1].scriptPubKey, coin, tokenid, totalsupply, oracletxid, M, N, pubkeys, taddr, prefix, prefix2) != 'B' || refcoin != coin)
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "MakeGatewaysImportTx invalid coin - bindtxid=" << bindtxid.GetHex() << " coin=" << coin.c_str() << std::endl);
        return("");
    } eliminate link err */
    n = (int32_t)pubkeys.size();
    merkleroot = zeroid;
    for (i = m = 0; i < n; i++)
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "MakeGatewaysImportTx using pubkeys[" << i << "]=" << HexStr(pubkeys[i]) << std::endl);
        if ((mhash = GatewaysReverseScan(txid, height, oracletxid, OraclesBatontxid(oracletxid, pubkeys[i]))) != zeroid)
        {
            if (merkleroot == zeroid)
                merkleroot = mhash, m = 1;
            else if (mhash == merkleroot)
                m ++;
            publishers.push_back(pubkeys[i]);
            txids.push_back(txid);
        }
    }
    
    LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "MakeGatewaysImportTx burntxid=" << burntxid.GetHex() << " nodes m=" << m << " of n=" << n << std::endl);
    if (merkleroot == zeroid || m < n / 2) // none or less than half oracle nodes sent merkleroot
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "MakeGatewaysImportTx couldnt find merkleroot for block height=" << height << "coin=" << coin.c_str() << " oracleid=" << oracletxid.GetHex() << " m=" << m << " vs n=" << n << std::endl );
        return("");
    }
    if (GatewaysCointxidExists(cp, burntxid) != 0)
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "MakeGatewaysImportTx burntxid=" << burntxid.GetHex() << " already exists" << std::endl);
        return("");
    }
    if (!ImportCoinGatewaysVerify(depositaddr, oracletxid, ivout, coin, burntxid, rawburntx, proof, merkleroot))
    {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "MakeGatewaysImportTx could not validate burntx, txid=" << burntxid.GetHex() << std::endl);
        return("");
    }


    std::vector<uint256> leaftxids;
    BitcoinGetProofMerkleRoot(proof, leaftxids);
    MerkleBranch newBranch(0, leaftxids);
    TxProof txProof = std::make_pair(burntxid, newBranch);

    std::vector<CTxOut> vouts;

    // This is an unfinished func! To be implemented yet...

    return  HexStr(E_MARSHAL(ss << MakeImportCoinTransaction(txProof, burntx, vouts)));

    /*if (AddNormalinputs(mtx, mypk, 3 * txfee, 4) > 0)
    {
        mtx.vout.push_back(MakeCC1vout(cp->evalcode, txfee, destpub));
        mtx.vout.push_back(CTxOut(txfee, CScript() << ParseHex(HexStr(CCtxidaddr(txidaddr, burntxid))) << OP_CHECKSIG));
        return(FinalizeCCTx(0, cp, mtx, mypk, txfee, EncodeGatewaysImportTxOpRet(0xFFFFFFFF, coin, bindtxid, publishers, txids, height, burntxid, ivout, rawburntx, proof, destpub, amount)));
    }
    LOGSTREAM("importcoin", LEV_INFO, stream << "MakeGatewaysImportTx coud not find normal imputs" << std::endl);*/
    return("");
}

// makes source tx for self import tx
CMutableTransaction MakeSelfImportSourceTx(CTxDestination &dest, int64_t amount)
{
    const int64_t txfee = 10000;
    int64_t inputs, change;
    CPubKey myPubKey = Mypubkey();
    struct CCcontract_info *cpDummy, C;

    cpDummy = CCinit(&C, EVAL_TOKENS);  // this is just for FinalizeCCTx to work

    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());

    if (AddNormalinputs(mtx, myPubKey, 2 * txfee, 4) == 0) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "MakeSelfImportSourceTx() warning: cannot find normal inputs for txfee" << std::endl);
    }
    
    CScript scriptPubKey = GetScriptForDestination(dest);
    mtx.vout.push_back(CTxOut(txfee, scriptPubKey));

    //make opret with 'burned' amount:
    FinalizeCCTx(0, cpDummy, mtx, myPubKey, txfee, CScript() << OP_RETURN << E_MARSHAL(ss << (uint8_t)EVAL_IMPORTCOIN << (uint8_t)'A' << amount));
    return mtx;
}

// make sure vin is signed by pubkey33
bool CheckVinPubKey(const CTransaction &sourcetx, int32_t i, uint8_t pubkey33[33])
{
    CTransaction vintx;
    uint256 blockHash;
    char destaddr[64], pkaddr[64];

    if (i < 0 || i >= sourcetx.vin.size())
        return false;

    if( !myGetTransaction(sourcetx.vin[i].prevout.hash, vintx, blockHash) ) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "CheckVinPubKey() could not load vintx" << sourcetx.vin[i].prevout.hash.GetHex() << std::endl);
        return false;
    }
    if( sourcetx.vin[i].prevout.n < vintx.vout.size() && Getscriptaddress(destaddr, vintx.vout[sourcetx.vin[i].prevout.n].scriptPubKey) != 0 )
    {
        pubkey2addr(pkaddr, pubkey33);
        if (strcmp(pkaddr, destaddr) == 0) {
            return true;
        }
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "CheckVinPubKey() mismatched vin[" << i << "].prevout.n=" << sourcetx.vin[i].prevout.n << " -> destaddr=" << destaddr << " vs pkaddr=" << pkaddr << std::endl);
    }
    return false;
}

// ac_import=PUBKEY support:
// prepare a tx for creating import tx and quasi-burn tx
int32_t GetSelfimportProof(const CMutableTransaction &sourceMtx, CMutableTransaction &templateMtx, ImportProof &proofNull) // find burnTx with hash from "other" daemon
{
    MerkleBranch newBranch; 
    CMutableTransaction tmpmtx; 
    //CTransaction sourcetx; 

    tmpmtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), komodo_nextheight());

    /*
    if (!E_UNMARSHAL(ParseHex(rawsourcetx), ss >> sourcetx)) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "GetSelfimportProof: could not unmarshal source tx" << std::endl);
        return(-1);
    }

    if (sourcetx.vout.size() == 0) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "GetSelfimportProof: vout size is 0" << std::endl);
        return -1;
    } */

	/*if (ivout < 0) {  // "ivout < 0" means "find"  
		// try to find vout
		CPubKey myPubkey = Mypubkey();
		ivout = 0;
		// skip change:
		if (sourcetx.vout[ivout].scriptPubKey == (CScript() << ParseHex(HexStr(myPubkey)) << OP_CHECKSIG))
			ivout++;
	}

    if (ivout >= sourcetx.vout.size()) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "GetSelfimportProof: needed vout not found" << std::endl);
        return -1;
    } */

    int32_t ivout = 0;

	// LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "GetSelfimportProof: using vout[" << ivout << "] of the passed rawtx" << std::endl);

    CScript scriptPubKey = sourceMtx.vout[ivout].scriptPubKey;

	//mtx is template for import tx
    templateMtx = sourceMtx;
    templateMtx.fOverwintered = tmpmtx.fOverwintered;
    
    //malleability fix for burn tx:
    //mtx.nExpiryHeight = tmpmtx.nExpiryHeight;
    templateMtx.nExpiryHeight = sourceMtx.nExpiryHeight;

    templateMtx.nVersionGroupId = tmpmtx.nVersionGroupId;
    templateMtx.nVersion = tmpmtx.nVersion;
    templateMtx.vout.clear();
    templateMtx.vout.resize(1);

    uint8_t evalCode, funcId;
    int64_t burnAmount;
    vscript_t vopret;
    if( !GetOpReturnData(sourceMtx.vout.back().scriptPubKey, vopret) ||
        !E_UNMARSHAL(vopret, ss >> evalCode; ss >> funcId; ss >> burnAmount)) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "GetSelfimportProof() could not unmarshal source tx opret" << std::endl);
        return -1;
    }
    templateMtx.vout[0].nValue = burnAmount;
    templateMtx.vout[0].scriptPubKey = scriptPubKey;

    // not sure we need this now as we create sourcetx ourselves:
    /*if (sourcetx.GetHash() != sourcetxid) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "GetSelfimportProof: passed source txid incorrect" << std::endl);
        return(-1);
    }*/

    // check ac_pubkey:
    if (!CheckVinPubKey(sourceMtx, 0, ASSETCHAINS_OVERRIDE_PUBKEY33)) {
        return -1;
    }
    proofNull = ImportProof(std::make_pair(sourceMtx.GetHash(), newBranch));
    return 0;
}

// use proof from the above functions to validate the import

int32_t CheckBEAMimport(TxProof proof,std::vector<uint8_t> rawproof,CTransaction burnTx,std::vector<CTxOut> payouts)
{
    // check with dual-BEAM daemon via ASSETCHAINS_BEAMPORT for validity of burnTx
    return(-1);
}

int32_t CheckCODAimport(TxProof proof,std::vector<uint8_t> rawproof,CTransaction burnTx,std::vector<CTxOut> payouts)
{
    // check with dual-CODA daemon via ASSETCHAINS_CODAPORT for validity of burnTx
    return(-1);
}

int32_t CheckGATEWAYimport(TxProof proof,std::vector<uint8_t> rawproof,CTransaction burnTx,std::vector<CTxOut> payouts)
{
    // ASSETCHAINS_SELFIMPORT is coin
    // check for valid burn from external coin blockchain and if valid return(0);
    return(-1);
}

int32_t CheckPUBKEYimport(TxProof proof,std::vector<uint8_t> rawproof,CTransaction burnTx,std::vector<CTxOut> payouts)
{
    // if burnTx has ASSETCHAINS_PUBKEY vin, it is valid return(0);
    LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "proof txid=" << proof.first.GetHex() << std::endl);

    uint256 sourcetxid = proof.first, hashBlock;
    CTransaction sourcetx;

    if (!myGetTransaction(sourcetxid, sourcetx, hashBlock)) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "could not load source txid=" << sourcetxid.GetHex() << std::endl);
        return -1;
    }

    if (sourcetx.vout.size() == 0) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "no vouts in source txid=" << sourcetxid.GetHex() << std::endl);
        return -1;
    }

    // might be malleable:
    if (burnTx.nExpiryHeight != sourcetx.nExpiryHeight) {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "burntx nExpiryHeight incorrect for source txid=" << sourcetxid.GetHex() << std::endl);
        return -1;
    }

    //ac_pubkey check:
    if (!CheckVinPubKey(sourcetx, 0, ASSETCHAINS_OVERRIDE_PUBKEY33)) {
        return -1;
    }

    // get source tx opret:
    std::vector<uint8_t> vopret;
    uint8_t evalCode, funcId;
    int64_t amount;

    if (!GetOpReturnData(sourcetx.vout.back().scriptPubKey, vopret) || 
        vopret.size() == 0 || 
        !E_UNMARSHAL(vopret, ss >> evalCode; ss >> funcId; ss >> amount) || 
        evalCode != EVAL_IMPORTCOIN || funcId != 'A') {
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "none or incorrect opret to validate in source txid=" << sourcetxid.GetHex() << std::endl);
        return -1;
    }

    LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "importTx amount=" << payouts[0].nValue << " burnTx amount=" << burnTx.vout[0].nValue << " opret amount=" << amount << " source txid=" << sourcetxid.GetHex() << std::endl);

    // amount malleability check with the opret from the source tx: 
    if (payouts[0].nValue != amount) { // assume that burntx amount is checked in the common code in Eval::ImportCoin()
        LOGSTREAM("importcoin", CCLOG_INFO, stream << "importTx amount != amount in the opret of source txid=" << sourcetxid.GetHex() << std::endl);
        return -1;
    }

    return(0);
}

bool Eval::ImportCoin(const std::vector<uint8_t> params, const CTransaction &importTx, unsigned int nIn)
{
    ImportProof proof; CTransaction burnTx; std::vector<CTxOut> payouts; uint64_t txfee = 10000;
    uint32_t targetCcid; std::string targetSymbol; uint256 payoutsHash; std::vector<uint8_t> rawproof;

    LOGSTREAM("importcoin", CCLOG_DEBUG1, stream << "Validating import tx..., txid=" << importTx.GetHash().GetHex() << std::endl);

    if ( importTx.vout.size() < 2 )
        return Invalid("too-few-vouts");
    // params
    bool isNewImportTx = false;
    if (!(isNewImportTx = UnmarshalImportTx(importTx, proof, burnTx, payouts)) && !UnmarshalImportTxVout0(importTx, proof, burnTx, payouts))
        return Invalid("invalid-import-tx-params");

    // Control all aspects of this transaction
    // It should not be at all malleable
    if (MakeImportCoinTransaction(proof, burnTx, payouts, importTx.nExpiryHeight).GetHash() != importTx.GetHash() &&    // ExistsImportTombstone prevents from burn tx duplication
        MakeImportCoinTransactionVout0(proof, burnTx, payouts, importTx.nExpiryHeight).GetHash() != importTx.GetHash() )  // compatibility
        return Invalid("non-canonical-import-tx");
    // get burn params
    if (!UnmarshalBurnTx(burnTx, targetSymbol, &targetCcid, payoutsHash, rawproof) && !UnmarshalBurnTxOld(burnTx, targetSymbol, &targetCcid, payoutsHash, rawproof)) //with support for old burn tx
        return Invalid("invalid-burn-tx");
    
    if( burnTx.vout.size() == 0 )
        return Invalid("invalid-burn-tx-no-vouts");

    vscript_t vimportOpret;
    if (isNewImportTx && !GetOpReturnData(importTx.vout.back().scriptPubKey, vimportOpret) ||       // new import tx
        !isNewImportTx && !GetOpReturnData(importTx.vout[0].scriptPubKey, vimportOpret) ||          // it is old import tx
        vimportOpret.empty())
        return Invalid("invalid-import-tx-no-opret");


    uint256 tokenid = zeroid;
    // check burn amount
    if( !isNewImportTx || vimportOpret.begin()[0] == EVAL_IMPORTCOIN )  // for coins (both for new or old opret)
    {
        uint64_t burnAmount = burnTx.vout.back().nValue;
        if (burnAmount == 0)
            return Invalid("invalid-burn-amount");
        uint64_t totalOut = 0;
        for (int i=0; i<importTx.vout.size(); i++)
            totalOut += importTx.vout[i].nValue;
        if (totalOut > burnAmount || totalOut < burnAmount-txfee )
            return Invalid("payout-too-high-or-too-low");
    }
    else if (vimportOpret.begin()[0] == EVAL_TOKENS) { // for tokens (new opret with tokens)
        struct CCcontract_info *cpTokens, CCtokens_info;
        std::vector<std::pair<uint8_t, vscript_t>>  oprets;
        uint8_t evalCodeInOpret;
        std::vector<CPubKey> voutTokenPubkeys;
        vscript_t vnonfungibleOpret;
        uint8_t nonfungibleEvalCode = 0;

        cpTokens = CCinit(&CCtokens_info, EVAL_TOKENS);

        if (DecodeTokenOpRet(importTx.vout.back().scriptPubKey, evalCodeInOpret, tokenid, voutTokenPubkeys, oprets) == 0)  
            return Invalid("cannot-decode-import-tx-token-opret");

        GetOpretBlob(oprets, OPRETID_NONFUNGIBLEDATA, vnonfungibleOpret);
        if (!vnonfungibleOpret.empty())
            nonfungibleEvalCode = vnonfungibleOpret.begin()[0];

        // calc outputs for burn tx
        int64_t burnAmount = 0;
        for (auto v : burnTx.vout)
            if (v.scriptPubKey.IsPayToCryptoCondition() && 
                CTxOut(v.nValue, v.scriptPubKey) == MakeTokensCC1vout(nonfungibleEvalCode ? nonfungibleEvalCode : EVAL_TOKENS, v.nValue, pubkey2pk(ParseHex(CC_BURNPUBKEY))) )  // burned to dead pubkey
                burnAmount += v.nValue;

        // calc outputs for import tx
        int64_t importAmount = 0;
        for (auto v : importTx.vout)  
            if (v.scriptPubKey.IsPayToCryptoCondition() && 
                !IsTokenMarkerVout(v))  // should not be marker here
                importAmount += v.nValue;

        if( burnAmount != importAmount )
            return Invalid("token-payout-too-high-or-too-low");

    }
    else {
        return Invalid("invalid-burn-tx-incorrect-opret");
    }

    // for tokens check burn, import, tokenbase tx 
    if (!tokenid.IsNull()) {
        
        std::string sourceSymbol;
        CTransaction tokenbaseTx;
        if (!E_UNMARSHAL(rawproof, ss >> sourceSymbol; ss >> tokenbaseTx))
            return Invalid("cannot-unmarshal-rawproof-for-tokens");

        uint256 sourceTokenId;
        std::vector<std::pair<uint8_t, vscript_t>>  oprets;
        uint8_t evalCodeInOpret;
        std::vector<CPubKey> voutTokenPubkeys;
        if (burnTx.vout.size() > 0 && DecodeTokenOpRet(burnTx.vout.back().scriptPubKey, evalCodeInOpret, sourceTokenId, voutTokenPubkeys, oprets) == 0)
            return Invalid("cannot-decode-burn-tx-token-opret");

        if (sourceTokenId != tokenbaseTx.GetHash())              // check tokenid in burn tx opret maches the passed tokenbase tx (to prevent cheating by importing user)
            return Invalid("incorrect-token-creation-tx-passed");

        std::vector<std::pair<uint8_t, vscript_t>>  opretsSrc;
        vscript_t vorigpubkeySrc;
        std::string nameSrc, descSrc;
        if (DecodeTokenCreateOpRet(tokenbaseTx.vout.back().scriptPubKey, vorigpubkeySrc, nameSrc, descSrc, opretsSrc) == 0) 
            return Invalid("cannot-decode-token-creation-tx");

        std::vector<std::pair<uint8_t, vscript_t>>  opretsImport;
        vscript_t vorigpubkeyImport;
        std::string nameImport, descImport;
        if (importTx.vout.size() == 0 || DecodeTokenCreateOpRet(importTx.vout.back().scriptPubKey, vorigpubkeySrc, nameSrc, descSrc, opretsImport) == 0)
            return Invalid("cannot-decode-token-import-tx");

        // check that name,pubkey,description in import tx correspond ones in token creation tx in the source chain:
        if (vorigpubkeySrc != vorigpubkeyImport ||
            nameSrc != nameImport ||
            descSrc != descImport)
            return Invalid("import-tx-token-params-incorrect");
    }


    // Check burntx shows correct outputs hash
    if (payoutsHash != SerializeHash(payouts))
        return Invalid("wrong-payouts");
    if (targetCcid < KOMODO_FIRSTFUNGIBLEID)
        return Invalid("chain-not-fungible");
    // Check proof confirms existance of burnTx
    if ( targetCcid != 0xffffffff )
    {
        if ( targetCcid != GetAssetchainsCC() || targetSymbol != GetAssetchainsSymbol() )
            return Invalid("importcoin-wrong-chain");

        TxProof merkleBranchProof;
        std::vector<uint256> notaryTxids;

        if (proof.IsMerkleBranch(merkleBranchProof)) {
            uint256 target = merkleBranchProof.second.Exec(burnTx.GetHash());
            LOGSTREAM("importcoin", CCLOG_DEBUG2, stream << "Eval::ImportCoin() momom target=" << target.GetHex() << " merkleBranchProof.first=" << merkleBranchProof.first.GetHex() << std::endl);
            if (!CheckMoMoM(merkleBranchProof.first, target)) {
                LOGSTREAM("importcoin", CCLOG_INFO, stream << "MoMoM check failed for importtx=" << importTx.GetHash().GetHex() << std::endl);
                return Invalid("momom-check-fail");
            }
        } else if (proof.IsNotaryTxids(notaryTxids)) {
            if (!CheckNotariesApproval(burnTx.GetHash(), notaryTxids)) {
                return Invalid("notaries-approval-check-fail");
            }
        }
        else  {
            return Invalid("invalid-import-proof");
        }
    }
    else
    {
        TxProof merkleBranchProof;
        if (!proof.IsMerkleBranch(merkleBranchProof)) 
            return Invalid("invalid-import-proof-for-0xFFFFFFFF");

        if ( targetSymbol == "BEAM" )
        {
            if ( ASSETCHAINS_BEAMPORT == 0 )
                return Invalid("BEAM-import-without-port");
            else if ( CheckBEAMimport(merkleBranchProof,rawproof,burnTx,payouts) < 0 )
                return Invalid("BEAM-import-failure");
        }
        else if ( targetSymbol == "CODA" )
        {
            if ( ASSETCHAINS_CODAPORT == 0 )
                return Invalid("CODA-import-without-port");
            else if ( CheckCODAimport(merkleBranchProof,rawproof,burnTx,payouts) < 0 )
                return Invalid("CODA-import-failure");
        }
        else if ( targetSymbol == "PUBKEY" )
        {
            if ( ASSETCHAINS_SELFIMPORT != "PUBKEY" )
                return Invalid("PUBKEY-import-when-notPUBKEY");
            else if ( CheckPUBKEYimport(merkleBranchProof,rawproof,burnTx,payouts) < 0 )
                return Invalid("PUBKEY-import-failure");
        }
        else
        {
            if ( targetSymbol != ASSETCHAINS_SELFIMPORT )
                return Invalid("invalid-gateway-import-coin");
            else if ( CheckGATEWAYimport(merkleBranchProof,rawproof,burnTx,payouts) < 0 )
                return Invalid("GATEWAY-import-failure");
        }
    }

    // return Invalid("test-invalid");
    LOGSTREAM("importcoin", CCLOG_DEBUG2, stream << "Valid import tx! txid=" << importTx.GetHash().GetHex() << std::endl);

    /*
    if (vimportOpret.begin()[0] == EVAL_TOKENS)
        return Invalid("test-invalid-tokens-are-good!!");
    else
        return Invalid("test-invalid-coins-are-good!!");
    */
    return Valid();
}
