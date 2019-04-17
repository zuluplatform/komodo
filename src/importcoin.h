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

#ifndef IMPORTCOIN_H
#define IMPORTCOIN_H

#include "cc/eval.h"
#include "coins.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include <cryptoconditions.h>

enum ProofKind : uint8_t {
    PROOF_NONE = 0x00,
    PROOF_MERKLEBRANCH = 0x11,
    PROOF_NOTARYTXIDS = 0x12,
    PROOF_MERKLEBLOCK = 0x13
};

class ImportProof {

private:
    uint8_t proofKind;
    TxProof proofBranch;
    std::vector<uint256> notaryTxids;
    std::vector<uint8_t> proofBlock;

public:
    ImportProof() { proofKind = PROOF_NONE; }
    ImportProof(const TxProof &_proofBranch) {
        proofKind = PROOF_MERKLEBRANCH; proofBranch = _proofBranch;
    }
    ImportProof(const std::vector<uint256> &_notaryTxids) {
        proofKind = PROOF_NOTARYTXIDS; notaryTxids = _notaryTxids;
    }
    ImportProof(const std::vector<uint8_t> &_proofBlock) {
        proofKind = PROOF_MERKLEBLOCK; proofBlock = _proofBlock;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(proofKind);
        if (proofKind == PROOF_MERKLEBRANCH)
            READWRITE(proofBranch);
        else if (proofKind == PROOF_NOTARYTXIDS)
            READWRITE(notaryTxids);
        else if (proofKind == PROOF_MERKLEBLOCK)
            READWRITE(proofBlock);
    }

    bool IsMerkleBranch(TxProof &_proofBranch) {
        if (proofKind == PROOF_MERKLEBRANCH) {
            _proofBranch = proofBranch;
            return true;
        }
        else
            return false;
    }
    bool IsNotaryTxids(std::vector<uint256> &_notaryTxids) {
        if (proofKind == PROOF_NOTARYTXIDS) {
            _notaryTxids = notaryTxids;
            return true;
        }
        else
            return false;
    }
    bool IsMerkleBlock(std::vector<uint8_t> &_proofBlock) {
        if (proofKind == PROOF_MERKLEBLOCK) {
            _proofBlock = proofBlock;
            return true;
        }
        else
            return false;
    }
};


CAmount GetCoinImportValue(const CTransaction &tx);

CTransaction MakeImportCoinTransaction(const ImportProof &proof, const CTransaction &burnTx, const std::vector<CTxOut> &payouts, uint32_t nExpiryHeightOverride = 0);
CTransaction MakeImportCoinTransactionVout0(const ImportProof &proof, const CTransaction &burnTx, const std::vector<CTxOut> &payouts, uint32_t nExpiryHeightOverride = 0);

CTxOut MakeBurnOutput(CAmount value, uint32_t targetCCid, const std::string &targetSymbol, const std::vector<CTxOut> &payouts, const std::vector<uint8_t> &rawproof);

bool UnmarshalBurnTx(const CTransaction &burnTx, std::string &targetSymbol, uint32_t *targetCCid, uint256 &payoutsHash, std::vector<uint8_t> &rawproof);    // evalcode in opret
bool UnmarshalBurnTxOld(const CTransaction &burnTx, std::string &targetSymbol, uint32_t *targetCCid, uint256 &payoutsHash, std::vector<uint8_t>&rawproof);  // no evalcode in opret
bool UnmarshalImportTx(const CTransaction &importTx, ImportProof &proof, CTransaction &burnTx, std::vector<CTxOut> &payouts);       // new ImportProof and vout back
//bool UnmarshalImportTxOld(const CTransaction &importTx, ImportProof &proof, CTransaction &burnTx, std::vector<CTxOut> &payouts);  // txproof
bool UnmarshalImportTxVout0(const CTransaction &importTx, ImportProof &proof, CTransaction &burnTx, std::vector<CTxOut> &payouts);  // new ImportProof but vout0

bool VerifyCoinImport(const CScript& scriptSig, TransactionSignatureChecker& checker, CValidationState &state);

void AddImportTombstone(const CTransaction &importTx, CCoinsViewCache &inputs, int nHeight);
void RemoveImportTombstone(const CTransaction &importTx, CCoinsViewCache &inputs);
int ExistsImportTombstone(const CTransaction &importTx, const CCoinsViewCache &inputs);

bool CheckVinPubKey(const CTransaction &sourcetx, int32_t i, uint8_t pubkey33[33]);

#endif /* IMPORTCOIN_H */
