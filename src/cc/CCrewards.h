/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
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


#ifndef CC_REWARDS_H
#define CC_REWARDS_H

#include "CCinclude.h"

#define EVAL_REWARDS 0xe5

bool RewardsValidate(struct CCcontract_info *cp,Eval* eval,const CTransaction &tx);

std::string RewardsFund(uint64_t txfee,char *planstr,uint64_t funds,uint64_t APR,uint64_t minseconds,uint64_t maxseconds,uint64_t mindeposit);
std::string RewardsLock(uint64_t txfee,char *planstr,uint64_t amount)
std::string RewardsUnlock(uint64_t txfee);

#endif