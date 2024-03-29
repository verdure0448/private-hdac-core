// Copyright (c) 2014-2016 The Bitcoin Core developers
// Original code was distributed under the MIT software license.
// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
// 
// 2018/02/00   Code optimization
//============================================================================================


#ifndef RPCWALLET_H
#define	RPCWALLET_H

#include "structs/base58.h"
#include "utils/core_io.h"
#include "rpc/rpcserver.h"
#include "core/init.h"
#include "utils/util.h"
#include "wallet/wallet.h"

#include <boost/assign/list_of.hpp>
#include "json/json_spirit_utils.h"
#include "json/json_spirit_value.h"


#include "hdac/hdac.h"
#include "wallet/wallettxs.h"
#include "rpc/rpcutils.h"

/* HDAC START
 * sk_20180126 */
extern CAmount maxTxFee;
extern int64_t COIN;
extern unsigned int MIN_RELAY_TX_FEE;
/* HDAC END */

void SendMoneyToSeveralAddresses(const std::vector<CTxDestination> addresses, CAmount nValue, CWalletTx& wtxNew,mc_Script *dropscript,CScript scriptOpReturn,const std::vector<CTxDestination>& fromaddresses,bool deductfee=0);
vector<CTxDestination> ParseAddresses(string param, bool create_full_list, bool allow_scripthash);
void FindAddressesWithPublishPermission(std::vector<CTxDestination>& fromaddresses,mc_EntityDetails *stream_entity);
set<string> ParseAddresses(Value param, isminefilter filter);
bool CBitcoinAddressFromTxEntity(CBitcoinAddress &address,mc_TxEntity *lpEntity);
Object StreamItemEntry(const CWalletTx& wtx,const unsigned char *stream_id, bool verbose);
Object TxOutEntry(const CTxOut& TxOutIn,int vout,const CTxIn& TxIn,uint256 hash,mc_Buffer *amounts,mc_Script *lpScript);
void WalletTxToJSON(const CWalletTx& wtx, Object& entry,bool skipWalletConflicts = false, int vout = -1);
void MinimalWalletTxToJSON(const CWalletTx& wtx, Object& entry);
Object AddressEntry(CBitcoinAddress& address,uint32_t verbose);
void SetSynchronizedFlag(CTxDestination &dest,Object &ret);




#endif	// RPCWALLET_H 

