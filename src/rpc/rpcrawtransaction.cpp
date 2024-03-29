// Copyright (c) 2010 Satoshi Nakamoto
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


#include "structs/base58.h"
#include "primitives/transaction.h"
#include "utils/core_io.h"
#include "core/init.h"
#include "wallet/keystore.h"
#include "core/main.h"
#include "net/net.h"
#include "rpc/rpcserver.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"
#include "structs/uint256.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include "json/json_spirit_utils.h"
#include "json/json_spirit_value.h"

#include "hdac/hdac.h"
#include "rpc/rpcutils.h"
#include "utils/util.h"

using namespace boost;
using namespace boost::assign;
using namespace json_spirit;
using namespace std;

#include "utils/utilmoneystr.h"
#include "wallet/wallettxs.h"

bool OutputCanSend(COutput out);
uint32_t mc_CheckSigScriptForMutableTx(const unsigned char *src,int size);
Value mc_ExtractDetailsJSONObject(const unsigned char *script,uint32_t total);



void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;


    const CScript& scriptToShow=RemoveOpDropsIfNeeded(scriptPubKey);

    out.push_back(Pair("asm", scriptToShow.ToString()));
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptToShow.begin(), scriptToShow.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    Array a;
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}


#ifdef FEATURE_HDAC_AUTO_IMPORT_ADDRESS

bool	IsAddressExistInWallet(string addr)
{
    static string latest[100];
    static int idx = 0;

    for (int nn = 0; nn < 100; nn++)
    {
    	if (latest[nn].size() == 0)
	{
	    latest[nn] = addr;
	    return false;
	}
	else if (latest[nn] == addr)	// found
	{
	    if(fDebug>3)LogPrint("import", "	Address %s found. skip...\n", addr.c_str());
	    return true;
	}
    }

    // if not found addr and latest[] is full, then replace one
    latest[idx] = addr;
    idx++;
    idx = idx % 100;

    return false;
}


// AcceptToMemPool() 트랜잭션이 들어오면, 주소와 값 모두 출력..
int	AddAddressToWallet(const CTransaction& tx, const string funcname)
{
    int	naddr = 0;
    bool ismining = 0;

    if (fDebug>2)LogPrint("import", "AddAddressToWallet(tx, %s)\n", funcname);

    Array vin;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        Object in;
        if (tx.IsCoinBase())
	{
            if (fDebug>1)LogPrint("import", "	IN: coinbase=%s\n", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()).c_str());
	    ismining = 1;
	}
        else {
            if (fDebug>1)LogPrint("import", "	IN: txid=%s\n", txin.prevout.hash.GetHex().c_str());
        }
    }

    Array vout;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        Object out;
        if (fDebug>1 || ismining)LogPrint("import", "	txOUT: vout[%d] value=%.8lf\n", i, (double)(txout.nValue)/(double)COIN);

    	txnouttype type;
    	vector<CTxDestination> addresses;
	int nRequired = 0;
	if (!ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired)) {
		continue;
	}
	Array a;
	BOOST_FOREACH(const CTxDestination& addr, addresses)
	{
		if (fDebug>1 || ismining)LogPrint("import", "	OUT: address=%s\n", CBitcoinAddress(addr).ToString().c_str());
		if (GetBoolArg("-autoimportaddress", false) && !IsAddressExistInWallet(CBitcoinAddress(addr).ToString()))
		{
			Array params(3);
			params[0] = CBitcoinAddress(addr).ToString();
			params[1] = "";
			params[2] = false;

			Value ret = importaddress(params, false);
			if (ret == Value::null)
				if (fDebug>1 || ismining)LogPrintf("Auto import address: %s\n", CBitcoinAddress(addr).ToString().c_str());
		}
	}
    }
    return naddr;
}


// AcceptToMemPool() 트랜잭션이 들어오면, 주소와 값 모두 출력..
int	AddAddressToWallet(const CWalletTx& wtx, const string funcname)
{
    int	naddr = 0;
    bool ismining = 0;

    if (fDebug>2)LogPrint("import", "AddAddressToWallet(wtx, %s)\n", funcname);

    Array vin;
    BOOST_FOREACH(const CTxIn& txin, wtx.vin)
    {
        Object in;
        if (wtx.IsCoinBase())
	{
            if (fDebug>1)LogPrint("import", "	IN: coinbase=%s\n", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()).c_str());
	    ismining = 1;
	}
        else {
            if (fDebug>1)LogPrint("import", "	IN: txid=%s\n", txin.prevout.hash.GetHex().c_str());
        }
    }

    Array vout;
    for (unsigned int i = 0; i < wtx.vout.size(); i++)
    {
        const CTxOut& txout = wtx.vout[i];
        Object out;
        if (fDebug>1 || ismining)LogPrint("import", "	wtxOUT: vout[%d] value=%.8lf\n", i, (double)(txout.nValue)/(double)COIN);

    	txnouttype type;
    	vector<CTxDestination> addresses;
	int nRequired = 0;
	if (!ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired)) {
		continue;
	}
	Array a;
	BOOST_FOREACH(const CTxDestination& addr, addresses)
	{
		if (fDebug>1 || ismining)LogPrint("import", "	OUT: address=%s\n", CBitcoinAddress(addr).ToString().c_str());
		if (GetBoolArg("-autoimportaddress", false) && !IsAddressExistInWallet(CBitcoinAddress(addr).ToString()))
		{
			Array params(3);
			params[0] = CBitcoinAddress(addr).ToString();
			params[1] = "";
			params[2] = false;

			Value ret = importaddress(params, false);
			if (ret == Value::null)
				if (fDebug>1 || ismining)LogPrintf("Auto import address: %s\n", CBitcoinAddress(addr).ToString().c_str());
		}
	}
    }
    return naddr;
}

#endif	// FEATURE_HDAC_AUTO_IMPORT_ADDRESS


void TxToJSON(const CTransaction& tx, const uint256 hashBlock, Object& entry)
{
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));
    Array vin;
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        Object in;
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (int64_t)txin.prevout.n));
            Object o;
            o.push_back(Pair("asm", txin.scriptSig.ToString()));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }
        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));


    mc_Buffer *asset_amounts=mc_gState->m_TmpBuffers->m_RpcABBuffer2;
    asset_amounts->Clear();

    mc_Script *lpScript=mc_gState->m_TmpBuffers->m_RpcScript4;
    lpScript->Clear();


    Array vdata;
    Array vInputCache;
    bool is_issuefirst=false;
    bool is_issuemore=false;
    int64_t issuerawqty=0;
    unsigned char details_script[MC_ENT_MAX_SCRIPT_SIZE];
    unsigned char short_txid[MC_AST_SHORT_TXID_SIZE];
    char asset_name[MC_ENT_MAX_NAME_SIZE+1];
    int multiple;
    int details_script_size=0;
    int err;
    bool detals_script_found=false;
    uint32_t new_entity_type;
    new_entity_type=MC_ENT_TYPE_NONE;
    set<uint256> streams_already_seen;

    Array vout;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        Object out;
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (int64_t)i));
        Object o;
        ScriptPubKeyToJSON(txout.scriptPubKey, o, true);
        out.push_back(Pair("scriptPubKey", o));

// TODO too many duplicate code with ListWalletTransactions and may be AccepHdacTransaction
        const CScript& script1 = tx.vout[i].scriptPubKey;
        CScript::const_iterator pc1 = script1.begin();

        lpScript->SetScript((unsigned char*)(&pc1[0]),(size_t)(script1.end()-pc1),MC_SCR_TYPE_SCRIPTPUBKEY);

        Value op_return_data;
        string full_script_hex="";
        int asset_update;
        uint32_t value_offset;
        size_t value_size;
        vInputCache.clear();

        if(lpScript->IsOpReturnScript())
        {
            //int e=lpScript->GetNumElements()-1;

            lpScript->SetElement(0);
            err=lpScript->GetNewEntityType(&new_entity_type,&asset_update,details_script,&details_script_size);
            if((err == 0) && (new_entity_type == MC_ENT_TYPE_ASSET))
            {
                if(asset_update == 0)
                {
                    detals_script_found=true;
                    is_issuefirst=true;
                    *asset_name=0x00;
                    multiple=1;
                    value_offset=mc_FindSpecialParamInDetailsScript(details_script,details_script_size,MC_ENT_SPRM_NAME,&value_size);
                    if(value_offset<(uint32_t)details_script_size)
                    {
                        memcpy(asset_name,details_script+value_offset,value_size);
                        asset_name[value_size]=0x00;
                    }
                    value_offset=mc_FindSpecialParamInDetailsScript(details_script,details_script_size,MC_ENT_SPRM_ASSET_MULTIPLE,&value_size);
                    if(value_offset<(uint32_t)details_script_size)
                    {
                        multiple=mc_GetLE(details_script+value_offset,value_size);
                    }
                }
            }
            else
            {
                err=lpScript->GetEntity(short_txid);
                if(err == 0)
                {
                    lpScript->SetElement(1);
                    err=lpScript->GetNewEntityType(&new_entity_type,&asset_update,details_script,&details_script_size);
                    if((err == 0) && (new_entity_type == MC_ENT_TYPE_ASSET))
                    {
                        if(asset_update)
                        {
                            detals_script_found=true;
                            is_issuemore=true;
                        }
                    }
                }
            }

            size_t elem_size;
            const unsigned char *elem;
            int cs_err,cs_offset,cs_new_offset,cs_size,cs_vin;
            unsigned char *cs_script;

            if(lpScript->GetNumElements()<=1)
            {
                if(lpScript->GetNumElements()==1)
                {
                    elem = lpScript->GetData(lpScript->GetNumElements()-1,&elem_size);
                    vdata.push_back(OpReturnEntry(elem,elem_size,tx.GetHash(),i));
                }
            }
            else
            {
                elem = lpScript->GetData(lpScript->GetNumElements()-1,&elem_size);
                if(elem_size)
                {
                    vdata.push_back(OpReturnEntry(elem,elem_size,tx.GetHash(),i));
                }

                lpScript->SetElement(0);
                if(lpScript->GetNewEntityType(&new_entity_type))
                {
                    cs_offset=0;
                    while( (cs_err=lpScript->GetCachedScript(cs_offset,&cs_new_offset,&cs_vin,&cs_script,&cs_size)) == MC_ERR_NOERROR )
                    {
                        if(cs_offset)
                        {
                            Object cs_obj;
                            cs_obj.push_back(Pair("vin", cs_vin));
                            CScript scriptInputCache(cs_script, cs_script + cs_size);
                            cs_obj.push_back(Pair("asm", scriptInputCache.ToString()));
                            cs_obj.push_back(Pair("hex", HexStr(scriptInputCache.begin(), scriptInputCache.end())));
                            vInputCache.push_back(cs_obj);
                        }
                        cs_offset=cs_new_offset;
                    }
                }
            }
        }

        if(vInputCache.size())
        {
            out.push_back(Pair("inputcache", vInputCache));
        }

        int required=0;
        bool is_genesis;
        bool is_valid_asset;

        asset_amounts->Clear();
        if(CreateAssetBalanceList(txout,asset_amounts,lpScript,&required))
        {
            Array assets;
            unsigned char *ptr;
            const unsigned char *txid;

            for(int a=0;a<asset_amounts->GetCount();a++)
            {
                Object asset_entry;
                ptr=(unsigned char *)asset_amounts->GetRow(a);

                uint256 hash=tx.GetHash();
                txid=(unsigned char*)&hash;
                is_genesis=true;
                is_valid_asset=true;
                if( (mc_GetABRefType(ptr) != MC_AST_ASSET_REF_TYPE_SPECIAL) &&
                    (mc_GetABRefType(ptr) != MC_AST_ASSET_REF_TYPE_GENESIS) )
                {
                    mc_EntityDetails entity;
                    if(mc_gState->m_Assets->FindEntityByFullRef(&entity,ptr))
                    {
                        is_genesis=false;
                        txid=entity.GetTxID();
                    }
                    else
                    {
                        is_valid_asset=false;
                    }
                }

                if(is_valid_asset)
                {
                    asset_entry=AssetEntry(txid,mc_GetABQuantity(ptr),0x05);
                    if(is_genesis)
                    {
                        asset_entry.push_back(Pair("type", "issuefirst"));
                        issuerawqty+=mc_GetABQuantity(ptr);
                        is_issuefirst=true;
                    }
                    else
                    {
                        switch(mc_GetABScriptType(ptr))
                        {
                            case MC_SCR_ASSET_SCRIPT_TYPE_TRANSFER:
                                asset_entry.push_back(Pair("type", "transfer"));
                                break;
                            case MC_SCR_ASSET_SCRIPT_TYPE_FOLLOWON:
                                asset_entry.push_back(Pair("type", "issuemore"));
                                issuerawqty+=mc_GetABQuantity(ptr);
                                is_issuemore=true;
                                break;
                            case MC_SCR_ASSET_SCRIPT_TYPE_TRANSFER | MC_SCR_ASSET_SCRIPT_TYPE_FOLLOWON:
                                asset_entry.push_back(Pair("type", "issuemore+transfer"));
                                issuerawqty+=mc_GetABQuantity(ptr);
                                is_issuemore=true;
                                break;
                            case 0:
                                asset_entry.push_back(Pair("type", "issuefirst"));
                                is_issuefirst=true;
                                break;
                        }
                    }

                    assets.push_back(asset_entry);
                }
            }

            out.push_back(Pair("assets", assets));
        }
        Array permissions=PermissionEntries(txout,lpScript,false);
        out.push_back(Pair("permissions", permissions));

        Array items;
        Value data_item_entry=DataItemEntry(tx,i,streams_already_seen, 0x03);
        if(!data_item_entry.is_null())
        {
            items.push_back(data_item_entry);
        }
        out.push_back(Pair("items", items));

        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));
    if(is_issuefirst || is_issuemore)
    {
        Object issue;
        Object details;
        uint32_t offset,next_offset,param_value_start;
        size_t param_value_size;
        bool is_open=false;
        if(detals_script_found)
        {
        	Value vfields;
        	vfields=mc_ExtractDetailsJSONObject(details_script,details_script_size);

            offset=0;

            while((int)offset<details_script_size)
            {
                next_offset=mc_GetParamFromDetailsScript(details_script,details_script_size,offset,&param_value_start,&param_value_size);
                if(param_value_start > 0)
                {
                    if(details_script[offset])
                    {
                        if(details_script[offset] != 0xff)
                        {
                            string param_name((char*)details_script+offset);
                            string param_value((char*)details_script+param_value_start,(char*)details_script+param_value_start+param_value_size);
                            details.push_back(Pair(param_name, param_value));
                        }
                    }
                    else
                    {
                        switch(details_script[offset+1])
                        {
                            case MC_ENT_SPRM_FOLLOW_ONS:
                                if( (param_value_size > 0) && (param_value_size <= 4) )
                                {
                                    if(mc_GetLE(details_script+param_value_start,param_value_size))
                                    {
                                        is_open=true;
                                    }
                                }
                                break;
                        }
                    }
                }
                offset=next_offset;
            }
            if(is_issuefirst)
            {
                issue.push_back(Pair("type", "issuefirst"));
                if(strlen(asset_name))
                {
                    issue.push_back(Pair("name", string(asset_name)));
                }
                issue.push_back(Pair("multiple", multiple));
                issue.push_back(Pair("open", is_open));
            }
            if(is_issuemore)
            {
                issue.push_back(Pair("type", "issuemore"));
                mc_EntityDetails genesis_entity;
                unsigned char *ptr;
                uint256 genesis_hash;
                if(mc_gState->m_Assets->FindEntityByShortTxID(&genesis_entity,short_txid))
                {
                    ptr=(unsigned char *)genesis_entity.GetName();
                    if(ptr && strlen((char*)ptr))
                    {
                        issue.push_back(Pair("name", string((char*)ptr)));
                    }
                    genesis_hash=*(uint256*)genesis_entity.GetTxID();
                    issue.push_back(Pair("issuetxid", genesis_hash.GetHex()));
                    ptr=(unsigned char *)genesis_entity.GetRef();
                    string assetref="";
                    if(genesis_entity.IsUnconfirmedGenesis())
                    {
                        Value null_value;
                        issue.push_back(Pair("assetref",null_value));
                    }
                    else
                    {
                        assetref += itostr((int)mc_GetLE(ptr,4));
                        assetref += "-";
                        assetref += itostr((int)mc_GetLE(ptr+4,4));
                        assetref += "-";
                        assetref += itostr((int)mc_GetLE(ptr+8,2));
                        issue.push_back(Pair("assetref", assetref));
                    }
                }
            }
            if(vfields.type() == null_type )
            {
            	vfields=details;
            }
            issue.push_back(Pair("details", vfields));
        }
        entry.push_back(Pair("issue", issue));
    }
    if(new_entity_type == MC_ENT_TYPE_STREAM)
    {
        uint256 txid=tx.GetHash();
        entry.push_back(Pair("create", StreamEntry((unsigned char*)&txid,0x05)));
    }

    entry.push_back(Pair("data", vdata));


    if (hashBlock != 0) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

Value getrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error("Help message not found\n");

    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw JSONRPCError(RPC_TX_NOT_FOUND, "No information available about transaction");

    CMutableTransaction txToShow=tx;

    if (GetBoolArg("-hideknownopdrops", false))
    {
        for (unsigned int i = 0; i < txToShow.vout.size(); i++)
        {
            txToShow.vout[i].scriptPubKey=RemoveOpDropsIfNeeded(txToShow.vout[i].scriptPubKey);
        }
    }

    string strHex = EncodeHexTx(txToShow);

    if (!fVerbose)
        return strHex;

    Object result;
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);

    return result;
}

#ifdef ENABLE_WALLET
Value listunspent(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error("Help message not found\n");

    RPCTypeCheck(params, list_of(int_type)(int_type)(array_type));

    int64_t nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int64();

    int64_t nMaxDepth = 9999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int64();

    set<CBitcoinAddress> setAddress;
    set<uint160> setAddressUints;
    set<uint160> *lpSetAddressUint=NULL;
    CTxDestination dest;
    if (params.size() > 2) {
        Array inputs = params[2].get_array();
        BOOST_FOREACH(Value& input, inputs) {
            CBitcoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid address: ")+input.get_str());
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_str());
            setAddress.insert(address);

            dest=address.Get();
            const CKeyID *lpKeyID=boost::get<CKeyID> (&dest);
            const CScriptID *lpScriptID=boost::get<CScriptID> (&dest);
            if(lpKeyID)
            {
                setAddressUints.insert(*(uint160*)lpKeyID);
            }
            else
            {
                if(lpScriptID)
                {
                    setAddressUints.insert(*(uint160*)lpScriptID);
                }
           }
        }

        if(setAddressUints.size())
        {
            lpSetAddressUint=&setAddressUints;
        }
    }

    mc_Buffer *asset_amounts=mc_gState->m_TmpBuffers->m_RpcABBuffer1;
    asset_amounts->Clear();

    mc_Script *lpScript=mc_gState->m_TmpBuffers->m_RpcScript3;
    lpScript->Clear();

    {
        LOCK(pwalletMain->cs_wallet);
        pwalletMain->nNextUnspentOptimization=mc_TimeNowAsUInt()+GetArg("-autocombinesuspend", 15);
    }

    Array results;
    vector<COutput> vecOutputs;
    assert(pwalletMain != NULL);
    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true, true, 0, lpSetAddressUint);
    BOOST_FOREACH(const COutput& out, vecOutputs) {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        CTxOut txout;
        uint256 hash=out.GetHashAndTxOut(txout);

        if (setAddress.size()) {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            if (!setAddress.count(address))
                continue;
        }

        CAmount nValue = txout.nValue;
        const CScript& pk = RemoveOpDropsIfNeeded(txout.scriptPubKey);
        Object entry;

        entry.push_back(Pair("txid", hash.GetHex()));
        entry.push_back(Pair("vout", out.i));
        CTxDestination address;
        if (ExtractDestination(txout.scriptPubKey, address)) {
            entry.push_back(Pair("address", CBitcoinAddress(address).ToString()));
            if (pwalletMain->mapAddressBook.count(address))
                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name));
        }
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {

                // Bitcoin issue #6056 with booust 1.58 fixed in https://github.com/bitcoin/bitcoin/commit/8b08d9530b93c7a98e7387167ecd2cd5b0563bfb
                const CScriptID& hash = boost::get<CScriptID>(address);

                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount",ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations",out.nDepth));


        if(OutputCanSend(out))
        {
            entry.push_back(Pair("cansend", true));
            entry.push_back(Pair("spendable", out.fSpendable));
        }
        else
        {
            entry.push_back(Pair("cansend", false));
            entry.push_back(Pair("spendable", false));
        }

        asset_amounts->Clear();
        if(CreateAssetBalanceList(txout,asset_amounts,lpScript))
        {
            Array assets;
            unsigned char *ptr;
            const unsigned char *txid;

            for(int a=0;a<asset_amounts->GetCount();a++)
            {
                Object asset_entry;
                ptr=(unsigned char *)asset_amounts->GetRow(a);

                txid=(unsigned char*)&hash;
                if( (mc_GetABRefType(ptr) != MC_AST_ASSET_REF_TYPE_SPECIAL) &&
                    (mc_GetABRefType(ptr) != MC_AST_ASSET_REF_TYPE_GENESIS) )
                {
                    mc_EntityDetails entity;
                    if(mc_gState->m_Assets->FindEntityByFullRef(&entity,ptr))
                    {
                        txid=entity.GetTxID();
                    }
                }

                asset_entry=AssetEntry(txid,mc_GetABQuantity(ptr),0x00);
                assets.push_back(asset_entry);
            }

            entry.push_back(Pair("assets", assets));
        }
        Array permissions=PermissionEntries(txout,lpScript,false);
        entry.push_back(Pair("permissions", permissions));
//        entry.push_back(Pair("spendable", out.fSpendable));

        results.push_back(entry);
    }

    return results;
}
#endif


Value appendrawchange(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error("Help message not found\n");

    // parse hex string from parameter
    CTransaction tx;
    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    CBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");

    bool fFeeAmountIsSet=false;
    CAmount nFeeAmount = 0;
    if (params.size() > 2 && params[2].type() != null_type)
    {
        nFeeAmount = AmountFromValue(params[2]);
        fFeeAmountIsSet=true;
    }

    Object result;
    string strError="";
    CAmount nAmount;

    vector <CTxOut> input_txouts;
    vector <string> input_errors;

    if(!GetTxInputsAsTxOuts(tx, input_txouts, input_errors,strError))
    {
        if(strError.size())
        {
            throw JSONRPCError(RPC_OUTPUT_NOT_FOUND, strError);
        }
        BOOST_FOREACH(const string& err, input_errors)
        {
            if(err.size())
            {
                throw JSONRPCError(RPC_OUTPUT_NOT_FOUND, err);
            }
        }
    }

    mc_Buffer *asset_amounts=mc_gState->m_TmpBuffers->m_RpcABBuffer1;
    asset_amounts->Clear();
    mc_Buffer *amounts=mc_gState->m_TmpBuffers->m_RpcABBuffer2;
    amounts->Clear();

    mc_Script *lpScript=mc_gState->m_TmpBuffers->m_RpcScript3;
    lpScript->Clear();

    int allowed=0;
    int required=0;

    nAmount=0;
    asset_amounts->Clear();
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        if(ParseHdacTxOutToBuffer(0,txout,asset_amounts,lpScript,&allowed,&required,strError))
        {
            nAmount+=txout.nValue;
        }
    }

    nAmount=-nAmount;
    for(int i=0;i<asset_amounts->GetCount();i++)
    {
        uint64_t quantity=mc_GetABQuantity(asset_amounts->GetRow(i));
        quantity=-quantity;
        mc_SetABQuantity(asset_amounts->GetRow(i),quantity);
    }

    allowed=0;
    required=0;
    int i=0;
    BOOST_FOREACH(const CTxOut& txout, input_txouts)
    {
        if(ParseHdacTxOutToBuffer(tx.vin[i].prevout.hash,txout,asset_amounts,lpScript,&allowed,&required,strError))
        {
            nAmount+=txout.nValue;
        }
        i++;
    }

    if(nAmount < 0)
    {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, output native currency value is higher than input");
    }

    amounts->Clear();
    for(int i=0;i<asset_amounts->GetCount();i++)
    {
        if(mc_GetABRefType(asset_amounts->GetRow(i)) == MC_AST_ASSET_REF_TYPE_GENESIS)
        {
            throw JSONRPCError(RPC_UNCONFIRMED_ENTITY, "Unconfirmed issue transaction in input");
        }
        if(mc_GetABRefType(asset_amounts->GetRow(i)) != MC_AST_ASSET_REF_TYPE_SPECIAL)
        {
            int64_t quantity=mc_GetABQuantity(asset_amounts->GetRow(i));
            if(quantity < 0)
            {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, output asset value is higher than input");
            }
            if(quantity > 0)
            {
                amounts->Add(asset_amounts->GetRow(i));
            }
        }
    }

    {
        int assets_per_opdrop=(MAX_SCRIPT_ELEMENT_SIZE-4)/(mc_gState->m_NetworkParams->m_AssetRefSize+MC_AST_ASSET_QUANTITY_SIZE);
    
        if(amounts->GetCount() > assets_per_opdrop)
        {
            throw JSONRPCError(RPC_NOT_ALLOWED, strprintf("Too many assets, maximal number for this chain - %d",assets_per_opdrop));
        }
    }

    CScript scriptChange=GetScriptForDestination(address.Get());

    size_t elem_size;
    const unsigned char *elem;
    lpScript->Clear();

    if(amounts->GetCount())
    {
        lpScript->SetAssetQuantities(amounts,MC_SCR_ASSET_SCRIPT_TYPE_TRANSFER);
        for(int element=0;element < lpScript->GetNumElements();element++)
        {
            elem = lpScript->GetData(element,&elem_size);
            if(elem)
            {
                scriptChange << vector<unsigned char>(elem, elem + elem_size) << OP_DROP;
            }
            else
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Internal error: cannot create asset transfer script");
            }
        }
    }


    CAmount change_amount;
    CAmount min_output=-1;                                                              // Calculate minimal output for the change
    min_output=MCP_MINIMUM_PER_OUTPUT;

    if(min_output<0)
    {
        min_output=3*(::minRelayTxFee.GetFee(GetSerializeSize(SER_DISK,0)+148u));
    }

    CMutableTransaction txNew;

    if(nAmount < nFeeAmount)
    {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, remaining native currency value is lower than required fee");
    }

    txNew.vin.clear();
    txNew.vout.clear();

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        txNew.vin.push_back(txin);
    }
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        txNew.vout.push_back(txout);
    }

    if( (nAmount >= nFeeAmount) || (amounts->GetCount() > 0) )
    {
        change_amount=nAmount-nFeeAmount;
        if(change_amount<min_output)
        {
            if(amounts->GetCount() > 0)
            {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, output asset value is higher than input");
            }
        }
        else
        {
            CTxOut txout(change_amount, scriptChange);
            txNew.vout.push_back(txout);
            if(!fFeeAmountIsSet)
            {
                minRelayTxFee = CFeeRate(MIN_RELAY_TX_FEE);
                unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
                nBytes+=txNew.vin.size()*108;
                nBytes=((nBytes-1)/1000+1)*1000;
                nFeeAmount=::GetMinRelayFee(tx,nBytes,false);
                if(change_amount != (nAmount-nFeeAmount))
                {
                    change_amount=nAmount-nFeeAmount;
                    if(change_amount<min_output)
                    {
                        if(amounts->GetCount() > 0)
                        {
                            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, output asset value is higher than input");
                        }
                        else
                        {
                            txNew.vout.pop_back();
                        }
                    }
                    else
                    {
                        txNew.vout.back().nValue=change_amount;
                    }
                }
            }
        }
    }


    return EncodeHexTx(txNew);
}


void AddCacheInputScriptIfNeeded(CMutableTransaction& rawTx,Array inputs, bool fRequired)
{
    vector <CScript> script_for_cache;
    vector <int> cache_array;
    bool fMissingScript=false;

    BOOST_FOREACH(const Value& input, inputs) {
        const Object& o = input.get_obj();

        const Value& vout_v = find_value(o, "vout");
        if (vout_v.type() != int_type)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        const Value& scriptPubKeyString = find_value(o, "scriptPubKey");

        if(!scriptPubKeyString.is_null())
        {
            bool fIsHex;
            if( (scriptPubKeyString.type() != str_type) || (scriptPubKeyString.get_str().size() == 0) )
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, scriptPubKey must not be empty");
            }

            vector<unsigned char> dataData(ParseHex(scriptPubKeyString.get_str().c_str(),fIsHex));
            if(!fIsHex)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, scriptPubKey must be hexadecimal string");
            }
            CScript scriptPubKey(dataData.begin(), dataData.end());

            script_for_cache.push_back(scriptPubKey);
        }
        else
        {
            script_for_cache.push_back(CScript());
        }

        const Value& cache_this = find_value(o, "cache");
        int cache_value=-1;
        if(!cache_this.is_null())
        {
            cache_value=0;
            if(cache_this.type() != bool_type)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, cache must be boolean");
            }
            if(cache_this.get_bool())
            {
                if(scriptPubKeyString.is_null())
                {
                    fMissingScript=true;
                }
                cache_value=1;
            }
        }
        cache_array.push_back(cache_value);
    }

    if(fRequired)
    {
        if(!fMissingScript)
        {
            for(int i=0;i<(int)script_for_cache.size();i++)
            {
                if(script_for_cache[i].size() == 0)
                {
                    fMissingScript=true;
                }
            }
        }
    }

    if(fMissingScript)
    {
        CCoinsView viewDummy;
        CCoinsViewCache view(&viewDummy);
        {
            LOCK(mempool.cs);
            CCoinsViewCache &viewChain = *pcoinsTip;
            CCoinsViewMemPool viewMempool(&viewChain, mempool);
            view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

            BOOST_FOREACH(const CTxIn& txin, rawTx.vin) {
                const uint256& prevHash = txin.prevout.hash;
                CCoins coins;
                view.AccessCoins(prevHash); // this is certainly allowed to fail
            }

            view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
        }
        for(int i=0;i<(int)script_for_cache.size();i++)
        {
            if(script_for_cache[i].size() == 0)
            {
                const Object& o = inputs[i].get_obj();
                uint256 txid = ParseHashO(o, "txid");
                int vout_v = find_value(o, "vout").get_int();

                CCoinsModifier coins = view.ModifyCoins(txid);
                if (coins->IsAvailable(vout_v))
                {
                    script_for_cache[i]=coins->vout[vout_v].scriptPubKey;
                }
                else
                {
                    throw JSONRPCError(RPC_OUTPUT_NOT_FOUND, "Previous output scriptPubKey not found");
                }
            }
        }
    }

    bool fNewOutputs=false;

    for(int i=0;i<(int)script_for_cache.size();i++)
    {
        if( (cache_array[i] < 0) && fRequired)
        {
            CTxDestination addressRet;
            if(ExtractDestinationScriptValid(script_for_cache[i], addressRet))
            {
                const unsigned char *aptr;
                aptr=GetAddressIDPtr(addressRet);
                if(aptr)
                {
                    if(mc_gState->m_Permissions->CanAdmin(NULL,aptr))
                    {
                        cache_array[i]=1;
                    }
                }
            }
        }
        if(cache_array[i] == 1)
        {
            fNewOutputs=true;
        }
    }

    int cs_offset;
    cs_offset=0;
    cache_array.push_back(1);

    if(fNewOutputs)
    {
        mc_Script *lpDetails=mc_gState->m_TmpBuffers->m_RpcScript4;
        lpDetails->Clear();
        for(int i=0;i<(int)cache_array.size();i++)
        {
            if(cache_array[i] == 1)
            {
                if( (cs_offset+9+script_for_cache[i].size() > MAX_SCRIPT_ELEMENT_SIZE) || (i == (int)cache_array.size() -1) )
                {
                    if(cs_offset>0)
                    {
                        size_t bytes;
                        const unsigned char *script;
                        CScript scriptOpReturn=CScript();

                        script=lpDetails->GetData(0,&bytes);
                        scriptOpReturn << vector<unsigned char>(script, script + bytes) << OP_DROP << OP_RETURN;
                        CTxOut txout(0,scriptOpReturn);
                        rawTx.vout.push_back(txout);
                        lpDetails->Clear();
                    }
                }

                if(i < (int)cache_array.size() - 1)
                {
                    if(cs_offset == 0)
                    {
                        lpDetails->SetCachedScript(cs_offset,&cs_offset,-1,NULL,-1);
                    }
                    const CScript& script3 = script_for_cache[i];
                    CScript::const_iterator pc3 = script3.begin();

                    lpDetails->SetCachedScript(cs_offset,&cs_offset,i,(unsigned char*)&pc3[0],script3.size());
                }
            }
        }
    }
}




Value appendrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error("Help message not found\n");

    RPCTypeCheck(params, list_of(str_type)(array_type));

    CTransaction source_tx;
    Array inputs = params[1].get_array();
    Object sendTo;

    if (params.size() > 2)
    {
        if(params[2].type() != obj_type)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid addresses, should be object");

        sendTo= params[2].get_obj();
    }
    bool new_outputs=false;
    if(sendTo.size())
    {
        new_outputs=true;
    }
    if (params.size() > 3 && params[3].type() == array_type)
    {
        if(params[3].get_array().size())
        {
            new_outputs=true;
        }
    }

    if(params[0].get_str().size())
    {
        if (!DecodeHexTx(source_tx, params[0].get_str()))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

        for (unsigned int i = 0; i < source_tx.vin.size(); i++)
        {
            const CScript& script2 = source_tx.vin[i].scriptSig;
            CScript::const_iterator pc2 = script2.begin();
            uint32_t disallowed=mc_CheckSigScriptForMutableTx((unsigned char*)(&pc2[0]),(int)(script2.end()-pc2));

            if(inputs.size())
            {
                if(disallowed & 0x01)
                {
                    throw JSONRPCError(RPC_NOT_ALLOWED, "Cannot append inputs without violating existing signatures");
                }
            }
            if(new_outputs)
            {
                if(disallowed & 0x02)
                {
                    throw JSONRPCError(RPC_NOT_ALLOWED, "Cannot append outputs without violating existing signatures");
                }
                if(disallowed & 0x04)
                {
                    if(i > source_tx.vout.size())
                    {
                        throw JSONRPCError(RPC_NOT_ALLOWED, "Cannot append outputs without violating existing signatures");
                    }
                }
            }
        }
    }

    Array inputs_for_signature;

    CMutableTransaction rawTx;
    for (unsigned int i = 0; i < source_tx.vin.size(); i++)
    {
        rawTx.vin.push_back(source_tx.vin[i]);
        if(i < source_tx.vout.size())
        {
            rawTx.vout.push_back(source_tx.vout[i]);
        }
    }

    BOOST_FOREACH(const Value& input, inputs) {
        const Object& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const Value& vout_v = find_value(o, "vout");
        if (vout_v.type() != int_type)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        CTxIn in(COutPoint(txid, nOutput));
        rawTx.vin.push_back(in);

        const Value& scriptPubKey = find_value(o, "scriptPubKey");
        if(!scriptPubKey.is_null())
        {
            inputs_for_signature.push_back(input);
        }
    }

    vector <pair<CScript, CAmount> > vecSend;
    int required=0;
    bool fCachedInputScriptRequired=false;
    vecSend=ParseRawOutputMultiObject(sendTo,&required);
    BOOST_FOREACH (const PAIRTYPE(CScript, CAmount)& s, vecSend)
    {
        CTxOut out(s.second, s.first);
        rawTx.vout.push_back(out);
    }

    if( required & (MC_PTP_ADMIN | MC_PTP_MINE) )
    {
        if(mc_gState->m_NetworkParams->GetInt64Param("supportminerprecheck"))
        {
            fCachedInputScriptRequired=true;
        }
    }

    AddCacheInputScriptIfNeeded(rawTx,inputs,fCachedInputScriptRequired);

    mc_EntityDetails entity;
    mc_gState->m_TmpAssetsOut->Clear();
    for(int i=0;i<(int)rawTx.vout.size();i++)
    {
        FindFollowOnsInScript(rawTx.vout[i].scriptPubKey,mc_gState->m_TmpAssetsOut,mc_gState->m_TmpScript);
    }
    entity.Zero();
    if(mc_gState->m_TmpAssetsOut->GetCount())
    {
        if(!mc_gState->m_Assets->FindEntityByFullRef(&entity,mc_gState->m_TmpAssetsOut->GetRow(0)))
        {
            throw JSONRPCError(RPC_ENTITY_NOT_FOUND, "Follow-on script rejected - asset not found");
        }
    }


    if (params.size() > 3 && params[3].type() != null_type)
    {
        BOOST_FOREACH(const Value& data, params[3].get_array())
        {
            CScript scriptOpReturn=ParseRawMetadata(data,0xFFFF,&entity,NULL);
            CTxOut out(0, scriptOpReturn);
            rawTx.vout.push_back(out);
        }
    }

    for (unsigned int i = source_tx.vin.size(); i < source_tx.vout.size(); i++)
    {
        rawTx.vout.push_back(source_tx.vout[i]);
    }

    string action="";
    string hex=EncodeHexTx(rawTx);
    Value signedTx;
    Value txid;
    bool sign_it=false;
    bool lock_it=false;
    bool send_it=false;
    if (params.size() > 4 && params[4].type() != null_type)
    {
        ParseRawAction(params[4].get_str(),lock_it,sign_it,send_it);
    }

    if(sign_it)
    {
        Array signrawtransaction_params;
        signrawtransaction_params.push_back(hex);
        if(inputs_for_signature.size())
        {
            signrawtransaction_params.push_back(inputs_for_signature);
        }
        signedTx=signrawtransaction(signrawtransaction_params,false);
    }
    if(lock_it)
    {
        BOOST_FOREACH(const CTxIn& txin, rawTx.vin)
        {
            COutPoint outpt(txin.prevout.hash, txin.prevout.n);
            pwalletMain->LockCoin(outpt);
        }
    }
    if(send_it)
    {
        Array sendrawtransaction_params;
        BOOST_FOREACH(const Pair& s, signedTx.get_obj())
        {
            if(s.name_=="complete")
            {
                if(!s.value_.get_bool())
                {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Transaction was not signed properly");
                }
            }
            if(s.name_=="hex")
            {
                sendrawtransaction_params.push_back(s.value_.get_str());
            }
        }
        txid=sendrawtransaction(sendrawtransaction_params,false);
    }

    if(send_it)
    {
        return txid;
    }

    if(sign_it)
    {
        return signedTx;
    }

    return hex;
}

Value createrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error("Help message not found\n");

    RPCTypeCheck(params, list_of(array_type)(obj_type));

    Array ext_params;
    ext_params.push_back("");
    BOOST_FOREACH(const Value& value, params)
    {
        ext_params.push_back(value);
    }

    return appendrawtransaction(ext_params,fHelp);

    Array inputs = params[0].get_array();
    Object sendTo = params[1].get_obj();
    Array inputs_for_signature;

    CMutableTransaction rawTx;

    BOOST_FOREACH(const Value& input, inputs) {
        const Object& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const Value& vout_v = find_value(o, "vout");
        if (vout_v.type() != int_type)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        CTxIn in(COutPoint(txid, nOutput));
        rawTx.vin.push_back(in);

        const Value& scriptPubKey = find_value(o, "scriptPubKey");
        if(!scriptPubKey.is_null())
        {
            inputs_for_signature.push_back(input);
        }
    }

    vector <pair<CScript, CAmount> > vecSend;
    int required=0;
    bool fCachedInputScriptRequired=false;
    vecSend=ParseRawOutputMultiObject(sendTo,&required);
    BOOST_FOREACH (const PAIRTYPE(CScript, CAmount)& s, vecSend)
    {
        CTxOut out(s.second, s.first);
        rawTx.vout.push_back(out);
    }

    if( required & (MC_PTP_ADMIN | MC_PTP_MINE) )
    {
        if(mc_gState->m_NetworkParams->GetInt64Param("supportminerprecheck"))
        {
            fCachedInputScriptRequired=true;
        }
    }

    AddCacheInputScriptIfNeeded(rawTx,inputs,fCachedInputScriptRequired);

    mc_EntityDetails entity;
    mc_gState->m_TmpAssetsOut->Clear();
    for(int i=0;i<(int)rawTx.vout.size();i++)
    {
        FindFollowOnsInScript(rawTx.vout[i].scriptPubKey,mc_gState->m_TmpAssetsOut,mc_gState->m_TmpScript);
    }
    entity.Zero();
    if(mc_gState->m_TmpAssetsOut->GetCount())
    {
        if(!mc_gState->m_Assets->FindEntityByFullRef(&entity,mc_gState->m_TmpAssetsOut->GetRow(0)))
        {
            throw JSONRPCError(RPC_ENTITY_NOT_FOUND, "Follow-on script rejected - asset not found");
        }
    }


    if (params.size() > 2 && params[2].type() != null_type)
    {
        BOOST_FOREACH(const Value& data, params[2].get_array())
        {
            CScript scriptOpReturn=ParseRawMetadata(data,0xFFFF,&entity,NULL);
            CTxOut out(0, scriptOpReturn);
            rawTx.vout.push_back(out);
        }
    }

    string action="";
    string hex=EncodeHexTx(rawTx);
    Value signedTx;
    Value txid;
    bool sign_it=false;
    bool lock_it=false;
    bool send_it=false;
    if (params.size() > 3 && params[3].type() != null_type)
    {
        ParseRawAction(params[3].get_str(),lock_it,sign_it,send_it);
    }

    if(sign_it)
    {
        Array signrawtransaction_params;
        signrawtransaction_params.push_back(hex);
        if(inputs_for_signature.size())
        {
            signrawtransaction_params.push_back(inputs_for_signature);
        }
        signedTx=signrawtransaction(signrawtransaction_params,false);
    }
    if(lock_it)
    {
        BOOST_FOREACH(const CTxIn& txin, rawTx.vin)
        {
            COutPoint outpt(txin.prevout.hash, txin.prevout.n);
            pwalletMain->LockCoin(outpt);
        }
    }
    if(send_it)
    {
        Array sendrawtransaction_params;
        BOOST_FOREACH(const Pair& s, signedTx.get_obj())
        {
            if(s.name_=="complete")
            {
                if(!s.value_.get_bool())
                {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Transaction was not signed properly");
                }
            }
            if(s.name_=="hex")
            {
                sendrawtransaction_params.push_back(s.value_.get_str());
            }
        }
        txid=sendrawtransaction(sendrawtransaction_params,false);
    }

    if(send_it)
    {
        return txid;
    }

    if(sign_it)
    {
        return signedTx;
    }

    return hex;
}



Value appendrawmetadata(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2 )
        throw runtime_error("Help message not found\n");

    CMutableTransaction tx;

    vector<unsigned char> txData(ParseHex(params[0].get_str()));

    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    ssData >> tx;

    mc_EntityDetails entity;
    mc_gState->m_TmpAssetsOut->Clear();
    for(int i=0;i<(int)tx.vout.size();i++)
    {
        FindFollowOnsInScript(tx.vout[i].scriptPubKey,mc_gState->m_TmpAssetsOut,mc_gState->m_TmpScript);
    }
    entity.Zero();
    if(mc_gState->m_TmpAssetsOut->GetCount())
    {
        if(!mc_gState->m_Assets->FindEntityByFullRef(&entity,mc_gState->m_TmpAssetsOut->GetRow(0)))
        {
            throw JSONRPCError(RPC_ENTITY_NOT_FOUND, "Follow-on script rejected - asset not found");
        }
    }

    CScript scriptOpReturn=ParseRawMetadata(params[1],0xFFFF,&entity,NULL);

    CTxOut txout(0, scriptOpReturn);
    tx.vout.push_back(txout);

    return EncodeHexTx(tx);
}

Value disablerawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("Help message not found\n");

    RPCTypeCheck(params, list_of(str_type));

    if( (pwalletMain->lpAssetGroups == NULL) || (pwalletMain->lpAssetGroups == 0) )
    {
        throw JSONRPCError(RPC_NOT_SUPPORTED, "disablerawtx supported only for protocol=hdac");
    }

    CTransaction tx;

    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");


    EnsureWalletIsUnlocked();
    LOCK (pwalletMain->cs_wallet_send);

    bool input_found=false;
    bool permission_found=false;
    string strLastError;

    for(int i=0;i<(int)tx.vin.size();i++)
    {
        string strError;
        CTxOut preparedTxOut;
        if(FindPreparedTxOut(preparedTxOut,tx.vin[i].prevout,strError))
        {
            if( (pwalletMain->IsMine(preparedTxOut) & ISMINE_SPENDABLE) != ISMINE_NO )
            {
                bool take_it=true;
                CWalletTx wtx;
                vector<CScript> scriptPubKeys;
                CReserveKey reservekey(pwalletMain);
                CAmount nFeeRequired;
                string strError;
                set<CTxDestination> thisFromAddresses;
                set<CTxDestination> *lpFromAddresses;
                CScript scriptOpReturn;
                vector<COutPoint> vCoinsToUse;
                COutPoint outpt=tx.vin[i].prevout;

                bool wasLocked=pwalletMain->IsLockedCoin(outpt.hash,outpt.n);
                bool wasUnlocked=false;

                input_found=true;
                vCoinsToUse.push_back(outpt);
                scriptPubKeys.push_back(preparedTxOut.scriptPubKey);

                const CScript& script1 = preparedTxOut.scriptPubKey;
                CTxDestination addressRet;
                if(!ExtractDestination(script1, addressRet))
                {
                    take_it=false;
                }

                CKeyID *lpKeyID=boost::get<CKeyID> (&addressRet);
                if(lpKeyID == NULL)
                {
                    take_it=false;
                }

                if(mc_gState->m_Permissions->CanSend(NULL,(unsigned char*)(lpKeyID)) == 0)
                {
                    take_it=false;
                }

                if(mc_gState->m_Permissions->CanReceive(NULL,(unsigned char*)(lpKeyID)) == 0)
                {
                    take_it=false;
                }


                if(take_it)
                {
                    permission_found=true;
                    thisFromAddresses.insert(addressRet);

                    lpFromAddresses=NULL;
                    if(thisFromAddresses.size())
                    {
                        lpFromAddresses=&thisFromAddresses;
                    }

                    if(wasLocked)
                    {
                        pwalletMain->UnlockCoin(outpt);
                        wasUnlocked=true;
                    }
                    if (!pwalletMain->CreateTransaction(scriptPubKeys, preparedTxOut.nValue, scriptOpReturn, wtx, reservekey, nFeeRequired, strError, NULL, lpFromAddresses,1,-1,-1,&vCoinsToUse))
                    {
                        take_it=false;
                        if (preparedTxOut.nValue + nFeeRequired > pwalletMain->GetBalance())
                        {
                            strLastError=strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));;
                        }
                        else
                        {
                            strLastError=strError;
                        }
                    }
                }

                if(take_it)
                {
                    string strRejectReason;
                    if (!pwalletMain->CommitTransaction(wtx, reservekey, strRejectReason))
                    {
                        if(strLastError.size() == 0 )
                        {
                            strLastError=strRejectReason;
                        }
                        take_it=false;
                    }
                }

                if(take_it)
                {
                    return  wtx.GetHash().GetHex();
                }
                else
                {
                    if(wasUnlocked)
                    {
                        pwalletMain->LockCoin(outpt);
                        wasUnlocked=false;
                    }
                }
            }
        }
    }

    if(input_found)
    {
        if(!permission_found)
        {
            throw JSONRPCError(RPC_INSUFFICIENT_PERMISSIONS, "At least one of the input addresses should have send and receive permission ");
        }
        else
        {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, strLastError);
        }
    }

    throw JSONRPCError(RPC_INPUTS_NOT_MINE, "Couldn't find unspent input in this tx belonging to this wallet.");
}




Value decoderawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("Help message not found\n");

    RPCTypeCheck(params, list_of(str_type));

    CTransaction tx;

    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    Object result;
    TxToJSON(tx, 0, result);

    return result;
}

Value decodescript(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("Help message not found\n");

    RPCTypeCheck(params, list_of(str_type));

    Object r;
    CScript script;
    if (params[0].get_str().size() > 0){
        vector<unsigned char> scriptData(ParseHexV(params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false);

    r.push_back(Pair("p2sh", CBitcoinAddress(CScriptID(script)).ToString()));
    return r;
}

Value signrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error("Help message not found\n");

    RPCTypeCheck(params, list_of(str_type)(array_type)(array_type)(str_type), true);

    bool fOffline=GetBoolArg("-offline",false);
    if(fOffline && (params.size() < 2) )
    {
    	throw JSONRPCError(RPC_NOT_SUPPORTED, "prevtxs is required in offline mode");
    }

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CMutableTransaction> txVariants;
    while (!ssData.empty()) {
        try {
            CMutableTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (const std::exception &) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);
    bool fComplete = true;

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);

    if(!fOffline)
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH(const CTxIn& txin, mergedTx.vin) {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.AccessCoins(prevHash); // this is certainly allowed to fail
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2 && params[2].type() != null_type) {
        fGivenKeys = true;
        Array keys = params[2].get_array();
        BOOST_FOREACH(Value k, keys) {
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            if (!key.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else
        EnsureWalletIsUnlocked();
#endif

    // Add previous txouts given in the RPC call:
    if (params.size() > 1 && params[1].type() != null_type) {
        Array prevTxs = params[1].get_array();
        BOOST_FOREACH(Value& p, prevTxs) {
            if (p.type() != obj_type)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            Object prevOut = p.get_obj();

            RPCTypeCheck(prevOut, map_list_of("txid", str_type)("vout", int_type)("scriptPubKey", str_type));

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

	    {
                CCoinsModifier coins = view.ModifyCoins(txid);
                if (coins->IsAvailable(nOut) && coins->vout[nOut].scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + coins->vout[nOut].scriptPubKey.ToString() + "\nvs:\n"+
                        scriptPubKey.ToString();
                    throw JSONRPCError(RPC_OUTPUT_NOT_FOUND, err);
                }
                if ((unsigned int)nOut >= coins->vout.size())
                    coins->vout.resize(nOut+1);
                coins->vout[nOut].scriptPubKey = scriptPubKey;
                coins->vout[nOut].nValue = 0; // we don't know the actual output value
	    }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) {
                RPCTypeCheck(prevOut, map_list_of("txid", str_type)("vout", int_type)("scriptPubKey", str_type)("redeemScript",str_type));
                Value v = find_value(prevOut, "redeemScript");
                if (!(v == Value::null)) {
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    if (params.size() > 3 && params[3].type() != null_type) {
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ;
        string strHashType = params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (coins == NULL || !coins->IsAvailable(txin.prevout.n)) {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = coins->vout[txin.prevout.n].scriptPubKey;

        txin.scriptSig.clear();
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CMutableTransaction& txv, txVariants) {
            txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SKIP_SEND_PERMISSION_CHECK, MutableTransactionSignatureChecker(&mergedTx, i)))
            fComplete = false;
    }

    Object result;
    result.push_back(Pair("hex", EncodeHexTx(mergedTx)));
    result.push_back(Pair("complete", fComplete));

    return result;
}

Value sendrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error("Help message not found\n");

    RPCTypeCheck(params, list_of(str_type)(bool_type));

    // parse hex string from parameter
    CTransaction tx;
    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();

    bool fOverrideFees = false;
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool();

    CCoinsViewCache &view = *pcoinsTip;
    const CCoins* existingCoins = view.AccessCoins(hashTx);
    bool fHaveMempool = mempool.exists(hashTx);
    bool fHaveChain = existingCoins && existingCoins->nHeight < 1000000000;
    bool fMissingInputs;
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, !fOverrideFees)) {
            if(state.IsInvalid())
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            else

            {
                if(state.GetRejectReason().size())
                {
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, state.GetRejectReason());
                }
                else
                {
                    if(!mempool.exists(hashTx))
                    {
                        if(fMissingInputs)
                        {
                            if(!fHaveChain)
                            {
                                throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "missing inputs");
                            }
                        }
                        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
                    }
                }
            }

        }

        if(pwalletMain)
        {
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outp=tx.vin[i].prevout;
                pwalletMain->UnlockCoin(outp);
            }
        }


    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }

    RelayTransaction(tx);

    return hashTx.GetHex();
}
