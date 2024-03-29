// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2014-2016 The Bitcoin Core developers
// Original code was distributed under the MIT software license.
// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
// 
// 2018/01/00	Code optimization
//============================================================================================


#include "wallet_ismine.h"

#include "keys/key.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"

#include <boost/foreach.hpp>

using namespace std;

typedef vector<unsigned char> valtype;

unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys)
    {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

isminetype IsMineKeyID(const CKeyStore& keystore, const CKeyID& dest)
{
    if (keystore.HaveKey(dest))
        return ISMINE_SPENDABLE;
    if (keystore.HaveWatchOnly(GetScriptForDestination(dest)))
        return ISMINE_WATCH_ONLY;
    return ISMINE_NO;    
}

isminetype IsMineScriptID(const CKeyStore& keystore, const CScriptID& dest)
{
    CScript subscript;
    if (keystore.GetCScript(dest, subscript)) {
        isminetype ret = IsMine(keystore, subscript);
        if (ret == ISMINE_SPENDABLE)
            return ret;
    }    
    if (keystore.HaveWatchOnly(GetScriptForDestination(dest)))
        return ISMINE_WATCH_ONLY;
    return ISMINE_NO;    
}

isminetype IsMine(const CKeyStore &keystore, const CTxDestination& dest)
{
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script);
}

isminetype IsMine(const CKeyStore &keystore, const CScript& scriptPubKey)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!TemplateSolver(scriptPubKey, whichType, vSolutions)) {
        if (keystore.HaveWatchOnly(scriptPubKey.RemoveOpDrops()))
            return ISMINE_WATCH_ONLY;
        return ISMINE_NO;
    }

    
    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_SCRIPTHASH:
    {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            isminetype ret = IsMine(keystore, subscript);
            if (ret == ISMINE_SPENDABLE)
                return ret;
        }
        break;
    }
    case TX_MULTISIG:
    {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (HaveKeys(keys, keystore) == keys.size())
            return ISMINE_SPENDABLE;
        break;
    }
    }

    if (keystore.HaveWatchOnly(scriptPubKey.RemoveOpDrops()))
        return ISMINE_WATCH_ONLY;
    return ISMINE_NO;
}
