// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2014-2016 The Bitcoin Core developers
// Original code was distributed under the MIT software license.
// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
/*============================================================================================
   History
   
   2018/02/00   Code optimization
============================================================================================*/

#include "script/standard.h"

#include "keys/pubkey.h"
#include "script/script.h"
#include "utils/util.h"
#include "utils/utilstrencodings.h"

#include "hdac/hdac.h"

#include <boost/foreach.hpp>

using namespace std;

typedef vector<unsigned char> valtype;

unsigned nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

const char* GetTxnOutputType(txnouttype t)
{
    switch (t)
    {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_NULL_DATA: return "nulldata";
    }
    return NULL;
}

/**
 * Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
 */
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, vector<vector<unsigned char> >& vSolutionsRet)
{
    // Templates
    static multimap<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

        // Empty, provably prunable, data-carrying output
        if (GetBoolArg("-datacarrier", true))
            mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_RETURN << OP_SMALLDATA));
                        
        mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_RETURN));
        
        mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_DROPDATA << OP_DROP << OP_RETURN));            
        mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_DROPDATA << OP_DROP << OP_RETURN << OP_SMALLDATA));            
        mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_DROPDATA << OP_DROP << OP_DROPDATA << OP_DROP << OP_RETURN));            
        mTemplates.insert(make_pair(TX_NULL_DATA, CScript() << OP_DROPDATA << OP_DROP << OP_DROPDATA << OP_DROP << OP_RETURN << OP_SMALLDATA));            
        
        mTemplates.insert(make_pair(TX_SCRIPTHASH, CScript() << OP_HASH160 << OP_PUBKEYHASH << OP_EQUAL));
    }

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL

    // Scan templates
    const CScript& script1 = scriptPubKey;
    BOOST_FOREACH(const PAIRTYPE(txnouttype, CScript)& tplate, mTemplates)
    {
        CScript script2 = CScript(tplate.second);
        
        for(int d=0;d<=MCP_STD_OP_DROP_COUNT;d++)
        {
            vSolutionsRet.clear();
    
            opcodetype opcode1, opcode2;
            vector<unsigned char> vch1, vch2;
    
            // Compare
            CScript::const_iterator pc1 = script1.begin();
            CScript::const_iterator pc2 = script2.begin();
            while (true)
            {
                if (pc1 == script1.end() && pc2 == script2.end())
                {
                    // Found a match
                    typeRet = tplate.first;
                    if (typeRet == TX_MULTISIG)
                    {
                        // Additional checks for TX_MULTISIG:
                        unsigned char m = vSolutionsRet.front()[0];
                        unsigned char n = vSolutionsRet.back()[0];
                        if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                            return false;
                    }
                    return true;
                }
                if (!script1.GetOp(pc1, opcode1, vch1))
                    break;
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;
    
                // Template matching opcodes:
                if (opcode2 == OP_PUBKEYS)
                {
                    while (vch1.size() >= 33 && vch1.size() <= 65)
                    {
                        vSolutionsRet.push_back(vch1);
                        if (!script1.GetOp(pc1, opcode1, vch1))
                            break;
                    }
                    if (!script2.GetOp(pc2, opcode2, vch2))
                        break;
                    // Normal situation is to fall through
                    // to other if/else statements
                }
    
                if (opcode2 == OP_PUBKEY)
                {
                    if (vch1.size() < 33 || vch1.size() > 65)
                        break;
                    vSolutionsRet.push_back(vch1);
                }
                else if (opcode2 == OP_PUBKEYHASH)
                {
                    if (vch1.size() != sizeof(uint160))
                        break;
                    vSolutionsRet.push_back(vch1);
                }
                else if (opcode2 == OP_SMALLINTEGER)
                {   // Single-byte small integer pushed onto vSolutions
                    if (opcode1 == OP_0 ||
                        (opcode1 >= OP_1 && opcode1 <= OP_16))
                    {
                        char n = (char)CScript::DecodeOP_N(opcode1);
                        vSolutionsRet.push_back(valtype(1, n));
                    }
                    else
                        break;
                }
                else if (opcode2 == OP_SMALLDATA)
                {
                    // small pushdata, <= nMaxDatacarrierBytes
                    nMaxDatacarrierBytes=MAX_OP_RETURN_RELAY;
                    if (vch1.size() > nMaxDatacarrierBytes)
                        break;
                }
                else if (opcode2 == OP_DROPDATA)
                {
                    // small pushdata, <= nMaxDatacarrierBytes
                    if (vch1.size() > MAX_SCRIPT_ELEMENT_SIZE)
                        break;
                }
                else if (opcode1 != opcode2 || vch1 != vch2)
                {
                    // Others must match exactly
                    break;
                }
            }
            
            script2 << OP_DROPDATA << OP_DROP;
        }
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char> >& vSolutions)
{
    switch (t)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return -1;
    case TX_PUBKEY:
        return 1;
    case TX_PUBKEYHASH:
        return 2;
    case TX_MULTISIG:
        if (vSolutions.size() < 1 || vSolutions[0].size() < 1)
            return -1;
        return vSolutions[0][0] + 1;
    case TX_SCRIPTHASH:
        return 1; // doesn't include args needed by the script
    }
    return -1;
}

bool IsStandardFull(const CScript& scriptPubKey, txnouttype& whichType)
{
    vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_MULTISIG)
    {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    }

    return whichType != TX_NONSTANDARD;
}

bool ExtractDestinationScriptValid(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    CScript::const_iterator pc1 = scriptPubKey.begin();
    unsigned char *ptr;
    int size;
    
    ptr=(unsigned char*)(&pc1[0]);
    size=scriptPubKey.end()-pc1;
        
    if( (size >= 25) && (ptr[0] == OP_DUP) )                                    // pay-to-pubkeyhash
    {
        addressRet = CKeyID(*(uint160*)(ptr+3));
        return true;        
    }
    
    if( (size >= 23) && (ptr[0] == OP_HASH160) )                                // pay-to-scripthash
    {
        addressRet = CScriptID(*(uint160*)(ptr+2));
        return true;
        
    }
    
    if( size >= 35 )                                                            // pay-to-pubkey
    {
        if( (ptr[0] >= 33) && (ptr[0] <= 65) )                              
        {
            if(size >= 2+ptr[0])
            {
                CPubKey pubKey(ptr+1, ptr+1+ptr[0]);
                if (!pubKey.IsValid())
                    return false;

                addressRet = pubKey.GetID();
                return true;                
            }
        }
    }
    
    return false;
}

bool ExtractDestinationFull(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid())
            return false;

        addressRet = pubKey.GetID();
        return true;
    }
    else if (whichType == TX_PUBKEYHASH)
    {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_SCRIPTHASH)
    {        
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    }
    // Multisig txns have more than one address...
    return false;
}

bool ExtractDestinationsFull(const CScript& scriptPubKey, txnouttype& typeRet, vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    vector<valtype> vSolutions;

    const CScript& scriptPubKeyDestinationOnly=scriptPubKey.RemoveOpDrops();
    if (!Solver(scriptPubKeyDestinationOnly, typeRet, vSolutions))
        return false;

    if (typeRet == TX_NULL_DATA){
        // This is data, not addresses
        return false;
    }

    if (typeRet == TX_MULTISIG)
    {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
            CPubKey pubKey(vSolutions[i]);
            if (!pubKey.IsValid())
                continue;

            CTxDestination address = pubKey.GetID();
            addressRet.push_back(address);
        }

        if (addressRet.empty())
            return false;
    }
    else
    {
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestinationScriptValid(scriptPubKeyDestinationOnly, address))
           return false;
        addressRet.push_back(address);
    }

    return true;
}

bool IsStandardNullData(const CScript& scriptPubKey,bool standard_check)
{
    opcodetype opcode;
    vector<unsigned char> vch;
    bool recheck=false;
    bool fixed=true;
	int op_drop_count=0;
    int max_op_drop_count=2;
    unsigned int sizes[2];
    sizes[0]=0;
    sizes[1]=0;
    
    CScript::const_iterator pc = scriptPubKey.begin();
    
    while( op_drop_count < max_op_drop_count+1 )
    {
        if(!scriptPubKey.GetOp(pc, opcode))
        {
            return false;
        }
        
        if(opcode == OP_RETURN)
        {
            op_drop_count=max_op_drop_count+1;
        }
        else
        {
            if(op_drop_count == max_op_drop_count)
            {
                return false;
            }
        }
        
        if(op_drop_count < max_op_drop_count+1)
        {
            if( opcode < OP_PUSHDATA1 )
            {
                sizes[op_drop_count]=(unsigned int)opcode;
            }
            else
            {
                if( opcode <= OP_PUSHDATA4 )
                {
                    if( !fixed || standard_check )
                    {
                        recheck=true;                    
                    }
                }         
                else
                {
                    if(fixed)
                    {
                        return false;
                    }
                }
            }
        
            if(!scriptPubKey.GetOp(pc, opcode))
            {
                return false;
            }
            if(opcode != OP_DROP)
            {
                return false;
            }
            op_drop_count++;
        }        
    }
    
    if (pc < scriptPubKey.end())
    {
        if(pc + OP_PUSHDATA1 < scriptPubKey.end())
        {
            scriptPubKey.GetOp(pc, opcode, vch);
            if( !fixed || standard_check )
            {
                if (vch.size() > MAX_OP_RETURN_RELAY)
                {
                    return false;
                }
            }
        }
        else
        {
            scriptPubKey.GetOp(pc, opcode);
            if(opcode >= OP_PUSHDATA1)
            {
                return false;
            }
            if( !fixed || standard_check )
            {
                if ((unsigned int)opcode > MAX_OP_RETURN_RELAY)
                {
                    return false;
                }            
            }
        }
        if(scriptPubKey.GetOp(pc, opcode))
        {
            return false;
        }
    }

    if( !fixed || standard_check )
    {
	    if(recheck)
	    {
	        pc = scriptPubKey.begin();

	        op_drop_count=0;
	        while( op_drop_count < max_op_drop_count+1 )
	        {
	            scriptPubKey.GetOp(pc, opcode, vch);
	            if(opcode == OP_RETURN)
	            {
	                op_drop_count=max_op_drop_count+1;
	            }
	            if( opcode >= OP_PUSHDATA1 )
	            {
	                if( opcode <= OP_PUSHDATA4 )
	                {
	                    sizes[op_drop_count]=(unsigned int)vch.size();
	                }            
	            }
	            if(op_drop_count < max_op_drop_count+1)
	            {
	                scriptPubKey.GetOp(pc, opcode);
	                op_drop_count++;
	            }        
	        }                       
	    }

	    for(op_drop_count=0;op_drop_count<max_op_drop_count;op_drop_count++)
	    {
	        if( sizes[op_drop_count] > MAX_SCRIPT_ELEMENT_SIZE )
	        {
	            return false;
	        }            
	    }
    }
    
    return true;
}

bool ExtractDestinations10008(const CScript& scriptPubKey, txnouttype& typeRet, vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    opcodetype opcode;
    vector<unsigned char> vch;

    nRequiredRet=1;
    
    CScript::const_iterator pc = scriptPubKey.begin();
    
    if (scriptPubKey.GetOp(pc, opcode))
    {
        if(opcode == OP_DUP)
        {
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_HASH160) )
            {
                return false;
            }
            if ( !scriptPubKey.GetOp(pc, opcode, vch) || (vch.size() != 20) )
            {
                return false;
            }
            addressRet.push_back(CKeyID(uint160(vch)));
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_EQUALVERIFY) )
            {
                return false;
            }
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_CHECKSIG) )
            {
                return false;
            }
            typeRet = TX_PUBKEYHASH;
        }
        else
        {
            if(opcode == OP_HASH160)
            {
                if ( !scriptPubKey.GetOp(pc, opcode, vch) || (vch.size() != 20) )
                {
                    return false;
                }
                addressRet.push_back(CScriptID(uint160(vch)));
                if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_EQUAL) )
                {
                    return false;
                }
                typeRet = TX_SCRIPTHASH;
            }
            else
            {
                if(IsStandardNullData(scriptPubKey,false))
                {
                    typeRet=TX_NULL_DATA;
                    return false;
                }
                else
                {
                    return ExtractDestinationsFull(scriptPubKey,typeRet,addressRet,nRequiredRet);
                }
            }
        }
    }
    
    if (pc < scriptPubKey.end())                                                // This code should match behavior of RemoveOpDrops
    {
        if (scriptPubKey.GetOp(pc, opcode))
        {
            if(opcode != OP_RETURN)
            {
                if (pc < scriptPubKey.end())                                    
                {
                    if (scriptPubKey.GetOp(pc, opcode))
                    {
                        if(opcode == OP_DROP)
                        {
                            return true;
                        }
                    }                    
                }
            }
        }
    }    
    else
    {
        return true;
    }
    
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    return true;
}

CTxDestination VectorToAddress(vector<unsigned char>& vch)
{
    CTxDestination addressRet;
    addressRet=CNoDestination();
    
    if( (vch.size() >= 33) && (vch.size() <= 65) )                              
    {
        CPubKey pubKey(vch.begin(), vch.end());
        if (pubKey.IsValid())
        {
            addressRet = pubKey.GetID();            
        }
    }    
    
    return addressRet;
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, vector<CTxDestination>& addressRet, int& nRequiredRet,vector<vector<unsigned char> >* lpvSolutionsRet)
{    
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    opcodetype opcode;
    vector<unsigned char> vch;
    CTxDestination pkAddress;
    int n;

    nRequiredRet=1;
    
    CScript::const_iterator pc = scriptPubKey.begin();
    
    if (scriptPubKey.GetOp(pc, opcode))
    {
        if(opcode == OP_DUP)                                                    // pay-to-pubkeyhash
        {
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_HASH160) )
            {
                return false;
            }
            if ( !scriptPubKey.GetOp(pc, opcode, vch) || (vch.size() != 20) )
            {
                return false;
            }
            addressRet.push_back(CKeyID(uint160(vch)));
            if(lpvSolutionsRet)
            {
                lpvSolutionsRet->push_back(vch);
            }
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_EQUALVERIFY) )
            {
                return false;
            }
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_CHECKSIG) )
            {
                return false;
            }
            typeRet = TX_PUBKEYHASH;
        }
        else
        {
            if(opcode == OP_HASH160)                                            // pay-to-scripthash
            {
                if ( !scriptPubKey.GetOp(pc, opcode, vch) || (vch.size() != 20) )
                {
                    return false;
                }
                addressRet.push_back(CScriptID(uint160(vch)));
                if(lpvSolutionsRet)
                {
                    lpvSolutionsRet->push_back(vch);
                }
                if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_EQUAL) )
                {
                    return false;
                }
                typeRet = TX_SCRIPTHASH;
            }
            else
            {
                if(IsStandardNullData(scriptPubKey,false))                      // null-data
                {
                    typeRet=TX_NULL_DATA;
                    return false;
                }
                else
                {
                    pc = scriptPubKey.begin();
                    if ( !scriptPubKey.GetOp(pc, opcode, vch) )
                    {
                        return false;
                    }
                    
                    pkAddress=VectorToAddress(vch);
                    if( boost::get<CKeyID> (&pkAddress) )                       // pay-to-pubkey
                    {
                        if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_CHECKSIG) )
                        {
                            return false;
                        }
                        addressRet.push_back(pkAddress);                        
                        if(lpvSolutionsRet)
                        {
                            lpvSolutionsRet->push_back(vch);
                        }
                        typeRet = TX_PUBKEY;
                    }
                    else
                    {
                        if ( (opcode >= OP_1 && opcode <= OP_16) )              // bare multisig
                        {
                            nRequiredRet=CScript::DecodeOP_N(opcode);
                            if(lpvSolutionsRet)
                            {
                                lpvSolutionsRet->push_back(valtype(1, (char)nRequiredRet));
                            }

                            n=-1;
                            while(n != (int)addressRet.size())
                            {
                                if ( !scriptPubKey.GetOp(pc, opcode, vch) )
                                {
                                    return false;
                                }
                                if ( (opcode >= OP_1 && opcode <= OP_16) )
                                {
                                    n=CScript::DecodeOP_N(opcode);
                                    if(n != (int)addressRet.size())
                                    {
                                        return false;
                                    }                                    
                                }
                                else
                                {
                                    pkAddress=VectorToAddress(vch);
                                    if( boost::get<CKeyID> (&pkAddress) )
                                    {
                                        addressRet.push_back(pkAddress);                        
                                        if(lpvSolutionsRet)
                                        {
                                            lpvSolutionsRet->push_back(vch);
                                        }
                                    }
                                    else
                                    {
                                        return false;
                                    }
                                }
                            }
                            if(lpvSolutionsRet)
                            {
                                lpvSolutionsRet->push_back(valtype(1, (char)n));
                            }
                            
                            
                            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_CHECKMULTISIG) )
                            {
                                return false;
                            }                            
                            typeRet = TX_MULTISIG;
                        }
                        else
                        {
                            return false;                            
                        }
                    }
                }
            }
        }
    }
    
    while(pc < scriptPubKey.end())
    {
        if ( !scriptPubKey.GetOp(pc, opcode) || (opcode > OP_PUSHDATA4) )
        {
            typeRet = TX_NONSTANDARD;
            return false;
        }                            
        if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_DROP) )
        {
            typeRet = TX_NONSTANDARD;
            return false;
        }                            
    }    
    
    return true;   
}

bool TemplateSolver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet)
{
    vector<CTxDestination> addressRet;
    int nRequiredRet;
    
    return ExtractDestinations(scriptPubKey,typeRet,addressRet,nRequiredRet,&vSolutionsRet);
}


bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    vector<CTxDestination> addressRets;
    txnouttype typeRet;
    int nRequiredRet;
    
    if(!ExtractDestinations(scriptPubKey,typeRet,addressRets,nRequiredRet))
    {
        return false; 
    }
    
    if(typeRet == TX_MULTISIG)
    {
        return false;
    }
    
    addressRet=addressRets[0];
    return true;
}

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType)
{
    opcodetype opcode;
    vector<unsigned char> vch;
    whichType = TX_NONSTANDARD;
    int max_op_drops;

    CScript::const_iterator pc = scriptPubKey.begin();
    
    if (scriptPubKey.GetOp(pc, opcode))
    {
        if(opcode == OP_DUP)
        {
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_HASH160) )
            {
                return false;
            }
            if ( !scriptPubKey.GetOp(pc, opcode, vch) || (vch.size() != 20) )
            {
                return false;
            }
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_EQUALVERIFY) )
            {
                return false;
            }
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_CHECKSIG) )
            {
                return false;
            }
            whichType = TX_PUBKEYHASH;            
        }
        else
        {
            if(opcode == OP_HASH160)
            {
                if ( !scriptPubKey.GetOp(pc, opcode, vch) || (vch.size() != 20) )
                {
                    return false;
                }
                if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_EQUAL) )
                {
                    return false;
                }
                whichType = TX_SCRIPTHASH;
            }
            else
            {
                if(IsStandardNullData(scriptPubKey,true))
                {
                    whichType=TX_NULL_DATA;
                    return true;
                }
                else
                {
                    return IsStandardFull(scriptPubKey,whichType);
                }
            }
        }
    }

    max_op_drops=MCP_STD_OP_DROP_COUNT;
    
    for(int d=0;d<max_op_drops;d++)
    {
        if (pc < scriptPubKey.end())                                            
        {
            if ( !scriptPubKey.GetOp(pc, opcode, vch) || (vch.size() > MAX_SCRIPT_ELEMENT_SIZE) )
            {
                whichType = TX_NONSTANDARD;
                return false;
            }
            if ( !scriptPubKey.GetOp(pc, opcode) || (opcode != OP_DROP) )
            {
                whichType = TX_NONSTANDARD;
                return false;
            }
        }
        else
        {
            return true;
        }
    }
    
    if (pc < scriptPubKey.end())                                                
    {
        whichType = TX_NONSTANDARD;
        return false;
    }    
    
    return true;
}


namespace
{
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }
};
}

CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;

    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;

    script << CScript::EncodeOP_N(nRequired);
    BOOST_FOREACH(const CPubKey& key, keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
    return script;
}

CScript GetScriptForPubKey(const CPubKey& key)
{
    CScript script;
    script << ToByteVector(key);
    script << OP_CHECKSIG;

    return script;    
}

