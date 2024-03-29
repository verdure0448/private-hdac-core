// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Original code was distributed under the MIT software license.
// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
//
// 2018/02/00   Code optimization
// 2018/03/11   included custfile
//              TX priority
//============================================================================================


#include "cust/custhdac.h"

#include "miner/miner.h"

#include "structs/amount.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "structs/hash.h"
#include "core/main.h"
#include "net/net.h"
#include "structs/base58.h"
#include "chain/pow.h"
#include "utils/timedata.h"
#include "utils/util.h"
#include "utils/utilmoneystr.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include "chain/epow.h"

#include "hdac/hdac.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>


//#undef HDAC_PRIVATE_BLOCKCHAIN	// HDAC LJM 180427 ==> tx ordering problem ==> LJM 180620


using namespace std;

bool CanMineWithLockedBlock();
bool IsTxBanned(uint256 txid);
int LastForkedHeight();


//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint256> setDependsOn;
#ifdef HDAC_PRIVATE_BLOCKCHAIN
    CFeeRate feeRate;
#else
    CAmount tFee;
#endif        // HDAC_PRIVATE_BLOCKCHAIN
    double dPriority;

#ifdef HDAC_PRIVATE_BLOCKCHAIN
    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
#else
    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), tFee(0), dPriority(0)
#endif        // HDAC_PRIVATE_BLOCKCHAIN
    {
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee rate, so:
#ifdef HDAC_PRIVATE_BLOCKCHAIN
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
#else
typedef boost::tuple<double, CAmount, const CTransaction*> TxPriority;
#endif        // HDAC_PRIVATE_BLOCKCHAIN
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }

    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

bool UpdateTime(CBlockHeader* pblock, const CBlockIndex* pindexPrev)
{

    uint32_t original_nTime=pblock->nTime;
    uint32_t original_nBits=pblock->nBits;

    pblock->nTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // Updating time can change work required on testnet:
    if (Params().AllowMinDifficultyBlocks())
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);

    if((original_nTime != pblock->nTime) || (original_nBits != pblock->nBits))
    {
        return true;
    }
    return false;

}



bool CreateBlockSignature(CBlock *block,uint32_t hash_type,CWallet *pwallet)
{
    int coinbase_tx,op_return_output;
    uint256 hash_to_verify;
    uint256 original_merkle_root;
    std::vector<unsigned char> vchSigOut;
    std::vector<unsigned char> vchPubKey;

    block->nMerkleTreeType=MERKLETREE_FULL;
    block->nSigHashType=BLOCKSIGHASH_NONE;

    if(block->vSigner[0] == 0)
    {
        return false;
    }

    coinbase_tx=-1;
    op_return_output=-1;
    for (unsigned int i = 0; i < block->vtx.size(); i++)
    {
        if(coinbase_tx<0)
        {
            const CTransaction &tx = block->vtx[i];
            if (block->vtx[i].IsCoinBase())
            {
                coinbase_tx=i;
                for (unsigned int j = 0; j < tx.vout.size(); j++)
                {

                    const CScript& script1 = tx.vout[j].scriptPubKey;
                    if(script1.IsUnspendable())
                    {
                        op_return_output=j;
                    }
                }
            }
        }
    }

    if(coinbase_tx<0)
    {
        block->nSigHashType=BLOCKSIGHASH_INVALID;
        return false;
    }

    if((hash_type == BLOCKSIGHASH_HEADER) && (op_return_output >= 0))
    {
        block->nSigHashType=BLOCKSIGHASH_INVALID;
        return false;
    }
//    if(op_return_output >= 0)
    {
        CMutableTransaction tx=block->vtx[coinbase_tx];
        tx.vout.clear();
        for(int i=0;i<(int)block->vtx[coinbase_tx].vout.size();i++)
        {
            if((i != op_return_output) &&
               ((block->vtx[coinbase_tx].vout[i].nValue != 0) || (mc_gState->m_Permissions->m_Block == 0)))
            {
                tx.vout.push_back(block->vtx[coinbase_tx].vout[i]);
            }
        }
        block->vtx[coinbase_tx]=tx;
    }

    switch(hash_type)
    {
        case BLOCKSIGHASH_HEADER:
            block->nMerkleTreeType=MERKLETREE_NO_COINBASE_OP_RETURN;
            block->nSigHashType=BLOCKSIGHASH_HEADER;
            hash_to_verify=block->GetHash();
            break;
        case BLOCKSIGHASH_NO_SIGNATURE_AND_NONCE:
            block->nMerkleTreeType=MERKLETREE_NO_COINBASE_OP_RETURN;
            block->hashMerkleRoot=block->BuildMerkleTree();
            block->nNonce=0;
            hash_to_verify=block->GetHash();
            block->nMerkleTreeType=MERKLETREE_FULL;
            break;
        default:
            block->nSigHashType=BLOCKSIGHASH_INVALID;
            return false;
    }

    CMutableTransaction tx=block->vtx[coinbase_tx];
    tx.vout.clear();
    for(int i=0;i<(int)block->vtx[coinbase_tx].vout.size();i++)
    {
        tx.vout.push_back(block->vtx[coinbase_tx].vout[i]);
    }

    CTxOut txOut;

    txOut.nValue = 0;
    txOut.scriptPubKey = CScript() << OP_RETURN;

    size_t elem_size;
    const unsigned char *elem;

    vchPubKey=std::vector<unsigned char> (block->vSigner+1, block->vSigner+1+block->vSigner[0]);

    CPubKey pubKeyOut(vchPubKey);
    CKey key;
    if(!pwallet->GetKey(pubKeyOut.GetID(), key))
    {
        return false;
    }

    vector<unsigned char> vchSig;
    key.Sign(hash_to_verify, vchSig);

    mc_Script *lpScript;
    lpScript=new mc_Script;

    lpScript->SetBlockSignature(vchSig.data(),vchSig.size(),hash_type,block->vSigner+1,block->vSigner[0]);

    for(int element=0;element < lpScript->GetNumElements();element++)
    {
        elem = lpScript->GetData(element,&elem_size);
        if(elem)
        {
            txOut.scriptPubKey << vector<unsigned char>(elem, elem + elem_size);
        }
    }
    delete lpScript;

    tx.vout.push_back(txOut);

    block->vtx[coinbase_tx]=tx;

    switch(hash_type)
    {
        case BLOCKSIGHASH_NO_SIGNATURE_AND_NONCE:
            block->hashMerkleRoot=block->BuildMerkleTree();
            break;
    }

    return true;
}


CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn,CWallet *pwallet,CPubKey *ppubkey,int *canMine,CBlockIndex** ppPrev)        // multichain 1.0.2.1
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (Params().MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

    // Create coinbase tx
    CMutableTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();

    txNew.vout.resize(1);

    int prevCanMine=MC_PTP_MINE;
    if(canMine)
    {
        prevCanMine=*canMine;
    }

    txNew.vout[0].scriptPubKey = scriptPubKeyIn;

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CTransaction());
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);

    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    // unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    // nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CAmount nFees = 0;
    bool fPreservedMempoolOrder=true;

    {
        LOCK2(cs_main, mempool.cs);

        CBlockIndex* pindexPrev = chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        if(ppPrev)        // multichain 1.0.2.1
        {
                *ppPrev=pindexPrev;
        }
        CCoinsViewCache view(pcoinsTip);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());

        set <uint256> setAdded;

#ifdef HDAC_PRIVATE_BLOCKCHAIN
        double orderPriority=mempool.mapTx.size();
#endif        // HDAC_PRIVATE_BLOCKCHAIN

        mempool.defragmentHashList();

        for(int pos=0;pos<mempool.hashList->m_Count;pos++)
        {
            uint256 hash = *(uint256*)mempool.hashList->GetRow(pos);

            if(!mempool.exists(hash))
            {
                if(fDebug>1)LogPrint("hdac","Hdac-miner: Tx not found in the mempool: %s\n",hash.GetHex().c_str());
                fPreservedMempoolOrder=false;
                continue;
            }
            if(IsTxBanned(hash))
            {
                if(fDebug>1)LogPrint("hdac","Hdac-miner: Banned Tx: %s\n",hash.GetHex().c_str());
                fPreservedMempoolOrder=false;
                continue;
            }

            const CTransaction& tx = mempool.mapTx[hash].GetTx();


            if (tx.IsCoinBase() || !IsFinalTx(tx, nHeight))
            {
                if(fDebug>1)LogPrint("hdac","Hdac-miner: Coinbase or not final tx found: %s\n",tx.GetHash().GetHex().c_str());
                fPreservedMempoolOrder=false;
                continue;
            }

            COrphan* porphan = NULL;
#ifdef HDAC_PRIVATE_BLOCKCHAIN
            double dPriority = 0;
            CAmount nTotalIn = 0;
#endif        // HDAC_PRIVATE_BLOCKCHAIN
            bool fMissingInputs = false;

            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                if (!view.HaveCoins(txin.prevout.hash))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        if(fDebug>0)LogPrintf("ERROR: mempool transaction missing input\n");
                        if (fDebug>1) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies

                    if(setAdded.count(txin.prevout.hash) == 0)
                    {

                        if (!porphan)
                        {
                            // Use list for automatic deletion
                            vOrphan.push_back(COrphan(&tx));
                            porphan = &vOrphan.back();
                        }
                        mapDependers[txin.prevout.hash].push_back(porphan);
                        porphan->setDependsOn.insert(txin.prevout.hash);

                    }
#ifdef HDAC_PRIVATE_BLOCKCHAIN
                    nTotalIn += mempool.mapTx[txin.prevout.hash].GetTx().vout[txin.prevout.n].nValue;
#endif        // HDAC_PRIVATE_BLOCKCHAIN
                    continue;
                }
                const CCoins* coins = view.AccessCoins(txin.prevout.hash);
                assert(coins);

#ifdef HDAC_PRIVATE_BLOCKCHAIN
                CAmount nValueIn = coins->vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = nHeight - coins->nHeight;

                dPriority += (double)nValueIn * nConf;
#endif        // HDAC_PRIVATE_BLOCKCHAIN
            }
            if (fMissingInputs)
            {
                if(fDebug>1)LogPrint("hdac","Hdac-miner: Missing inputs for %s\n",tx.GetHash().GetHex().c_str());
                fPreservedMempoolOrder=false;
                continue;
            }

#ifdef HDAC_PRIVATE_BLOCKCHAIN
            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = tx.ComputePriority(dPriority, nTxSize);


            // Priority ignored - txs are processed in the order they were accepted
            dPriority=orderPriority;
            orderPriority-=1.;

            mempool.ApplyDeltas(hash, dPriority, nTotalIn);

            CFeeRate feeRate(nTotalIn-tx.GetValueOut(), nTxSize);
#else
            double dPriority = 0;
            CAmount tFees = 0;
                
            mempool.ApplyDeltas(hash, dPriority, tFees);
#endif        // HDAC_PRIVATE_BLOCKCHAIN

            if (porphan)
            {
                if(fDebug>1)LogPrint("hdac","Hdac-miner: Orphan %s\n",tx.GetHash().GetHex().c_str());
                porphan->dPriority = dPriority;
#ifdef HDAC_PRIVATE_BLOCKCHAIN
                porphan->feeRate = feeRate;
#else
                porphan->tFee = tFees;
#endif        // HDAC_PRIVATE_BLOCKCHAIN
                fPreservedMempoolOrder=false;
            }
            else

            {
                setAdded.insert(tx.GetHash());
#ifdef HDAC_PRIVATE_BLOCKCHAIN
                vecPriority.push_back(TxPriority(dPriority, feeRate, &tx));
#else
                vecPriority.push_back(TxPriority(dPriority, tFees, &tx));
#endif        // HDAC_PRIVATE_BLOCKCHAIN
            }

        }

        // Collect transactions into block
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = 100;
#ifdef HDAC_PRIVATE_BLOCKCHAIN
        TxPriorityCompare comparer(false);
#else
        set <uint256> addedBlockTx;
        TxPriorityCompare comparer(true);
#endif        // HDAC_PRIVATE_BLOCKCHAIN
        bool overblocksize_logged=false;

        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
#ifdef HDAC_PRIVATE_BLOCKCHAIN
            CFeeRate feeRate = vecPriority.front().get<1>();
#else
            CAmount tFees = vecPriority.front().get<1>();
#endif        // HDAC_PRIVATE_BLOCKCHAIN
            const CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
            {
                if(!overblocksize_logged)
                {
                    overblocksize_logged=true;
                    if(fDebug>1)LogPrint("hdac","Hdac-miner: Over block size: %s\n",tx.GetHash().GetHex().c_str());
                }
                continue;
            }
            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
            {
                if(fDebug>1)LogPrint("hdac","Hdac-miner: Over sigop count 1: %s\n",tx.GetHash().GetHex().c_str());
                continue;
            }

            // Skip free transactions if we're past the minimum block size:
            const uint256& hash = tx.GetHash();
#ifdef HDAC_PRIVATE_BLOCKCHAIN
            double dPriorityDelta = 0;
            CAmount nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
#else
            COrphan* norphan = NULL;
#endif        // HDAC_PRIVATE_BLOCKCHAIN

            if (!view.HaveInputs(tx))
            {
                if(fDebug>1)LogPrint("hdac","Hdac-miner: No inputs for %s\n",tx.GetHash().GetHex().c_str());

#ifdef HDAC_PRIVATE_BLOCKCHAIN
#else
                BOOST_FOREACH(const CTxIn& txin, tx.vin)
                {
                    if (!view.HaveCoins(txin.prevout.hash))
                    {
                        if(addedBlockTx.count(txin.prevout.hash) == 0)
                        {
                            if (!norphan)
                            {
                                vOrphan.push_back(COrphan(&tx));
                                norphan = &vOrphan.back();
                            }
                                
                            mapDependers[txin.prevout.hash].push_back(norphan);
                            norphan->setDependsOn.insert(txin.prevout.hash);
                            break;
                        }
                    }
                }
                
                if(norphan)
                {
                    norphan->dPriority = dPriority;
                    norphan->tFee = tFees;
                    fPreservedMempoolOrder=false;
                }
#endif        // HDAC_PRIVATE_BLOCKCHAIN
                continue;
            }

#ifdef HDAC_PRIVATE_BLOCKCHAIN
#else
            addedBlockTx.insert(tx.GetHash());
#endif        // HDAC_PRIVATE_BLOCKCHAIN

            CAmount nTxFees = view.GetValueIn(tx)-tx.GetValueOut();

            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
            {
                if(fDebug>1)LogPrint("hdac","Hdac-miner: Over sigop count 2: %s\n",tx.GetHash().GetHex().c_str());
                continue;
            }

            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            CValidationState state;

            if(!fPreservedMempoolOrder)
            {
                if (!CheckInputs(tx, state, view, false, 0, true))
                {
                    if(fDebug>1)LogPrint("hdac","Hdac-miner: CheckInput failure %s\n",tx.GetHash().GetHex().c_str());
                    continue;
                }
            }
            CTxUndo txundo;
            UpdateCoins(tx, state, view, txundo, nHeight);

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

#ifdef HDAC_PRIVATE_BLOCKCHAIN
            if (fPrintPriority)
            {
                LogPrintf("Add tx to bloack : priority %.1f fee %s txid %s\n",
                    dPriority, feeRate.ToString(), tx.GetHash().ToString());
            }
#endif        // HDAC_PRIVATE_BLOCKCHAIN

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
#ifdef HDAC_PRIVATE_BLOCKCHAIN
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
#else
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->tFee, porphan->ptx));
#endif        // HDAC_PRIVATE_BLOCKCHAIN
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("Hdac-miner: nLastBlockTx=%u, nLastBlockSize=%u \n", nLastBlockTx, nLastBlockSize);

        // Compute final coinbase transaction.
        txNew.vout[0].nValue = GetBlockValue(nHeight, nFees);
        txNew.vin[0].scriptSig = CScript() << nHeight << OP_0;

        if(ppubkey != NULL)
        {
          pblock->vSigner[0]=ppubkey->size();
          memcpy(pblock->vSigner+1,ppubkey->begin(),pblock->vSigner[0]);
        }

        pblock->vtx[0] = txNew;
        pblocktemplate->vTxFees[0] = -nFees;


        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        UpdateTime(pblock, pindexPrev);
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock);
        pblock->nNonce         = 0;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        bool testValidity=true;

        // If this node cannot mine for some reason (permission or diversity, block is not tested for validity to avoid exception
        if(canMine)
        {
            const unsigned char *pubkey_hash=(unsigned char *)Hash160(ppubkey->begin(),ppubkey->end()).begin();
            *canMine=mc_gState->m_Permissions->CanMine(NULL,pubkey_hash);
            if((*canMine & MC_PTP_MINE) == 0)
            {
                if(prevCanMine & MC_PTP_MINE)
                {
                    if(fDebug>0)LogPrintf("hdac: HdacMiner: cannot mine now, waiting...\n");	// HDAC
                }
                testValidity=false;
            }
            else
            {
                if((prevCanMine & MC_PTP_MINE) == 0)
                {
                    if(fDebug>0)LogPrintf("CreateNewBlock(): total size %u\n", nBlockSize);
                    if(fDebug>0)LogPrintf("hdac: HdacMiner: Starting mining...\n");	// HDAC
                }
            }
        }

        if(GetBoolArg("-avoidtestingblockvalidity",true))
        {
            testValidity=false;
        }

        if(testValidity)
        {
            CValidationState state;
            if (!TestBlockValidity(state, *pblock, pindexPrev, false, false))
                throw std::runtime_error("CreateNewBlock() : TestBlockValidity failed");
        }
    }

    return pblocktemplate.release();
}


CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn)
{
    return CreateNewBlock(scriptPubKeyIn,NULL,NULL,NULL,NULL);        // multichain 1.0.2.1
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce,CWallet *pwallet)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(pblock->vtx[0]);

    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;

    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;

    CreateBlockSignature(pblock,BLOCKSIGHASH_NO_SIGNATURE_AND_NONCE,pwallet);
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();

}


#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//
double dHashesPerSec = 0.0;
int64_t nHPSTimerStart = 0;

#if 0
//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
//
bool static ScanHash(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash,uint16_t success_and_mask)
{
    // Write the first 76 bytes of the block header to a double-SHA256 state.
    CHash256 hasher;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *pblock;
    assert(ss.size() == 80);
    hasher.Write((unsigned char*)&ss[0], 76);
    while (true) {
        nNonce++;

        // Write the last 4 bytes of the block header (the nonce) to a copy of
        // the double-SHA256 state, and compute the result.
        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if( (((uint16_t*)phash)[15] & success_and_mask) == 0)
        {
            return true;
        }

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xffff) == 0)
            return false;
        if ((nNonce & 0xfff) == 0)
            boost::this_thread::interruption_point();
    }
}
#endif


bool static ScanHashWithLyra(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash,uint16_t success_and_mask)
{
    CBlockHeader block = *pblock;

    while (true) {
        nNonce++;

        // Write the last 4 bytes of the block header (the nonce) to a copy of
        // the double-SHA256 state, and compute the result.
//        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target

//      if (((uint16_t*)phash)[15] == 0)
//          return true;

        block.nNonce = nNonce;
        *phash = block.GetPoWHash(true);
        //fpow = CheckProofOfWork(*phash, pblock->nBits, true);
        if( (((uint16_t*)phash)[15] & success_and_mask) == 0)
        {
            return true;
        }

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xffff) == 0)
            return false;
        if ((nNonce & 0xfff) == 0)
            boost::this_thread::interruption_point();
    }
}


CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey)
{
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey))
        return NULL;

    CScript scriptPubKey = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
    return CreateNewBlock(scriptPubKey);
}


// Block should be mined for specific keys, not just any from pool
CBlockTemplate* CreateNewBlockWithDefaultKey(CWallet *pwallet,int *canMine,const set<CTxDestination>* addresses,CBlockIndex** ppPrev)        // multichain 1.0.2.1
{
    CPubKey pubkey;
    bool key_found;

    {
        LOCK(cs_main);
        key_found=pwallet->GetKeyFromAddressBook(pubkey,MC_PTP_MINE,addresses);
    }
    if(!key_found)
    {
        if(canMine)
        {
            if(*canMine & MC_PTP_MINE)
            {
                *canMine=0;
                if(fDebug>0)LogPrintf("hdac: Cannot find address having mining permission\n");
            }
        }
        return NULL;
    }

    const unsigned char *pubkey_hash=(unsigned char *)Hash160(pubkey.begin(),pubkey.end()).begin();

    CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << vector<unsigned char>(pubkey_hash, pubkey_hash + 20) << OP_EQUALVERIFY << OP_CHECKSIG;

    return CreateNewBlock(scriptPubKey,pwallet,&pubkey,canMine,ppPrev);        // multichain 1.0.2.1
}



bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    if(fDebug>1)LogPrint("hdacminor","%s\n", pblock->ToString());
    if(fDebug>1)LogPrint("mcminer","Hdac-miner: generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if(mc_gState->m_NodePausedState & MC_NPS_MINING)
        {
            return error("HdacMiner : mining is paused, generated block is dropped");
        }
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
        {
            return error("HdacMiner : generated block is stale");
        }
    }

    // Remove key from key pool
    reservekey.KeepKey();

    // Track how many getdata requests this block gets
    {
        LOCK(wallet.cs_wallet);
        wallet.mapRequestCount[pblock->GetHash()] = 0;
    }

    // Process this block the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(state, NULL, pblock))
        return error("HdacMiner : ProcessNewBlock, block not accepted");

    return true;
}

set <CTxDestination> LastActiveMiners(CBlockIndex* pindexTip, CPubKey *kLastMiner, int nMinerPoolSize)
{
    int nRelativeWindowSize=5;

    int nTotalMiners=mc_gState->m_Permissions->GetMinerCount();
    int nActiveMiners=mc_gState->m_Permissions->GetActiveMinerCount();
    int nDiversityMiners=0;
    int nWindowSize;
    CBlockIndex* pindex;
    set <CTxDestination> sMiners;

    if(MCP_ANYONE_CAN_MINE == 0)
    {
       nDiversityMiners=nTotalMiners-nActiveMiners;
    }

    nWindowSize=nRelativeWindowSize*nMinerPoolSize+nDiversityMiners;

    pindex=pindexTip;
    for(int i=0;i<nWindowSize;i++)
    {
        if((int)sMiners.size() < nMinerPoolSize)
        {
            if(pindex)
            {
                if(!pindex->kMiner.IsValid())
                {
                    CBlock block;
                    if(ReadBlockFromDisk(block,pindex))
                    {
                        if(block.vSigner[0])
                        {
                            pindex->kMiner.Set(block.vSigner+1, block.vSigner+1+block.vSigner[0]);
                        }
                    }
                }
                if(pindex->kMiner.IsValid())
                {
                    CKeyID addr=pindex->kMiner.GetID();
                    if(mc_gState->m_Permissions->CanMine(NULL,addr.begin()))
                    {
                        if(sMiners.find(addr) == sMiners.end())
                        {
                            sMiners.insert(addr);
                        }
                    }
                }
                if(pindex == pindexTip)
                {
                    *kLastMiner=pindex->kMiner;
                }
                pindex=pindex->pprev;
            }
        }
    }

    return sMiners;
}

int GetMaxActiveMinersCount()
{
    if(MCP_ANYONE_CAN_MINE)
    {
        return 1048576;
    }
    else
    {
        return mc_gState->m_Permissions->GetActiveMinerCount();
    }
}

double GetMinerAndExpectedMiningStartTime(CWallet *pwallet,CPubKey *lpkMiner,set <CTxDestination> *lpsMinerPool,double *lpdMiningStartTime,double *lpdActiveMiners,uint256 *lphLastBlockHash,int *lpnMemPoolSize)
{
    int nMinerPoolSizeMin=4;
    int nMinerPoolSizeMax=16;
    double dRelativeSpread=1.;
    double dRelativeMinerPoolSize=0.25;
    double dAverageCreateBlockTime=2;
    double dMinerDriftMin=mc_gState->m_NetworkParams->ParamAccuracy();
    double dEmergencyMinersConvergenceRate=2.;
    int nPastBlocks=12;

    set <CTxDestination> sPrevMinerPool;
    set <CTxDestination> sThisMinerPool;
    CBlockIndex* pindex;
    CBlockIndex* pindexTip;
    CPubKey kLastMiner;
    CPubKey kThisMiner;

    bool fNewBlock=false;
    bool fWaitingForMiner=false;
    bool fInMinerPool;
    int nMinerPoolSize,nStdMinerPoolSize,nWindowSize;
    double dTargetSpacing,dSpread,dExpectedTimeByLast,dExpectedTimeByPast,dEmergencyMiners,dExpectedTime,dExpectedTimeMin,dExpectedTimeMax,dAverageGap;
    double dMinerDrift,dActualMinerDrift;

    pindexTip = chainActive.Tip();

    if(*lpdMiningStartTime >= 0)
    {
        if(*lphLastBlockHash == pindexTip->GetBlockHash())
        {
            if( (*lpnMemPoolSize > 0) || (mempool.hashList->m_Count == 0) )
            {
                if(lpkMiner->IsValid())
                {
                    return *lpdMiningStartTime;
                }
                else
                {
                    fWaitingForMiner=true;
                    fNewBlock=true;
                }
            }
        }
        else
        {
            fNewBlock=true;
        }
    }
    else
    {
        fNewBlock=true;
    }

    *lphLastBlockHash=pindexTip->GetBlockHash();
    *lpnMemPoolSize=mempool.hashList->m_Count;

    if( (Params().Interval() > 0) ||                                            // POW
        (mc_gState->m_Permissions->m_Block <= 1) )
    {
        pwallet->GetKeyFromAddressBook(kThisMiner,MC_PTP_MINE);
        *lpkMiner=kThisMiner;
        *lpdMiningStartTime=mc_TimeNowAsDouble();                               // start mining immediately
        return *lpdMiningStartTime;
    }


    dMinerDrift=Params().MiningTurnover();
    if(dMinerDrift > 1.0)
    {
        dMinerDrift=1.0;
    }
    dMinerDrift-=dMinerDriftMin;
    if(dMinerDrift < 0)
    {
        dMinerDrift=0.;
    }

    dTargetSpacing=Params().TargetSpacing();
    dSpread=dRelativeSpread*dTargetSpacing;

    *lpdMiningStartTime=mc_TimeNowAsDouble() + 0.5 * dTargetSpacing;
    dExpectedTimeByLast=pindexTip->dTimeReceived+dTargetSpacing;
    if(dExpectedTimeByLast < mc_TimeNowAsDouble() + dTargetSpacing - 0.5 * dSpread) // Can happen while in reorg or if dTimeReceived is not set
    {
        dExpectedTimeByLast=mc_TimeNowAsDouble() + dTargetSpacing;
        *lpdMiningStartTime=dExpectedTimeByLast;
        fNewBlock=false;
    }
    dExpectedTimeMin=dExpectedTimeByLast - 0.5 * dSpread;
    dExpectedTimeMax=dExpectedTimeByLast + 0.5 * dSpread;

    dAverageGap=0;
    nWindowSize=0;
    if(fNewBlock)
    {
        pindex=pindexTip;
        dExpectedTimeByPast=0;
        for(int i=0;i<nPastBlocks;i++)
        {
            if(pindex && (pindex->dTimeReceived > 0.5))
            {
                dExpectedTimeByPast+=pindex->dTimeReceived;
                nWindowSize++;
                dAverageGap=pindex->dTimeReceived;
                pindex=pindex->pprev;
            }
        }

        dAverageGap=(dExpectedTimeByLast-dAverageGap) / nWindowSize;

        dExpectedTimeByPast /= nWindowSize;
        dExpectedTimeByPast += (nWindowSize + 1) * 0.5 * dTargetSpacing;


        if(dAverageGap < 0.5*dTargetSpacing)                                    // Catching up
        {
            dExpectedTime=mc_TimeNowAsDouble() + dTargetSpacing;
            nWindowSize=0;
        }
        else
        {
            if(nWindowSize < nPastBlocks)
            {
                dExpectedTime=dExpectedTimeByLast;
            }
            else
            {
                dExpectedTime=dExpectedTimeByPast;
                if(dExpectedTime > dExpectedTimeMax)
                {
                    dExpectedTime = dExpectedTimeMax;
                }
                if(dExpectedTime < dExpectedTimeMin)
                {
                    dExpectedTime = dExpectedTimeMin;
                }
            }
        }

        *lpdMiningStartTime=dExpectedTime;
    }

    fInMinerPool=false;
    sPrevMinerPool=*lpsMinerPool;
    nStdMinerPoolSize=(int)(dRelativeMinerPoolSize * dSpread / dAverageCreateBlockTime);
    if(nStdMinerPoolSize < nMinerPoolSizeMin)
    {
        nStdMinerPoolSize=nMinerPoolSizeMin;
    }
    if(nStdMinerPoolSize > nMinerPoolSizeMax)
    {
        nStdMinerPoolSize=nMinerPoolSizeMax;
    }
    nMinerPoolSize=nStdMinerPoolSize;
    nStdMinerPoolSize=(int)(dMinerDrift * nStdMinerPoolSize) + 1;

    dActualMinerDrift=dMinerDrift;
    if(dActualMinerDrift < dMinerDriftMin)
    {
        dActualMinerDrift=dMinerDriftMin;
    }

    sThisMinerPool=LastActiveMiners(pindexTip,&kLastMiner,nStdMinerPoolSize);
    nMinerPoolSize=sThisMinerPool.size();
    *lpsMinerPool=sThisMinerPool;

    fInMinerPool=false;
    if(!pwallet->GetKeyFromAddressBook(kThisMiner,MC_PTP_MINE,&sThisMinerPool))
    {
        pwallet->GetKeyFromAddressBook(kThisMiner,MC_PTP_MINE);
    }
    else
    {
        fInMinerPool=true;
    }

    if( fInMinerPool ||
        (sPrevMinerPool.find(kLastMiner.GetID()) == sPrevMinerPool.end()) ||
        (*lpdActiveMiners < -0.5) )
    {
        *lpdActiveMiners=(double)GetMaxActiveMinersCount() - nMinerPoolSize;
        *lpdActiveMiners/=dActualMinerDrift;
    }
    *lpdActiveMiners *= (1. - dActualMinerDrift);
    if(*lpdActiveMiners < 1.0)
    {
        *lpdActiveMiners=1;
    }
    if(dMinerDrift >= dMinerDriftMin)
    {
        if(!fInMinerPool)
        {
            if( (*lpdActiveMiners < 0.5) || ( mc_RandomDouble() < dMinerDrift /(*lpdActiveMiners)))
            {
                fInMinerPool=true;
                nMinerPoolSize++;
            }
        }
    }
    if(fInMinerPool)
    {
        *lpdActiveMiners=(double)GetMaxActiveMinersCount() - nMinerPoolSize;
        *lpdActiveMiners/=dActualMinerDrift;
    }

    if(fInMinerPool)
    {
        *lpdMiningStartTime += mc_RandomDouble() * dSpread;
        *lpdMiningStartTime -= dSpread / (nMinerPoolSize + 1);
    }
    else
    {
        dEmergencyMiners=(double)GetMaxActiveMinersCount();
        *lpdMiningStartTime=dExpectedTimeMax;
        *lpdMiningStartTime += dSpread;
        *lpdMiningStartTime -= dSpread / (nMinerPoolSize + 1);
        *lpdMiningStartTime += dAverageCreateBlockTime + mc_RandomDouble() * dAverageCreateBlockTime;
        while( (dEmergencyMiners > 0.5) && (mc_RandomDouble() > 1./(dEmergencyMiners)))
        {
            *lpdMiningStartTime += dAverageCreateBlockTime;
            dEmergencyMiners /= dEmergencyMinersConvergenceRate;
        }
    }

    if(!fWaitingForMiner)
    {
        if(kThisMiner.IsValid())
        {
            CBitcoinAddress addr=CBitcoinAddress(kThisMiner.GetID());
            if(fDebug>1)LogPrint("Hdacminer","Hdac-miner: delay: %8.3fs, miner: %s, height: %d, gap: %8.3fs, miners: (tot: %d, max: %d, pool: %d)%s\n",
                             *lpdMiningStartTime-mc_TimeNowAsDouble(),addr.ToString().c_str(),
                             chainActive.Tip()->nHeight,dAverageGap,
                             mc_gState->m_Permissions->GetMinerCount(),GetMaxActiveMinersCount(),
                             nMinerPoolSize,fInMinerPool ? ( (nMinerPoolSize > (int)lpsMinerPool->size()) ? " In Pool New" : " In Pool Old" )  : " Not In Pool");
        }
        else
        {
            if(fDebug>1)LogPrint("Hdacminer","Hdac-miner: miner not found, height: %d, gap: %8.3fs, miners: (tot: %d, max: %d, pool: %d)\n",
                             chainActive.Tip()->nHeight,dAverageGap,
                             mc_gState->m_Permissions->GetMinerCount(),GetMaxActiveMinersCount(),
                             nMinerPoolSize);
        }
    }
    *lpkMiner=kThisMiner;
    return *lpdMiningStartTime;
}

void static BitcoinMiner(CWallet *pwallet)
{
    if(fDebug>0)LogPrintf("HdacMiner started\n");	// HDAC
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("Hdac-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;


    int canMine;
    int prevCanMine;
    canMine=MC_PTP_MINE;
    prevCanMine=canMine;

    double dActiveMiners=-1;
    double dMiningStartTime=-1.;
    uint256 hLastBlockHash=0;
    int nMemPoolSize=0;
    set <CTxDestination> sMinerPool;
    CPubKey kMiner;

    int wSize=10;
    int wPos=0;
    int EmptyBlockToMine;
    uint64_t wCount[10];
    double wTime[10];
    memset(wCount,0,wSize*sizeof(uint64_t));
    memset(wTime,0,wSize*sizeof(uint64_t));

    uint16_t success_and_mask=0xffff;
    int min_bits;

    if(Params().Interval() <= 0)
    {
        min_bits=(int)mc_gState->m_NetworkParams->GetInt64Param("powminimumbits");
        if(min_bits < 16)
        {
            success_and_mask = success_and_mask << (16 - min_bits);
        }
    }


    try {
        while (true) {

            bool not_setup_period=true;

            if(mc_gState->m_NodePausedState & MC_NPS_MINING)
            {
                __US_Sleep(1000);
                boost::this_thread::interruption_point();
            }

            if((canMine & MC_PTP_MINE) == 0)
            {
                if(mc_gState->m_Permissions->m_Block > 1)
                {
                    __US_Sleep(1000);
                }
                boost::this_thread::interruption_point();
            }
            if(mc_gState->m_Permissions->IsSetupPeriod())
            {
                not_setup_period=false;
            }
            if(mc_gState->m_Permissions->m_Block <= 1)
            {
                not_setup_period=false;
            }

            if (Params().MiningRequiresPeers()
                    && not_setup_period
                    && ((mc_gState->m_Permissions->GetMinerCount() > 1)
                        || (MCP_ANYONE_CAN_MINE != 0))) {

                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.

                bool wait_for_peers=true;
                if(wait_for_peers)
                {
                    int active_nodes=0;
                    while ((active_nodes == 0) &&
                           ( (mc_gState->m_Permissions->GetMinerCount() > 1)
                          || (MCP_ANYONE_CAN_MINE != 0)
                           ) && Params().MiningRequiresPeers())
                    {
                        vector<CNode*> vNodesCopy = vNodes;
                        BOOST_FOREACH(CNode* pnode, vNodesCopy)
                        {
                            if(pnode->fSuccessfullyConnected)
                            {
                                active_nodes++;
                            }
                        }

                        if(active_nodes == 0)
                        {
                            MilliSleep(1000);
                            boost::this_thread::interruption_point();
                        }
                    }
                }
            }

            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrev = chainActive.Tip();
            EmptyBlockToMine=0;

            bool fMineEmptyBlocks=true;
            if(Params().MineEmptyRounds()+mc_gState->m_NetworkParams->ParamAccuracy()>= 0)
            {
                fMineEmptyBlocks=false;
                CBlockIndex* pindex=pindexPrev;
                int nMaxEmptyBlocks,nEmptyBlocks,nMinerCount;

                nMaxEmptyBlocks=0;
                nEmptyBlocks=0;
                nMinerCount=1;
                if(MCP_ANYONE_CAN_MINE == 0)
                {
                    nMinerCount=mc_gState->m_Permissions->GetMinerCount()-mc_gState->m_Permissions->GetActiveMinerCount()+1;
                }
                double d=Params().MineEmptyRounds()*nMinerCount-mc_gState->m_NetworkParams->ParamAccuracy();
                if(d >= 0)
                {
                    nMaxEmptyBlocks=(int)d+1;
                }

                fMineEmptyBlocks=false;
                while(!fMineEmptyBlocks && (pindex != NULL) && (nEmptyBlocks < nMaxEmptyBlocks))
                {
                    if(pindex->nTx > 1)
                    {
                        fMineEmptyBlocks=true;
                    }
                    else
                    {
                        nEmptyBlocks++;
                        pindex=pindex->pprev;
                    }
                }
                if(pindex == NULL)
                {
                    fMineEmptyBlocks=true;
                }
            }
            if(!fMineEmptyBlocks)
            {
                if(chainActive.Tip()->nHeight <= LastForkedHeight())
                {
                    EmptyBlockToMine=chainActive.Tip()->nHeight+1;
                    if(fDebug>1)LogPrint("mcminer","Hdac-miner: Chain is forked on height %d, ignoring mine-empty-rounds, mining on height %d\n", LastForkedHeight(),chainActive.Tip()->nHeight+1);
                    fMineEmptyBlocks=true;
                }
            }
            if(fMineEmptyBlocks)
            {
                nMemPoolSize=1;
            }

            canMine=MC_PTP_MINE;
            if(mc_TimeNowAsDouble() < GetMinerAndExpectedMiningStartTime(pwallet, &kMiner,&sMinerPool, &dMiningStartTime,&dActiveMiners,&hLastBlockHash,&nMemPoolSize))
            {
                canMine=0;
            }
            else
            {
                if(!kMiner.IsValid())
                {
                    canMine=0;
                }
                else
                {
                    if( !fMineEmptyBlocks
                            && not_setup_period
                            && (mempool.hashList->m_Count == 0)
                            )
                    {
                        canMine=0;
                    }
                    else
                    {
                        if(!CanMineWithLockedBlock())
                        {
                            canMine=0;
                        }
                    }
                }
            }

#if 0
            if(mc_gState->m_ProtocolVersionToUpgrade > mc_gState->m_NetworkParams->ProtocolVersion())
            {
                canMine=0;
            }
#endif

            if(mc_gState->m_NodePausedState & MC_NPS_MINING)
            {
                canMine=0;
            }

            if(fReindex)
            {
                canMine=0;
            }

            if(canMine & MC_PTP_MINE)
            {
                const unsigned char *pubkey_hash=(unsigned char *)Hash160(kMiner.begin(),kMiner.end()).begin();
                CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << vector<unsigned char>(pubkey_hash, pubkey_hash + 20) << OP_EQUALVERIFY << OP_CHECKSIG;
                canMine=prevCanMine;
                auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(scriptPubKey,pwallet,&kMiner,&canMine,&pindexPrev));        // multichain 1.0.2.1
                prevCanMine=canMine;

            if (!pblocktemplate.get())
            {
                if(fDebug>0)LogPrintf("Error in HdacMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");	//HDAC
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce,pwallet);

#ifndef FEATURE_HDAC_DISABLE_EPOW

            /* HDAC START */
            if(!CheckBlockWindow(kMiner))
            {
                    static int BW_C_TIMER_ = 0;
                    int64_t now=GetAdjustedTime();
                    if(now%10==0)
                    {
                            if(BW_C_TIMER_%10==0)
                            {
                                    int wz=0, nf=0, bh=0;
                                    GetCurrentBlockWindowInfo(wz, nf, bh);
				    std::string msg = strprintf("Miner[%s] is within Block Window. Waiting... NOW: %d WZ: %d NF: %d BH: %d", GetMinerAddress(kMiner), now, wz, nf, bh);
                                    if(fDebug>0)LogPrintf("hdac: %s\n", msg);
                            }

                            BW_C_TIMER_ = 0;
                    }
                    BW_C_TIMER_++;

                    __US_Sleep(100);
            }
            /* HDAC END */

#endif	// HDAC_PRIVATE_BLOCKCHAIN

            if(fDebug>0)LogPrint("hdacminer","Hdac-miner: Running HdacMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            //
            // Search
            //
            int64_t nStart = GetTime();
            uint256 hashTarget = uint256().SetCompact(pblock->nBits);
            uint256 hash;
            uint32_t nNonce = 0;
            uint32_t nOldNonce = 0;

            double wStartTime=mc_TimeNowAsDouble();
            uint64_t wThisCount=0;
            while (true) {

                if(EmptyBlockToMine)
                {
                    if(chainActive.Tip()->nHeight != EmptyBlockToMine-1)
                    {
                        if(fDebug>1)LogPrint("mcminer","Hdac-miner: Avoiding mining block %d, required %d\n", chainActive.Tip()->nHeight+1,EmptyBlockToMine);
                        break;
                    }
                }

                bool fFound = ScanHashWithLyra(pblock, nNonce, &hash, success_and_mask);
                uint32_t nHashesDone = nNonce - nOldNonce;
                nOldNonce = nNonce;

                wThisCount+=nHashesDone;

                // Check if something found
                if (fFound)
                {
                    if (hash <= hashTarget)
                    {
                        // Found a solution
                        pblock->nNonce = nNonce;
                        assert(hash == pblock->GetPoWHash());

                        SetThreadPriority(THREAD_PRIORITY_NORMAL);

                        if(fDebug>0)LogPrintf("HdacMiner: Block Found - %s, prev: %s, height: %d, txs: %d\n",
                                                hash.GetHex(),pblock->hashPrevBlock.ToString().c_str(),
                                                mc_gState->m_Permissions->m_Block+1,
                                                (int)pblock->vtx.size());

#if 0
                        if(mc_gState->m_ProtocolVersionToUpgrade > mc_gState->m_NetworkParams->ProtocolVersion())
                        {
                            LogPrintf("HdacMiner: Waiting for upgrade, block is dropped\n");	// HDAC
                        }
                        else
#endif
                        {
                            if(!ProcessBlockFound(pblock, *pwallet, reservekey))
                            {
                                __US_Sleep(1000);
                                boost::this_thread::interruption_point();
                            }
                        }


                        SetThreadPriority(THREAD_PRIORITY_LOWEST);

                        // In regression test mode, stop mining after a block is found.
                        if (Params().MineBlocksOnDemand())
                            throw boost::thread_interrupted();

                        break;
                    }
                }

                // Meter hashes/sec
                static int64_t nHashCounter;
                if (nHPSTimerStart == 0)
                {
                    nHPSTimerStart = GetTimeMillis();
                    nHashCounter = 0;
                }
                else
                    nHashCounter += nHashesDone;
                if (GetTimeMillis() - nHPSTimerStart > 4000)
                {
                    static CCriticalSection cs;
                    {
                        LOCK(cs);
                        if (GetTimeMillis() - nHPSTimerStart > 4000)
                        {
                            dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                            nHPSTimerStart = GetTimeMillis();
                            nHashCounter = 0;
                            static int64_t nLogTime;
                            if (GetTime() - nLogTime > 30 * 60)
                            {
                                nLogTime = GetTime();
                                if(fDebug>0)LogPrintf("hashmeter %6.0f khash/s\n", dHashesPerSec/1000.0);
                            }
                        }
                    }
                }

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point();
                // Regtest mode doesn't require peers
                if (vNodes.empty() && Params().MiningRequiresPeers()
                        && not_setup_period
                        && ( (mc_gState->m_Permissions->GetMinerCount() > 1)
                        || (MCP_ANYONE_CAN_MINE != 0)))
                {
                    break;
                }
                if (nNonce >= 0xffff0000)
                    break;
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (pindexPrev != chainActive.Tip())
                    break;

                // Update nTime every few seconds

                if(UpdateTime(pblock, pindexPrev))
                {

                    CreateBlockSignature(pblock,BLOCKSIGHASH_NO_SIGNATURE_AND_NONCE,pwallet);

                }
                if (Params().AllowMinDifficultyBlocks())
                {
                    // Changing pblock->nTime can change work required on testnet:
                    hashTarget.SetCompact(pblock->nBits);
                }
            }

            double wTimeNow=mc_TimeNowAsDouble();
            if(wTimeNow>wStartTime+0.01)
            {
                wCount[wPos]=wThisCount;
                wTime[wPos]=wTimeNow-wStartTime;
                wPos=(wPos+1)%wSize;
                dHashesPerSec=wThisCount/(wTimeNow-wStartTime);
            }

            }
            else
            {
                if(mc_gState->m_Permissions->m_Block > 1)
                {
                    __US_Sleep(100);
                }
            }

        }
    }
    catch (boost::thread_interrupted)
    {
        if(fDebug>0)LogPrintf("HdacMiner terminated\n");	// HDAC
        throw;
    }
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
{
    static boost::thread_group* minerThreads = NULL;

    if (nThreads < 0) {
        // In regtest threads defaults to 1
        if (Params().DefaultMinerThreads())
            nThreads = Params().DefaultMinerThreads();
        else
            nThreads = boost::thread::hardware_concurrency();
    }

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();

        minerThreads->join_all();


        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&BitcoinMiner, pwallet));
}

#endif // ENABLE_WALLET
