// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin developers
// Original code was distributed under the MIT software license.
// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
// 
// 2018/01/00	Rename file 
// 2018/02/00   Code optimization
//============================================================================================


#include "core/main.h"
#include "utils/util.h"
#include "hdac/hdac.h"
#include "wallet/wallettxs.h"

extern mc_WalletTxs* pwalletTxsMain;


using namespace std;

bool AcceptHdacTransaction(const CTransaction& tx, 
                                 const CCoinsViewCache &inputs,
                                 int offset,
                                 bool accept,
                                 string& reason,
                                 uint32_t *replay);
bool AcceptAdminMinerPermissions(const CTransaction& tx,
                                 int offset,
                                 bool verify_signatures,
                                 string& reason,
                                 uint32_t *result);
bool AcceptAssetTransfers(const CTransaction& tx, const CCoinsViewCache &inputs, string& reason);
bool AcceptAssetGenesis(const CTransaction &tx,int offset,bool accept,string& reason);
bool AcceptPermissionsAndCheckForDust(const CTransaction &tx,bool accept,string& reason);
bool IsTxBanned(uint256 txid);


bool ReplayMemPool(CTxMemPool& pool, int from,bool accept)
{
    int pos;
    uint256 hash;
    
    int total_txs=pool.hashList->m_Count;
    
    LogPrint("hdac", "hdac: Replaying memory pool (%d new transactions, total %d)\n",total_txs-from,total_txs);
    mc_gState->m_Permissions->MempoolPermissionsCopy();
    
    for(pos=from;pos<pool.hashList->m_Count;pos++)
    {
        hash=*(uint256*)pool.hashList->GetRow(pos);
        if(pool.exists(hash))
        {
            const CTxMemPoolEntry entry=pool.mapTx[hash];
            const CTransaction& tx = entry.GetTx();            
            string removed_type="";
            string reason;
            list<CTransaction> removed;
            
            if(IsTxBanned(hash))
            {
                removed_type="banned";                                    
            }
            else
            {
                int permissions_from,permissions_to;
                permissions_from=mc_gState->m_Permissions->m_MempoolPermissions->GetCount();
                if(entry.FullReplayRequired())
                {
                    LOCK(pool.cs);
                    CCoinsView dummy;
                    CCoinsViewCache view(&dummy);
                    CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
                    view.SetBackend(viewMemPool);
                    if(!AcceptHdacTransaction(tx,view,-1,accept,reason,NULL))
                    {
                        removed_type="rejected";                    
                    }
                }
                else
                {
                   if(mc_gState->m_Permissions->MempoolPermissionsCheck(entry.ReplayPermissionFrom(),entry.ReplayPermissionTo()) == 0) 
                   {
                        removed_type="rejected";                                               
                   }                        
                }
                if(removed_type.size() == 0)
                {
                    permissions_to=mc_gState->m_Permissions->m_MempoolPermissions->GetCount();
                    pool.mapTx[hash].SetReplayNodeParams(entry.FullReplayRequired(),permissions_from,permissions_to);                    
                }
            }

            if(removed_type.size())
            {
                LogPrintf("hdac: Tx %s removed from the mempool (%s), reason: %s\n",tx.GetHash().ToString().c_str(),removed_type.c_str(),reason.c_str());
                pool.remove(tx, removed, true, "replay");                    
            }
            else
            {
                if(pwalletTxsMain->AddTx(NULL,tx,-1,NULL,-1,0))
                {
                    removed_type="error";
                    reason="wallet";
                    LogPrintf("hdac: Tx %s removed from the mempool (%s), reason: %s\n",tx.GetHash().ToString().c_str(),removed_type.c_str(),reason.c_str());
                    pool.remove(tx, removed, true, "replay");                                        
                }
            }
        }
    }
    
    return true;
}

void FindSigner(CBlock *block,unsigned char *sig,int *sig_size,uint32_t *hash_type)
{
    int key_size;
    block->vSigner[0]=0;

    for (unsigned int i = 0; i < block->vtx.size(); i++)
    {
        const CTransaction &tx = block->vtx[i];
        if (tx.IsCoinBase())
        {
            for (unsigned int j = 0; j < tx.vout.size(); j++)
            {
                mc_gState->m_TmpScript1->Clear();

                const CScript& script1 = tx.vout[j].scriptPubKey;
                CScript::const_iterator pc1 = script1.begin();

                mc_gState->m_TmpScript1->SetScript((unsigned char*)(&pc1[0]),(size_t)(script1.end()-pc1),MC_SCR_TYPE_SCRIPTPUBKEY);

                for (int e = 0; e < mc_gState->m_TmpScript1->GetNumElements(); e++)
                {
                    if(block->vSigner[0] == 0)
                    {
                       mc_gState->m_TmpScript1->SetElement(e);

                        *sig_size=255;
                        key_size=255;
                        if(mc_gState->m_TmpScript1->GetBlockSignature(sig,sig_size,hash_type,block->vSigner+1,&key_size) == 0)
                        {
                            block->vSigner[0]=(unsigned char)key_size;
                        }
                    }
                }
            }
        }
    }
}
bool VerifyBlockSignature(CBlock *block,bool force)
{
    unsigned char sig[255];
    int sig_size;//,key_size;
    uint32_t hash_type;
    uint256 hash_to_verify;
    uint256 original_merkle_root;
    uint32_t original_nonce;
	bool ReverseSwitch = false;
	CMutableTransaction reTx = block->vtx[0];
    std::vector<unsigned char> vchSigOut;
    std::vector<unsigned char> vchPubKey;
    std::vector<uint256> savedMerkleTree;
    
    if(!force)
    {
        if(block->nMerkleTreeType != MERKLETREE_UNKNOWN)
        {
            if(block->nSigHashType == BLOCKSIGHASH_INVALID)
            {
                return false;
            }
            return true;
        }
    }

    //uint32_t temp_merkel = block->nMerkleTreeType;
            
    block->nMerkleTreeType=MERKLETREE_FULL;
    block->nSigHashType=BLOCKSIGHASH_NONE;

    FindSigner(block, sig, &sig_size, &hash_type);

    if(block->vSigner[0])
    {
        switch(hash_type)
        {
            case BLOCKSIGHASH_HEADER:
                block->nMerkleTreeType=MERKLETREE_NO_COINBASE_OP_RETURN;
                block->nSigHashType=BLOCKSIGHASH_HEADER;
                hash_to_verify=block->GetHash();
                break;
            case BLOCKSIGHASH_NO_SIGNATURE_AND_NONCE:
				reTx = block->vtx[0];
				original_merkle_root = block->hashMerkleRoot;
				original_nonce = block->nNonce;

				block->nMerkleTreeType = MERKLETREE_NO_COINBASE_OP_RETURN;
				savedMerkleTree = block->vMerkleTree;

			/* HDAC START */
			{

				int coinbase_tx = 0;

				CMutableTransaction tx = block->vtx[coinbase_tx];

				std::string strMsg("880000000000000022");

				std::string strSearch = "/P2SH/"; // "2f503253482f";

				std::vector<unsigned char> scriptV = tx.vin[0].scriptSig;

				std::string scriptStr(scriptV.begin(), scriptV.end());

				int idx = 0;

				int idxStart = 0;

				idx = scriptStr.find(strSearch);

				if (idx > 0)
				{
					ReverseSwitch = true;
					//Q(0x51) (0x01) (0x15) (0x06) /(0x2f) P(0x50) 2(0x32) S(0x53) H(0x48) /(0x2f) (0x12)

					idxStart = idx + strSearch.length();

					std::string strAppended(scriptStr.begin() + idxStart,scriptStr.end());

					//unsigned char ch = '0';
					typename std::vector<unsigned char>::iterator pc = scriptV.begin();

					for (int i = 0; pc < scriptV.end(); i++, pc++)
					{
						//ch = *pc;
						if (i >= idxStart)
						{
							*pc = 0;              // replace entity with zero;
							tx.vin[0].scriptSig[i] = 0;
						}
					}
					std::string strTmp(scriptV.begin(), scriptV.end());
				}
				block->vtx[coinbase_tx] = tx;
			}
			/* HDAC END */

			block->hashMerkleRoot = block->BuildMerkleTree();
			block->nNonce = 0;
			hash_to_verify = block->GetHash();

			if(ReverseSwitch)
				block->vtx[0] = reTx;

			block->hashMerkleRoot = original_merkle_root;
			block->nNonce = original_nonce;

			block->nMerkleTreeType = MERKLETREE_FULL;

			if (savedMerkleTree.size()) {
				block->vMerkleTree = savedMerkleTree;
			} else {
				block->BuildMerkleTree();
			}

			break;
            default:
                LogPrintf("hdac: Invalid hash type received in block signature\n");
                block->nSigHashType=BLOCKSIGHASH_INVALID;
                return false;
        }
        
        vchSigOut=std::vector<unsigned char> (sig, sig+sig_size);
        vchPubKey=std::vector<unsigned char> (block->vSigner+1, block->vSigner+1+block->vSigner[0]);

        CPubKey pubKeyOut(vchPubKey);
        if (!pubKeyOut.IsValid())
        {
            block->nSigHashType=BLOCKSIGHASH_INVALID;
            return false;
        }

        if(!pubKeyOut.Verify(hash_to_verify,vchSigOut))
        {
            LogPrintf("hdac: Wrong block signature\n");
            block->nSigHashType=BLOCKSIGHASH_INVALID;
            return false;
        }
    }
    else
    {
        if(block->hashPrevBlock != uint256(0))
        {
            LogPrintf("hdac: Block signature not found\n");                
            block->nSigHashType=BLOCKSIGHASH_INVALID;
            return false;
        }
    }
    return true;
}

bool ReadTxFromDisk(CBlockIndex* pindex,int32_t offset,CTransaction& tx)
{
    CAutoFile file(OpenBlockFile(pindex->GetBlockPos(), true), SER_DISK, CLIENT_VERSION);
    if (file.IsNull())
    {
        LogPrintf("VerifyBlockMiner: Could not load block %s (height %d) from disk\n",pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
        return false;
    }
    try 
    {
        fseek(file.Get(), offset, SEEK_CUR);
        file >> tx;
    } 
    catch (std::exception &e) 
    {
        LogPrintf("VerifyBlockMiner: Could not deserialize tx at offset %d block %s (height %d) from disk\n",offset,pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
        return false;
    }

    return true;
}

bool VerifyBlockMiner(CBlock *block_in,CBlockIndex* pindexNew)
{
    if( (mc_gState->m_NetworkParams->GetInt64Param("supportminerprecheck") == 0) ||
        (MCP_ANYONE_CAN_MINE) )                               
    {
        pindexNew->fPassedMinerPrecheck=true;
        return true;
    }
    
    if(pindexNew->pprev == NULL)
    {
        pindexNew->fPassedMinerPrecheck=true;
        return true;        
    }
    
    bool fReject=false;
    const CBlockIndex *pindexFork = chainActive.FindFork(pindexNew);
    
    if(pindexFork == pindexNew)
    {        
        pindexNew->fPassedMinerPrecheck=true;
        return true;        
    }
    
    CBlockIndex *pindex;
    const CBlock *pblock;
    CBlock branch_block;
    vector <CBlockIndex *> branch;
    vector <uint160> miners;
    int pos,branch_size,record,i;
    uint32_t last_after_fork;
    bool fVerify;
    bool fRolledBack;
    uint32_t admin_miner_count;
    int32_t offsets[MC_PLS_SIZE_OFFSETS_PER_ROW];
    uint256 block_hash;
    vector<unsigned char> vchPubKey;
    
    fRolledBack=false;
    branch_size=pindexNew->nHeight-pindexFork->nHeight;
    branch.resize(branch_size);
    miners.resize(branch_size);
        
    pos=branch_size-1;
    pindex=pindexNew;

    CBlock last_block;
    CBlock *pblock_last;
    pblock_last=block_in;
    if(block_in == NULL)
    {
        if ( ((pindexNew->nStatus & BLOCK_HAVE_DATA) == 0 ) || !ReadBlockFromDisk(last_block, pindexNew) )
        {
            LogPrintf("VerifyBlockMiner: Block %s (height %d) miner verification skipped - block not found\n",pindexNew->GetBlockHash().ToString().c_str(),pindexNew->nHeight);        
            fReject=true;                                              
        }       
        pblock_last=&last_block;
    }

    vchPubKey=vector<unsigned char> (pblock_last->vSigner+1, pblock_last->vSigner+1+pblock_last->vSigner[0]);
    CPubKey pubKeyNew(vchPubKey);
    CKeyID pubKeyHashNew=pubKeyNew.GetID();
    miners[pos]=*(uint160*)(pubKeyHashNew.begin());      

    if(fReject)
    {
        fReject=false;
        goto exitlbl;                    
    }
    
    LogPrint("hdac","VerifyBlockMiner: Block: %d, Fork: %d, Chain: %d\n",pindexNew->nHeight,pindexFork->nHeight,mc_gState->m_Permissions->m_Block);
    
    while(pindex != pindexFork)
    {
        if(pindex->nStatus & BLOCK_FAILED_MASK)
        {
            LogPrintf("VerifyBlockMiner: Invalid block %s (height %d)\n",pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
            fReject=true;
            goto exitlbl;            
        }
        
        branch[pos]=pindex;
        pos--;
        pindex=pindex->pprev;
    }

    last_after_fork=0;
    fRolledBack=true;
    mc_gState->m_Permissions->RollBackBeforeMinerVerification(pindexFork->nHeight);
    LogPrint("hdac","VerifyBlockMiner: Rolled back to block %d\n",mc_gState->m_Permissions->m_Block);

    for(pos=0;pos<branch_size;pos++)
    {
        LogPrint("hdac","VerifyBlockMiner: Verifying block %d\n",mc_gState->m_Permissions->m_Block+1);
        pindex=branch[pos];
        block_hash=pindex->GetBlockHash();
        fVerify=false;
        pblock=NULL;
        if(pindex == pindexNew)
        {
            fVerify=true;
            pblock=pblock_last;            
        }
        if(!fVerify && (mc_gState->m_Permissions->GetBlockMiner(&block_hash,(unsigned char*)&miners[pos],&admin_miner_count) == MC_ERR_NOERROR) )
        {
            LogPrint("hdac","VerifyBlockMiner: Verified block %s (height %d)\n",pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
            if(miners[pos] == miners[branch_size - 1])
            {
                last_after_fork=pindex->nHeight;
            }
            record=1;
            while(mc_gState->m_Permissions->GetBlockAdminMinerGrants(&block_hash,record,offsets) == MC_ERR_NOERROR)
            {
                for(i=0;i<MC_PLS_SIZE_OFFSETS_PER_ROW;i++)
                {
                    if(offsets[i])
                    {
                        CTransaction tx;
                        string reason;
                        if(!ReadTxFromDisk(pindex,offsets[i],tx))
                        {
                            fReject=true;
                            goto exitlbl;                            
                        }
                        LogPrint("hdac","VerifyBlockMiner: Grant tx %s in block %s (height %d)\n",tx.GetHash().ToString().c_str(),pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
                        if(!AcceptAdminMinerPermissions(tx,offsets[i],false,reason,NULL))
                        {
                            LogPrintf("VerifyBlockMiner: tx %s: %s\n",tx.GetHash().ToString().c_str(),reason.c_str());
                            fReject=true;
                            goto exitlbl;                            
                        }
                    }
                }
                record++;
            }
            mc_gState->m_Permissions->IncrementBlock(admin_miner_count);
        }
        else
        {
            if(pblock == NULL)
            {
                LogPrint("hdac","VerifyBlockMiner: Unverified block %s (height %d)\n",pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
                if ( ((pindex->nStatus & BLOCK_HAVE_DATA) == 0 ) || !ReadBlockFromDisk(branch_block, pindex) )
                {
                    LogPrintf("VerifyBlockMiner: Could not load block %s (height %d) from disk\n",pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
                    LogPrintf("VerifyBlockMiner: Block %s (height %d) miner verification skipped\n",pindexNew->GetBlockHash().ToString().c_str(),pindexNew->nHeight);        
                    fReject=false;                                              // We cannot neglect subsequent blocks, but it is unverified
                    goto exitlbl;                    
                }
                pblock = &branch_block;                
                vchPubKey=vector<unsigned char> (branch_block.vSigner+1, branch_block.vSigner+1+branch_block.vSigner[0]);
                CPubKey pubKey(vchPubKey);
                CKeyID pubKeyHash=pubKey.GetID();
                miners[pos]=*(uint160*)(pubKeyHash.begin());      
                if(miners[pos] == miners[branch_size - 1])
                {
                    last_after_fork=pindex->nHeight;
                }
                if(mc_gState->m_Permissions->CanMineBlockOnFork(&miners[pos],pindex->nHeight,last_after_fork) == 0)
                {
                    LogPrintf("VerifyBlockMiner: Permission denied for miner %s received in block signature\n",CBitcoinAddress(pubKeyHash).ToString().c_str());
                    fReject=true;
                    goto exitlbl;                    
                }
            }
            else
            {
                LogPrint("hdac","VerifyBlockMiner: New block %s (height %d)\n",pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
                if(mc_gState->m_Permissions->CanMineBlockOnFork(&miners[pos],pindex->nHeight,last_after_fork) == 0)
                {
                    LogPrintf("VerifyBlockMiner: Permission denied for miner %s received in block signature\n",CBitcoinAddress(pubKeyHashNew).ToString().c_str());
                    fReject=true;
                    goto exitlbl;                    
                }
            }
            int off=80+GetSizeOfCompactSize(pblock->vtx.size());
            for (unsigned int i = 0; i < pblock->vtx.size(); i++)
            {
                const CTransaction &tx = pblock->vtx[i];
                string reason;
                uint32_t result;
                int mempool_size=mc_gState->m_Permissions->m_MemPool->GetCount();
                if(!AcceptAdminMinerPermissions(tx,off,true,reason,&result))
                {
                    LogPrintf("VerifyBlockMiner: tx %s: %s\n",tx.GetHash().ToString().c_str(),reason.c_str());
                    fReject=true;
                    goto exitlbl;                            
                }
                if(mempool_size != mc_gState->m_Permissions->m_MemPool->GetCount())
                {
                    LogPrint("hdac","VerifyBlockMiner: Grant tx %s in block %s (height %d)\n",tx.GetHash().ToString().c_str(),pindex->GetBlockHash().ToString().c_str(),pindex->nHeight);
                }
                
                off+=tx.GetSerializeSize(SER_NETWORK,tx.nVersion);
            }
            mc_gState->m_Permissions->StoreBlockInfo(&miners[pos],&block_hash);
        }
        pindex->fPassedMinerPrecheck=true;
    }
    
exitlbl:

    if(fRolledBack)
    {
        LogPrint("hdac","VerifyBlockMiner: Restoring chain, block %d\n",mc_gState->m_Permissions->m_Block);
        mc_gState->m_Permissions->RestoreAfterMinerVerification();
        LogPrint("hdac","VerifyBlockMiner: Restored on block %d\n",mc_gState->m_Permissions->m_Block);
    }

    if(fReject)
    {
        LogPrintf("VerifyBlockMiner: Block %s (height %d) miner verification failed\n",pindexNew->GetBlockHash().ToString().c_str(),pindexNew->nHeight);        
    }

    return !fReject;
}


bool CheckBlockPermissions(const CBlock& block,CBlockIndex* prev_block,unsigned char *lpMinerAddress)
{
    bool checked=true;
    const unsigned char *genesis_key;
    int key_size;
    vector<unsigned char> vchSigOut;
    vector<unsigned char> vchPubKey;
    
    LogPrint("hdac","hdac: Checking block signature and miner permissions...\n");
            
    key_size=255;    
    
    mc_gState->m_Permissions->CopyMemPool();
    mc_gState->m_Permissions->ClearMemPool();
    
    if(checked)
    {
        if(prev_block)
        {
            if((block.nSigHashType == BLOCKSIGHASH_UNKNOWN) || (block.nSigHashType == BLOCKSIGHASH_INVALID))
            {
                checked=false;
            }        
            else
            {
                vchPubKey=vector<unsigned char> (block.vSigner+1, block.vSigner+1+block.vSigner[0]);

                CPubKey pubKeyOut(vchPubKey);
                if (!pubKeyOut.IsValid())
                {
                    LogPrintf("hdac: Invalid pubkey received in block signature\n");
                    checked = false;
                }
                if(checked)
                {    
                    CKeyID pubKeyHash=pubKeyOut.GetID();
                    memcpy(lpMinerAddress,pubKeyHash.begin(),20);
                    if(!mc_gState->m_Permissions->CanMine(NULL,pubKeyHash.begin()))
                    {
                        LogPrintf("hdac: Permission denied for miner %s received in block signature\n",CBitcoinAddress(pubKeyHash).ToString().c_str());
                        checked = false;
                    }
                }                
            }
        }
        else
        {
            genesis_key=(unsigned char*)mc_gState->m_NetworkParams->GetParam("genesispubkey",&key_size);
            vchPubKey=vector<unsigned char> (genesis_key, genesis_key+key_size);

            CPubKey pubKeyOut(vchPubKey);
            if (!pubKeyOut.IsValid())
            {
                LogPrintf("hdac: Invalid pubkey received in block signature\n");
                checked = false;
            }
            if(checked)
            {    
                CKeyID pubKeyHash=pubKeyOut.GetID();
                memcpy(lpMinerAddress,pubKeyHash.begin(),20);
            }        
        }
    }
 
    mc_gState->m_Permissions->RestoreMemPool();
    
    return checked;
}

