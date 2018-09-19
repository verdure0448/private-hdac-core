// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
// 
// 2018/01/00	Master features added
// 2018/04/27	Merge public blockchain features
// 2018/04/27	BBC NEWS: North Korea's Kim Jong-un pledges 'new history' with South Korea
//============================================================================================


#ifndef __CUST_HDAC_H_
#define	__CUST_HDAC_H_


#define HDAC_PRIVATE_BLOCKCHAIN		// HDAC LJM 180427 
//#define HDAC_PUBLIC_BLOCKCHAIN


#define HDAC_VERSION_DEFINITION

//#define FEATURE_HPAY_NOT_OPTIMIZE_UNSPENTLIST

//#define FEATURE_HPAY_LIMITFREERELAY_NOT_USED

#define FEATURE_HPAY_INIT_AS_PARAMS

//#define FEATURE_HPAY_FEE_FIX

#define FEATURE_HPAY_DISABLED_WALLET_DUMP

#define FEATURE_HPAY_MAX_NUM_RPC_THREAD

#ifdef FEATURE_HPAY_MAX_NUM_RPC_THREAD
#define MAX_RPC_THREAD  100
#endif	// FEATURE_HPAY_MAX_NUM_RPC_THREAD 

//#define FEATURE_HPAY_TX_CONFIRM_TARGET

#define FEATURE_HPAY_UPDATE_PARAMS_HASH

#define FEATURE_HPAY_PREVENT_REMOVE_DATADIR

#define FEATURE_HPAY_IMPORT_ALL_ADDR_WITH_TX

#define FEATURE_HPAY_MAX_NATIVE_CURRENCY

#define FEATURE_HPAY_DB_CACHE_SIZE

#define FEATURE_HPAY_RETRIEVE_ZERO_CONFIRM_BALANCE

#define FEATURE_HPAY_GET_PEER_NODE_BLOCK_HEIGHT

#define FEATURE_HPAY_SKIP_VERIFY_PERM_WATCHONLY_ADDR



#define FEATURE_HDAC_AUTO_IMPORT_ADDRESS

#define FEATURE_HDAC_EXTENDED_PERMISSIONS

#ifdef HDAC_PRIVATE_BLOCKCHAIN
#define FEATURE_HDAC_DISABLE_EPOW	// Disabled in private blockchain
#define FEATURE_HDAC_KASSE_ASM		// Kasse ASM enabled at Private Blockchain (params.dat sync problem)
#endif

#define FEATURE_HDAC_QUANTUM_RANDOM_NUMBER


#endif	// __CUST_HDAC_H_ 

