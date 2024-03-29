// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
// 
// 2018/04/19	Add history 
// 2018/07/20   kasse-asm parameter added. (HDAC_KASSE_ASM variable added)
//============================================================================================

#ifndef GLOBALS_H
#define	GLOBALS_H

mc_State* mc_gState;

/*
   below parameters are reassigned in params.dat
*/
unsigned int MIN_RELAY_TX_FEE = 1000;                                           // new
unsigned int MAX_OP_RETURN_RELAY = 40;                                          // standard.h
unsigned int MAX_BLOCK_SIZE = 8 * 1024 * 1024;                                  // block.h 8MB
unsigned int DEFAULT_BLOCK_MAX_SIZE = 8 * 1024 * 1024;                          // main.h 8MB
unsigned int MAX_BLOCKFILE_SIZE = 0x8000000;                                    // main.h 256MB
unsigned int MAX_STANDARD_TX_SIZE = 100000;                                     // main.h
unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
unsigned int MAX_TX_SIGOPS = MAX_BLOCK_SIGOPS/5;

int COINBASE_MATURITY = 100;                                                    // main.h
unsigned int MAX_SIZE = 0x02000000;                                             // serialize,h 64MB
int64_t COIN = 100000000;                                                       // amount.h
int64_t CENT = 1000000;                                                         // amount.h
int64_t MAX_MONEY = 21000000 * COIN;                                            // amount.h
unsigned int MAX_SCRIPT_ELEMENT_SIZE=520;                                       // script.h
int MAX_OP_RETURN_SHOWN=16384;

int MCP_MAX_STD_OP_RETURN_COUNT=0;
int64_t MCP_INITIAL_BLOCK_REWARD=0;
int64_t MCP_FIRST_BLOCK_REWARD=0;
int MCP_TARGET_BLOCK_TIME=0;
int HDAC_KASSE_ASM=0;			// Hdac LJM 180720
int MCP_ANYONE_CAN_ADMIN=0;
int MCP_ANYONE_CAN_MINE=0;
int MCP_ANYONE_CAN_CONNECT=0;
int MCP_ANYONE_CAN_SEND=0;
int MCP_ANYONE_CAN_RECEIVE=0;
int MCP_ANYONE_CAN_CREATE=0;
int MCP_ANYONE_CAN_ACTIVATE=0;
int64_t MCP_MINIMUM_PER_OUTPUT=0;
int MCP_ALLOW_ARBITRARY_OUTPUTS=1;
int MCP_ALLOW_MULTISIG_OUTPUTS=0;
int MCP_ALLOW_P2SH_OUTPUTS=0;
int MCP_WITH_NATIVE_CURRENCY=0;
int MCP_STD_OP_DROP_COUNT=0;
int MCP_STD_OP_DROP_SIZE=0;
int MCP_ANYONE_CAN_RECEIVE_EMPTY=0;


#endif	// GLOBALS_H 

