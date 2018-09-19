// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
//
// 2018/02/00   Code optimization
//============================================================================================


#ifndef __HDAC_VERSION_H_
#define	__HDAC_VERSION_H_

#define HDAC_PROTOCOL_VERSION	20000

#ifndef STRINGIZE
#define STRINGIZE(X)		DO_STRINGIZE(X)
#endif

#ifndef DO_STRINGIZE
#define DO_STRINGIZE(X)		#X
#endif

#define HDAC_BUILD_MAJOR	0
#define HDAC_BUILD_MINOR	91
#define HDAC_BUILD_REVISION	0
// Build version is major.minor.revision ( 0.91.0 )

#define HDAC_BUILD_DESC_NUMERIC	20000091

#define HDAC_VERSION_DESC(maj, min, rev) \
		DO_STRINGIZE(maj) "." DO_STRINGIZE(min) "." DO_STRINGIZE(rev)

#define HDAC_BUILD_DESC HDAC_VERSION_DESC(HDAC_BUILD_MAJOR,HDAC_BUILD_MINOR,HDAC_BUILD_REVISION)

#define HDAC_FULL_DESC(build, protocol) \
    "build " build " protocol " DO_STRINGIZE(protocol)


#ifndef HDAC_FULL_VERSION
#define HDAC_FULL_VERSION HDAC_FULL_DESC(HDAC_BUILD_DESC, HDAC_PROTOCOL_VERSION)
#endif

#define PARAMS_HASH__TESTNET "71adccf9ff5ee20ed1cff336dc5944318d1db3ee769d15b988e1f26372b5954e"
#define PARAMS_HASH_MAINNET "6d8b1ae3e537672d4046193e93fa6764fc63ed4a9e4ff8ac57554a5b0491454a"


#endif	// __HDAC_VERSION_H_

