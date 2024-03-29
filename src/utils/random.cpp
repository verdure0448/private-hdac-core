// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Original code was distributed under the MIT/X11 software license.
// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
//
// 2018/07/02   GetQuantumRandomBytes(): EYL QRNG(Quantum Random Number Generator) support
//============================================================================================


#include "cust/custhdac.h"

#include "utils/random.h"

#include "crypto/sha512.h"
#ifdef WIN32
#include "utils/compat.h" // for Windows API
#include <wincrypt.h>
#endif
#include "utils/serialize.h"        // for begin_ptr(vec)
#include "utils/util.h"             // for LogPrint()
#include "utils/utilstrencodings.h" // for GetTime()

#include <stdlib.h>
#include <limits>

#ifndef WIN32
#include <sys/time.h>
#else
#undef FEATURE_HDAC_QUANTUM_RANDOM_NUMBER	// WIN32 not support
#endif

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>


static void RandFailure()
{
    if(fDebug>0)LogPrintf("Failed to read randomness, aborting\n");
    abort();
}


static inline int64_t GetPerformanceCounter()
{
    int64_t nCounter = 0;
#ifdef WIN32
    QueryPerformanceCounter((LARGE_INTEGER*)&nCounter);
#else
    timeval t;
    gettimeofday(&t, NULL);
    nCounter = (int64_t)(t.tv_sec * 1000000 + t.tv_usec);
#endif
    return nCounter;
}


void RandAddSeed()
{
    // Seed with CPU performance counter
    int64_t nCounter = GetPerformanceCounter();
    RAND_add(&nCounter, sizeof(nCounter), 1.5);
    OPENSSL_cleanse((void*)&nCounter, sizeof(nCounter));
}


static void RandAddSeedPerfmon()
{
    RandAddSeed();

    // This can take up to 2 seconds, so only do it every 10 minutes
    static int64_t nLastPerfmon;
    if (GetTime() < nLastPerfmon + 10 * 60)
        return;
    nLastPerfmon = GetTime();

#ifdef WIN32
    // Don't need this on Linux, OpenSSL automatically uses /dev/urandom
    // Seed with the entire set of perfmon data
    std::vector<unsigned char> vData(250000, 0);
    long ret = 0;
    unsigned long nSize = 0;
    const size_t nMaxSize = 10000000; // Bail out at more than 10MB of performance data
    while (true) {
        nSize = vData.size();
        ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", NULL, NULL, begin_ptr(vData), &nSize);
        if (ret != ERROR_MORE_DATA || vData.size() >= nMaxSize)
            break;
        vData.resize(std::max((vData.size() * 3) / 2, nMaxSize)); // Grow size of buffer exponentially
    }
    RegCloseKey(HKEY_PERFORMANCE_DATA);
    if (ret == ERROR_SUCCESS) {
        RAND_add(begin_ptr(vData), nSize, nSize / 100.0);
        OPENSSL_cleanse(begin_ptr(vData), nSize);
        if(fDebug>1)LogPrint("rand", "%s: %lu bytes\n", __func__, nSize);
    } else {
        static bool warned = false; // Warn only once
        if (!warned) {
            if(fDebug>0)LogPrintf("%s: Warning: RegQueryValueExA(HKEY_PERFORMANCE_DATA) failed with code %i\n", __func__, ret);
            warned = true;
        }
    }
#endif
}


/** Get 32 bytes of system entropy. */
static void GetOSRand(unsigned char *ent32)
{
#ifdef WIN32
    HCRYPTPROV hProvider;
    int ret = CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!ret) {
        RandFailure();
    }
    ret = CryptGenRandom(hProvider, 32, ent32);
    if (!ret) {
        RandFailure();
    }
    CryptReleaseContext(hProvider, 0);
#else
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        RandFailure();
    }
    int have = 0;
    do {
        ssize_t n = read(f, ent32 + have, 32 - have);
        if (n <= 0 || n + have > 32) {
            RandFailure();
        }
        have += n;
    } while (have < 32);
    close(f);
#endif
}

void memory_cleanse(void *ptr, size_t len)
{
    OPENSSL_cleanse(ptr, len);
}


#ifdef FEATURE_HDAC_QUANTUM_RANDOM_NUMBER

void GetRandBytes_org(unsigned char* buf, int num)
{
    if (RAND_bytes(buf, num) != 1) {
        RandFailure();        
//        if(fDebug>0)LogPrintf("%s: OpenSSL RAND_bytes() failed with error: %s\n", __func__, ERR_error_string(ERR_get_error(), NULL));
//        assert(false);
    }
}


void GetStrongRandBytes_org(unsigned char* out, int num)
{
    assert(num <= 32);
    CSHA512 hasher;
    unsigned char buf[64];

    // First source: OpenSSL's RNG
    RandAddSeedPerfmon();
    GetRandBytes(buf, 32);
    hasher.Write(buf, 32);

    // Second source: OS RNG
    GetOSRand(buf);
    hasher.Write(buf, 32);

    // Produce output
    hasher.Finalize(buf);
    memcpy(out, buf, num);
    memory_cleanse(buf, 64);
}


#define QRNG_DEVICE0	"/dev/qrng_u3_0"
#define QRNG_DEVICE1	"/dev/qrng_u3_1"

static	int	_QRNG_fd = -1;


//
// EYL QRNG support function
// Two QRNG device support
//
void QRNG_RAND_bytes(unsigned char* out, int num)
{
    static time_t lasttime = 0;

    if (_QRNG_fd == -1)
        _QRNG_fd = open(QRNG_DEVICE0, O_RDONLY);
    if (_QRNG_fd == -1)
        _QRNG_fd = open(QRNG_DEVICE1, O_RDONLY);
    if (time(NULL) - lasttime > 30)
    {
        if (fDebug>4)LogPrintf("%s: QRNG fd=%d\n", __func__, _QRNG_fd);
    }

    if (_QRNG_fd == -1)		// QRNG is not available
    {
        GetRandBytes_org(out, num);
        return;
    }
    if (time(NULL) - lasttime > 60)
    	LogPrintf("%s: QRNG(Quantum Random Number Generator) endbaled and replaces RAND_bytes().\n", __func__);
    lasttime = time(NULL);

    int nread = read(_QRNG_fd, out, num);
    if (fDebug>3)LogPrintf("%s: QRNG read bytes=%d\n", __func__, nread);

    if (nread != num)	// read failed
    {
        _QRNG_fd = -1;
        GetRandBytes_org(out, num);
    }
}


void GetRandBytes(unsigned char* buf, int num)
{
    QRNG_RAND_bytes(buf, num);
}


//
// EYL QRNG support function
// Two QRNG device support
//
void QRNG_GetStrongRandBytes(unsigned char* out, int num)
{
    static time_t lasttime = 0;

    if (_QRNG_fd == -1)
        _QRNG_fd = open(QRNG_DEVICE0, O_RDONLY);
    if (_QRNG_fd == -1)
        _QRNG_fd = open(QRNG_DEVICE1, O_RDONLY);
    if (fDebug>3)LogPrintf("%s: QRNG fd=%d\n", __func__, _QRNG_fd);

    if (_QRNG_fd == -1)		// QRNG is not available
    {
        GetStrongRandBytes_org(out, num);
        return;
    }
    if (time(NULL) - lasttime > 3600)
    	LogPrintf("%s: QRNG(Quantum Random Number Generator) endbaled and replaces GetStrongRandBytes().\n", __func__);
    lasttime = time(NULL);

    int nread = read(_QRNG_fd, out, num);
    if (fDebug>3)LogPrintf("%s: QRNG read=%d\n", __func__, nread);

    if (nread != num)	// read failed
    {
        _QRNG_fd = -1;
        GetStrongRandBytes_org(out, num);
    }
}


void GetStrongRandBytes(unsigned char* out, int num)
{
    QRNG_GetStrongRandBytes(out, num);
}

#else	// FEATURE_HDAC_QUANTUM_RANDOM_NUMBER

void GetRandBytes(unsigned char* buf, int num)
{
    if (RAND_bytes(buf, num) != 1) {
        RandFailure();        
//      if(fDebug>0)LogPrintf("%s: OpenSSL RAND_bytes() failed with error: %s\n", __func__, ERR_error_string(ERR_get_error(), NULL));
//      assert(false);
    }
}


void GetStrongRandBytes(unsigned char* out, int num)
{
    assert(num <= 32);
    CSHA512 hasher;
    unsigned char buf[64];

    // First source: OpenSSL's RNG
    RandAddSeedPerfmon();
    GetRandBytes(buf, 32);
    hasher.Write(buf, 32);

    // Second source: OS RNG
    GetOSRand(buf);
    hasher.Write(buf, 32);

    // Produce output
    hasher.Finalize(buf);
    memcpy(out, buf, num);
    memory_cleanse(buf, 64);
}

#endif	// FEATURE_HDAC_QUANTUM_RANDOM_NUMBER


uint64_t GetRand(uint64_t nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64_t nRange = (std::numeric_limits<uint64_t>::max() / nMax) * nMax;
    uint64_t nRand = 0;
    do {
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand));
    } while (nRand >= nRange);
    return (nRand % nMax);
}


int GetRandInt(int nMax)
{
    return GetRand(nMax);
}


uint256 GetRandHash()
{
    uint256 hash;
    GetRandBytes((unsigned char*)&hash, sizeof(hash));
    return hash;
}


uint32_t insecure_rand_Rz = 11;
uint32_t insecure_rand_Rw = 11;

void seed_insecure_rand(bool fDeterministic)
{
    // The seed values have some unlikely fixed points which we avoid.
    if (fDeterministic) {
        insecure_rand_Rz = insecure_rand_Rw = 11;
    } else {
        uint32_t tmp;
        do {
            GetRandBytes((unsigned char*)&tmp, 4);
        } while (tmp == 0 || tmp == 0x9068ffffU);
        insecure_rand_Rz = tmp;
        do {
            GetRandBytes((unsigned char*)&tmp, 4);
        } while (tmp == 0 || tmp == 0x464fffffU);
        insecure_rand_Rw = tmp;
    }
}
