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
// 2018/01/00	Change RPC session management
// 2018/03/00   Number of rpcthreads changed 4 to 10
// 2018/07/17	asmcmd() function added (aes.h aes.c added)
// 2018/07/20   kasse-asm parameter added
//              ASM verification via root stream (key=ASM)
//              Added commands:
//                  asm
//                  asm off
//                  asm disable
//                  asm <PASSWORD> add
//                  asm <PASSWORD> remove
//                  asm <PASSWORD> <SECONDS>
//============================================================================================


#include "cust/custhdac.h"

#include "rpc/rpcserver.h"

#include "structs/base58.h"
#include "core/init.h"
#include "core/main.h"
#include "ui/ui_interface.h"
#include "utils/util.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include "json/json_spirit_writer_template.h"

#include <boost/asio/ip/tcp.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio/deadline_timer.hpp>

//#include "aes.h"


using namespace boost;
using namespace boost::asio;
using namespace json_spirit;
using namespace std;

using boost::asio::deadline_timer;
using boost::asio::ip::tcp;


static std::string strRPCUserColonPass;

static bool fRPCRunning = false;
static bool fRPCInWarmup = true;
static std::string rpcWarmupStatus("RPC server started");
static CCriticalSection cs_rpcWarmup;

//! These are created by StartRPCThreads, destroyed in StopRPCThreads
static asio::io_service* rpc_io_service = NULL;
static map<string, boost::shared_ptr<deadline_timer> > deadlineTimers;
static ssl::context* rpc_ssl_context = NULL;
static boost::thread_group* rpc_worker_group = NULL;
static boost::asio::io_service::work *rpc_dummy_work = NULL;
static std::vector<CSubNet> rpc_allow_subnets; //!< List of subnets to allow RPC connections from
static std::vector< boost::shared_ptr<ip::tcp::acceptor> > rpc_acceptors;


/* HDAC START */
class tcp_session :private boost::noncopyable, public boost::enable_shared_from_this<tcp_session>
{
public:
	tcp::socket socket_;
 	deadline_timer input_deadline_;
 	deadline_timer output_deadline_;
  	AcceptedConnection *conn;

 	tcp_session(boost::asio::io_service& io_service)
    : socket_(io_service),
      input_deadline_(io_service),
      output_deadline_(io_service)
 	{
	  input_deadline_.expires_at(boost::posix_time::pos_infin);
	  output_deadline_.expires_at(boost::posix_time::pos_infin);

 	};

	tcp::socket& socket()
	{
		return socket_;
	}

	void stop()
	{
	   boost::system::error_code ignored_ec;
	   socket_.close(ignored_ec);
	   input_deadline_.cancel();
	   output_deadline_.cancel();
	}

	bool stopped() const
	{
		return !socket_.is_open();
	}

 	 void check_deadline(deadline_timer* deadline)
	 {
	   if (stopped())
		 return;

	   // Check whether the deadline has passed. We compare the deadline against
	   // the current time since a new asynchronous operation may have moved the
	   // deadline before this actor had a chance to run.
	   if (deadline->expires_at() <= deadline_timer::traits_type::now())
	   {
		 // The deadline has passed. Stop the session. The other actors will
		 // terminate as soon as possible.
		   stop();
	   }
	   else
	   {
		 // Put the actor back to sleep.
		 deadline->async_wait(boost::bind(&tcp_session::check_deadline, this, deadline));
	   }
	 };

 	void ServiceConnection(AcceptedConnection *conn);

};


static tcp_session * tcpsession = NULL;


string JSONRPCRequestForLog(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    map<string, int>::iterator it = mapLogParamCounts.find(strMethod);
    if (it != mapLogParamCounts.end())
    {
        Array visible_params;
        if(it->second != 0)
        {
            if(strMethod == "signrawtransaction")
            {
                visible_params=params;
                if (visible_params.size() > 2 && visible_params[2].type() != null_type)
                {
                    visible_params[2]="[<PRIVATE KEYS>]";
                }
            }
        }
        request.push_back(Pair("params", visible_params));
    }
    else
    {
        request.push_back(Pair("params", params));
    }
/*
    request.push_back(Pair("id", id));
    request.push_back(Pair("chain_name", string(mc_gState->m_Params->NetworkName())));
 */
    return write_string(Value(request), false) + "\n";
}


void RPCTypeCheck(const Array& params,
                  const list<Value_type>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    BOOST_FOREACH(Value_type t, typesExpected)
    {
        if (params.size() <= i)
            break;

        const Value& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s, got %s",
                                   Value_type_name[t], Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheck(const Object& o,
                  const map<string, Value_type>& typesExpected,
                  bool fAllowNull)
{
    BOOST_FOREACH(const PAIRTYPE(string, Value_type)& t, typesExpected)
    {
        const Value& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == null_type)
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first));

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   Value_type_name[t.second], t.first, Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if(COIN == 0)
    {
        if(dAmount != 0)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");
        }
    }
    else
    {
        if (dAmount < 0.0 || dAmount > (double)MAX_MONEY/(double)COIN)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");
    }

    CAmount nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");
    return nAmount;
}

Value ValueFromAmount(const CAmount& amount)
{
    if(COIN == 0)
    {
        return (double)amount;
    }
    return (double)amount / (double)COIN;
}

uint256 ParseHashV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    if (64 != strHex.length())
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be of length %d (not %d)", strName, 64, strHex.length()));
     uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const Object& o, string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}
vector<unsigned char> ParseHexV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}
vector<unsigned char> ParseHexO(const Object& o, string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}


/**
 * Note: This interface may still be subject to change.
 */

string CRPCTable::help(string strCommand) const
{
    string strRet;
    string category;
    set<rpcfn_type> setDone;
    vector<pair<string, const CRPCCommand*> > vCommands;

    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
        vCommands.push_back(make_pair(mi->second->category + mi->first, mi->second));
    sort(vCommands.begin(), vCommands.end());

    BOOST_FOREACH(const PAIRTYPE(string, const CRPCCommand*)& command, vCommands)
    {
        const CRPCCommand *pcmd = command.second;
        string strMethod = pcmd->name;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;
        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand)
            continue;
#ifdef ENABLE_WALLET
        if (pcmd->reqWallet && !pwalletMain)
            continue;
#endif

        string strHelp="";
        map<string, string>::iterator it = mapHelpStrings.find(strMethod);
        if (it == mapHelpStrings.end())
        {
            try
            {
                Array params;
                rpcfn_type pfn = pcmd->actor;
                if (setDone.insert(pfn).second)
                    (*pfn)(params, true);
            }
            catch (std::exception& e)
            {
                strHelp = string(e.what());
            }
        }
        else
        {
            strHelp=it->second;
        }

        if(strHelp != "")
        {
            if (strCommand == "")
            {
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));

                if (category != pcmd->category)
                {
                    if (!category.empty())
                        strRet += "\n";
                    category = pcmd->category;
                    string firstLetter = category.substr(0,1);
                    boost::to_upper(firstLetter);
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n";
                }
            }
            strRet += strHelp + "\n";
        }
/*
        try
        {
            Array params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
            {
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));

                if (category != pcmd->category)
                {
                    if (!category.empty())
                        strRet += "\n";
                    category = pcmd->category;
                    string firstLetter = category.substr(0,1);
                    boost::to_upper(firstLetter);
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n";
                }
            }
            strRet += strHelp + "\n";
        }
 */
    }

    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand);
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

Value help(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error("Help message not found\n");

    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    if(strCommand.size())
    {
        if(setAllowedWhenLimited.size())
        {
            if( setAllowedWhenLimited.count(strCommand) == 0 )
            {
                throw JSONRPCError(RPC_NOT_ALLOWED, "Method not allowed with current setting of -rpcallowmethod runtime parameter");
            }
        }
    }

    return tableRPC.help(strCommand);
}


Value stop(const Array& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp || params.size() > 1)
        throw runtime_error("Help message not found\n");
    // Shutdown will take long enough that the response should get back
    StartShutdown();
    return "Hdac server stopping";
}


//
// ASM device management
//
class asmlist {
private:
    string keyhash[100];
    int keyexpire[100];
    bool keyuse[100];
    int freeidx;
    int available_asm;

public:
    asmlist() { reset(); }
    ~asmlist() { reset(); }

    void reset()
    {
        memset(keyexpire, 0, sizeof(keyexpire));
        memset(keyuse, 0, sizeof(keyuse));
        freeidx = -1;
        available_asm = 0;
    }

    int set(string hash, bool use)
    {
        int ii = 0;

        freeidx = -1;
        for (ii = 0; ii < 100; ii++)
        {
            if (keyhash[ii] == "" && freeidx == -1)
                freeidx = ii;
            if (keyhash[ii] == hash)
            {
	        LogPrintf("Kasse ASM: ASM updated. use=%d hash=%s\n", use, hash.c_str());
                keyuse[ii] = use;
                return ii;
            }
        }
        if (ii >= 100 && freeidx >= 0)
        {
	    LogPrintf("Kasse ASM: New ASM added. use=%d hash=%s\n", use, hash.c_str());
            keyhash[freeidx] = hash;
            keyuse[freeidx] = use;
            return freeidx;
        }
        return -1;
    }

    int avail()
    {
        int nuse = 0;
        for (int ii = 0; ii < 100; ii++)
        {
            if (keyuse[ii])
                nuse++;
        }
        available_asm = nuse;

        return available_asm;
    }

    int check(string hash)
    {
        for (int ii = 0; ii < 100; ii++)
        {
            if (keyhash[ii] == hash && keyuse[ii] == true)
                return 1;
        }
        return 0;
    }
};

asmlist _asmmap;
time_t	_asm_timeout = 0;


//
// asm			 => display remaining seconds
// asm off / asm disable => disable admin mode
// asm history
// asm PASSWORD add	 => Add current ASM module hash
// asm PASSWORD remove	 => Rmove current ASM module hash
// asm PASSWORD SECONDS	 => Check ASM validity
//
Value asmcmd(const Array& params, bool fHelp)
{
    int	add_hash = 0, remove_hash = 0, history = 0;
    char tmp[200];


    // Command: asm 
    if (params.size() == 0 && _asm_timeout > time(NULL))
    {
        sprintf(tmp, "%ld", _asm_timeout - time(NULL));
	string msg = tmp;
	return msg;
    }

    // Command: asm off / asm disable
    if (params.size() == 1)
    {
        string strCmd = params[0].get_str();
	if (strCmd == "off" || strCmd == "disable")
	{
	    _asm_timeout = 0;
	    LogPrintf("Kasse ASM: disabled!\n");
            return "ASM disabled";
	}
	else if (strCmd == "history")
	{
	    history = 1;
	}
    }

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "asm off\n"
            "asm disable\n"
            "asm \"passphrase\" add\n"
            "asm \"passphrase\" remove\n"
            "asm \"passphrase\" timeout\n"
            "\nEnables admin mode for 'timeout' seconds.\n"
            "Hdac Kasse ASM hardware module required (Not a Kasse hardware wallet)\n"
            "Hdac Kasse ASM module was developed for Hdac Private Blockchain Admin mode security enhancement\n"
            "This is needed prior to performing transactions related to private keys such as sending assets\n"
            "\nArguments:\n"
            "1. off or diable      (string, required) Disable ASM enabled admin mode\n"
            "1. \"passphrase\"       (string, required) The ASM key encryption passphrase\n"
            "2. timeout            (numeric, required) The time to keep the ASM key in seconds.\n"
            "2. add                (string, required) Add current ASM key from the root stream\n"
            "2. remove             (string, required) Remove current ASM key from the root stream\n"
            "\nExamples:\n"
            "\nunlock the admin mode for 60 seconds\n"
            + HelpExampleCli("asm", "\"my pass phrase\" 60\n")
        );

    if (fHelp)
        return true;


    string strDataDir = GetDataDir().string();

    // ASM check request...
    string reqfile = strDataDir + "/hdac-asm.req";
    FILE *reqfp = fopen(reqfile.c_str(), "wb");
    if (reqfp)
    	fclose(reqfp);

    sleep(4);

    // Alternately, find a way to make params[0] mlock()'d to begin with.
    string strPass = params[0].get_str();

    if (strPass.length() <= 0)
    {
        throw runtime_error(
            "asm <passphrase> <timeout>\n"
            "Enables admin mode for <timeout> seconds.");
    }

    int nSleepTime = 0;
    if (params.size() >= 2)
    {
	string strCmd = params[1].get_str();
	if (atoi(strCmd.c_str()) > 0)
	    nSleepTime = atoi(strCmd.c_str());
	else 
	{
	    string strCmd = params[1].get_str();
	    if (strCmd == "add")
	        add_hash = 1;
	    else if (strCmd == "remove")
	        remove_hash = 1;
	}
    }
    

    // load key hashes: root ASM 
    Array list_params(4);
    list_params[0] = "root";
    list_params[1] = "ASM";
    list_params[2] = false;
    list_params[3] = 100;

    Value asmlist = liststreamkeyitems(list_params, false);

    Array& asms = asmlist.get_array();
    for (int ii = 0; ii < (int)asms.size(); ii++)
    {
        const Object obj = asms[ii].get_obj();
	const Value& val = find_value(obj, "data");
	if (val.type() == str_type)
	{
	    // 1111hash => use
	    // 0000hash => not use
	    string hash = val.get_str();
	    if (hash.substr(0, 4) == "0000")
	    {
		if (history)
	    	    printf("Removed: %s\n", hash.substr(4).c_str());
		_asmmap.set(hash.substr(4).c_str(), false);
	    }
	    else if (hash.substr(0, 4) == "1111")
	    {
		if (history)
	    	    printf("Added:   %s\n", hash.substr(4).c_str());
		_asmmap.set(hash.substr(4).c_str(), true);
	    }
	}
    }

    if (history)
    	return "";

    uint8_t    passwdhash[32] = {0};
    uint8_t    key256[32] = {0}, keyhash[32] = {0};
    uint8_t    iv[16] = {0,0,0, 6,6,1,2,2,0, 0xFF, 6,6,1,2,2,0};
    char       buf[256] = {0};
    time_t     curtime = 0;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, strPass.c_str(), strPass.length());
    SHA256_Final(passwdhash, &ctx);

    memcpy(key256, passwdhash, 32);
    memcpy(iv, strPass.c_str(), strPass.length());


    // Load ASM output
    string infile = strDataDir + "/hdac-asm.out";
    
    FILE *infp = fopen(infile.c_str(), "rb");
    if (infp == NULL)
    {
        _asm_timeout = 0;
        string msg = "ERROR: Cannot open ASM data file " + infile + "\n";
	LogPrintf("Kasse ASM: %s", msg.c_str());
        throw runtime_error(msg);
    }

    uint8_t outbuf[256] = {0};
    char    id[16] = {0};
    uint8_t privkey[32] = {0};

    if (fgets(buf, sizeof(buf), infp))
    {
        if (buf[strlen(buf)-1] == '\n')
            buf[strlen(buf)-1] = 0;

        if (fDebug>1)LogPrintf("READ=%s\n", buf);

        int len = strlen(buf);
        if (len < 128)
	{
	    _asm_timeout = 0;
	    LogPrintf("Kasse ASM: ERROR: ASM data incorrect!\n");
            throw runtime_error("ERROR: ASM data incorrect!\n");
	}

	// decryption
        mc_HexToBin(outbuf, buf, strlen(buf));

        memcpy(&curtime, &outbuf[0], sizeof(curtime));
        memcpy(id, &outbuf[16], 16);
        memcpy(privkey, &outbuf[32], 32);

        if (strncmp(id, "Hdac ASM", 8) != 0)
	{
	    _asm_timeout = 0;
	    LogPrintf("Kasse ASM: ERROR: ASM password incorrect!\n");
            throw runtime_error("ERROR: ASM password incorrect!\n");
	}

        if (time(NULL) - curtime > 60)
	{
	    _asm_timeout = 0;
	    LogPrintf("Kasse ASM: ERROR: ASM timestamp expired!\n");
            throw runtime_error("ERROR: ASM timestamp expired!\n");
	}

        uint8_t tmp[64] = {0}, calckeyhash[32] = {0};
        memcpy(tmp, privkey, 32);

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, privkey, 32);
        SHA256_Final(&tmp[32], &ctx);

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, tmp, 64);	// hash: privkey(32) + privkey hash(32)
        SHA256_Final(calckeyhash, &ctx);

        if (fDebug>1)LogPrintf("Kasse ASM: Verification OK! Id=%s: Admin mode enabled for %d seconds\n", id, nSleepTime);

        /*****
        printf("\nPrivate Key: ");
        for (int ii = 0; ii < 32; ii++)
            printf("%02X", privkey[ii]);
        printf("\n");
        *****/

	if (nSleepTime > 0)
	    _asm_timeout = time(NULL) + nSleepTime;

	// Initial setup: publish root ASM HASH
	if (add_hash || remove_hash)
	{
		char    hexstr[100] = {0};

		Array pub_params(3);
		pub_params[0] = "root";
		pub_params[1] = "ASM";
		memset(hexstr, 0, sizeof(hexstr));
		mc_BinToHex(&hexstr[4], calckeyhash, 32);
		if (remove_hash)
		{
			hexstr[0] = '0';
			hexstr[1] = '0';
			hexstr[2] = '0';
			hexstr[3] = '0';
			LogPrintf("Kasse ASM: Remove hash %s\n", &hexstr[4]);
		}
		else	// add_hash or initial setup
		{
			hexstr[0] = '1';
			hexstr[1] = '1';
			hexstr[2] = '1';
			hexstr[3] = '1';
			LogPrintf("Kasse ASM: Add hash %s\n", &hexstr[4]);
		}
		pub_params[2] = hexstr;

		Value ret = publish(pub_params, false);
		if (ret == Value::null)
		{
			LogPrintf("ERRPR: ASM hash registration to the root stream failed!\n");
			throw runtime_error("ERRPR: ASM hash registration to the root stream failed!\n");
		}
		else
		{
		    _asmmap.set(&hexstr[4], remove_hash ? false : true);
		}
	}

	memset(tmp, 0, sizeof(tmp));
	mc_BinToHex(tmp, calckeyhash, 32);

	if (!_asmmap.check((char *)tmp))
	{
	    _asm_timeout = 0;
	    LogPrintf("Kasse ASM: ERROR: ASM key hash not matched!\n");
            throw runtime_error("ERROR: ASM key hash not matched!\n");
	}
    }

    fclose(infp);

    // bzero(buf, sizeof(buf));
    memset(buf, 0x00, sizeof(buf));
    if (add_hash)
        sprintf(buf, "Current ASM key added to the root stream for authentication");
    else if (remove_hash)
    {
	_asm_timeout = 0;
        sprintf(buf, "Current ASM key removed to the root stream for authentication");
    }
    else 
        sprintf(buf, "ASM enabled for %d seconds", nSleepTime);
    string msg = buf;
    LogPrintf("Kasse ASM: %s\n", buf);

    return msg;
}


string AllowedPausedServices()
{
    string ret="incoming,mining";

    return ret;
}


uint32_t GetPausedServices(const char *str)
{
    uint32_t result,type;
    char* ptr;
    char* start;
    char* ptrEnd;
    char c;

    ptr=(char*)str;
    ptrEnd=ptr+strlen(ptr);
    start=ptr;

    result=0;

    while(ptr<=ptrEnd)
    {
        c=*ptr;
        if( (c == ',') || (c ==0x00))
        {
            if(ptr > start)
            {
                type=0;
                if(memcmp(start,"incoming",  ptr-start) == 0)type = MC_NPS_INCOMING;
                if(memcmp(start,"mining",    ptr-start) == 0)type = MC_NPS_MINING;
                if(memcmp(start,"reaccepting", ptr-start) == 0)type = MC_NPS_REACCEPT;

                if(type == 0)
                {
                    return 0;
                }
                result |= type;
                start=ptr+1;
            }
        }
        ptr++;
    }

    return  result;
}


Value pausecmd(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error("Help message not found\n");

    uint32_t type=0;
    if (params.size() > 0 && params[0].type() != null_type && !params[0].get_str().empty())
    {
        type=GetPausedServices(params[0].get_str().c_str());
    }

    if(type == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid task");

    LOCK(cs_main);

    mc_gState->m_NodePausedState |= type;

    if(fDebug>1)LogPrintf("Node paused state is set to %08X\n",mc_gState->m_NodePausedState);

    return "Paused";
}

Value resumecmd(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error("Help message not found\n");

    uint32_t type=0;
    if (params.size() > 0 && params[0].type() != null_type && !params[0].get_str().empty())
    {
        type=GetPausedServices(params[0].get_str().c_str());
    }

    if(type == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid task");

    LOCK(cs_main);

    mc_gState->m_NodePausedState &= (MC_NPS_ALL ^ type);

    if( type & MC_NPS_REACCEPT )
    {
        pwalletMain->ReacceptWalletTransactions();
    }

    if(fDebug>1)LogPrintf("Node paused state is set to %08X\n",mc_gState->m_NodePausedState);

    return "Resumed";
}

CRPCTable::CRPCTable()
{
}

void CRPCTable::initialize()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < vStaticRPCCommands.size(); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vStaticRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
    for (vcidx = 0; vcidx < vStaticRPCWalletReadCommands.size(); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vStaticRPCWalletReadCommands[vcidx];
        mapWalletReadCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](string name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}


bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0,6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    string strUserPass = DecodeBase64(strUserPass64);
    return TimingResistantEqual(strUserPass, strRPCUserColonPass);
}

void ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();
    if (code == RPC_INVALID_REQUEST) nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND) nStatus = HTTP_NOT_FOUND;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply, false) << std::flush;
}

CNetAddr BoostAsioToCNetAddr(boost::asio::ip::address address)
{
    CNetAddr netaddr;
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
    if (address.is_v6()
     && (address.to_v6().is_v4_compatible()
      || address.to_v6().is_v4_mapped()))
        address = address.to_v6().to_v4();

    if(address.is_v4())
    {
        boost::asio::ip::address_v4::bytes_type bytes = address.to_v4().to_bytes();
        netaddr.SetRaw(NET_IPV4, &bytes[0]);
    }
    else
    {
        boost::asio::ip::address_v6::bytes_type bytes = address.to_v6().to_bytes();
        netaddr.SetRaw(NET_IPV6, &bytes[0]);
    }
    return netaddr;
}

bool ClientAllowed(const boost::asio::ip::address& address)
{
    CNetAddr netaddr = BoostAsioToCNetAddr(address);
    BOOST_FOREACH(const CSubNet &subnet, rpc_allow_subnets)
        if (subnet.Match(netaddr))
            return true;
    return false;
}

template <typename Protocol>
class AcceptedConnectionImpl : public AcceptedConnection
{
public:
    AcceptedConnectionImpl(
            asio::io_service& io_service,
            ssl::context &context,
            bool fUseSSL) :
        sslStream(io_service, context),
        _d(sslStream, fUseSSL),
        _stream(_d)
    {
    }

    virtual std::iostream& stream()
    {
        return _stream;
    }

    virtual std::string peer_address_to_string() const
    {
        return peer.address().to_string();
    }

    virtual void close()
    {
        _stream.close();
    }

    typename Protocol::endpoint peer;
    asio::ssl::stream<typename Protocol::socket> sslStream;

private:
    SSLIOStreamDevice<Protocol> _d;
    iostreams::stream< SSLIOStreamDevice<Protocol> > _stream;
};


//! Forward declaration required for RPCListen
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             bool fUseSSL,
                             boost::shared_ptr< AcceptedConnection > conn,
                             const boost::system::error_code& error);

/**
 * Sets up I/O resources to accept and handle a new connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCListen(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                   ssl::context& context,
                   const bool fUseSSL)
{
    // Accept connection
    boost::shared_ptr< AcceptedConnectionImpl<Protocol> > conn(new AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL));

    acceptor->async_accept(
            conn->sslStream.lowest_layer(),
            conn->peer,
            boost::bind(&RPCAcceptHandler<Protocol, SocketAcceptorService>,
                acceptor,
                boost::ref(context),
                fUseSSL,
                conn,
                _1));
}


/**
 * Accept and handle incoming connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             const bool fUseSSL,
                             boost::shared_ptr< AcceptedConnection > conn,
                             const boost::system::error_code& error)
{
    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != asio::error::operation_aborted && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL);

    AcceptedConnectionImpl<ip::tcp>* tcp_conn = dynamic_cast< AcceptedConnectionImpl<ip::tcp>* >(conn.get());

    if (error)
    {
        // TODO: Actually handle errors
        if(fDebug>4)LogPrintf("%s: Error: %s\n", __func__, error.message());
    }
    // Restrict callers by IP.  It is important to
    // do this before starting client thread, to filter out
    // certain DoS and misbehaving clients.
    else if (tcp_conn && !ClientAllowed(tcp_conn->peer.address()))
    {
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (!fUseSSL)
            conn->stream() << HTTPError(HTTP_FORBIDDEN, false) << std::flush;
        conn->close();
        tcpsession->stop();
    }
    else {
    	tcpsession->conn = conn.get();
        tcpsession->ServiceConnection(conn.get());
        conn->close();
        tcpsession->stop();
    }
}

static ip::tcp::endpoint ParseEndpoint(const std::string &strEndpoint, int defaultPort)
{
    std::string addr;
    int port = defaultPort;
    SplitHostPort(strEndpoint, port, addr);
    return ip::tcp::endpoint(asio::ip::address::from_string(addr), port);
}

void mc_InitRPCListIfLimited()
{
    if (mapArgs.count("-rpcallowmethod"))
    {
        setAllowedWhenLimited.insert("help");
        BOOST_FOREACH(const std::string& methods, mapMultiArgs["-rpcallowmethod"])
        {
            stringstream ss(methods);
            string tok;
            while(getline(ss, tok, ','))
            {
                setAllowedWhenLimited.insert(tok);
            }
        }
    }
}


void StartRPCThreads()
{
    mc_InitRPCList(vStaticRPCCommands,vStaticRPCWalletReadCommands);
    mc_InitRPCListIfLimited();
    tableRPC.initialize();

    rpc_allow_subnets.clear();
    rpc_allow_subnets.push_back(CSubNet("127.0.0.0/8")); // always allow IPv4 local subnet
    rpc_allow_subnets.push_back(CSubNet("::1")); // always allow IPv6 localhost
    if (mapMultiArgs.count("-rpcallowip"))
    {
        const vector<string>& vAllow = mapMultiArgs["-rpcallowip"];
        BOOST_FOREACH(string strAllow, vAllow)
        {
            CSubNet subnet(strAllow);
            if(!subnet.IsValid())
            {
                uiInterface.ThreadSafeMessageBox(
                    strprintf("Invalid -rpcallowip subnet specification: %s. Valid are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24).", strAllow),
                    "", CClientUIInterface::MSG_ERROR);
                StartShutdown();
                return;
            }
            rpc_allow_subnets.push_back(subnet);
        }
    }
    std::string strAllowed;
    BOOST_FOREACH(const CSubNet &subnet, rpc_allow_subnets)
        strAllowed += subnet.ToString() + " ";
    if(fDebug>4)LogPrint("rpc", "Allowing RPC connections from: %s\n", strAllowed);

    strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    if (((mapArgs["-rpcpassword"] == "") ||
         (mapArgs["-rpcuser"] == mapArgs["-rpcpassword"])) && Params().RequireRPCPassword())
    {
        unsigned char rand_pwd[32];
        GetRandBytes(rand_pwd, 32);

        uiInterface.ThreadSafeMessageBox(strprintf(
            _("To use hdacd, you must set an rpcpassword in the configuration file:\n"
              "%s\n"
              "It is recommended you use the following random password:\n"
              "rpcuser=hdacrpc\n"
              "rpcpassword=%s\n"
              "(you do not need to remember this password)\n"
              "The username and password MUST NOT be the same.\n"
              "If the file does not exist, create it with owner-readable-only file permissions.\n"
              "It is also recommended to set alertnotify so you are notified of problems;\n"
              "for example: alertnotify=echo %%s | mail -s \"Hdac Alert\" admin@foo.com\n"),
                GetConfigFile().string(),
                EncodeBase58(&rand_pwd[0],&rand_pwd[0]+32)),
                "", CClientUIInterface::MSG_ERROR | CClientUIInterface::SECURE);

        StartShutdown();
        return;
    }

    assert(rpc_io_service == NULL);
    rpc_io_service = new asio::io_service();
    rpc_ssl_context = new ssl::context(*rpc_io_service, ssl::context::sslv23);

    tcpsession = new tcp_session(*rpc_io_service);

    const bool fUseSSL = GetBoolArg("-rpcssl", false);

    if (fUseSSL)
    {
        rpc_ssl_context->set_options(ssl::context::no_sslv2 | ssl::context::no_sslv3);

        filesystem::path pathCertFile(GetArg("-rpcsslcertificatechainfile", "server.cert"));
        if (!pathCertFile.is_complete()) pathCertFile = filesystem::path(GetDataDir()) / pathCertFile;
        if (filesystem::exists(pathCertFile)) rpc_ssl_context->use_certificate_chain_file(pathCertFile.string());
        else 
        {
            if(fDebug>4)LogPrintf("ThreadRPCServer ERROR: missing server certificate file %s\n", pathCertFile.string());
	}

        filesystem::path pathPKFile(GetArg("-rpcsslprivatekeyfile", "server.pem"));
        if (!pathPKFile.is_complete()) pathPKFile = filesystem::path(GetDataDir()) / pathPKFile;
        if (filesystem::exists(pathPKFile)) rpc_ssl_context->use_private_key_file(pathPKFile.string(), ssl::context::pem);
        else 
        {
            if(fDebug>4)LogPrintf("ThreadRPCServer ERROR: missing server private key file %s\n", pathPKFile.string());
	}

        string strCiphers = GetArg("-rpcsslciphers", "TLSv1.2+HIGH:TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!3DES:@STRENGTH");
        SSL_CTX_set_cipher_list(rpc_ssl_context->impl(), strCiphers.c_str());
    }

    std::vector<ip::tcp::endpoint> vEndpoints;
    bool bBindAny = false;
    int defaultPort = GetArg("-rpcport", BaseParams().RPCPort());
    if (!mapArgs.count("-rpcallowip")) // Default to loopback if not allowing external IPs
    {
        vEndpoints.push_back(ip::tcp::endpoint(asio::ip::address_v6::loopback(), defaultPort));
        vEndpoints.push_back(ip::tcp::endpoint(asio::ip::address_v4::loopback(), defaultPort));
        if (mapArgs.count("-rpcbind"))
        {
            if(fDebug>4)LogPrintf("WARNING: option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect\n");
        }
    } else if (mapArgs.count("-rpcbind")) // Specific bind address
    {
        BOOST_FOREACH(const std::string &addr, mapMultiArgs["-rpcbind"])
        {
            try {
                vEndpoints.push_back(ParseEndpoint(addr, defaultPort));
            }
            catch(const boost::system::system_error &)
            {
                uiInterface.ThreadSafeMessageBox(
                    strprintf(_("Could not parse -rpcbind value %s as network address"), addr),
                    "", CClientUIInterface::MSG_ERROR);
                StartShutdown();
                return;
            }
        }
    } else { // No specific bind address specified, bind to any
        vEndpoints.push_back(ip::tcp::endpoint(asio::ip::address_v6::any(), defaultPort));
        vEndpoints.push_back(ip::tcp::endpoint(asio::ip::address_v4::any(), defaultPort));
        // Prefer making the socket dual IPv6/IPv4 instead of binding
        // to both addresses seperately.
        bBindAny = true;
    }

    bool fListening = false;
    std::string strerr;
    std::string straddress;
    BOOST_FOREACH(const ip::tcp::endpoint &endpoint, vEndpoints)
    {
        try {
            asio::ip::address bindAddress = endpoint.address();
            straddress = bindAddress.to_string();
            if(fDebug>4)LogPrintf("Binding RPC on address %s port %i (IPv4+IPv6 bind any: %i)\n", straddress, endpoint.port(), bBindAny);
            boost::system::error_code v6_only_error;
            boost::shared_ptr<ip::tcp::acceptor> acceptor(new ip::tcp::acceptor(*rpc_io_service));

            acceptor->open(endpoint.protocol());
            acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

            // Try making the socket dual IPv6/IPv4 when listening on the IPv6 "any" address
            acceptor->set_option(boost::asio::ip::v6_only(
                !bBindAny || bindAddress != asio::ip::address_v6::any()), v6_only_error);

            acceptor->bind(endpoint);
            acceptor->listen(socket_base::max_connections);

            RPCListen(acceptor, *rpc_ssl_context, fUseSSL);

            fListening = true;
            rpc_acceptors.push_back(acceptor);
            // If dual IPv6/IPv4 bind successful, skip binding to IPv4 separately
            if(bBindAny && bindAddress == asio::ip::address_v6::any() && !v6_only_error)
                break;
        }
        catch(boost::system::system_error &e)
        {
            if(fDebug>4)LogPrintf("ERROR: Binding RPC on address %s port %i failed: %s\n", straddress, endpoint.port(), e.what());
            strerr = strprintf(_("An error occurred while setting up the RPC address %s port %u for listening: %s"), straddress, endpoint.port(), e.what());
        }
    }

    if (!fListening) {
        uiInterface.ThreadSafeMessageBox(strerr, "", CClientUIInterface::MSG_ERROR);
        StartShutdown();
        return;
    }

    rpc_worker_group = new boost::thread_group();

#ifdef FEATURE_HPAY_MAX_NUM_RPC_THREAD
    for (int i = 0; i < GetArg("-rpcthreads", MAX_RPC_THREAD); i++)
#else
    for (int i = 0; i < GetArg("-rpcthreads", 10); i++)
#endif	// FEATURE_HPAY_MAX_NUM_RPC_THREAD
    {
        rpc_worker_group->create_thread(boost::bind(&asio::io_service::run, rpc_io_service));
    }

    fRPCRunning = true;
}

void StartDummyRPCThread()
{
    if(rpc_io_service == NULL)
    {
        rpc_io_service = new asio::io_service();
        /* Create dummy "work" to keep the thread from exiting when no timeouts active,
         * see http://www.boost.org/doc/libs/1_51_0/doc/html/boost_asio/reference/io_service.html#boost_asio.reference.io_service.stopping_the_io_service_from_running_out_of_work */
        rpc_dummy_work = new asio::io_service::work(*rpc_io_service);
        rpc_worker_group = new boost::thread_group();
        rpc_worker_group->create_thread(boost::bind(&asio::io_service::run, rpc_io_service));
        fRPCRunning = true;
    }
}

void StopRPCThreads()
{
    if (rpc_io_service == NULL) return;
    // Set this to false first, so that longpolling loops will exit when woken up
    fRPCRunning = false;

    // First, cancel all timers and acceptors
    // This is not done automatically by ->stop(), and in some cases the destructor of
    // asio::io_service can hang if this is skipped.
    boost::system::error_code ec;
    BOOST_FOREACH(const boost::shared_ptr<ip::tcp::acceptor> &acceptor, rpc_acceptors)
    {
        acceptor->cancel(ec);
        if (ec)
            if(fDebug>4)LogPrintf("%s: Warning: %s when cancelling acceptor", __func__, ec.message());
    }
    rpc_acceptors.clear();
    BOOST_FOREACH(const PAIRTYPE(std::string, boost::shared_ptr<deadline_timer>) &timer, deadlineTimers)
    {
        timer.second->cancel(ec);
        if (ec)
            if(fDebug>4)LogPrintf("%s: Warning: %s when cancelling timer", __func__, ec.message());
    }
    deadlineTimers.clear();

    rpc_io_service->stop();
    cvBlockChange.notify_all();
    if (rpc_worker_group != NULL)
        rpc_worker_group->join_all();
    delete rpc_dummy_work; rpc_dummy_work = NULL;
    delete rpc_worker_group; rpc_worker_group = NULL;
    delete rpc_ssl_context; rpc_ssl_context = NULL;
    delete rpc_io_service; rpc_io_service = NULL;
}

bool IsRPCRunning()
{
    return fRPCRunning;
}

void SetRPCWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus;
}

void SetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

bool RPCIsInWarmup(std::string *outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

void RPCRunHandler(const boost::system::error_code& err, boost::function<void(void)> func)
{
    if (!err)
        func();
}

void RPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds)
{
    assert(rpc_io_service != NULL);

    if (deadlineTimers.count(name) == 0)
    {
        deadlineTimers.insert(make_pair(name,
                                        boost::shared_ptr<deadline_timer>(new deadline_timer(*rpc_io_service))));
    }
    deadlineTimers[name]->expires_from_now(posix_time::seconds(nSeconds));
    deadlineTimers[name]->async_wait(boost::bind(RPCRunHandler, _1, func));
}

class JSONRequest
{
public:
    Value id;
    string strMethod;
    Array params;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
};

void JSONRequest::parse(const Value& valRequest)
{
    // Parse request
    if (valRequest.type() != obj_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const Object& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    Value valMethod = find_value(request, "method");
    if (valMethod.type() == null_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (valMethod.type() != str_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");

    // command name
    strMethod = valMethod.get_str();
    if (strMethod != "getblocktemplate")
        if(fDebug>4)LogPrint("rpc", "ThreadRPCServer method=%s\n", SanitizeString(strMethod));

    // Hdac ASM security mode			// Hdac LJM 180720
    if (HDAC_KASSE_ASM > 0)
    {
        if (_asm_timeout <= 0 || (_asm_timeout - time(NULL)) <= 0)	// restrict command set
	{
	    if ((strMethod.substr(0, 3) == "get" && strMethod.substr(0, 6) != "getnew") ||
	        strMethod.substr(0, 4) == "list" || strMethod.substr(0, 4) == "help" ||
	        strMethod.substr(0, 3) == "asm" || strMethod.substr(0, 6) == "decode")
	    {
	        // Allow read only commands 
	    }
	    else
	    {
		LogPrintf("Kasse ASM not enabled: %s command rejected!\n", strMethod.c_str());
	        throw JSONRPCError(RPC_INVALID_REQUEST, "Kasse ASM not enabled! (Use 'asm PASSWORD add' command first)");
	    }
	}
    }

    Value valChainName = find_value(request, "chain_name");
    if (valChainName.type() != null_type)
    {
        if (valChainName.type() != str_type)
            throw JSONRPCError(RPC_INVALID_REQUEST, "Chain name must be a string");
        if (strcmp(valChainName.get_str().c_str(),mc_gState->m_Params->NetworkName()))
            throw JSONRPCError(RPC_INVALID_REQUEST, "Wrong chain name");
    }

    // Parse params
    Value valParams = find_value(request, "params");
    if (valParams.type() == array_type)
        params = valParams.get_array();
    else if (valParams.type() == null_type)
        params = Array();
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}


static Object JSONRPCExecOne(const Value& req)
{
    Object rpc_result;

    JSONRequest jreq;
    uint32_t wallet_mode=mc_gState->m_WalletMode;

    try {
        jreq.parse(req);

        Value result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, Value::null, jreq.id);
    }
    catch (Object& objError)
    {
        mc_gState->m_WalletMode=wallet_mode;
        if(fDebug>2)LogPrint("api","API request failure A\n");
        rpc_result = JSONRPCReplyObj(Value::null, objError, jreq.id);
    }
    catch (std::exception& e)
    {
        mc_gState->m_WalletMode=wallet_mode;
        if(fDebug>2)LogPrint("api","API request failure B\n");

        rpc_result = JSONRPCReplyObj(Value::null,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

static string JSONRPCExecBatch(const Array& vReq)
{
    Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return write_string(Value(ret), false) + "\n";
}

static bool HTTPReq_JSONRPC(AcceptedConnection *conn,
                            string& strRequest,
                            map<string, string>& mapHeaders,
                            bool fRun)
{
    // Check authorization
    if (mapHeaders.count("authorization") == 0)
    {
        conn->stream() << HTTPError(HTTP_UNAUTHORIZED, false) << std::flush;
        return false;
    }

    if (!HTTPAuthorized(mapHeaders))
    {
        if(fDebug>4)LogPrintf("ThreadRPCServer incorrect password attempt from %s\n", conn->peer_address_to_string());
        /* Deter brute-forcing
           If this results in a DoS the user really
           shouldn't have their RPC port exposed. */
        MilliSleep(250);

        conn->stream() << HTTPError(HTTP_UNAUTHORIZED, false) << std::flush;
        return false;
    }

    JSONRequest jreq;
    uint32_t wallet_mode=mc_gState->m_WalletMode;
    if(fDebug>1)LogPrint("api","API request from %s\n",conn->peer_address_to_string().c_str());

    try
    {
        // Parse request
        Value valRequest;
        if (!read_string(strRequest, valRequest))
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

        // Return immediately if in warmup
        {
            LOCK(cs_rpcWarmup);
            if (fRPCInWarmup)
                throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
        }

        string strReply;

        // singleton request
        if (valRequest.type() == obj_type) {
            jreq.parse(valRequest);

            Value result = tableRPC.execute(jreq.strMethod, jreq.params);

            // Send reply
            strReply = JSONRPCReply(result, Value::null, jreq.id);

        // array of requests
        } else if (valRequest.type() == array_type)
            strReply = JSONRPCExecBatch(valRequest.get_array());
        else
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

        conn->stream() << HTTPReplyHeader(HTTP_OK, fRun, strReply.size()) << strReply << std::flush;
    }
    catch (Object& objError)
    {
        mc_gState->m_WalletMode=wallet_mode;
        if(fDebug>2)LogPrint("api","API request failure: %s, code: %d\n",jreq.strMethod.c_str(),find_value(objError, "code").get_int());

        ErrorReply(conn->stream(), objError, jreq.id);
        return false;
    }
    catch (std::exception& e)
    {
        mc_gState->m_WalletMode=wallet_mode;
        if(fDebug>2)LogPrint("api","API request failure D\n");

        ErrorReply(conn->stream(), JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        return false;
    }
    return true;
}


void tcp_session::ServiceConnection(AcceptedConnection *conn)
{
    bool fRun = true;

    while (fRun && !ShutdownRequested())
    {
        int nProto = 0;
        map<string, string> mapHeaders;
        string strRequest, strMethod, strURI;

        // Read HTTP request line
        if (!ReadHTTPRequestLine(conn->stream(), nProto, strMethod, strURI))
            break;

        // Read HTTP message headers and body
        ReadHTTPMessage(conn->stream(), mapHeaders, strRequest, nProto, MAX_SIZE);

        /* HDAC START */
        input_deadline_.expires_from_now(boost::posix_time::seconds(DEFAULT_RPC_HTTP_SERVER_TIMEOUT));

        input_deadline_.async_wait(
            boost::bind(&tcp_session::check_deadline,
            		this, &input_deadline_));
        /* HDAC END */

        // HTTP Keep-Alive is false; close connection immediately
        if ((mapHeaders["connection"] == "close") || (!GetBoolArg("-rpckeepalive", false)))
            fRun = false;

        // Process via JSON-RPC API
        if (strURI == "/") {
            //if (!HTTPReq_JSONRPC(conn, strRequest, mapHeaders, fRun))
        		/* HDAC START */
                bool ret = HTTPReq_JSONRPC(conn, strRequest, mapHeaders, fRun);
                {
               	    output_deadline_.expires_from_now(boost::posix_time::seconds(DEFAULT_RPC_HTTP_SERVER_TIMEOUT));
                    output_deadline_.async_wait(
                        boost::bind(&tcp_session::check_deadline,
                        this, &output_deadline_));
                }
                if(!ret)
                break;
               /* HDAC END */


        // Process via HTTP REST API
        } else if (strURI.substr(0, 6) == "/rest/" && GetBoolArg("-rest", false)) {
            //if (!HTTPReq_REST(conn, strURI, mapHeaders, fRun))
        	/* HDAC START */
            bool ret = HTTPReq_REST(conn, strURI, mapHeaders, fRun);
            {
           	output_deadline_.expires_from_now(boost::posix_time::seconds(DEFAULT_RPC_HTTP_SERVER_TIMEOUT));
           	output_deadline_.async_wait(
                boost::bind(&tcp_session::check_deadline,
                this, &output_deadline_));
            }
           if(!ret)
                break;
           /* HDAC END */

        } else {
            conn->stream() << HTTPError(HTTP_NOT_FOUND, false) << std::flush;
            break;
        }
    }
}


json_spirit::Value CRPCTable::execute(const std::string &strMethod, const json_spirit::Array &params) const
{
    // Find method
    const CRPCCommand *pcmd = tableRPC[strMethod];
    if (!pcmd)
    {
        if( ((mc_gState->m_SessionFlags & MC_SSF_COLD) == 0) || (mapHelpStrings.count(strMethod) == 0) )
        {
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");
        }
        else
        {
            throw JSONRPCError(RPC_NOT_SUPPORTED, "Method not available in cold version of Hdac");
        }
    }
#ifdef ENABLE_WALLET
    if (pcmd->reqWallet && !pwalletMain)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
#endif

#if 0
    if(mc_gState->m_ProtocolVersionToUpgrade > mc_gState->m_NetworkParams->ProtocolVersion())
    {
        if( setAllowedWhenWaitingForUpgrade.count(strMethod) == 0 )
        {
            throw JSONRPCError(RPC_UPGRADE_REQUIRED, strprintf("BlockChain was upgraded to protocol version %d, please upgrade Hdac",mc_gState->m_ProtocolVersionToUpgrade));
        }
    }
#endif

    if(GetBoolArg("-offline",false))
    {
        if( setAllowedWhenOffline.count(strMethod) == 0 )
        {
            throw JSONRPCError(RPC_NOT_SUPPORTED, "Method not available with -offline runtime parameter");
        }
    }

    if(setAllowedWhenLimited.size())
    {
        if( setAllowedWhenLimited.count(strMethod) == 0 )
        {
            throw JSONRPCError(RPC_NOT_ALLOWED, "Method not allowed with current setting of -rpcallowmethod runtime parameter");
        }
    }

    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode", false) &&
        !pcmd->okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);

    try
    {
        // Execute
        if(fDebug>0)
        {
            string strRequest = JSONRPCRequestForLog(strMethod, params, 1);
            LogPrint("api","API request: %s\n",strRequest.c_str());
        }

        Value result;
        {
            if (pcmd->threadSafe)
                result = pcmd->actor(params, false);
#ifdef ENABLE_WALLET
            else if (!pwalletMain) {
                LOCK(cs_main);
                result = pcmd->actor(params, false);
            } else {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                uint32_t wallet_mode=mc_gState->m_WalletMode;
                string strResultNone;
                string strResult;
                if(LogAcceptCategory("walletcompare"))
                {
                    if(wallet_mode & MC_WMD_MAP_TXS)
                    {
                        if(mapWalletReadCommands.count(strMethod))
                        {
                            mc_gState->m_WalletMode=MC_WMD_NONE;
                            result = pcmd->actor(params, false);
                            strResultNone=JSONRPCReply(result, Value::null, 1);
                            mc_gState->m_WalletMode=wallet_mode;
                        }
                    }
                }
                result = pcmd->actor(params, false);

                if(LogAcceptCategory("walletcompare"))
                {
                    if(wallet_mode & MC_WMD_MAP_TXS)
                    {
                        if(mapWalletReadCommands.count(strMethod))
                        {
                            strResult=JSONRPCReply(result, Value::null, 1);
                            if(strcmp(strResultNone.c_str(),strResult.c_str()))
                            {
                                string strRequestBad = JSONRPCRequestForLog(strMethod, params, 1);
                                if(fDebug>4)LogPrint("walletcompare","walletcompare: ERROR: Result mismatch on API request: %s\n",strRequestBad.c_str());
                                if(fDebug>4)LogPrint("walletcompare","walletcompare: %s\n",strResultNone.c_str());
                                if(fDebug>4)LogPrint("walletcompare","walletcompare: %s\n",strResult.c_str());
                            }
                            else
                            {
                                if(fDebug>4)LogPrint("walletcompare","walletcompare: match: %s \n",strMethod.c_str());
                            }
                        }
                    }
                }
            }
#else // ENABLE_WALLET
            else {
                LOCK(cs_main);
                result = pcmd->actor(params, false);
            }
#endif // !ENABLE_WALLET
        }

        if(fDebug>1)LogPrint("api","API request successful: %s\n",strMethod.c_str());

        return result;
    }
    catch (std::exception& e)
    {
        if(fDebug>1)LogPrint("api","API request failure: %s\n",strMethod.c_str());
        if(strcmp(e.what(),"Help message not found\n") == 0)
        {
            throw JSONRPCError(RPC_MISC_ERROR, mc_RPCHelpString(strMethod).c_str());
        }
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}

std::string HelpExampleCli(string methodname, string args){
    return "> hdac-cli " + std::string(mc_gState->m_NetworkParams->Name()) + " " + methodname + " " + args + "\n";
}

std::string HelpExampleRpc(string methodname, string args){
    return "> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
    		"\"method\": \"" + methodname + "\", \"params\": [" + args + "] }' -H 'content-type: text/plain;' http://127.0.0.1:"+
            strprintf("%d",(int)mc_gState->m_NetworkParams->GetInt64Param("defaultrpcport")) + "\n";
}

CRPCTable tableRPC;
std::map<std::string, std::string> mapHelpStrings;
std::map<std::string, int> mapLogParamCounts;
std::set<std::string> setAllowedWhenWaitingForUpgrade;
std::set<std::string> setAllowedWhenOffline;
std::set<std::string> setAllowedWhenLimited;

std::vector<CRPCCommand> vStaticRPCCommands;
std::vector<CRPCCommand> vStaticRPCWalletReadCommands;


