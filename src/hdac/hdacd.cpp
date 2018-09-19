// Copyright (c) 2014-2016 The Bitcoin Core developers
// Original code was distributed under the MIT software license.
// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017-2018 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
//============================================================================================
// History
//
// 2018/01/00        Rename file
// 2018/02/00   Code optimization
// 2018/03/19   included custfile
//              added rehashparam
//============================================================================================


#include "cust/custhdac.h"

#include "version/clientversion.h"
#include "rpc/rpcserver.h"
#include "core/init.h"
#include "core/main.h"
#include "ui/noui.h"
#include "ui/ui_interface.h"
#include "utils/util.h"


#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include "hdac/hdac.h"
#include "chainparams/globals.h"
static bool fDaemon;

void DebugPrintClose();

void DetectShutdownThread(boost::thread_group* threadGroup)
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        threadGroup->interrupt_all();
        threadGroup->join_all();
    }
}

bool mc_DoesParentDataDirExist()
{
    if (mapArgs.count("-datadir"))
    {
        boost::filesystem::path path=boost::filesystem::system_complete(mapArgs["-datadir"]);
        if (!boost::filesystem::is_directory(path))
        {
            return false;
        }
    }
    return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
bool AppInit(int argc, char* argv[])
{
    boost::thread_group threadGroup;
    boost::thread* detectShutdownThread = NULL;

    bool fRet = false;

    int size;
    int err = MC_ERR_NOERROR;
    int pipes[2];
    int bytes_read;
    int bytes_written;
    char bufOutput[4096];
    bool is_daemon;
    void *ptr;

    //
    // Parameters
    //


    mc_gState=new mc_State;

    mc_gState->m_Params->Parse(argc, argv, MC_ETP_DAEMON);
    mc_CheckDataDirInConfFile();

    if(mc_gState->m_Params->NetworkName())
    {
        if(strlen(mc_gState->m_Params->NetworkName()) > MC_PRM_NETWORK_NAME_MAX_SIZE)
        {
            fprintf(stderr, "Error: invalid chain name: %s\n",mc_gState->m_Params->NetworkName());
            return false;
        }
    }

    if(!mc_DoesParentDataDirExist())
    {
        fprintf(stderr,"\nError: Data directory %s needs to exist before calling hdacd. Exiting...\n\n",mapArgs["-datadir"].c_str());
        return false;
    }


    mc_gState->m_Params->HasOption("-?");

    // Process help and version before taking care about datadir
    if (mc_gState->m_Params->HasOption("-?") ||
        mc_gState->m_Params->HasOption("-help") ||
        mc_gState->m_Params->HasOption("-version") ||
        (mc_gState->m_Params->NetworkName() == NULL))
    {
#ifdef FEATURE_HDAC_KASSE_ASM
        fprintf(stdout,"\nHdac %s Daemon (protocol %d) ASM - public 1.05 compatible\n\n",mc_gState->GetVersion(),mc_gState->GetProtocolVersion());
#else
        fprintf(stdout,"\nHdac %s Daemon (protocol %d) - public 1.05 compatible\n\n",mc_gState->GetVersion(),mc_gState->GetProtocolVersion());
#endif	// FEATURE_HDAC_KASSE_ASM

        std::string strUsage = "";
        if (mc_gState->m_Params->HasOption("-version"))
        {
            strUsage += LicenseInfo();
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  hdacd <blockchain-name> [options]                     " + _("Start Hdac Core Daemon") + "\n";
            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());

        delete mc_gState;
        return true;
    }

    if(!GetBoolArg("-shortoutput", false))
    {
#ifdef FEATURE_HDAC_KASSE_ASM
        fprintf(stdout,"\nHdac %s Daemon (latest protocol %d) ASM - Private Blockchain (public 1.05 compatible)\n\n", mc_gState->GetVersion(),mc_gState->GetProtocolVersion());
#else
        fprintf(stdout,"\nHdac %s Daemon (latest protocol %d) - Private Blockchain (public 1.05 compatible)\n\n", mc_gState->GetVersion(),mc_gState->GetProtocolVersion());
#endif	// FEATURE_HDAC_KASSE_ASM
    }

    pipes[1]=STDOUT_FILENO;
    is_daemon=false;
#ifndef WIN32
        fDaemon = GetBoolArg("-daemon", false);

        if (fDaemon)
        {
            delete mc_gState;

            if(!GetBoolArg("-shortoutput", false))
            {
                fprintf(stdout, "Starting up node...\n\n");
            }

            if (pipe(pipes))
            {
                fprintf(stderr, "Error: couldn't create pipe between parent and child processes\n");
                return false;
            }

            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }

            if(pid == 0)
            {
                is_daemon=true;
                close(pipes[0]);
            }

            if (pid > 0)                                                        // Parent process, pid is child process id
            {
//                delete mc_gState;
                close(pipes[1]);
                bytes_read=1;
                while(bytes_read>0)
                {
                    bytes_read=read(pipes[0],bufOutput,4096);
                    if(bytes_read <= 0)
                    {
                        return true;
                    }
                    bytes_written=write(STDOUT_FILENO,bufOutput,bytes_read);
                    if(bytes_written != bytes_read)
                    {
                        return true;
                    }
                }
                return true;
            }

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "ERROR: setsid() returned %d errno %d\n", sid, errno);

            mc_gState=new mc_State;

            mc_gState->m_Params->Parse(argc, argv, MC_ETP_DAEMON);
            mc_CheckDataDirInConfFile();
        }
#endif

    mc_GenerateConfFiles(mc_gState->m_Params->NetworkName());

    err=mc_gState->m_Params->ReadConfig(mc_gState->m_Params->NetworkName());

    if(err)
    {
        fprintf(stderr,"ERROR: Couldn't read parameter file for blockchain %s. Exiting...\n",mc_gState->m_Params->NetworkName());
        delete mc_gState;
        return false;
    }

#ifdef FEATURE_HPAY_UPDATE_PARAMS_HASH
    if(GetBoolArg("-reparams", false))
    {
        do
        {
                    err=mc_gState->m_NetworkParams->Read(mc_gState->m_Params->NetworkName());
                    if(err) break;
                    err = mc_gState->m_NetworkParams->ReHashParams();
        }
        while(0);

        if(err)
        {
            fprintf(stderr,"ERROR: Couldn't -reparams  errno 0x%08X Exiting...\n",err);
            delete mc_gState;
            return false;
        }
    }
#endif        // FEATURE_HPAY_UPDATE_PARAMS_HASH

    err=mc_gState->m_NetworkParams->Read(mc_gState->m_Params->NetworkName());
    if(err)
    {
        fprintf(stderr,"ERROR: Couldn't read configuration file for blockchain %s. Please try upgrading Hdac. Exiting...\n",mc_gState->m_Params->NetworkName());
        delete mc_gState;
        return false;
    }

    err=mc_gState->m_NetworkParams->Validate();
    if(err)
    {
        fprintf(stderr,"ERROR: Couldn't validate parameter set for blockchain %s. Exiting...\n",mc_gState->m_Params->NetworkName());
        delete mc_gState;
        return false;
    }

    if(GetBoolArg("-reindex", false))
    {
        mc_RemoveDir(mc_gState->m_Params->NetworkName(),"permissions.db");
        mc_RemoveFile(mc_gState->m_Params->NetworkName(),"permissions",".dat",MC_FOM_RELATIVE_TO_DATADIR);
        mc_RemoveFile(mc_gState->m_Params->NetworkName(),"permissions",".log",MC_FOM_RELATIVE_TO_DATADIR);
    }

    mc_gState->m_Permissions= new mc_Permissions;
    err=mc_gState->m_Permissions->Initialize(mc_gState->m_Params->NetworkName(),0);
    if(err)
    {
        if(err == MC_ERR_CORRUPTED)
        {
            fprintf(stderr,"\nERROR: Couldn't initialize permission database for blockchain %s. Please restart hdacd with reindex=1.\n",mc_gState->m_Params->NetworkName());
        }
        else
        {
            fprintf(stderr,"\nERROR: Couldn't initialize permission database for blockchain %s. Probably hdacd for this blockchain is already running. Exiting...\n",mc_gState->m_Params->NetworkName());
        }
        delete mc_gState;
        return false;
    }

    ptr=mc_gState->m_NetworkParams->GetParam("chainprotocol",NULL);
    if(ptr)
    {
        if (strcmp((char*)ptr,"hdac") != 0)
	{
	}
    }

    if( (mc_gState->m_NetworkParams->GetParam("protocolversion",&size) != NULL) &&
        (mc_gState->GetProtocolVersion() < (int)mc_gState->m_NetworkParams->GetInt64Param("protocolversion")) )
    {
            fprintf(stderr,"ERROR: Parameter set for blockchain %s was generated by Hdac running newer protocol version (%d)\n\n",
                    mc_gState->m_Params->NetworkName(),(int)mc_gState->m_NetworkParams->GetInt64Param("protocolversion"));
            fprintf(stderr,"Please upgrade Hdac\n\n");
            delete mc_gState;
            return false;
    }

    if( (mc_gState->m_NetworkParams->GetParam("protocolversion",&size) != NULL) &&
        (mc_gState->m_Features->MinProtocolVersion() > (int)mc_gState->m_NetworkParams->GetInt64Param("protocolversion")) )
    {
            fprintf(stderr,"ERROR: The protocol version (%d) for blockchain %s has been deprecated and was last supported in Hdac 1.0 beta 1\n\n",
                    (int)mc_gState->m_NetworkParams->GetInt64Param("protocolversion"),mc_gState->m_Params->NetworkName());
            delete mc_gState;
            return false;
    }

    if(!GetBoolArg("-verifyparamsethash", true))
    {
        if(mc_gState->m_NetworkParams->m_Status == MC_PRM_STATUS_INVALID)
        {
            mc_gState->m_NetworkParams->m_Status=MC_PRM_STATUS_VALID;
        }
    }

    switch(mc_gState->m_NetworkParams->m_Status)
    {
    case MC_PRM_STATUS_EMPTY:
    case MC_PRM_STATUS_MINIMAL:
        if(mc_gState->GetSeedNode() == NULL)
        {
            fprintf(stderr,"ERROR: Parameter set for blockchain %s is not complete. \n\n\n",mc_gState->m_Params->NetworkName());
            fprintf(stderr,"If you want to create new blockchain please run one of the following:\n\n");
            fprintf(stderr,"  hdac-util create %s\n",mc_gState->m_Params->NetworkName());
            fprintf(stderr,"  hdac-util clone <old-blockchain-name> %s\n",mc_gState->m_Params->NetworkName());
            fprintf(stderr,"\nAnd rerun hdacd %s\n\n\n",mc_gState->m_Params->NetworkName());
            fprintf(stderr,"If you want to connect to existing blockchain please specify seed node:\n\n");
            fprintf(stderr,"  hdacd %s@<seed-node-ip>\n",mc_gState->m_Params->NetworkName());
            fprintf(stderr,"  hdacd %s@<seed-node-ip>:<seed-node-port>\n\n\n",mc_gState->m_Params->NetworkName());
            delete mc_gState;
            return false;
        }
        break;
    case MC_PRM_STATUS_ERROR:
        fprintf(stderr,"ERROR: Parameter set for blockchain %s has errors. Please run one of the following:\n\n",mc_gState->m_Params->NetworkName());
        fprintf(stderr,"  hdac-util create %s\n",mc_gState->m_Params->NetworkName());
        fprintf(stderr,"  hdac-util clone <old-blockchain-name> %s\n",mc_gState->m_Params->NetworkName());
        fprintf(stderr,"\nAnd rerun hdacd %s\n",mc_gState->m_Params->NetworkName());
        delete mc_gState;
        return false;
    case MC_PRM_STATUS_INVALID:
        fprintf(stderr,"ERROR: Parameter set for blockchain %s is invalid. You may generate new network using these parameters by running:\n\n",mc_gState->m_Params->NetworkName());
        fprintf(stderr,"  hdac-util clone %s <new-blockchain-name>\n",mc_gState->m_Params->NetworkName());
        delete mc_gState;
        return false;
    case MC_PRM_STATUS_GENERATED:
    case MC_PRM_STATUS_VALID:
        break;
    default:
        fprintf(stderr,"INTERNAL ERROR: Unknown parameter set status %d\n",mc_gState->m_NetworkParams->m_Status);
        delete mc_gState;
        return false;
        break;
    }

    SelectHdacParams(mc_gState->m_Params->NetworkName());

    try
    {
        SoftSetBoolArg("-server", true);
        detectShutdownThread = new boost::thread(boost::bind(&DetectShutdownThread, &threadGroup));
        fRet = AppInit2(threadGroup,pipes[1]);
        if(is_daemon)
        {
            close(pipes[1]);
        }
    }
    catch (std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    if (!fRet)
    {
        if (detectShutdownThread)
            detectShutdownThread->interrupt();

        threadGroup.interrupt_all();
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of
        // the startup-failure cases to make sure they don't result in a hang due to some
        // thread-blocking-waiting-for-another-thread-during-startup case
    }
    if (detectShutdownThread)
    {
        detectShutdownThread->join();
        delete detectShutdownThread;
        detectShutdownThread = NULL;
    }

    Shutdown();
    DebugPrintClose();

#ifdef FEATURE_HPAY_PREVENT_REMOVE_DATADIR
    delete mc_gState;
#else

    std::string datadir_to_delete="";

    if(mc_gState->m_NetworkParams->Validate() == 0)
    {
        if(mc_gState->m_NetworkParams->m_Status == MC_PRM_STATUS_EMPTY)
        {
            datadir_to_delete=strprintf("%s",mc_gState->m_Params->NetworkName());
        }
    }

    delete mc_gState;

    if(datadir_to_delete.size())
    {
        mc_RemoveDataDir(datadir_to_delete.c_str());
    }
#endif	// FEATURE_HPAY_PREVENT_REMOVE_DATADIR

    return fRet;
}


int main(int argc, char* argv[])
{
    SetupEnvironment();

    // Connect hdacd signal handlers
    noui_connect();

    return (AppInit(argc, argv) ? 0 : 1);
}
