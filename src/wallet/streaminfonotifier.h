#ifndef STREAMINFONOTIFIER_H
#define STREAMINFONOTIFIER_H

#include <zmq.hpp>
#include "entities/asset.h"

class StreamInfoNotifier
{
public:
    static StreamInfoNotifier& instance() {
        static StreamInfoNotifier inst;
        return inst;
    }

    void sendMessage(std::string &msg);
    void bind(int port);

private:
    StreamInfoNotifier();

    zmq::context_t _context;
    zmq::socket_t _publisher;
    int _port;
};

class mc_Script;
class mc_AssetDB;
class uint160;
std::string findStreamItemData(mc_Script& parser);
std::string findStreamName(mc_AssetDB& assetDB, const unsigned char short_txid[MC_AST_SHORT_TXID_SIZE]);
std::string toStrWithBitcoinAddr(const uint160 &bitcoinAddr, bool redeemScript);

#endif // STREAMINFONOTIFIER_H
