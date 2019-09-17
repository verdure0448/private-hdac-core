#include "streaminfonotifier.h"
#include "script/script.h"
#include "structs/uint256.h"
#include "structs/base58.h"
#include "utils/utilstrencodings.h"

using namespace std;

StreamInfoNotifier::StreamInfoNotifier() :
    _context(1),
    _publisher(_context, ZMQ_PUB),
    _port(-1)
{
    ostringstream url;
    url << "tcp://*:" << _port;
    _publisher.bind(url.str());

    // after binding, the delay for sending message is necessary.
}

void StreamInfoNotifier::sendMessage(string &topic, string &msg)
{
    //zmq::socket_t publisher (_context, ZMQ_PUB);
    //publisher.bind("tcp://*:5556");
    std::ostringstream oStr;
    oStr << topic + " " << msg;
    string finalMsg = oStr.str();
    zmq::message_t message(finalMsg.begin(), finalMsg.end());

    _publisher.send(message);
}

void StreamInfoNotifier::bind(int port)
{
    ostringstream url;
    const string baseUrl("tcp://*:");
    if (_port > 0) {
        url << baseUrl << _port;
        _publisher.unbind(url.str());
    }
    _port = port;
    url.str("");
    url << baseUrl << _port;
    _publisher.bind(url.str());
}

string findStreamItemData(mc_Script& parser)
{
    size_t elem_size;
    const unsigned char *elem;

    elem = parser.GetData(2,&elem_size);

    return HexStr(elem,elem+elem_size);
}

string findStreamName(mc_AssetDB& assetDB, const unsigned char short_txid[MC_AST_SHORT_TXID_SIZE])
{
    mc_EntityDetails detailEntity;
    assetDB.FindEntityByShortTxID(&detailEntity, short_txid);
    return detailEntity.GetName();
}

string toStrWithBitcoinAddr(const uint160 &bitcoinAddr, bool redeemScript)
{
    string publisherAddr;
    if (redeemScript) {
        publisherAddr = CBitcoinAddress((CScriptID)bitcoinAddr).ToString();
    }
    else {
        publisherAddr = CBitcoinAddress((CKeyID)bitcoinAddr).ToString();
    }
    return publisherAddr;
}
