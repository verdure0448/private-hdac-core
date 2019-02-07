//
//  test for stream notification
//
//  HDAC Technology
//
#include <zmqpp/context.hpp>
#include <zmqpp/socket.hpp>
#include <zmqpp/message.hpp>
#include <iostream>
#include <sstream>

int main (int argc, char *argv[])
{
    zmqpp::context context;

    //  Socket to talk to server
    std::cout << "Collecting updates from weather server…\n" << std::endl;
    zmqpp::socket subscriber (context, zmqpp::socket_type::subscribe);
    //subscriber.connect("tcp://192.168.70.178:5557");
    subscriber.connect("tcp://localhost:5557");

    //  Subscribe to zipcode, default is NYC, 10001
 
    const char *filter = (argc > 1)? argv [1]: "stream {";

    subscriber.set(zmqpp::socket_option::subscribe, "stream {");
    //subscriber.setsockopt(ZMQ_SUBSCRIBE, filter, strlen (filter));
    //subscriber.setsockopt(ZMQ_SUBSCRIBE, nullptr, 0);

    //  Process 100 updates
    int update_nbr;
    long total_temp = 0;
    for (update_nbr = 0; update_nbr < 100; update_nbr++) {
        zmqpp::message update;

        std::string topic;
        std::string jsonStr;

        subscriber.receive(update);

        std::istringstream iss(update.get(0));
	
        iss >> topic >> jsonStr;
        std::cout << "received : " << jsonStr << std::endl;

    }

    return 0;
}
