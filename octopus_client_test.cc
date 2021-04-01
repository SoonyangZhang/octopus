#include <string>
#include <vector>
#include <memory>
#include <signal.h>
#include "octopus/octopus_base.h"
#include "base/cmdline.h"
#include "tcp/tcp_server.h"
#include "base/epoll_api.h"
using namespace basic;
using namespace std;
static volatile bool g_running=true;
void signal_exit_handler(int sig)
{
    g_running=false;
}
void signal_pipe_handler(int sig){
    if(SIGPIPE==sig){
        LOG(INFO)<<"ignore sigpipe";
    }
}
int main(int argc, char *argv[]){
    signal(SIGTERM, signal_exit_handler);
    signal(SIGINT, signal_exit_handler);
    signal(SIGTSTP, signal_exit_handler);
    signal(SIGPIPE , signal_pipe_handler);
    cmdline::parser a;
    a.add<string>("ci", '\0', "capture ip", false, "0.0.0.0");
    a.add<uint16_t>("cp", '\0', "cature port", false, 2233, cmdline::range(1, 65535));
    a.add<string>("psi", '\0', "proxy src ip", false, "0.0.0.0");

    a.add<string>("si", '\0', "server ip", true, "0.0.0.0");
    a.add<uint16_t>("sp", '\0', "server port", false, 3333, cmdline::range(1, 65535));

    a.parse_check(argc, argv);
    std::string capture_ip=a.get<string>("ci");
    uint16_t capture_port=a.get<uint16_t>("cp");
    std::string proxy_src_ip=a.get<string>("psi");
    std::string proxy_dst_ip=a.get<string>("si");
    uint16_t proxy_dst_port=a.get<uint16_t>("sp");
    std::vector<std::pair<sockaddr_storage,sockaddr_storage>> proxy_saddr_vec;
    {
        IpAddress ip_src;
        IpAddress ip_dst;
        ip_src.FromString(proxy_src_ip);
        ip_dst.FromString(proxy_dst_ip);
        uint16_t proxy_src_port=0;
        SocketAddress socket_addr_src(ip_src,proxy_src_port);
        SocketAddress socket_addr_dst(ip_dst,proxy_dst_port);
        sockaddr_storage saddr_from=socket_addr_src.generic_address();
        sockaddr_storage saddr_to=socket_addr_dst.generic_address();
        proxy_saddr_vec.push_back(std::make_pair(saddr_from,saddr_to));
    }
    uint64_t uuid=0;
    std::unique_ptr<OctopusCallerSocketFactory> socket_factory(new OctopusCallerSocketFactory(uuid,
    						proxy_saddr_vec));
    TcpServer server(std::move(socket_factory));
    PhysicalSocketServer *socket_server=server.socket_server();
    CHECK(socket_server);
    if(socket_server){
        int yes=1;
        if(socket_server->SetSocketOption(SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes))){
            DLOG(INFO)<<"set option error";
            return 0;
        }
    }
    IpAddress ip_addr;
    ip_addr.FromString(capture_ip);
    bool success=server.Init(ip_addr,capture_port);
    if(success){
        while(g_running){
            server.HandleEvent();
        }
    }
    return 0;
}
