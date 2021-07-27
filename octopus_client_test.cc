#include <string>
#include <vector>
#include <memory>
#include <signal.h>
#include "octopus/octopus_base.h"
#include "octopus/octopus_route.h"
#include "base/cmdline.h"
#include "base/base_ini.h"
#include "tcp/tcp_server.h"
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
//./oct_client -c oct_client_sp.conf
int main(int argc, char *argv[]){
    signal(SIGTERM, signal_exit_handler);
    signal(SIGINT, signal_exit_handler);
    signal(SIGTSTP, signal_exit_handler);
    signal(SIGPIPE , signal_pipe_handler);
    std::vector<IpAddress> local_ip_vec;
    std::unique_ptr<OctopusRouteIf> route_if;
    std::vector<std::pair<sockaddr_storage,sockaddr_storage>> proxy_saddr_vec;
    cmdline::parser a;
    std::string capture_ip("0.0.0.0");
    uint16_t capture_port=3333;
    a.add<string>("config", 'c', "config file", false, "oct.conf");
    a.parse_check(argc, argv);
    GetLocalIpAddress(local_ip_vec);
    //parser config
    {
        std::string conf_path_name=a.get<string>("config");
        std::string route_seg="route";
        std::string service_seg="service";
        ini_t *config=ini_load(conf_path_name.c_str());
        if(nullptr==config){
            DLOG(ERROR)<<"config path: "<<conf_path_name;
            return OCT_ERR;
        }
        const char *n_str=ini_get(config,route_seg.c_str(),"n");
        if(nullptr==n_str){
            DLOG(ERROR)<<"route number is not specified";
            return OCT_ERR;
        }
        int n=std::stoi(n_str);
        for(int i=0;i<n;i++){
            std::string seg=route_seg+std::to_string(i+1);
            const char *bind_ip=ini_get(config,seg.c_str(),"bind_ip");
            const char *peer_ip=ini_get(config,seg.c_str(),"peer_ip");
            const char *peer_port_str=ini_get(config,seg.c_str(),"peer_port");
            if(bind_ip&&peer_ip&&peer_port_str){
                IpAddress proxy_src_ip;
                IpAddress proxy_dst_ip;
                uint16_t proxy_src_port=0;
                uint16_t proxy_dst_port=0;
                proxy_src_ip.FromString(bind_ip);
                proxy_dst_ip.FromString(peer_ip);
                proxy_dst_port=std::stoi(peer_port_str);
                if (CheckIpExist(local_ip_vec,proxy_src_ip)){
                    SocketAddress socket_addr_src(proxy_src_ip,proxy_src_port);
                    SocketAddress socket_addr_dst(proxy_dst_ip,proxy_dst_port);
                    sockaddr_storage saddr_from=socket_addr_src.generic_address();
                    sockaddr_storage saddr_to=socket_addr_dst.generic_address();
                    proxy_saddr_vec.push_back(std::make_pair(saddr_from,saddr_to));
                }else{
                    DLOG(ERROR)<<"bind ip is not right: "<<bind_ip;
                }
            }else{
                DLOG(ERROR)<<"err in "<<seg;
                return OCT_ERR;
            }
        }
        const char *divert_ip=ini_get(config,service_seg.c_str(),"capture_ip");
        const char *divert_port=ini_get(config,service_seg.c_str(),"capture_port");
        if(nullptr==divert_port){
            DLOG(ERROR)<<"capture port is null";
            return OCT_ERR;
        }
        capture_port=std::stoi(divert_port);
        if(nullptr!=divert_ip){
            IpAddress ip;
            ip.FromString(divert_ip);
            if(CheckIpExist(local_ip_vec,ip)){
                capture_ip=divert_ip;
            }
        }
        DLOG(INFO)<<"proxy_saddr_vec size: "<<proxy_saddr_vec.size();
        DLOG(INFO)<<"capture "<<capture_ip<<":"<<capture_port;
    }
    
    route_if.reset(new OctopusOneRoute(proxy_saddr_vec));
    std::unique_ptr<OctopusCallerSocketFactory> socket_factory(new OctopusCallerSocketFactory(route_if.get()));
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
