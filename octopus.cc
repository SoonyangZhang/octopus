#include <unistd.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <signal.h>
#include "base/cmdline.h"
#include "base/base_ini.h"
#include "base/base_thread.h"
#include "logging/logging.h"
#include "octopus/octopus_base.h"
#include "tcp/tcp_server.h"
static volatile bool g_running=true;
static void octopus_signal_handler(int signo, siginfo_t *siginfo, void *ucontext){
    switch(signo){
        case octopus_signal_value(OCTOPUS_SHUTDOWN_SIGNAL):
        case octopus_signal_value(OCTOPUS_TERMINATE_SIGNAL):
        case SIGINT:
        case SIGHUP:
        case SIGTSTP:
            g_running=false;
            break;
        case SIGPIPE:
            LOG(INFO)<<"ignore sigpipe";
            break;
        default:
            break;
    }
}
octopus_signal_t  signals[] ={
    { octopus_signal_value(OCTOPUS_TERMINATE_SIGNAL),
      (char*)"SIG" octopus_str_value(OCTOPUS_TERMINATE_SIGNAL),
      (char*)"stop",octopus_signal_handler},
    {octopus_signal_value(OCTOPUS_SHUTDOWN_SIGNAL),
      (char*)"SIG" octopus_str_value(OCTOPUS_SHUTDOWN_SIGNAL),
      (char*)"quit",octopus_signal_handler},
    { SIGINT, (char*)"SIGINT", (char*)"", octopus_signal_handler },
    { SIGHUP, (char*)"SIGHUP", (char*)"", octopus_signal_handler },
    { SIGTSTP, (char*)"SIGTSTP",(char*)"", octopus_signal_handler },
    { SIGPIPE, (char*)"SIGPIPE",(char*)"", octopus_signal_handler },
    { 0, NULL, (char*)"", NULL}
};
int octopus_init_signals()
{
    octopus_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        memset(&sa, 0,sizeof(struct sigaction));

        if (sig->handler) {
            sa.sa_sigaction = sig->handler;
            sa.sa_flags = SA_SIGINFO;
        } else {
            sa.sa_handler = SIG_IGN;
        }
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
            LOG(ERROR)<<"error init signal "<<sig->name<<std::endl;
        }
    }
    return 0;
}
int octopus_fire_signal(const char *name,int pid){
    octopus_signal_t  *sig;
    for (sig = signals; sig->signo != 0; sig++) {
        if (strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) == -1){
                LOG(ERROR)<<"error fire signal "<<sig->name<<std::endl;
                return -1;
            }else{
                break;
            }
        }
    }
    return 0;
}
using namespace std;
using namespace basic;
namespace basic{
class OctopusService:public BaseThread{
public:
    bool Init(std::string &service_ip,uint16_t service_port);
    void Run() override;
private:
    std::unique_ptr<TcpServer> tcp_server_;
};
bool OctopusService::Init(std::string &service_ip,uint16_t service_port){
    IpAddress ip_addr;
    ip_addr.FromString(service_ip);
    std::unique_ptr<OctopusCalleeSocketFactory> socket_factory(new OctopusCalleeSocketFactory());
    tcp_server_.reset(new TcpServer(std::move(socket_factory)));
    bool success=tcp_server_->Init(ip_addr,service_port);
    if(!success){
        tcp_server_.reset(nullptr);
    }
    return success;
}
void OctopusService::Run(){
    while(running_&&tcp_server_){
        tcp_server_->HandleEvent();
    }
}
}
int main(int argc, char *argv[]){
    octopus_init_signals();
    cmdline::parser a;
    a.add<std::string>("signal", 's', "signal", false, "none");
    a.add<string>("conf", 'c', "config file", false, "oct.conf");
    a.add<string>("pid", 'p', "pid file", false, "oct.pid");
    a.parse_check(argc, argv);
    std::string action=a.get<std::string>("signal");
    std::string conf_pathname=a.get<string>("conf");
    std::string pid_pathname=a.get<string>("pid");
    std::string capture_ip("0.0.0.0");
    std::string service_ip("0.0.0.0");
    uint16_t capture_port=0,service_port=0;
    std::vector<std::pair<sockaddr_storage,sockaddr_storage>> proxy_saddr_vec;
    if (geteuid() != 0){
        LOG(INFO)<<"please run in root mode";
        return -1;
    }
    if(0==action.compare("stop")){
        int pid=octopus_read_pid(pid_pathname.c_str());
        if(pid>0){
           octopus_fire_signal(action.c_str(),pid);
        }
        return 1;
    }
    ini_t *config=ini_load(conf_pathname.c_str());
    if(!config){
        LOG(ERROR)<<"./oct -c oct.conf";
        return -1;
    }
    std::string route("route");
    const char *route_str_v=ini_get(config,"number",route.c_str());
    if(route_str_v){
        int n=std::stoi(route_str_v);
        for (int i=0;i<n;i++){
        	std::string segment=route+std::to_string(i+1);
        	const char *local_ip_str=ini_get(config,segment.c_str(),"local_ip");
        	const char *peer_ip_str=ini_get(config,segment.c_str(),"peer_ip");
        	const char *peer_port_str=ini_get(config,segment.c_str(),"peer_port");
        	if(local_ip_str&&peer_ip_str&&peer_port_str){
                IpAddress ip_src;
                IpAddress ip_dst;
                ip_src.FromString(local_ip_str);
                ip_dst.FromString(peer_ip_str);
                uint16_t proxy_src_port=0;
                uint16_t proxy_dst_port=std::stoi(peer_port_str);
                LOG(INFO)<<peer_ip_str<<":"<<proxy_dst_port;
                SocketAddress socket_addr_src(ip_src,proxy_src_port);
                SocketAddress socket_addr_dst(ip_dst,proxy_dst_port);
                sockaddr_storage saddr_from=socket_addr_src.generic_address();
                sockaddr_storage saddr_to=socket_addr_dst.generic_address();
                proxy_saddr_vec.push_back(std::make_pair(saddr_from,saddr_to));
        	}else{
        		LOG(ERROR)<<"wrong config";
        		return -1;
        	}
        }
    }
    const char *capture_port_str=ini_get(config,"service","capture_port");
    const char *service_port_str=ini_get(config,"service","service_port");
    if(capture_port_str&&service_port_str){
    	capture_port=std::stoi(capture_port_str);
    	service_port=std::stoi(service_port_str);;
        LOG(INFO)<<capture_port<<":"<<service_port;
    }else{
		LOG(ERROR)<<"wrong config";
		return -1;
    }
    int pid=octopus_read_pid(pid_pathname.c_str());
    if(pid){
        if(octopus_fire_signal(octopus_str_value(OCTOPUS_TERMINATE_SIGNAL),pid)!=0){
            return -1;
        }
        octopus_remove_pid(pid_pathname.c_str());
    }
    if(0==octopus_write_pid(pid_pathname.c_str())){
        return -1;
    }
    /*
        block sigpipe for pthread
        https://blog.csdn.net/suifengpiao_2011/article/details/51837805
        http://www.microhowto.info/howto/ignore_sigpipe_without_affecting_other_threads_in_a_process.html
        https://riptutorial.com/posix/example/17424/handle-sigpipe-generated-by-write---in-a-thread-safe-manner
    */
    sigset_t signal_mask;
    sigemptyset (&signal_mask);
    sigaddset (&signal_mask, SIGPIPE);
    int rc = pthread_sigmask (SIG_BLOCK, &signal_mask, NULL);
    if (rc != 0)
    {
        LOG(INFO)<<"block sigpipe error";
        return -1;
    } 
    std::unique_ptr<OctopusCallerSocketFactory> socket_factory(new OctopusCallerSocketFactory(proxy_saddr_vec));
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
    OctopusService service;
    if(!service.Init(service_ip,service_port)){
    	return -1;
    }
    service.Start();
    if(success){
        while(g_running){
            server.HandleEvent();
        }
    }
    service.Stop();
    octopus_remove_pid(pid_pathname.c_str());
    return 0;
}
