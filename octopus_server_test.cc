#include <string>
#include <vector>
#include <memory>
#include <signal.h>
#include <execinfo.h> //for  backtrace
#include "octopus/octopus_base.h"
#include "base/cmdline.h"
#include "tcp/tcp_server.h"
static volatile bool g_running=true;
const int kBacktraceSize=128;
void signal_exit_handler(int sig)
{
    g_running=false;
}
void signal_pipe_handler(int sig){
    if(SIGPIPE==sig){
        LOG(INFO)<<"ignore sigpipe";
    }
}
void dump(void)
{
    int j, nptrs;
    void *buffer[kBacktraceSize];
    char **strings;
    nptrs = backtrace(buffer, kBacktraceSize);
    printf("backtrace() returned %d addresses\n", nptrs);

    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        perror("backtrace_symbols");
        exit(EXIT_FAILURE);
    }
    for (j = 0; j < nptrs; j++)
        printf("[%02d] %s\n", j, strings[j]);

    free(strings);
}
extern "C"
void __cxa_pure_virtual () {
  std::cout<<"In My Pure Virtual Call!"<<std::endl;
  dump();
}
using namespace std;
using namespace basic;
int main(int argc, char *argv[]){
    signal(SIGTERM, signal_exit_handler);
    signal(SIGINT, signal_exit_handler);
    signal(SIGTSTP, signal_exit_handler);
    signal(SIGPIPE , signal_pipe_handler);
    cmdline::parser a;
    a.add<string>("bi", '\0', "bind ip", false, "0.0.0.0");
    a.add<uint16_t>("bp", '\0', "bind port", false, 3333, cmdline::range(1, 65535));
    a.parse_check(argc, argv);
    std::string bind_ip=a.get<string>("bi");
    uint16_t bind_port=a.get<uint16_t>("bp");
    LOG(INFO)<<bind_ip<<":"<<bind_port;
    IpAddress ip_addr;
    ip_addr.FromString(bind_ip);
    std::unique_ptr<OctopusCalleeSocketFactory> socket_factory(new OctopusCalleeSocketFactory());
    TcpServer server(std::move(socket_factory));
    bool success=server.Init(ip_addr,bind_port);
    if(success){
        while(g_running){
            server.HandleEvent();
        }
    }
    return 0;
}

