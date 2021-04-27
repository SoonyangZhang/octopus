/*
ref: https://github.com/teddyyy/arproxy
To capture packet in daemon mode, the flag IFF_PROMISC is a must.
What a lesson.
2021/04/05  04:54
*/
#include <string>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <set>
#include <memory.h>

#include "octopus/octopus_base.h"
#include "base/ip_address.h"
#include "base/cmdline.h"
#include "base/base_ini.h"
#include "logging/logging.h"

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define ETHER_HEADER_LEN sizeof(struct ether_header)
#define ETHER_ARP_LEN sizeof(struct ether_arp)
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
#define HW_TYPE 1
#define ETH_ALEN 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
unsigned char BROADCAST_ADDR[ETH_ALEN]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
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
            DLOG(INFO)<<"ignore sigpipe";
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
            DLOG(ERROR)<<"error init signal "<<sig->name<<std::endl;
        }
    }
    return 0;
}
int octopus_fire_signal(const char *name,int pid){
    octopus_signal_t  *sig;
    for (sig = signals; sig->signo != 0; sig++) {
        if (strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) == -1){
                DLOG(ERROR)<<"error fire signal "<<sig->name<<std::endl;
                return -1;
            }else{
                int status=0;
                waitpid(pid,&status,0);
                break;
            }
        }
    }
    return 0;
}
void err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}
void fill_arp_packet(struct ether_arp *arp_packet,
const unsigned char *src_mac,const unsigned char *dst_mac,
struct in_addr *src_in_addr, struct in_addr *dst_in_addr,int opcodes)
{
    arp_packet->arp_hrd = htons(ARPHRD_ETHER);
    arp_packet->arp_pro = htons(ETHERTYPE_IP);
    arp_packet->arp_hln = ETH_ALEN;
    arp_packet->arp_pln = IPV4_LENGTH;
    arp_packet->arp_op = htons(opcodes);
    memcpy(arp_packet->arp_sha, src_mac,ETH_ALEN);
    memcpy(arp_packet->arp_tha, dst_mac,ETH_ALEN);
    memcpy(arp_packet->arp_spa, src_in_addr, IPV4_LENGTH);
    memcpy(arp_packet->arp_tpa, dst_in_addr, IPV4_LENGTH);
}
 void send_arp_reply(struct sockaddr *saddr_ll,
 const unsigned char *src_mac,const unsigned char *dst_mac,
 struct in_addr *dst, struct in_addr* target, 
 int sock, int opcodes){
    struct ether_header *eth_header;
    char buf[ETHER_ARP_PACKET_LEN];
    bzero(buf, ETHER_ARP_PACKET_LEN);
    eth_header = (struct ether_header *)buf;
    memcpy(eth_header->ether_shost, src_mac, ETH_ALEN);
    memcpy(eth_header->ether_dhost, dst_mac, ETH_ALEN);
    eth_header->ether_type = htons(ETHERTYPE_ARP);
    struct ether_arp arp_packet;
    fill_arp_packet(&arp_packet,src_mac,dst_mac,target,dst,opcodes);
    memcpy(buf + ETHER_HEADER_LEN, &arp_packet, ETHER_ARP_LEN);
    sendto(sock, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)saddr_ll, sizeof(struct sockaddr_ll));
 }
using namespace std;
using namespace basic;
int main(int argc, char **argv){
    octopus_init_signals();
    cmdline::parser a;
    a.add<std::string>("signal", 's', "signal", false, "none");
    a.add<string>("config", 'c', "config file", false, "arp_acl.conf");
    a.add<string>("pidfile", 'p', "pid file", false, "arp_reply.pid");
    a.add<string>("logfile", '\0', "log file", false, "arp_reply.log");
    a.parse_check(argc, argv);
    std::string action=a.get<std::string>("signal");
    std::string conf_pathname=a.get<string>("config");
    std::string pid_pathname=a.get<string>("pidfile");
    std::string log_pathname=a.get<string>("logfile");
    std::string ifname("eth0");
    std::set<uint32_t> src_acl;
    std::set<uint32_t> dst_acl;
    char buffer[ETHER_ARP_PACKET_LEN];
    struct ether_header  *eh=(struct ether_header *)buffer;
    struct ether_arp *arp_packet = (struct ether_arp *)(buffer+ETHER_HEADER_LEN);
    if (geteuid() != 0){
        DLOG(ERROR)<<"please run in root mode";
        return -1;
    }
    if(0==action.compare("stop")){
        int pid=octopus_read_pid(pid_pathname.c_str());
        if(pid>0){
           octopus_fire_signal(action.c_str(),pid);
        }
        return 0;
    }
    int pid=octopus_read_pid(pid_pathname.c_str());
    if(pid){
        DLOG(INFO)<<" arp_reply is already running";
        return 0;
    }
    ini_t *config=ini_load(conf_pathname.c_str());
    if(!config){
        DLOG(ERROR)<<"./arp_reply -c arp_acl.conf";
        return -1;
    }
    const char *capture_if_str=ini_get(config,"service","capture_if");
    if(capture_if_str){
        ifname=std::string(capture_if_str);
        DLOG(INFO)<<capture_if_str;
    }else{
        DLOG(ERROR)<<"wrong config in service section";
        return -1;
    }
    {
        bool success=true;
        const char *section="src-acl";
        const char *num_str=ini_get(config,section,"num");
        if(num_str){
            int n=std::stoi(num_str);
            for(int i=0;i<n;i++){
                std::string key="ip"+std::to_string(i+1);
                const char *ip_str=ini_get(config,section,key.c_str());
                if(ip_str){
                    IpAddress ip_addr;
                    ip_addr.FromString(ip_str);
                    if(ip_addr.IsIPv4()){
                        uint32_t ip32=0;
                        struct in_addr in4=ip_addr.GetIPv4();
                        memcpy((void*)&ip32,&in4,sizeof(ip32));
                        src_acl.insert(ip32);
                    }
                }else{
                    success=false;
                    break;
                }
            }
        }
        if(!success){
            DLOG(ERROR)<<"wring acl list";
            return -1;
        }
    }

    {
        bool success=true;
        const char *section="dst-acl";
        const char *num_str=ini_get(config,section,"num");
        if(num_str){
            int n=std::stoi(num_str);
            for(int i=0;i<n;i++){
                std::string key="ip"+std::to_string(i+1);
                const char *ip_str=ini_get(config,section,key.c_str());
                if(ip_str){
                    IpAddress ip_addr;
                    ip_addr.FromString(ip_str);
                    if(ip_addr.IsIPv4()){
                        uint32_t ip32=0;
                        struct in_addr in4=ip_addr.GetIPv4();
                        memcpy((void*)&ip32,&in4,sizeof(ip32));
                        dst_acl.insert(ip32);
                    }
                }else{
                    success=false;
                    break;
                }
            }
        }
        if(!success){
            DLOG(ERROR)<<"wring acl list";
            return -1;
        }
    }
    //octopus_daemonise();
    #if !defined(NDEBUG)
        std::fstream f_log;
        f_log.open(log_pathname.c_str(),std::fstream::out);
    #endif
    if(0==octopus_write_pid(pid_pathname.c_str())){
        DLOG(ERROR)<<"write pid failed";
        octopus_remove_pid(pid_pathname.c_str());
        return -1;
    }
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (-1==sock) {
        DLOG(ERROR)<<strerror(errno);
        return -1;
    }
    struct sockaddr_ll saddr_ll;
    unsigned char src_mac[ETH_ALEN];
    struct ifreq ifr;
    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    memcpy(ifr.ifr_name, ifname.c_str(),ifname.size());
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1){
        DLOG(ERROR)<<strerror(errno);
        close(sock);
        sock=-1;
        octopus_remove_pid(pid_pathname.c_str());
        return -1;        
    }
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;
    
    ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
    if (ioctl (sock, SIOCGIFFLAGS, &ifr) < 0) {
        DLOG(ERROR)<<strerror(errno);
        close(sock);
        sock=-1;
        octopus_remove_pid(pid_pathname.c_str());
        return -1;
    }
    
    
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, ifname.c_str(),ifname.size());
/*
    if (ioctl(sock, SIOCGIFADDR, &ifr) == -1){
        DLOG(ERROR)<<strerror(errno);
        close(sock);
        sock=-1;
        #if !defined(NDEBUG)
        f_log<<"SIOCGIFADDR "<<strerror(errno)<<errno<<std::endl;
        #endif
        octopus_remove_pid(pid_pathname.c_str());
        return -1;
    }
*/
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)==-1){
        DLOG(ERROR)<<strerror(errno);
        close(sock);
        sock=-1;
        octopus_remove_pid(pid_pathname.c_str());
        return -1;
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    while(g_running){
        bzero(buffer, ETHER_ARP_PACKET_LEN);
        int r=recv(sock,buffer,ETHER_ARP_PACKET_LEN, 0);
        if(r>0&&(ntohs(eh->ether_type)==ETHERTYPE_ARP)&&(ntohs(arp_packet->arp_op)==ARP_REQUEST)){
            eh->ether_type = htons(ETHERTYPE_ARP);
            in_addr src_in_addr=*(struct in_addr *)arp_packet->arp_spa;
            in_addr target_in_addr =*(struct in_addr *)arp_packet->arp_tpa;
            bool responce=false;
            uint32_t from=0;
            uint32_t to=0;
            memcpy(&from,(void*)&src_in_addr,sizeof(from));
            memcpy(&to,(void*)&target_in_addr,sizeof(to));
            auto it1=dst_acl.find(to);
            if(it1!=dst_acl.end()){
                responce=true;
            }else{
                auto it2=src_acl.find(from);
                if(it2!=src_acl.end()){
                    responce=true;
                }
            }
            if(responce){
                send_arp_reply((struct sockaddr*)&saddr_ll,src_mac,BROADCAST_ADDR,
                                &src_in_addr,&target_in_addr,sock,ARPOP_REPLY);
                #if !defined(NDEBUG)
                    IpAddress src_addr(src_in_addr);
                    IpAddress target_addr(target_in_addr);
                    if(f_log.is_open()){
                        f_log<<src_addr.ToString()<<":"<<target_addr.ToString()<<std::endl;
                    }
                #endif
            }
        }
    }
    #if !defined(NDEBUG)
        f_log.close();
    #endif
    close(sock);
    octopus_remove_pid(pid_pathname.c_str());
    return 0;
}
