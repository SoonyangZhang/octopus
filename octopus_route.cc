#include <memory.h>
#include <unistd.h>
#include "logging/logging.h"
#include "octopus/octopus_route.h"
#include "octopus/octopus_base.h"
#include "octopus/octopus_define.h"
namespace basic{
OctopusOneRoute::OctopusOneRoute(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec){
    for(auto it=proxy_saddr_vec.begin();it!=proxy_saddr_vec.end();it++){
        proxy_saddr_vec_.push_back(std::make_pair(it->first,it->second));
    }
}
void OctopusOneRoute::OnAcceptConnection(BaseContext *context,int fd){
    int n=proxy_saddr_vec_.size();
    OctopusDispatcher *dispatcher=nullptr;
    sockaddr_storage origin_src_saddr;
    sockaddr_storage origin_dst_saddr;
    OctopusSessionKey uuid;
    socklen_t addr_len = sizeof(sockaddr_storage);
    if(n<=0){
        close(fd);
        return ;
    }
    getpeername(fd,(sockaddr*)&origin_src_saddr,&addr_len);
    getsockname(fd,(sockaddr*)&origin_dst_saddr,&addr_len);
    {
        SocketAddress socket_addr(origin_src_saddr);
        IpAddress host=socket_addr.host();
        in_addr ipv4=host.GetIPv4();
        memcpy(&uuid.from,&ipv4,sizeof(uuid.from));
        uuid.src_port=socket_addr.port();
        DLOG(INFO)<<"origin src "<<socket_addr.ToString();
    }
    {
        SocketAddress socket_addr(origin_dst_saddr);
        IpAddress host=socket_addr.host();
        in_addr ipv4=host.GetIPv4();
        memcpy(&uuid.to,&ipv4,sizeof(uuid.to));
        uuid.dst_port=socket_addr.port();
        DLOG(INFO)<<"origin dst "<<socket_addr.ToString();
    }
    
    if(1==n){
        dispatcher=new OctopusDispatcher(context,fd,uuid,OCT_DISPA_C,1,
                create_null_ref<OctopusDispatcherManager>());
        dispatcher->CreateSingleConnection(proxy_saddr_vec_[0].first,proxy_saddr_vec_[0].second);
    }else{
        dispatcher=new OctopusDispatcher(context,fd,uuid,OCT_DISPA_C,0,
                create_null_ref<OctopusDispatcherManager>());
        dispatcher->CreateMutipleConnections(proxy_saddr_vec_);
    }
    UNUSED(dispatcher);
}
}
