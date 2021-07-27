#pragma once
#include <vector>
#include "base/base_context.h"
#include "base/socket_address.h"
namespace basic{
class OctopusRouteIf{
public:
    virtual ~OctopusRouteIf(){}
    virtual void OnAcceptConnection(BaseContext *context,int fd)=0;
};
class OctopusOneRoute:public OctopusRouteIf{
public:
    OctopusOneRoute(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec);
    virtual void OnAcceptConnection(BaseContext *context,int fd);
private:
    std::vector<std::pair<sockaddr_storage,sockaddr_storage>> proxy_saddr_vec_;
};
}
