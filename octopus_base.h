#pragma once
#include <stdint.h>
#include <string>
#include <atomic>
#include <memory>
#include <deque>
#include <set>
#include <vector>
#include <map>

#include "base/base_alarm.h"
#include "base/base_context.h"
#include "tcp/tcp_types.h"
#include "tcp/tcp_server.h"
#include "base/epoll_api.h"
#include "base/socket_address.h"
#include "tpproxy/bandwidth.h"
#include "tpproxy/windowed_filter.h"
#include "tpproxy/interval_budget.h"
#include "octopus/octopus_error_codes.h"
namespace basic{
bool octopus_enable_epollet();
class OctopusDispatcher;
class OctopusDispatcherManager{
public:
	bool Register(uint64_t uuid,uint64_t ssid,OctopusDispatcher* dispatcher);
	bool UnRegister(uint64_t uuid,uint64_t ssid);
	OctopusDispatcher* Find(uint64_t uuid,uint64_t ssid);
    size_t RowSize() const;
    size_t ColumSize(uint64_t uuid) const;
private:
	std::map<uint64_t,std::map<uint64_t,OctopusDispatcher*>> tables_;
};
class OctopusBase{
public:
	OctopusBase(BaseContext *context,int fd);
	virtual ~OctopusBase(){}
	int GetWriteBudget(QuicTime::Delta delta_time) const;
protected:
    using MaxBandwidthFilter = WindowedFilter<QuicBandwidth,
                                            MaxFilter<QuicBandwidth>,
                                            int64_t,
                                            int64_t>;
	void FlushBuffer();
	void CloseFd();
    BaseContext *context_;
	int fd_;
	OctopusConnStatus status_=OCTOPUS_CONN_MIN;
    std::string rb_;
	std::string wb_;
	uint64_t send_bytes_=0;
	uint64_t recv_bytes_=0;
	MaxBandwidthFilter out_bw_filter_;
	QuicTime last_out_bw_ts_=QuicTime::Zero();
	int64_t last_out_bytes_acked_=0;
	int64_t round_=0;
    std::atomic<bool> destroyed_{false};
};
class OctopusHand:public OctopusBase,public EpollCallbackInterface{
public:
	OctopusHand(BaseContext *context,int fd,OctopusHandRole role,
			 OctopusDispatcherManager *manager,OctopusDispatcher *dispatcher);
	~OctopusHand();
	void WriteMeta(uint64_t uuid,uint64_t ssid,const struct sockaddr_storage &src_saddr,
			const struct sockaddr_storage &dst_saddr,bool sp_flag=true);
	bool AsynConnect(const struct sockaddr * addr,socklen_t addrlen);
	void SignalFrom(OctopusDispatcher* dispatcher,OctopusSignalCode code);
	void Sink(const char *pv,int sz);
	//for multipath transmission
	void SinkWithOff(uint64_t offset,const char *pv,int sz);
    // From EpollCallbackInterface
    void OnRegistration(EpollServer* eps, int fd, int event_mask) override{}
    void OnModification(int fd, int event_mask) override {}
    void OnEvent(int fd, EpollEvent* event) override;
    void OnUnregistration(int fd, bool replaced) override {}
    void OnShutdown(EpollServer* eps, int fd) override;
    std::string Name() const override;
	void OutBandwidthAlarm();
private:
    void OnCallerEvent(int fd, EpollEvent* event);
    void OnCalleeEvent(int fd, EpollEvent* event);
    void ConnClose(OctopusSignalCode code);
	void CalleeParseMeta();
	void SendMetaAck(OctopusSignalCode code);
    void DeleteSelf();
	OctopusHandRole role_;
	OctopusDispatcherManager *manager_=nullptr;
	OctopusDispatcher *dispatcher_=nullptr;
	std::unique_ptr<BaseAlarm> out_bw_alarm_;
	uint8_t msg_flag_=0;
	bool sp_flag_=true;
	bool wait_close_=false;
};
// default single path
class OctopusDispatcher:public OctopusBase,public EpollCallbackInterface,
public BaseContext::ExitVisitor{
public:
	OctopusDispatcher(BaseContext *context,int fd,uint64_t uuid,uint64_t ssid,
			OctopusDispatcherRole role,OctopusDispatcherManager *manager);
	virtual ~OctopusDispatcher();
	void SignalFrom(OctopusHand*hand,OctopusSignalCode code);
	//client side logic
	bool CreateSingleConnection(const sockaddr_storage &origin_src_saddr,
			const sockaddr_storage &origin_dst_saddr,
			const sockaddr_storage &proxy_src_saddr,
			const sockaddr_storage &proxy_dst_saddr);
	bool CreateMutipleConnections(const sockaddr_storage &origin_src_saddr,
			const sockaddr_storage &origin_dst_saddr,
			const std::vector<std::pair<sockaddr_storage,sockaddr_storage>>& proxy_saddrs
			);
	//server side logic
	bool AsynConnect(const struct sockaddr *addr,socklen_t addrlen);
	void RegisterHand(OctopusHand*hand);

	void Sink(const char *pv,int sz);
	//multipath transmission
    void SinkWithOff(uint64_t offset,const char *pv,int sz){}
	// From EpollCallbackInterface
    void OnRegistration(EpollServer* eps, int fd, int event_mask) override{}
    void OnModification(int fd, int event_mask) override {}
    void OnEvent(int fd, EpollEvent* event) override;
    void OnUnregistration(int fd, bool replaced) override {}
    void OnShutdown(EpollServer* eps, int fd) override;
    std::string Name() const override;
    //from BaseContext::ExitVisitor
    void ExitGracefully() override;
    virtual void HandleSocketAlarm();
protected:
    void ConnClose(OctopusSignalCode code);
    void DeleteSelf();
    uint64_t uuid_;
    uint64_t ssid_;
	OctopusDispatcherRole role_;
	OctopusDispatcherManager *manager_=nullptr;
	std::unique_ptr<BaseAlarm> socket_alarm_;
	QuicTime last_alarm_time_=QuicTime::Zero();
    std::set<OctopusHand*> wait_hands_;
    std::set<OctopusHand*> ready_hands_;
    bool wait_close_=false;
};
class OctopusCallerBackend:public Backend{
public:
	OctopusCallerBackend(uint64_t uuid,
			const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec);
	void CreateEndpoint(BaseContext *context,int fd) override;
private:
	uint64_t uuid_=0;
	uint64_t ssid_=0;
	const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec_;
};
class OctopusCallerSocketFactory:public SocketServerFactory{
public:
	OctopusCallerSocketFactory(uint64_t uuid,
			const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec);
	PhysicalSocketServer* CreateSocketServer(BaseContext *context) override;
private:
	uint64_t uuid_=0;
	std::vector<std::pair<sockaddr_storage,sockaddr_storage>> proxy_saddr_vec_;
};
class OctopusCalleeBackend:public Backend{
public:
	OctopusCalleeBackend(){}
	void CreateEndpoint(BaseContext *context,int fd) override;
private:
	OctopusDispatcherManager manager_;
};
class OctopusCalleeSocketFactory:public SocketServerFactory{
public:
	OctopusCalleeSocketFactory(){}
    PhysicalSocketServer* CreateSocketServer(BaseContext *context) override;
};
}
