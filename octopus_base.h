#pragma once
#include <stdint.h>
#include <string>
#include <signal.h>
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
#define octopus_signal_helper(n)     SIG##n
#define octopus_signal_value(n)      octopus_signal_helper(n)
#define octopus_str_value_helper(n)   #n
#define octopus_str_value(n)          octopus_str_value_helper(n)
#define OCTOPUS_SHUTDOWN_SIGNAL      QUIT
#define OCTOPUS_TERMINATE_SIGNAL     TERM
#define OCTOPUS_PIPE_SIGNAL      PIPE
typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
}octopus_signal_t;
namespace basic{
bool octopus_enable_epollet();
struct OctopusSessionKey{
	OctopusSessionKey():OctopusSessionKey(0,0,0,0){}
	OctopusSessionKey(uint32_t from,uint32_t to,
                   uint16_t src_port,uint16_t dst_port):
                	   from(from),to(to),
    src_port(src_port),dst_port(dst_port){}
    uint32_t from=0;
    uint32_t to=0;
    uint16_t src_port=0;
    uint16_t dst_port=0;
	bool operator < (const OctopusSessionKey &o) const
	{
		return from < o.from||to<o.to||
		src_port<o.src_port||dst_port<o.dst_port;
	}
};
class OctopusDispatcher;
class OctopusDispatcherManager{
public:
	bool Register(OctopusSessionKey &key,OctopusDispatcher* dispatcher);
	bool UnRegister(OctopusSessionKey &key);
	OctopusDispatcher* Find(OctopusSessionKey &key);
    size_t Size() const {return tables_.size();}
private:
	std::map<OctopusSessionKey,OctopusDispatcher*> tables_;
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
            OctopusDispatcherManager &manager,OctopusDispatcher *dispatcher);
    ~OctopusHand();
    void WriteMeta(OctopusSessionKey &uuid,bool sp_flag=true);
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
    OctopusDispatcherManager &manager_;
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
	OctopusDispatcher(BaseContext *context,int fd,OctopusSessionKey &uuid,
			OctopusDispatcherRole role,OctopusDispatcherManager &manager);
	virtual ~OctopusDispatcher();
	void SignalFrom(OctopusHand*hand,OctopusSignalCode code);
	//client side logic
	bool CreateSingleConnection(const sockaddr_storage &proxy_src_saddr,
			const sockaddr_storage &proxy_dst_saddr);
	bool CreateMutipleConnections(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>>& proxy_saddrs
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
    OctopusSessionKey uuid_;
	OctopusDispatcherRole role_;
	OctopusDispatcherManager &manager_;
	std::unique_ptr<BaseAlarm> socket_alarm_;
	QuicTime last_alarm_time_=QuicTime::Zero();
    std::set<OctopusHand*> wait_hands_;
    std::set<OctopusHand*> ready_hands_;
    bool wait_close_=false;
};
class OctopusCallerBackend:public Backend{
public:
	OctopusCallerBackend(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec);
	void CreateEndpoint(BaseContext *context,int fd) override;
private:
	const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec_;
};
class OctopusCallerSocketFactory:public SocketServerFactory{
public:
	OctopusCallerSocketFactory(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec);
	PhysicalSocketServer* CreateSocketServer(BaseContext *context) override;
private:
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
int octopus_write_pid(const char *pidfile);
int octopus_read_pid(const char *pidfile);
int octopus_remove_pid(const char *pidfile);
void octopus_daemonise(void);
}
