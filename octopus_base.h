#pragma once
#include <stdint.h>
#include <string>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <atomic>
#include <memory>
#include <deque>
#include <vector>
#include <map>

#include "base/base_alarm.h"
#include "base/base_context.h"
#include "tcp/tcp_types.h"
#include "tcp/tcp_server.h"
#include "base/epoll_api.h"
#include "base/socket_address.h"
#include "octopus/bandwidth.h"
#include "octopus/windowed_filter.h"
#include "octopus/octopus_route.h"
#include "octopus/octopus_define.h"
#include "sequencer/quic_stream_sequencer.h"
#define octopus_signal_helper(n)     SIG##n
#define octopus_signal_value(n)      octopus_signal_helper(n)
#define octopus_str_value_helper(n)   #n
#define octopus_str_value(n)          octopus_str_value_helper(n)
#define OCTOPUS_SHUTDOWN_SIGNAL      QUIT
#define OCTOPUS_TERMINATE_SIGNAL     TERM
#define OCTOPUS_PIPE_SIGNAL      PIPE
#define OCT_OK 0
#define OCT_ERR -1
#define FUC_INLINE inline
/*
                 dispatcher      hand              hand    dispatcher 
client-------------------proxy client-----------------proxy server-------------server
*/
typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
}octopus_signal_t;
namespace basic{
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
protected:
    int WriteOrBufferData(const char *pv,int sz);
    int OnFlushBuffer();
    void CloseFd();
    BaseContext *context_;
    int fd_=-1;
    OctConnStatus status_=(OctConnStatus)0;
    std::string rb_;
    std::string wb_;
    uint64_t send_bytes_=0;
    uint64_t recv_bytes_=0;
    std::atomic<bool> destroyed_{false};
};
class OctopusHand:public OctopusBase,public EpollCallbackInterface{
public:
    OctopusHand(BaseContext *context,int fd,OctRole role,
            OctopusDispatcherManager &manager,OctopusDispatcher *dispatcher);
    ~OctopusHand();
    void WriteMeta(OctopusSessionKey &uuid,uint8_t sp);
    bool AsynConnect(const struct sockaddr * addr,socklen_t addrlen);
    void SignalFrom(OctopusDispatcher* dispatcher,OctSigCodeT code);
    int Sink(const char *pv,int sz);
    //for multipath transmission
    int SinkWithOff(uint64_t offset,const char *pv,int sz);
    // From EpollCallbackInterface
    void OnRegistration(EpollServer* eps, int fd, int event_mask) override{}
    void OnModification(int fd, int event_mask) override {}
    void OnEvent(int fd, EpollEvent* event) override;
    void OnUnregistration(int fd, bool replaced) override {}
    void OnShutdown(EpollServer* eps, int fd) override;
    std::string Name() const override;
    void CountDeliveredRateAlarm();
    int GetWriteBudget() const;
private:
    void OnClientEvent(int fd, EpollEvent* event);
    void OnServerEvent(int fd, EpollEvent* event);
    bool HasCompleteFrame(const char *pv,int sz,uint64_t *offset,uint16_t *offset_bytes,uint64_t *length,uint16_t *length_bytes);
    void ProcessInData(const char *pv,int sz);
    void OnSignalingData(const char *pv,int sz);
    FUC_INLINE void ConnClose(OctSigCodeT code);
    void ParseMeta();
    void SendMetaAck(OctSigCodeT code);
    void DeleteSelf();
    using MaxBandwidthFilter = WindowedFilter<QuicBandwidth,
                                            MaxFilter<QuicBandwidth>,
                                            int64_t,
                                            int64_t>;
    
    OctopusDispatcherManager &manager_;
    OctopusDispatcher *dispatcher_=nullptr;
    std::unique_ptr<BaseAlarm> delivered_bw_alarm_;
    MaxBandwidthFilter max_rate_;
    QuicTime check_delivered_ts_=QuicTime::Zero();
    int64_t pre_bytes_acked_=0;
    int64_t round_=0;
    uint8_t meta_flag_=0;
    uint8_t role_:2,
            sp_flag_:1,  //1 single path transmission
            wait_close_:1,
            unused:4;
};
// default single path
class OctopusDispatcher:public OctopusBase,public EpollCallbackInterface,
public BaseContext::ExitVisitor,public quic::QuicStreamSequencer::StreamInterface{
public:
    OctopusDispatcher(BaseContext *context,int fd,OctopusSessionKey &uuid,
            OctRole role,uint8_t sp,OctopusDispatcherManager &manager);
    virtual ~OctopusDispatcher();
    void SignalFrom(OctopusHand*hand,OctSigCodeT code);
    //client side logic
    bool CreateSingleConnection(const sockaddr_storage &proxy_src_saddr,
            const sockaddr_storage &proxy_dst_saddr);
    bool CreateMutipleConnections(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>>& proxy_saddrs
            );
    //server side logic
    bool AsynConnect(const struct sockaddr *addr,socklen_t addrlen);
    void RegisterHand(OctopusHand*hand);
    
    int Sink(const char *pv,int sz);
    //multipath transmission
    int SinkWithOff(uint64_t offset,const char *pv,int sz);
    // From EpollCallbackInterface
    void OnRegistration(EpollServer* eps, int fd, int event_mask) override{}
    void OnModification(int fd, int event_mask) override {}
    void OnEvent(int fd, EpollEvent* event) override;
    void OnUnregistration(int fd, bool replaced) override {}
    void OnShutdown(EpollServer* eps, int fd) override;
    std::string Name() const override;
    //from BaseContext::ExitVisitor
    void ExitGracefully() override;
    //from quic::QuicStreamSequencer::StreamInterface
    void OnDataAvailable() override;
    void OnFinRead() override{}
    void AddBytesConsumed(quic::QuicByteCount bytes) override{}
    void Reset(quic::QuicRstStreamErrorCode error) override{}
    void OnUnrecoverableError(quic::QuicErrorCode error,const std::string& details) override;
    quic::QuicStreamId id() const override { return 0;}
    
    void SocketRWAlarm();
protected:
    FUC_INLINE void HandleSignalAtClient(OctopusHand*hand,OctSigCodeT code);
    FUC_INLINE void HandleSignalAtServer(OctopusHand*hand,OctSigCodeT code);
    bool CreateConnection(const sockaddr_storage &proxy_src_saddr,
            const sockaddr_storage &proxy_dst_saddr);
    /**
    * \brief read incoming data and schedule.
    * \return fin=true fd closed
    */
    bool ScheduleData(OctopusHand *hand,int budget,int *read_sz);
    bool MpScheduleData();
    void SendDataWithinLimit(OctopusHand *hand,const char *pv,int sz);
    FUC_INLINE void ConnClose(OctSigCodeT code);
    void DeleteSelf();
    OctopusSessionKey uuid_;
    OctopusDispatcherManager &manager_;
    std::unique_ptr<BaseAlarm> rw_alarm_;
    QuicTime rw_alarm_ts_=QuicTime::Zero();
    std::deque<OctopusHand*> wait_hands_;
    std::deque<OctopusHand*> ready_hands_;
    //0 is reserved for signaling
    uint8_t schedule_index_=0;
    uint64_t w_offset_=0;
    uint8_t role_:2,
            sp_flag_:1,  //1 single path transmission
            wait_close_:1,
            unused:4;
    quic::QuicStreamSequencer sequencer_;
};
class OctopusCallerBackend:public Backend{
public:
	OctopusCallerBackend(OctopusRouteIf *route_if);
	void CreateEndpoint(BaseContext *context,int fd) override;
private:
	OctopusRouteIf *route_if_;
};
class OctopusCallerSocketFactory:public SocketServerFactory{
public:
	OctopusCallerSocketFactory(OctopusRouteIf *route_if);
	PhysicalSocketServer* CreateSocketServer(BaseContext *context) override;
private:
	OctopusRouteIf *route_if_;
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
    ~OctopusCalleeSocketFactory(){}
    PhysicalSocketServer* CreateSocketServer(BaseContext *context) override;
};
void octopus_daemonise(void);
bool CheckIpExist(std::vector<IpAddress> &ip_vec, IpAddress &ele);
}
