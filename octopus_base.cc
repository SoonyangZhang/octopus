#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h> //for sockaddr_in
#include <arpa/inet.h> //in_addr
#include <sys/ioctl.h>//ioctl
#include <sys/types.h> //for setsockopt
#include <sys/socket.h>
#include <linux/sockios.h>//SIOCOUTQ
#include <memory.h>
#include <assert.h>
#include <sys/file.h>
#include "octopus/octopus_base.h"
#include "tcp/tcp_info.h"
#include "base/byte_codec.h"
#include "logging/logging.h"
namespace basic{
namespace{
const int kBandwithWindowSize=10;
const int kSegmentSize=1500;
const int kBufferSize=1500;
const QuicBandwidth kMinBandwidth=QuicBandwidth::FromKBitsPerSecond(500);
const QuicTime::Delta kBandwidthInterval=QuicTime::Delta::FromMilliseconds(5);
const QuicTime::Delta kSocketRWInterval=QuicTime::Delta::FromMilliseconds(5);
const QuicTime::Delta kMinRoundTripTime=QuicTime::Delta::FromMilliseconds(5);
}
static bool OctopusEpollETFlag=false;
#define octopus_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
template<typename T>
T& create_null_ref() { return *static_cast<T*>(nullptr);}
bool octopus_enable_epollet(){
OctopusEpollETFlag=true;
}
static std::string OctopusHandRoleToString(OctopusHandRole rule) {
  switch (rule) {
    case OctopusHandRole::OCTOPUS_HAND_CLIENT:
      return "octopus_hand_client";
    case OctopusHandRole::OCTOPUS_HAND_SERVER:
      return "octopus_hand_server";
  }
  return "octopus_hand???";
}
static std::string OctopusDispatcherRuleToString(OctopusDispatcherRole rule) {
  switch (rule) {
    case OctopusDispatcherRole::OCTOPUS_DISPATCHER_CLIENT:
      return "octopus_dispatcher_client";
    case OctopusDispatcherRole::OCTOPUS_DISPATCHER_SERVER:
      return "octopus_dispatcher_server";
  }
  return "octopus_dispatcher???";
}
static std::string OctopusSignalCodeToString(OctopusSignalCode code){
    switch(code){
        case OCTOPUS_SIG_MIN:
            return "octopus_sig_min";
        case OCTOPUS_SIG_CONN_CONNECTING:
            return "octopus_sig_conn_connecting";
        case OCTOPUS_SIG_CONN_CONNECTED:
            return "octopus_sig_conn_connected";
        case OCTOPUS_SIG_CONN_FAILED:
            return "octopus_sig_conn_failed";
        case OCTOPUS_SIG_CONN_DISCONN:
            return "octopus_sig_conn_disconn";
        case OCTOPUS_SIG_DST_CONNECTED:
            return "octopus_sig_dst_connected";
        case OCTOPUS_SIG_DST_FAILED:
            return "octopus_sig_dst_failed";
    }
    return "octopus_sig???";
}
int bind_addr(struct sockaddr *addr,bool transparent){
    int fd=-1;
    int yes=1;
    fd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd<0){
    	DLOG(ERROR)<<strerror(errno);
        return fd;
    }
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int))!=0){
        DLOG(ERROR)<<strerror(errno);
        close(fd);
        fd=-1;
        return fd;
    }
    if(transparent&&setsockopt(fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(int))!=0){
    	DLOG(ERROR)<<strerror(errno);
        close(fd);
        fd=-1;
        return fd;
    }
    if(bind(fd, (struct sockaddr *)addr,sizeof(struct sockaddr_in))<0){
    	DLOG(ERROR)<<strerror(errno);
        close(fd);
        fd=-1;
        return fd;
    }
   return fd;
}
inline int read_pending(int fd){
	int pending=-1;
	if(fd>0){
		ioctl(fd, SIOCOUTQ, &pending);
	}
	return pending;
}

bool OctopusDispatcherManager::Register(OctopusSessionKey & uuid,OctopusDispatcher*dispatcher){
        bool ret=false;
        auto it=tables_.find(uuid);
        if(it==tables_.end()){
        	tables_.insert(std::make_pair(uuid,dispatcher));
        	ret=true;
        }
        return ret;
}
bool OctopusDispatcherManager::UnRegister(OctopusSessionKey & uuid){
    bool ret=false;
    auto it=tables_.find(uuid);
    if(it!=tables_.end()){
    	tables_.erase(it);
    	ret=true;
    }
    return ret;
}
OctopusDispatcher *OctopusDispatcherManager::Find(OctopusSessionKey &uuid){
	OctopusDispatcher *dispatcher=nullptr;
	auto it=tables_.find(uuid);
	if(it!=tables_.end()){
		dispatcher=it->second;
	}
    return dispatcher;
}

OctopusBase::OctopusBase(BaseContext *context,int fd):
context_(context),
fd_(fd),
out_bw_filter_(kBandwithWindowSize,QuicBandwidth::Zero(),0){}
/* the default SO_SNDBUF is 16384 bytes
 * the buffer can be increased dynamically
 * by assuming the rate is 2Mbps
 * when the buffer is fully occupied
 * the time is 16384*8/2=65 ms to drain buffer empty
 */
int OctopusBase::GetWriteBudget(QuicTime::Delta delta_time) const{
    int remain=0;
    if(fd_>0){
        struct tcp_info_copy info;
        memset(&info,0,sizeof(info));
        socklen_t info_size=sizeof(info);
        uint32_t min_rtt_micro=0;
        int pending=read_pending(fd_);
        if(getsockopt(fd_,IPPROTO_TCP,TCP_INFO,(void*)&info,&info_size)==0){
            min_rtt_micro=info.tcpi_min_rtt;
            CHECK(min_rtt_micro>0);
        }
        QuicTime::Delta rtt=QuicTime::Delta::FromMicroseconds(min_rtt_micro);
        if(rtt<kMinRoundTripTime){
        	rtt=kMinRoundTripTime;
        }
        int budget=0;
        QuicBandwidth estimate_bw=out_bw_filter_.GetBest();
        if (estimate_bw<kMinBandwidth){
            estimate_bw=kMinBandwidth;
        }
        budget=estimate_bw.ToBytesPerPeriod(2*rtt);
        if(budget>pending){
        	remain=budget-pending;
        	if(remain<kSegmentSize){
        		remain=kSegmentSize;
        	}
        }
        //DLOG(INFO)<<delta_time.ToMilliseconds()<<" "<<budget<<" "<<pending<<" "<<remain;
    }
    return remain;
}
void OctopusBase::FlushBuffer(){
    if(fd_<0){
        CHECK(wb_.size()==0);
        return ;
    }
    int remain=wb_.size();
    const char *data=wb_.data();
    bool flushed=false;
    while(remain>0){
        int target=std::min(kSegmentSize,remain);
        int n=send(fd_,data,target,0);
        CHECK(n<=target);
        if(n<=0){
            break;
        }
        send_bytes_+=n;
        flushed=true;
        data+=n;
        remain-=n;
    }
    if(flushed){
        if(remain>0){
            std::string copy(data,remain);
            copy.swap(wb_);
        }else{
            std::string null_str;
            null_str.swap(wb_);
        }
    }
}
inline void OctopusBase::CloseFd(){
    close(fd_);
    fd_=-1;
}
class OutBandwidthAlarmDelegate:public BaseAlarm::Delegate{
public:
    OutBandwidthAlarmDelegate(OctopusHand* entity):entity_(entity){}
    void OnAlarm() override{
        entity_->OutBandwidthAlarm();
    }
private:
    OctopusHand *entity_;
};
OctopusHand::OctopusHand(BaseContext *context,int fd,OctopusHandRole role,
        OctopusDispatcherManager &manager,OctopusDispatcher *dispatcher)
:OctopusBase(context,fd),role_(role),manager_(manager),dispatcher_(dispatcher){
    if(OCTOPUS_HAND_SERVER==role_){
        status_=OCTOPUS_CONN_CONNECTED;
        if(OctopusEpollETFlag){
            context_->epoll_server()->RegisterFD(fd_,this,EPOLLET|EPOLLIN);
        }else{
            context_->epoll_server()->RegisterFD(fd_,this,EPOLLIN);
        }
    }else{
    	status_=OCTOPUS_CONN_CONNECTING;
    }
}
OctopusHand::~OctopusHand(){
    if(out_bw_alarm_){
        out_bw_alarm_->Cancel();
    }
    DLOG(INFO)<<Name()<<" dtor "<<send_bytes_<<" "<<recv_bytes_;
}
void OctopusHand::WriteMeta(OctopusSessionKey &uuid,bool sp_flag){
    if(OCTOPUS_HAND_SERVER==role_){
        return;
    }
    if(!(msg_flag_&OCTOPUS_META_FLAG)){
        char buffer[kBufferSize];
        DataWriter writer(buffer,kBufferSize);
        uint8_t type=OCTOPUS_MSG_META;
        sp_flag_=sp_flag;
        bool success=writer.WriteUInt8(type)&&
                writer.WriteUInt8(sp_flag)&&
                writer.WriteUInt32(uuid.from)&&
                writer.WriteUInt32(uuid.to)&&
                writer.WriteUInt16(uuid.src_port)&&
                writer.WriteUInt16(uuid.dst_port);
        int old=wb_.size();
        wb_.resize(old+writer.length());
        memcpy(&wb_[old],writer.data(),writer.length());
        msg_flag_|=OCTOPUS_META_FLAG;
    }
}
bool OctopusHand::AsynConnect(const struct sockaddr *addr,socklen_t addrlen){
    bool ret=false;
    int yes=1;
    if(OCTOPUS_HAND_SERVER==role_){
        return ret;
    }
    //EPOLLOUT for flush meta data
    if(OctopusEpollETFlag){
        context_->epoll_server()->RegisterFD(fd_,this,EPOLLET|EPOLLIN|EPOLLOUT);
    }else{
        context_->epoll_server()->RegisterFD(fd_,this,EPOLLIN|EPOLLOUT);
    }
    if(connect(fd_,(struct sockaddr *)addr,addrlen) == -1&&errno != EINPROGRESS){
        //connect doesn't work, are we running out of available ports ? if yes, destruct the socket
        if (errno == EAGAIN){
            CloseFd();
            DeleteSelf();
            return ret;
        }
    }
    status_=OCTOPUS_CONN_CONNECTING;
    return true;
}
void OctopusHand::SignalFrom(OctopusDispatcher* dispatcher,OctopusSignalCode code){
    if(OCTOPUS_HAND_SERVER==role_){
        if(OCTOPUS_SIG_DST_FAILED==code||OCTOPUS_SIG_DST_CONNECTED==code){
            SendMetaAck(code);
            if(OCTOPUS_SIG_CONN_FAILED==code){
                ConnClose(code);
            }
        }
    }
    if(OCTOPUS_SIG_CONN_DISCONN==code){
        dispatcher_=nullptr;
        wait_close_=true;
        if(0==wb_.size()){
            ConnClose(code);
        }
    }
    DLOG(INFO)<<Name()<<" "<<OctopusSignalCodeToString(code);
}
void OctopusHand::Sink(const char *pv,int sz){
    if(!out_bw_alarm_){
        out_bw_alarm_.reset(context_->alarm_factory()->CreateAlarm(new OutBandwidthAlarmDelegate(this)));
        QuicTime now=context_->clock()->ApproximateNow();
        out_bw_alarm_->Update(now,QuicTime::Delta::Zero());
    }
    FlushBuffer();
    const char *data=pv;
    int remain=sz;
    if(0==wb_.size()){
        if(fd_>0){
            while(remain>0){
                int target=std::min(remain,kSegmentSize);
                int n=send(fd_,data,target,0);
                if(n<=0){
                    break;
                }
                data+=n;
                send_bytes_+=n;
                remain-=n;
            }
        }
    }
    if(remain>0){
        int old=wb_.size();
        wb_.resize(old+remain);
        memcpy(&wb_[old],data,remain);
    }
}
void OctopusHand::SinkWithOff(uint64_t offset,const char *pv,int sz){
//	reserved for multipath
}
void OctopusHand::OnEvent(int fd, EpollEvent* event){
    if(OCTOPUS_HAND_SERVER==role_){
        OnCalleeEvent(fd,event);
    }else if(OCTOPUS_HAND_CLIENT==role_){
        OnCallerEvent(fd,event);
    }
}
void OctopusHand::OnShutdown(EpollServer* eps, int fd){
    CloseFd();
    DeleteSelf();
}
std::string OctopusHand::Name() const{
	return OctopusHandRoleToString(role_);
}
void OctopusHand::OutBandwidthAlarm(){
    struct tcp_info_copy info;
    memset(&info,0,sizeof(info));
    socklen_t info_size=sizeof(info);
    uint64_t bytes_acked=0;
    uint32_t min_rtt_micro=0;
    if(getsockopt(fd_,IPPROTO_TCP,TCP_INFO,(void*)&info,&info_size)==0){
        bytes_acked=info.tcpi_bytes_acked;
        min_rtt_micro=info.tcpi_min_rtt;
    }
    QuicTime::Delta rtt=QuicTime::Delta::FromMicroseconds(min_rtt_micro);
    QuicTime::Delta update_interval=kBandwidthInterval;
    if(update_interval<rtt){
        update_interval=rtt;
    }
    QuicTime now=context_->clock()->ApproximateNow();
    if(last_out_bw_ts_!=QuicTime::Zero()){
        QuicBandwidth b=QuicBandwidth::Zero();
        if((bytes_acked>last_out_bytes_acked_)&&(now>last_out_bw_ts_)){
            b=QuicBandwidth::FromBytesAndTimeDelta(bytes_acked-last_out_bytes_acked_,now-last_out_bw_ts_);
        }
        out_bw_filter_.Update(b,round_);
        round_++;
    }
    last_out_bw_ts_=now;
    last_out_bytes_acked_=bytes_acked;
    out_bw_alarm_->Update(now+update_interval,QuicTime::Delta::Zero());
    if(wb_.size()>0){
        FlushBuffer();
    }
    if(wait_close_&&wb_.size()==0){
        ConnClose(OCTOPUS_SIG_CONN_DISCONN);
    }
}
//client event
void OctopusHand::OnCallerEvent(int fd, EpollEvent* event){
    char buffer[kBufferSize];
    if(event->in_events&(EPOLLERR|EPOLLHUP)){
        if(OCTOPUS_CONN_CONNECTING==status_){
            ConnClose(OCTOPUS_SIG_CONN_FAILED);
        }else{
            ConnClose(OCTOPUS_SIG_CONN_DISCONN);
        }
    }
    if(fd_>0&&(event->in_events&EPOLLIN)){
        if(sp_flag_){
            while(true){
                int n=read(fd_,buffer,kBufferSize);
                if(-1==n){
                    if(EINTR==errno||EWOULDBLOCK==errno||EAGAIN==errno){
                    	break;
                    }else{
                        ConnClose(OCTOPUS_SIG_CONN_DISCONN);
                    }
                    break;
                }
                if(0==n){
                    ConnClose(OCTOPUS_SIG_CONN_DISCONN);
                    break;
                }
                if(n>0){
                    recv_bytes_+=n;
                    if(0==(msg_flag_&OCTOPUS_META_ACK_FLAG)){
                        msg_flag_|=OCTOPUS_META_ACK_FLAG;
                        if(OCTOPUS_MSG_DST_CONNECTED==buffer[0]){
                            if(dispatcher_){
                                dispatcher_->SignalFrom(this,OCTOPUS_SIG_DST_CONNECTED);
                                if(n-1>0){
                                    dispatcher_->Sink(&buffer[1],n-1);
                                }
                            }
                        }
                        if(OCTOPUS_MSG_DST_FAILED==buffer[0]){
                            ConnClose(OCTOPUS_SIG_DST_FAILED);
                            break;
                        }
                    }else{
                        CHECK(dispatcher_);
                        dispatcher_->Sink(buffer,n);
                    }
                }
            }
        }else{
            //TODO multipath,parser offset
        }
    }
    if(fd>0&&(event->in_events&EPOLLOUT)){
        if (OCTOPUS_CONN_CONNECTING==status_){
            status_=OCTOPUS_CONN_CONNECTED;
            if(OctopusEpollETFlag){
                context_->epoll_server()->ModifyCallback(fd_,EPOLLET|EPOLLIN);
            }else{
                context_->epoll_server()->ModifyCallback(fd_,EPOLLIN);
            }
        }
        if(OCTOPUS_CONN_CONNECTED==status_){
            //flush meta data
            FlushBuffer();
        }
    }
}
//server event
void OctopusHand::OnCalleeEvent(int fd, EpollEvent* event){
    char buffer[kBufferSize];
    if(event->in_events&(EPOLLERR|EPOLLHUP)){
    	ConnClose(OCTOPUS_SIG_CONN_DISCONN);
    }
    if(fd_>0&&(event->in_events&EPOLLIN)){
        while(true){
            int n=read(fd_,buffer,kBufferSize);
            if(-1==n){
                if(EAGAIN==errno){
                }else{
                    ConnClose(OCTOPUS_SIG_CONN_DISCONN);
                }
                break;
            }
            if(0==n){
                ConnClose(OCTOPUS_SIG_CONN_DISCONN);
                break;
            }
            if(n>0){
                recv_bytes_+=n;
                if(0==(msg_flag_&OCTOPUS_META_FLAG)){
                    int old=rb_.size();
                    rb_.resize(old+n);
                    memcpy(&rb_[old],buffer,n);
                    CalleeParseMeta();
                }else{
                    CHECK(rb_.size()==0);
                    CHECK(dispatcher_!=nullptr);
                    dispatcher_->Sink(buffer,n);
                }
            }
        }
    }
}
inline void OctopusHand::ConnClose(OctopusSignalCode code){
    //server client 
    if(dispatcher_){
        dispatcher_->SignalFrom(this,code);
    }
    dispatcher_=nullptr;
    status_=OCTOPUS_CONN_DISCONN;
    context_->epoll_server()->UnregisterFD(fd_);
    CloseFd();
    DeleteSelf();
}
void OctopusHand::CalleeParseMeta(){
    if(0==(msg_flag_&OCTOPUS_META_FLAG)){
        DataReader reader(&rb_[0],rb_.size());
        uint8_t type=0;
        uint8_t sp=0;
        OctopusSessionKey uuid;
        bool success=reader.ReadUInt8(&type)&&
                reader.ReadUInt8(&sp)&&
                reader.ReadUInt32(&uuid.from)&&
                reader.ReadUInt32(&uuid.to)&&
                reader.ReadUInt16(&uuid.src_port)&&
                reader.ReadUInt16(&uuid.dst_port);
        if(success){
            msg_flag_|=OCTOPUS_META_FLAG;
            sp_flag_=sp;
            CHECK(&manager_!=nullptr);
            OctopusDispatcher *dispatcher=manager_.Find(uuid);
            if(nullptr==dispatcher){
                sockaddr_storage src_saddr;
                sockaddr_storage dst_saddr;
                {
                	in_addr  ipv4;
                	memcpy(&ipv4,&uuid.from,sizeof(uuid.from));
                    IpAddress ip_addr(ipv4);
                    SocketAddress socket_addr(ip_addr,uuid.src_port);
                    src_saddr=socket_addr.generic_address();
                    DLOG(INFO)<<"origin src "<<socket_addr.ToString();
                }
                {
                	in_addr  ipv4;
                	memcpy(&ipv4,&uuid.to,sizeof(uuid.to));
                    IpAddress ip_addr(ipv4);
                    SocketAddress socket_addr(ip_addr,uuid.dst_port);
                    dst_saddr=socket_addr.generic_address();
                    DLOG(INFO)<<"origin dst "<<socket_addr.ToString();
                }
                bool positive=false;
                int sock=bind_addr((sockaddr*)&src_saddr,true);
                if(sock>0){
                    dispatcher_=new OctopusDispatcher(context_,sock,uuid,OCTOPUS_DISPATCHER_SERVER,manager_);
                    if(!sp_flag_){
                        manager_.Register(uuid,dispatcher_);
                    }
                    if(dispatcher_->AsynConnect((const struct sockaddr*)&dst_saddr,sizeof(struct sockaddr_in))){
                        dispatcher_->RegisterHand(this);
                        positive=true;
                    }
                }
                if(!positive){
                    SendMetaAck(OCTOPUS_SIG_DST_FAILED);
                    ConnClose(OCTOPUS_SIG_DST_FAILED);
                }
                CHECK(reader.BytesRemaining()==0);
                rb_.clear();
            }else{
                dispatcher_=dispatcher;
                dispatcher_->RegisterHand(this);
            }

        }
    }
}
void OctopusHand::SendMetaAck(OctopusSignalCode code){
    if(fd_>0&&(0==(msg_flag_&OCTOPUS_META_ACK_FLAG))){
        msg_flag_|=OCTOPUS_META_ACK_FLAG;
        uint8_t type=0;
        if(OCTOPUS_SIG_DST_CONNECTED==code){
            type=OCTOPUS_MSG_DST_CONNECTED;
        }
        if(OCTOPUS_SIG_DST_FAILED==code){
            type=OCTOPUS_MSG_DST_FAILED;
        }
        CHECK(type!=0);
        send(fd_,(const void*)&type,sizeof(type),0);
        send_bytes_+=1;
        DLOG(INFO)<<OctopusSignalCodeToString(code);
    }
}
void OctopusHand::DeleteSelf(){
    if(destroyed_){
        return;
    }
    destroyed_=true;
    context_->PostTask([this]{
        delete this;
    });
}

class SocketAlarmDelegate:public BaseAlarm::Delegate{
public:
    SocketAlarmDelegate(OctopusDispatcher* entity):entity_(entity){}
    void OnAlarm() override{
        entity_->HandleSocketAlarm();
    }
private:
	OctopusDispatcher *entity_;
};
OctopusDispatcher::OctopusDispatcher(BaseContext *context,int fd,OctopusSessionKey &uuid,
		OctopusDispatcherRole role,OctopusDispatcherManager &manager)
:OctopusBase(context,fd),uuid_(uuid),role_(role),manager_(manager){
    if(OCTOPUS_DISPATCHER_CLIENT==role_){
        //client will not depend on epoll
        octopus_nonblocking(fd_);
        status_=OCTOPUS_CONN_CONNECTED;
    }else{
        status_=OCTOPUS_CONN_CONNECTING;
    }
    context_->RegisterExitVisitor(this);
}
OctopusDispatcher::~OctopusDispatcher(){
	if(socket_alarm_){
		socket_alarm_->Cancel();
	}
    DLOG(INFO)<<Name()<<" dtor "<<send_bytes_<<" "<<recv_bytes_;
}
void OctopusDispatcher::SignalFrom(OctopusHand*hand,OctopusSignalCode code){
    if(OCTOPUS_DISPATCHER_CLIENT==role_){
        if(OCTOPUS_SIG_DST_CONNECTED==code){
            wait_hands_.erase(hand);
            ready_hands_.insert(hand);
            if(!socket_alarm_){
                socket_alarm_.reset(context_->alarm_factory()->CreateAlarm(new SocketAlarmDelegate(this)));
                QuicTime now=context_->clock()->ApproximateNow();
                socket_alarm_->Update(now,QuicTime::Delta::Zero());
            }
        }
    }
    if(OCTOPUS_SIG_CONN_FAILED==code||OCTOPUS_SIG_CONN_DISCONN==code){
        wait_hands_.erase(hand);
        ready_hands_.erase(hand);
        if(wait_hands_.size()==0&&ready_hands_.size()==0){
            wait_close_=true;
            if(wb_.size()==0){
                ConnClose(OCTOPUS_SIG_CONN_DISCONN);
            }
        }
    }
    DLOG(INFO)<<Name()<<" "<<OctopusSignalCodeToString(code);
}
bool OctopusDispatcher::CreateSingleConnection(const sockaddr_storage &proxy_src_saddr,
                                const sockaddr_storage &proxy_dst_saddr){
    bool success=false;
    int sock=bind_addr((sockaddr*)&proxy_src_saddr,false);
    if (sock>0){
        OctopusHand *hand=new OctopusHand(context_,sock,OCTOPUS_HAND_CLIENT,manager_,this);
        hand->WriteMeta(uuid_,true);
        if(hand->AsynConnect((const struct sockaddr*)&proxy_dst_saddr,sizeof(struct sockaddr_in))){
            success=true;
            wait_hands_.insert(hand);
        }
    }
    if(!success){
        ConnClose(OCTOPUS_SIG_CONN_FAILED);
    }
    return success;
}
bool OctopusDispatcher::CreateMutipleConnections(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>>& proxy_saddrs){
    return false;
}
bool OctopusDispatcher::AsynConnect(const struct sockaddr *addr,socklen_t addrlen){
    bool ret=false;
    int yes=1;
    //EPOLLOUT for get connect status
    if(OctopusEpollETFlag){
        context_->epoll_server()->RegisterFD(fd_,this,EPOLLET|EPOLLIN|EPOLLOUT);
    }else{
        context_->epoll_server()->RegisterFD(fd_,this,EPOLLIN|EPOLLOUT);
    }
    if(connect(fd_,(struct sockaddr *)addr,addrlen) == -1&&errno != EINPROGRESS){
        //connect doesn't work, are we running out of available ports ? if yes, destruct the socket
        if (errno == EAGAIN){
            CloseFd();
            DeleteSelf();
            return ret;
        }
    }
    status_=OCTOPUS_CONN_CONNECTING;
    return true;
}
void OctopusDispatcher::RegisterHand(OctopusHand*hand){
    if(OCTOPUS_CONN_CONNECTING==status_){
        wait_hands_.insert(hand);
    }
    if(OCTOPUS_CONN_CONNECTED==status_){
        ready_hands_.insert(hand);
        hand->SignalFrom(this,OCTOPUS_SIG_DST_CONNECTED);
    }
}
void OctopusDispatcher::Sink(const char *pv,int sz){
    FlushBuffer();
    const char *data=pv;
    int remain=sz;
    if(0==wb_.size()){
        if(fd_>0){
            while(remain>0){
                int target=std::min(remain,kSegmentSize);
                int n=send(fd_,data,target,0);
                if(n<=0){
                    break;
                }
                data+=n;
                send_bytes_+=n;
                remain-=n;
            }
        }
    }
    if(remain>0){
        int old=wb_.size();
        wb_.resize(old+remain);
        memcpy(&wb_[old],data,remain);
    }
}
void OctopusDispatcher::OnEvent(int fd, EpollEvent* event){
//only call once
    if(event->in_events&(EPOLLERR|EPOLLHUP)){
        if(OCTOPUS_CONN_CONNECTING==status_){
            ConnClose(OCTOPUS_SIG_DST_FAILED);
        }
    }
    if(fd_>0&&(event->in_events&EPOLLOUT)){
        if(OCTOPUS_CONN_CONNECTING==status_){
            status_=OCTOPUS_CONN_CONNECTED;
            DLOG(INFO)<<"connect to origin dst "<<wait_hands_.size();
            for(auto it=wait_hands_.begin();it!=wait_hands_.end();it++){
                OctopusHand *hand=(*it);
                hand->SignalFrom(this,OCTOPUS_SIG_DST_CONNECTED);
            }
            CHECK(ready_hands_.size()==0);
            ready_hands_.swap(wait_hands_);
            context_->epoll_server()->UnregisterFD(fd_);
            if(!socket_alarm_){
                socket_alarm_.reset(context_->alarm_factory()->CreateAlarm(new SocketAlarmDelegate(this)));
                QuicTime now=context_->clock()->ApproximateNow();
                socket_alarm_->Update(now,QuicTime::Delta::Zero());
            }
        }
    }
}
void OctopusDispatcher::OnShutdown(EpollServer* eps, int fd){
    CloseFd();
    DeleteSelf();
}
std::string OctopusDispatcher::Name() const{
    return OctopusDispatcherRuleToString(role_);
}
void OctopusDispatcher::ExitGracefully(){
    CloseFd();
    DeleteSelf();
}
void OctopusDispatcher::HandleSocketAlarm(){
    char buffer[kBufferSize];
    if(fd_>0){
        FlushBuffer();
        QuicTime now=context_->clock()->ApproximateNow();
        QuicTime::Delta delta=kSocketRWInterval;
        if(last_alarm_time_!=QuicTime::Zero()&&now>last_alarm_time_){
            delta=now-last_alarm_time_;
        }
        last_alarm_time_=now;
        int budget=0;
        bool closed=false;
        if(ready_hands_.size()>0){
            auto it=ready_hands_.begin();
            budget=(*it)->GetWriteBudget(delta);
            while(budget>0){
                int target=std::min(budget,kBufferSize);
                int n=read(fd_,buffer,target);
                if(-1==n){
                    if(EINTR==errno||EWOULDBLOCK==errno||EAGAIN==errno){
                        break;
                    }else{
                        closed=true;
                    }
                    break;
                }
                if(0==n){
                    closed=true;
                    break;
                }
                if(n>0){
                    CHECK(n<=target);
                    recv_bytes_+=n;
                    budget-=n;
                    (*it)->Sink(buffer,n);
                }
            }
        }
        if(!closed){
            socket_alarm_->Update(now+kSocketRWInterval,QuicTime::Delta::Zero());
        }else{
            ConnClose(OCTOPUS_SIG_CONN_DISCONN);
        }
    
    }
}
void OctopusDispatcher::ConnClose(OctopusSignalCode code){
    for(auto it=wait_hands_.begin();it!=wait_hands_.end();it++){
        OctopusHand *hand=(*it);
        hand->SignalFrom(this,code);
    }
    for(auto it=ready_hands_.begin();it!=ready_hands_.end();it++){
        OctopusHand *hand=(*it);
        hand->SignalFrom(this,code);
    }
    wait_hands_.clear();
    ready_hands_.clear();
    CHECK(ready_hands_.size()==0);
    status_=OCTOPUS_CONN_DISCONN;
    if(&manager_!=nullptr){
    	manager_.UnRegister(uuid_);
    }
    context_->epoll_server()->UnregisterFD(fd_);
    context_->UnRegisterExitVisitor(this);
    CloseFd();
    DeleteSelf();
}
void OctopusDispatcher::DeleteSelf(){
    if(destroyed_){
        return;
    }
    destroyed_=true;
    context_->PostTask([this]{
        delete this;
    });
}

OctopusCallerBackend::OctopusCallerBackend(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec)
:proxy_saddr_vec_(proxy_saddr_vec){}
void OctopusCallerBackend::CreateEndpoint(BaseContext *context,int fd){
    sockaddr_storage origin_src_saddr;
    sockaddr_storage origin_dst_saddr;
    OctopusSessionKey uuid;
    socklen_t addr_len = sizeof(sockaddr_storage);
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

    CHECK(proxy_saddr_vec_.size()>0);
    OctopusDispatcher *dispatcher=new OctopusDispatcher(context,fd,uuid,
    				OCTOPUS_DISPATCHER_CLIENT,create_null_ref<OctopusDispatcherManager>());
    dispatcher->CreateSingleConnection(proxy_saddr_vec_[0].first,proxy_saddr_vec_[0].second);
    UNUSED(dispatcher);
}
OctopusCallerSocketFactory::OctopusCallerSocketFactory(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>> &proxy_saddr_vec)
:proxy_saddr_vec_(proxy_saddr_vec){}
PhysicalSocketServer* OctopusCallerSocketFactory::CreateSocketServer(BaseContext *context){
	 std::unique_ptr<OctopusCallerBackend> backend(new OctopusCallerBackend(proxy_saddr_vec_));
	 return new PhysicalSocketServer(context,std::move(backend));
}
void OctopusCalleeBackend::CreateEndpoint(BaseContext *context,int fd){
	OctopusHand *hand=new OctopusHand(context,fd,OCTOPUS_HAND_SERVER,manager_,nullptr);
	UNUSED(hand);
}
PhysicalSocketServer* OctopusCalleeSocketFactory::CreateSocketServer(BaseContext *context){
    std::unique_ptr<OctopusCalleeBackend> backend(new OctopusCalleeBackend());
    return new PhysicalSocketServer(context,std::move(backend));
}
int octopus_write_pid (const char *pidfile)
{
  FILE *f;
  int fd;
  int pid;

  if ( ((fd = open(pidfile, O_RDWR|O_CREAT, 0644)) == -1)
       || ((f = fdopen(fd, "r+")) == NULL) ) {
      fprintf(stderr, "Can't open or create %s.\n", pidfile ? pidfile : "(null)");
      return 0;
  }
  
#ifdef HAVE_FLOCK
  if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
      fscanf(f, "%d", &pid);
      fclose(f);
      printf("Can't lock, lock is held by pid %d.\n", pid);
      return 0;
  }
#endif

  pid = getpid();
  if (!fprintf(f,"%d\n", pid)) {
      printf("Can't write pid , %s.\n", strerror(errno));
      close(fd);
      return 0;
  }
  fflush(f);

#ifdef HAVE_FLOCK
  if (flock(fd, LOCK_UN) == -1) {
      printf("Can't unlock pidfile %s, %s.\n", pidfile, strerror(errno));
      close(fd);
      return 0;
  }
#endif
  close(fd);

  return pid;
}
int octopus_read_pid(const char *pidfile)
{
  FILE *f;
  int pid;

  if (!(f=fopen(pidfile,"r")))
    return 0;
  fscanf(f,"%d", &pid);
  fclose(f);
  return pid;
}
int octopus_remove_pid(const char *pidfile)
{
  return unlink (pidfile);
}
void octopus_daemonise(void)
{
    char *err;
    pid_t pid;
    
    pid = fork();
    if(pid < 0){
        err = strerror(errno);
        std::cout<<"error in fork "<<err<<std::endl;
        exit(1);
    }
    if(pid > 0){
        exit(0);
    }
    if(setsid() < 0){
        err = strerror(errno);
        std::cout<<"Error in setsid "<<err<<std::endl;
        exit(1);
    }
    
    assert(freopen("/dev/null", "r", stdin));
    assert(freopen("/dev/null", "w", stdout));
    assert(freopen("/dev/null", "w", stderr));
}
}

