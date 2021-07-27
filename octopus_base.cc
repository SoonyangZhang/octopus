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
#include <algorithm>
#include "octopus/octopus_base.h"
#include "tcp/tcp_info.h"
#include "base/byte_codec.h"
#include "logging/logging.h"
namespace basic{
#define octopus_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
namespace{
const int kInitOffset=1;
const int kBandwithWindowSize=10;
const int kSegmentSize=1500;
const int kBufferSize=1500;
const QuicBandwidth   kMinBandwidth=QuicBandwidth::FromKBitsPerSecond(500);
const QuicTime::Delta kSocketRWInterval=QuicTime::Delta::FromMilliseconds(5);
const QuicTime::Delta kMinRoundTripTime=QuicTime::Delta::FromMilliseconds(5);
const QuicTime::Delta kMaxRoundTripTime=QuicTime::Delta::FromMilliseconds(1000);
}
const char * oct_sig_str[]={
    "sig_min ",
    "sig_conn_ok ",
    "sig_conn_failed ",
    "sig_conn_fin ",
    "sig_conn_fatal ",
    "sig_dst_ok ",
    "sig_dst_failed ",
};
static std::string OctRoleStr(uint8_t rule) {
  switch (rule) {
    case OctRole::OCT_HAND_C:
      return " oct_hand_client ";
    case OctRole::OCT_HAND_S:
      return " oct_hand_server ";
    case OctRole::OCT_DISPA_C:
      return " oct_dispa_client ";
    case OctRole::OCT_DISPA_S:
      return " oct_dispa_server ";
  }
  return "oct_role_???";
}

static std::string OctSigCodeStr(OctSigCodeT code){
    std::string str;
    int n=sizeof(oct_sig_str)/sizeof(oct_sig_str[0]);
    for(int i=0;i<n;i++){
        OctSigCodeT flag=1<<i;
        if(code&flag){
           str=str+oct_sig_str[i+1];
        }
    }
    return str;
}
int bind_addr(struct sockaddr *addr,bool tpproxy){
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
    if(tpproxy&&setsockopt(fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(int))!=0){
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
//https://lore.kernel.org/patchwork/patch/239843/
//SIOCOUTQ output queue size (not sent + not acked)
//SIOCOUTQNSD output queue size (not sent only)
inline int out_pending(int fd){
    int pending=-1;
    if(fd>=0){
        ioctl(fd,SIOCOUTQNSD, &pending);
    }
    return pending;
}
//SIOCINQ  the number of unread bytes in the receive buffer
inline int unread_bytes(int fd){
    int rbuf_byres=-1;
    if(fd>=0){
        ioctl(fd,SIOCINQ,&rbuf_byres);
    }
    return rbuf_byres;
}
inline int budget_align(int budget){
    int pkts=(budget+kSegmentSize-1)/kSegmentSize;
    if(1==pkts){
        pkts+=1;
    }
    return pkts*kSegmentSize;
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
fd_(fd){}
int OctopusBase::WriteOrBufferData(const char *pv,int sz){
    int ret=OCT_OK,n=0;
    const char *data=pv;
    int remain=sz;
    if(0==wb_.size()){
        while(remain>0){
            n=send(fd_,data,remain,0);
            if(-1==n){
                if(EINTR==errno||EWOULDBLOCK==errno||EAGAIN==errno){
                    //normal 
                }else{
                    //error close
                    ret=OCT_ERR;
                }
                break;
            }else{
                if(0==n){
                    break;
                }
                send_bytes_+=n;
                data+=n;
                remain-=n;
            }
        }
    }
    if(remain>0){
        int old=wb_.size();
        wb_.resize(old+remain);
        memcpy(&wb_[old],data,remain);
    }
    return ret;
}
int OctopusBase::OnFlushBuffer(){
    int ret=OCT_OK;
    bool flushed=false;
    int remain=0;
    const char *data=nullptr;
    if(fd_<0||0==wb_.size()){
        return ret;
    }
    remain=wb_.size();
    data=wb_.data();
    while(remain>0){
        int n=send(fd_,data,remain,0);
        if(-1==n){
            if(EINTR==errno||EWOULDBLOCK==errno||EAGAIN==errno){
                //normal 
            }else{
                //error close
                ret=OCT_ERR;
            }
            break;
        }else{
            if(0==n){
                break;
            }
            send_bytes_+=n;
            flushed=true;
            data+=n;
            remain-=n;
        }
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
    return ret;
}
inline void OctopusBase::CloseFd(){
    close(fd_);
    fd_=-1;
}
class DeliveredRateAlarmDelegate:public BaseAlarm::Delegate{
public:
    DeliveredRateAlarmDelegate(OctopusHand* entity):entity_(entity){}
    void OnAlarm() override{
        entity_->CountDeliveredRateAlarm();
    }
private:
    OctopusHand *entity_;
};
OctopusHand::OctopusHand(BaseContext *context,int fd,OctRole role,
        OctopusDispatcherManager &manager,OctopusDispatcher *dispatcher):
OctopusBase(context,fd),
manager_(manager),
dispatcher_(dispatcher),
max_rate_(kBandwithWindowSize,QuicBandwidth::Zero(),0),
role_(role),
sp_flag_(0),
wait_close_(0){
    if(OCT_HAND_S==role_){
        context_->epoll_server()->RegisterFD(fd_,this,EPOLLET|EPOLLIN|EPOLLOUT);
        status_=OCT_CONN_OK;
    }else{
        status_=OCT_CONN_TRYING;
    }
}
OctopusHand::~OctopusHand(){
    if(delivered_bw_alarm_){
        delivered_bw_alarm_->Cancel();
    }
    DLOG(INFO)<<this<<Name()<<" dtor "<<send_bytes_<<" "<<recv_bytes_;
}
void OctopusHand::WriteMeta(OctopusSessionKey &uuid,uint8_t sp_flag){
    if(OCT_HAND_S==role_){
        return;
    }
    sp_flag_=sp_flag;
    if(!(meta_flag_&OCT_META_OK_F)){
        char buffer[kBufferSize];
        DataWriter writer(buffer,kBufferSize);
        uint8_t type=OCT_MSG_META;
        uint8_t flag=sp_flag_;
        bool success=writer.WriteUInt8(type)&&
                writer.WriteUInt8(flag)&&
                writer.WriteUInt32(uuid.from)&&
                writer.WriteUInt32(uuid.to)&&
                writer.WriteUInt16(uuid.src_port)&&
                writer.WriteUInt16(uuid.dst_port);
        int old=wb_.size();
        wb_.resize(old+writer.length());
        memcpy(&wb_[old],writer.data(),writer.length());
        meta_flag_|=OCT_META_OK_F;
    }
}
bool OctopusHand::AsynConnect(const struct sockaddr *addr,socklen_t addrlen){
    int yes=1;
    if(OCT_HAND_S==role_){
        return false;
    }
    context_->epoll_server()->RegisterFD(fd_,this,EPOLLET|EPOLLIN|EPOLLOUT);
    if(connect(fd_,(struct sockaddr *)addr,addrlen) == -1&&errno != EINPROGRESS){
        //connect doesn't work, are we running out of available ports ? if yes, destruct the socket
        if (errno == EAGAIN){
            CloseFd();
            DeleteSelf();
            return false;
        }
    }
    status_=OCT_CONN_TRYING;
    return true;
}
void OctopusHand::SignalFrom(OctopusDispatcher* dispatcher,OctSigCodeT code){
    if(OCT_HAND_S==role_){
        if(code&OCT_SIG_DST_OK){
            DLOG(INFO)<<"send meta dst ok";
            SendMetaAck(OCT_MSG_DST_OK);
        }
        if(code&OCT_SIG_DST_FAILED){
            DLOG(INFO)<<"send meta dst failure";
            SendMetaAck(OCT_MSG_DST_FAILED);
            dispatcher_=nullptr;
            ConnClose(OCT_SIG_CONN_FIN);
        }
        if(code&OCT_SIG_CONN_FATAl){
            DLOG(INFO)<<"fatal and send fin";
            dispatcher_=nullptr;
            ConnClose(OCT_SIG_CONN_FIN);
        }
        if(code&OCT_SIG_CONN_FIN){
            wait_close_=1;
            DLOG(INFO)<<"wait close 1";
            dispatcher_=nullptr;
            if(0==wb_.size()){
                DLOG(INFO)<<"send fin";
                ConnClose(OCT_SIG_CONN_FIN);
            }
        }
    }
    
    if(OCT_HAND_C==role_){
        if(code&OCT_SIG_CONN_FIN){
            wait_close_=1;
            DLOG(INFO)<<"wait close 1";
            dispatcher_=nullptr;
            if(0==wb_.size()){
                DLOG(INFO)<<"send fin";
                ConnClose(OCT_SIG_CONN_FIN);
            }
        }
        if(code&OCT_SIG_CONN_FATAl||code&OCT_SIG_DST_FAILED){
            dispatcher_=nullptr;
            DLOG(INFO)<<"fatal or failure";
            ConnClose(OCT_SIG_CONN_FIN);
        }
    }
}
int OctopusHand::Sink(const char *pv,int sz){
    int ret=OCT_OK;
    if(!delivered_bw_alarm_){
        delivered_bw_alarm_.reset(context_->alarm_factory()->CreateAlarm(new DeliveredRateAlarmDelegate(this)));
        QuicTime now=context_->clock()->ApproximateNow();
        delivered_bw_alarm_->Update(now,QuicTime::Delta::Zero());
    }
    ret=WriteOrBufferData(pv,sz);
    return ret;
}
//format:offset+pv_len+pv
int OctopusHand::SinkWithOff(uint64_t offset,const char *pv,int sz){
    int ret=OCT_OK;
    uint16_t offset_bytes=0,sz_bytes=0;
    offset_bytes=DataWriter::GetVarInt62Len(offset);
    sz_bytes=DataWriter::GetVarInt62Len(sz);
    int hz=offset_bytes+sz_bytes;
    uint64_t encode_buf[2];
    DataWriter writer((char*)encode_buf,sizeof(encode_buf));
    bool success=writer.WriteVarInt62(offset)&&writer.WriteVarInt62(sz);
    DCHECK(success);
    DCHECK(writer.length()==hz);
    ret=Sink(writer.data(),writer.length());
    DCHECK(OCT_OK==ret);
    ret=Sink(pv,sz);
    DLOG(INFO)<<this<<" "<<offset<<" "<<sz;
    return ret;
}
void OctopusHand::OnEvent(int fd, EpollEvent* event){
    if(OCT_HAND_S==role_){
        OnServerEvent(fd,event);
    }else if(OCT_HAND_C==role_){
        OnClientEvent(fd,event);
    }
}
void OctopusHand::OnShutdown(EpollServer* eps, int fd){
    CloseFd();
    DLOG(INFO)<<Name()<<" OnShutdown";
    DeleteSelf();
}
std::string OctopusHand::Name() const{
    return OctRoleStr(role_);
}
void OctopusHand::CountDeliveredRateAlarm(){
    struct tcp_info_copy info;
    memset(&info,0,sizeof(info));
    socklen_t info_size=sizeof(info);
    uint64_t bytes_acked=0;
    uint32_t min_rtt_us=0;
    if(getsockopt(fd_,IPPROTO_TCP,TCP_INFO,(void*)&info,&info_size)==0){
        bytes_acked=info.tcpi_bytes_acked;
        min_rtt_us=info.tcpi_min_rtt;
        if(~0==min_rtt_us){
            min_rtt_us=kMaxRoundTripTime.ToMicroseconds();
        }
    }
    QuicTime::Delta rtt=QuicTime::Delta::FromMicroseconds(min_rtt_us);
    //cap
    if(rtt<kMinRoundTripTime){
        rtt=kMinRoundTripTime;
    }
    if(rtt>kMaxRoundTripTime){
        rtt=kMaxRoundTripTime;
    }
    QuicTime::Delta new_interval=rtt;
    QuicTime now=context_->clock()->ApproximateNow();
    if(QuicTime::Zero()!=check_delivered_ts_){
        QuicBandwidth b=QuicBandwidth::Zero();
        if((bytes_acked>pre_bytes_acked_)&&(now>check_delivered_ts_)){
            b=QuicBandwidth::FromBytesAndTimeDelta(bytes_acked-pre_bytes_acked_,now-check_delivered_ts_);
        }
        max_rate_.Update(b,round_);
        round_++;
    }
    check_delivered_ts_=now;
    pre_bytes_acked_=bytes_acked;
    delivered_bw_alarm_->Update(now+new_interval,QuicTime::Delta::Zero());
    if(wait_close_&&wb_.size()==0){
        DLOG(INFO)<<"send fin";
        ConnClose(OCT_SIG_CONN_FIN);
    }
}
/* the default SO_SNDBUF is 16384 bytes
 * the buffer can be increased dynamically
 * by assuming the rate is 2Mbps
 * when the buffer is fully occupied
 * the time is 16384*8/2=65 ms to drain buffer empty
 */
int OctopusHand::GetWriteBudget()const{
    int budget=0;
    if(fd_>0){
        struct tcp_info_copy info;
        uint32_t budget_us=0;
        memset(&info,0,sizeof(info));
        socklen_t info_sz=sizeof(info);
        int unsent=out_pending(fd_);
        if(getsockopt(fd_,IPPROTO_TCP,TCP_INFO,(void*)&info,&info_sz)==0){
            uint32_t min_rtt_us=info.tcpi_min_rtt;
            budget_us=min_rtt_us;
        }
        if(0==budget_us||~0==budget_us){
            budget=20*kSegmentSize;
        }else{
            QuicBandwidth estimate_bw=max_rate_.GetBest();
            if (estimate_bw<kMinBandwidth){
                estimate_bw=kMinBandwidth;
            }
            QuicTime::Delta budget_time=QuicTime::Delta::FromMicroseconds(2*budget_us);
            budget=estimate_bw.ToBytesPerPeriod(budget_time);
            if(unsent>0){
                if(budget>=unsent){
                    budget=budget-unsent;
                }else{
                    budget=0;
                }
            }
        }
    }
    return budget;
}
//client event
void OctopusHand::OnClientEvent(int fd, EpollEvent* event){
    char buffer[kBufferSize];
    int n=0;
    bool fin=false;
    int sc=0;
    if(event->in_events&(EPOLLERR|EPOLLHUP)){
        if(OCT_CONN_TRYING==status_){
            //clear meta data
            wb_.clear();
            ConnClose(OCT_SIG_CONN_FAILED);
            return ;
        }else{   
            sc|=OCT_SIG_CONN_FIN;
            fin=true;
        }
    }
    
    if(fd_>0&&(event->in_events&EPOLLOUT)){
        if (OCT_CONN_TRYING==status_){
            status_=OCT_CONN_OK;
        }
        if(OCT_CONN_OK==status_){
            int ret=OnFlushBuffer();
            if(OCT_OK!=ret){
                sc|=OCT_SIG_CONN_FIN;
                fin=true;
            }
        }
    }
    
    if(fd_>0&&(event->in_events&EPOLLIN)){
        while(true){
            n=read(fd_,buffer,kBufferSize);
            if(-1==n){
                if(EINTR==errno||EWOULDBLOCK==errno||EAGAIN==errno){
                    //pass
                }else{
                    sc|=OCT_SIG_CONN_FIN;
                    fin=true;
                }
                break;
            }
            if(0==n){
                sc|=OCT_SIG_CONN_FIN;
                fin=true;
                break;
            }
            if(n>0){
                recv_bytes_+=n;
                if(0==(meta_flag_&OCT_META_ACK_F)){
                    meta_flag_|=OCT_META_ACK_F;
                    if(OCT_MSG_DST_OK==buffer[0]){
                        DLOG(INFO)<<this<<Name()<<" dst connected";
                        dispatcher_->SignalFrom(this,OCT_SIG_DST_OK);
                        if(n-1>0){
                            ProcessInData(&buffer[1],n-1);
                        }
                    }
                    if(OCT_MSG_DST_FAILED==buffer[0]){
                        DLOG(INFO)<<this<<Name()<<" dst failed";
                        sc|=OCT_SIG_DST_FAILED;
                        fin=true;
                        break;
                    }
                }else{
                    ProcessInData(buffer,n);
                }
            }
        }
    }
    if(fin){
        //OCT_SIG_DST_FAILED|OCT_SIG_CONN_FIN
        //OCT_SIG_CONN_FIN
        //OCT_SIG_DST_FAILED
        DLOG(INFO)<<Name()<<" "<<OctSigCodeStr(sc);
        if(sc&OCT_SIG_DST_FAILED){
            sc=OCT_SIG_DST_FAILED;
        }else{
            sc=OCT_SIG_CONN_FIN;
        }
        
        ConnClose(sc);
    }
}
//server event
void OctopusHand::OnServerEvent(int fd, EpollEvent* event){
    char buffer[kBufferSize];
    int n=0;
    bool fin=false;
    if(event->in_events&(EPOLLERR|EPOLLHUP)){
        DLOG(INFO)<<"fin";
        fin=true;
    }
    if(fd_>0&&(event->in_events&EPOLLOUT)){
        int ret=OnFlushBuffer();
        if(OCT_OK!=ret){
            DLOG(INFO)<<"fin";
            fin=true;
        }
    }
    if(fd_>0&&(event->in_events&EPOLLIN)){
        while(true){
            n=read(fd_,buffer,kBufferSize);
            if(-1==n){
                if(EINTR==errno||EWOULDBLOCK==errno||EAGAIN==errno){
                    //pass
                }else{
                    DLOG(INFO)<<"fin";
                    fin=true;
                }
                break;
            }
            if(0==n){
                DLOG(INFO)<<"fin";
                fin=true;
                break;
            }
            if(n>0){
                recv_bytes_+=n;
                if(0==(meta_flag_&OCT_META_OK_F)){
                    int old=rb_.size();
                    rb_.resize(old+n);
                    memcpy(&rb_[old],buffer,n);
                    ParseMeta();
                }else{
                    CHECK(dispatcher_);
                    ProcessInData(buffer,n);
                }
            }
        }
    }
    if(fin){
        DLOG(INFO)<<"sig fin";
        ConnClose(OCT_SIG_CONN_FIN);
    }
}
bool OctopusHand::HasCompleteFrame(const char *pv,int sz,uint64_t *offset,uint16_t *offset_bytes,uint64_t *length,uint16_t *length_bytes){
    bool ret=false;
    if(sz>0){
        DataReader reader(pv,sz);
        uint64_t offset1=0;
        uint16_t offset_bytes1=0;
        uint64_t length1=0;
        uint16_t length_bytes1=0;
        bool success=reader.ReadVarInt62(&offset1)&&reader.ReadVarInt62(&length1);
        if(success){
            offset_bytes1=DataWriter::GetVarInt62Len(offset1);
            length_bytes1=DataWriter::GetVarInt62Len(length1);
            int frame_sz=offset_bytes1+length_bytes1+length1;
            if(sz>=frame_sz){
                *offset=offset1;
                *offset_bytes=offset_bytes1;
                *length=length1;
                *length_bytes=length_bytes1;
                ret=true;
            }
        }
    }
    return ret;
}
void OctopusHand::ProcessInData(const char *pv,int sz){
    if(sz<=0){
        return;
    }
    if(1==sp_flag_){
        dispatcher_->Sink(pv,sz);
    }else{
        int old=rb_.size();
        rb_.resize(old+sz);
        memcpy(&rb_[old],pv,sz);
        const char *buf_ptr=rb_.data();
        int remain=rb_.size();
        bool consumed=false;
        while(remain>0){
            uint64_t offset=0,length=0;
            uint16_t offset_bytes=0,length_bytes=0;
            if(HasCompleteFrame(buf_ptr,remain,&offset,&offset_bytes,&length,&length_bytes)){
                int hdr_sz=offset_bytes+length_bytes;
                int frame_sz=hdr_sz+length;
                const char *data_ptr=buf_ptr+hdr_sz;
                //DLOG(INFO)<<this<<" off "<<offset<<" "<<frame_sz;
                if(offset>=kInitOffset){
                    dispatcher_->SinkWithOff(offset-kInitOffset,data_ptr,length);
                }else{
                    OnSignalingData(data_ptr,length);
                }
                buf_ptr+=frame_sz;
                remain-=frame_sz;
                consumed=true;     
            }else{
                //uncomplete
                break;
            }
        }
        //consumed
        if(consumed&&remain>0){
            std::string copy(buf_ptr,remain);
            copy.swap(rb_);
        }
        if(consumed&&0==remain){
            std::string null_str;
            null_str.swap(rb_);
            
        }
    }
}
void OctopusHand::OnSignalingData(const char *pv,int sz){
    
}
void OctopusHand::ConnClose(OctSigCodeT code){
    if(dispatcher_){
        if(wb_.size()!=0||rb_.size()!=0){
            code=OCT_SIG_CONN_FATAl;
            LOG(ERROR)<<this<<Name()<<" fatal error";
        }
        DLOG(INFO)<<Name()<<" "<<OctSigCodeStr(code);
        dispatcher_->SignalFrom(this,code);
        dispatcher_=nullptr;
    }
    status_=OCT_CONN_CLOSED;
    context_->epoll_server()->UnregisterFD(fd_);
    CloseFd();
    DeleteSelf();
}
void OctopusHand::ParseMeta(){
    if(0==(meta_flag_&OCT_META_OK_F)){
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
            rb_.clear();
            sockaddr_storage src_saddr;
            sockaddr_storage dst_saddr;
            {
                in_addr  ipv4;
                memcpy(&ipv4,&uuid.from,sizeof(uuid.from));
                IpAddress ip_addr(ipv4);
                SocketAddress socket_addr(ip_addr,uuid.src_port);
                src_saddr=socket_addr.generic_address();
                DLOG(INFO)<<this<<Name()<<"origin src "<<socket_addr.ToString();
            }
            {
                in_addr  ipv4;
                memcpy(&ipv4,&uuid.to,sizeof(uuid.to));
                IpAddress ip_addr(ipv4);
                SocketAddress socket_addr(ip_addr,uuid.dst_port);
                dst_saddr=socket_addr.generic_address();
                DLOG(INFO)<<this<<Name()<<"origin dst "<<socket_addr.ToString();
            }
            meta_flag_|=OCT_META_OK_F;
            sp_flag_=sp;
            CHECK(&manager_!=nullptr);
            OctopusDispatcher *dispatcher=manager_.Find(uuid);
            //DLOG(INFO)<<"mode "<<(uint32_t)sp_flag_<<" "<<(uintptr_t)dispatcher;
            if(nullptr==dispatcher){
                bool positive=false;
                int sock=bind_addr((sockaddr*)&src_saddr,true);
                if(sock>0){
                    dispatcher_=new OctopusDispatcher(context_,sock,uuid,OCT_DISPA_S,sp,manager_);
                    if(0==sp_flag_){
                        manager_.Register(uuid,dispatcher_);
                    }
                    if(dispatcher_->AsynConnect((const struct sockaddr*)&dst_saddr,sizeof(struct sockaddr_in))){
                        dispatcher_->RegisterHand(this);
                        positive=true;
                    }
                }else{
                    DLOG(INFO)<<this<<Name()<<"bind failed";
                }
                if(!positive){
                    SendMetaAck(OCT_SIG_DST_FAILED);
                    ConnClose(OCT_SIG_DST_FAILED);
                }
                CHECK(reader.BytesRemaining()==0);
            }else{
                dispatcher_=dispatcher;
                dispatcher_->RegisterHand(this);
            }

        }
    }
}
void OctopusHand::SendMetaAck(uint8_t type){
    if(fd_>0&&(0==(meta_flag_&OCT_META_ACK_F))){
        meta_flag_|=OCT_META_ACK_F;
        CHECK(type!=0);
        send(fd_,(const void*)&type,sizeof(type),0);
        send_bytes_+=1;
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

class ScheduleAlarmDelegate:public BaseAlarm::Delegate{
public:
    ScheduleAlarmDelegate(OctopusDispatcher* entity):entity_(entity){}
    void OnAlarm() override{
        entity_->SocketRWAlarm();
    }
private:
    OctopusDispatcher *entity_;
};
OctopusDispatcher::OctopusDispatcher(BaseContext *context,int fd,OctopusSessionKey &uuid,
		OctRole role,uint8_t sp,OctopusDispatcherManager &manager)
:OctopusBase(context,fd),uuid_(uuid),manager_(manager),
w_offset_(kInitOffset),
role_(role),
sp_flag_(sp),
wait_close_(0),
sequencer_(this){
    if(OCT_DISPA_C==role_){
        octopus_nonblocking(fd_);
        status_=OCT_CONN_OK;
    }else{
        status_=OCT_CONN_TRYING;
    }
    context_->RegisterExitVisitor(this);
}
OctopusDispatcher::~OctopusDispatcher(){
    if(rw_alarm_){
        rw_alarm_->Cancel();
    }
    DLOG(INFO)<<this<<Name()<<"dtor "<<send_bytes_<<" "<<recv_bytes_;
}
void OctopusDispatcher::SignalFrom(OctopusHand*hand,OctSigCodeT code){
    DLOG(INFO)<<Name()<<" "<<OctSigCodeStr(code);
    if(code&OCT_SIG_CONN_FATAl){
        for(auto it=wait_hands_.begin();it!=wait_hands_.end();it++){
            OctopusHand *ptr=(*it);
            if(hand!=ptr){
                (*it)->SignalFrom(this,OCT_SIG_CONN_FATAl);
            }
        }
        wait_hands_.clear();
        for(auto it=ready_hands_.begin();it!=ready_hands_.end();it++){
            OctopusHand *ptr=(*it);
            if(hand!=ptr){
                (*it)->SignalFrom(this,OCT_SIG_CONN_FATAl);
            }
        }
        ConnClose(OCT_SIG_CONN_FATAl);
        return ;
    }
    if(OCT_DISPA_C==role_){
        HandleSignalAtClient(hand,code);
    }
    if(code&OCT_SIG_CONN_FIN){
        auto it1=std::find(wait_hands_.begin(),wait_hands_.end(),hand);
        auto it2=std::find(ready_hands_.begin(),ready_hands_.end(),hand);
        if(it1!=wait_hands_.end()){
            wait_hands_.erase(it1);
        }
        if(it2!=ready_hands_.end()){
            ready_hands_.erase(it2);
        }
        if(wait_hands_.size()==0&&ready_hands_.size()==0){
            ConnClose(OCT_SIG_CONN_FIN);
        }
    }
}

//OCT_SIG_DST_OK
//OCT_SIG_CONN_FATAl OCT_SIG_CONN_FAILED OCT_SIG_DST_FAILED OCT_SIG_CONN_FIN 
void OctopusDispatcher::HandleSignalAtClient(OctopusHand*hand,OctSigCodeT code){
    if(code&OCT_SIG_DST_OK){
        auto it1=std::find(wait_hands_.begin(),wait_hands_.end(),hand);
        auto it2=std::find(ready_hands_.begin(),ready_hands_.end(),hand);
        CHECK(it1!=wait_hands_.end());
        CHECK(it2==ready_hands_.end());
        wait_hands_.erase(it1);
        ready_hands_.push_back(hand);
        if(!rw_alarm_){
            rw_alarm_.reset(context_->alarm_factory()->CreateAlarm(new ScheduleAlarmDelegate(this)));
            QuicTime now=context_->clock()->ApproximateNow();
            rw_alarm_->Update(now,QuicTime::Delta::Zero());
        }
    }

    if(code&OCT_SIG_DST_FAILED){
        CHECK(ready_hands_.size()==0);
        for(auto it=wait_hands_.begin();it!=wait_hands_.end();it++){
            OctopusHand *ptr=(*it);
            if(hand!=ptr){
                (*it)->SignalFrom(this,OCT_SIG_DST_FAILED);
            }
        }
        wait_hands_.clear();
        ConnClose(OCT_SIG_DST_FAILED);
        return ;
    }
    
    if(code&OCT_SIG_CONN_FAILED){
        auto it1=std::find(wait_hands_.begin(),wait_hands_.end(),hand);
        CHECK(it1!=wait_hands_.end());
        wait_hands_.erase(it1);
        if(wait_hands_.size()==0&&ready_hands_.size()==0){
            ConnClose(OCT_SIG_CONN_FIN);
        }
    }
}
//hand will send OCT_SIG_CONN_FIN OCT_SIG_CONN_FATAl
void OctopusDispatcher::HandleSignalAtServer(OctopusHand*hand,OctSigCodeT code){}
bool OctopusDispatcher::CreateConnection(const sockaddr_storage &proxy_src_saddr,
                                const sockaddr_storage &proxy_dst_saddr){
    bool success=false;
    int sock=bind_addr((sockaddr*)&proxy_src_saddr,false);
    if (sock>0){
        OctopusHand *hand=new OctopusHand(context_,sock,OCT_HAND_C,manager_,this);
        hand->WriteMeta(uuid_,sp_flag_);
        if(hand->AsynConnect((const struct sockaddr*)&proxy_dst_saddr,sizeof(struct sockaddr_in))){
            success=true;
            wait_hands_.push_back(hand);
        }
    }
    return success;
}
bool OctopusDispatcher::CreateSingleConnection(const sockaddr_storage &proxy_src_saddr,
                                const sockaddr_storage &proxy_dst_saddr){
    bool success=CreateConnection(proxy_src_saddr,proxy_dst_saddr);
    if(!success){
        ConnClose(OCT_SIG_CONN_FAILED);
    }
    return success;
}
bool OctopusDispatcher::CreateMutipleConnections(const std::vector<std::pair<sockaddr_storage,sockaddr_storage>>& proxy_saddrs){
    int routes=0;
    for(auto it=proxy_saddrs.begin();it!=proxy_saddrs.end();it++){
        const sockaddr_storage src=(*it).first;
        const sockaddr_storage dst=(*it).second;
        if(true==CreateConnection(src,dst)){
            routes++;
        }
    }
    if(0==routes){
        ConnClose(OCT_SIG_CONN_FAILED);
    }
    return routes>0;
}
bool OctopusDispatcher::AsynConnect(const struct sockaddr *addr,socklen_t addrlen){
    bool ret=false;
    int yes=1;
    context_->epoll_server()->RegisterFD(fd_,this,EPOLLET|EPOLLIN|EPOLLOUT);
    if(connect(fd_,(struct sockaddr *)addr,addrlen) == -1&&errno != EINPROGRESS){
        //connect doesn't work, are we running out of available ports ? if yes, destruct the socket
        if (errno == EAGAIN){
            CloseFd();
            DeleteSelf();
            return ret;
        }
    }
    status_=OCT_CONN_TRYING;
    return true;
}
void OctopusDispatcher::RegisterHand(OctopusHand*hand){
    if(OCT_CONN_TRYING==status_){
        auto it=std::find(wait_hands_.begin(),wait_hands_.end(),hand);
        if(it==wait_hands_.end()){
            wait_hands_.push_back(hand);
        }
    }
    if(OCT_CONN_OK==status_){
        auto it=std::find(ready_hands_.begin(),ready_hands_.end(),hand);
        if(it==ready_hands_.end()){
            ready_hands_.push_back(hand);
        }
        hand->SignalFrom(this,OCT_SIG_DST_OK);
    }
}
int OctopusDispatcher::Sink(const char *pv,int sz){
    int ret=OCT_ERR;
    if(sz>0){
        ret=WriteOrBufferData(pv,sz);
    }
    return ret;
}
int OctopusDispatcher::SinkWithOff(uint64_t offset,const char *pv,int sz){
    //multipath, store it to sequencer
    int ret=OCT_OK;
    int limit=std::numeric_limits<quic::QuicPacketLength>::max();
    DCHECK(sz<=limit);
    if(sz>0&&sz<=limit){
        quic::QuicStreamFrame frame(id(),false,offset,pv,(quic::QuicPacketLength)sz);
        sequencer_.OnStreamFrame(frame);
    }else{
        ret=OCT_ERR;
    }
    return ret;
}
//only call once
void OctopusDispatcher::OnEvent(int fd, EpollEvent* event){
    if(event->in_events&(EPOLLERR|EPOLLHUP)){
        if(OCT_CONN_TRYING==status_){
            DLOG(INFO)<<this<<Name()<<" "<<OctSigCodeStr(OCT_SIG_DST_FAILED);
            ConnClose(OCT_SIG_DST_FAILED);
            return;
        }
    }
    if(fd_>0&&(event->in_events&EPOLLOUT)){
        if(OCT_CONN_TRYING==status_){
            status_=OCT_CONN_OK;
            DLOG(INFO)<<this<<Name()<<"connect to origin dst "<<wait_hands_.size();
            for(auto it=wait_hands_.begin();it!=wait_hands_.end();it++){
                OctopusHand *hand=(*it);
                hand->SignalFrom(this,OCT_SIG_DST_OK);
            }
            CHECK(ready_hands_.size()==0);
            ready_hands_.swap(wait_hands_);
            context_->epoll_server()->UnregisterFD(fd_);
            if(!rw_alarm_){
                rw_alarm_.reset(context_->alarm_factory()->CreateAlarm(new ScheduleAlarmDelegate(this)));
                QuicTime now=context_->clock()->ApproximateNow();
                rw_alarm_->Update(now,QuicTime::Delta::Zero());
            }
        }
    }
}
void OctopusDispatcher::OnShutdown(EpollServer* eps, int fd){
    CloseFd();
    DeleteSelf();
}
std::string OctopusDispatcher::Name() const{
    return OctRoleStr(role_);
}
void OctopusDispatcher::ExitGracefully(){
    context_->epoll_server()->UnregisterFD(fd_);
    CloseFd();
    DeleteSelf();
}
void OctopusDispatcher::OnDataAvailable(){
    std::string buffer;
    sequencer_.Read(&buffer);
    DLOG(INFO)<<this<<" OnDataAvailable "<<buffer.size();
    Sink(buffer.data(),buffer.size());
}
void OctopusDispatcher::OnUnrecoverableError(quic::QuicErrorCode error,const std::string& details){
    LOG(INFO)<<quic::QuicErrorCodeToString(error)<<" "<<details;
    CHECK(0);
}
void OctopusDispatcher::SocketRWAlarm(){
    QuicTime now=context_->clock()->ApproximateNow();
    rw_alarm_ts_=now;
    OnFlushBuffer();
    //all hands closed,no need to read
    if(wait_close_&&wb_.size()==0){
        LOG(ERROR)<<"unread bytes "<<unread_bytes(fd_);
        ConnClose(OCT_SIG_CONN_FIN);
        return;
    }
    bool fin=false;
    if(1==sp_flag_){
        if(ready_hands_.size()>0){
            auto it=ready_hands_.begin();
            OctopusHand *hand=(*it);
            int budget=hand->GetWriteBudget();
            if(budget>0){
                fin=ScheduleData(hand,budget,nullptr);
            }
        }
    }else{
        fin=MpScheduleData();
    }
    if(!fin){
        rw_alarm_->Update(now+kSocketRWInterval,QuicTime::Delta::Zero());
    }else{
        ConnClose(OCT_SIG_CONN_FIN);
    }
}
bool OctopusDispatcher::ScheduleData(OctopusHand *hand,int budget,int *read_sz){
    bool fin=false;
    if(fd_<0){
        fin=true;
        return fin;
    }
    int alloc=budget_align(budget);
    std::unique_ptr<char[]> buffer(new char[alloc]);
    char *rbuf=buffer.get();
    int buf_pos=0;
    //the goal is to call read at least twice
    //TODO may try unread_bytes
    int capacity=alloc-kSegmentSize;
    while(capacity>0){
        int n=read(fd_,rbuf+buf_pos,capacity);
        if(-1==n){
            if(EINTR==errno||EWOULDBLOCK==errno||EAGAIN==errno){
                //no data available
            }else{
                fin=true;
            }
            break;
        }
        if(0==n){
            //peer closed
            fin=true;
            break;
        }
        if(n>0){
            buf_pos+=n;
            capacity=alloc-buf_pos;
        }
    }
    if(buf_pos>0){
        if(read_sz){
            *read_sz=buf_pos;
        }
        recv_bytes_+=buf_pos;
        if(1==sp_flag_){
            hand->Sink(rbuf,buf_pos);
        }else{
            SendDataWithinLimit(hand,rbuf,buf_pos);
        }
    }
    return fin;
}
bool OctopusDispatcher::MpScheduleData(){
    bool fin=false;
    if(fd_<0){
        fin=true;
        return fin;
    }
    int num_path=ready_hands_.size();
    for(int i=0;i<num_path;i++){
        int index=schedule_index_%num_path;
        OctopusHand *hand=ready_hands_[index];
        int r_sz=0;
        int budget=hand->GetWriteBudget();
        if(budget>0){
            fin=ScheduleData(hand,budget,&r_sz);
        }
        //no need to further read data from fd
        if(!fin&&r_sz<budget){
            if(r_sz>0){
                schedule_index_=schedule_index_+1;
            }
            break;
        }
        if(fin){
            break;
        }
        schedule_index_=schedule_index_+1;
    }
    return fin;
}
void OctopusDispatcher::SendDataWithinLimit(OctopusHand *hand,const char *pv,int sz){
    int remain=sz;
    int limit=std::numeric_limits<quic::QuicPacketLength>::max();
    while(remain>0){
        int len=std::min<int>(remain,limit);
        hand->SinkWithOff(w_offset_,pv,len);
        pv+=len;
        w_offset_+=len;
        remain-=len;
    }
}
void OctopusDispatcher::ConnClose(OctSigCodeT code){
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
    status_=OCT_CONN_CLOSED;
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

OctopusCallerBackend::OctopusCallerBackend(OctopusRouteIf *route_if)
:route_if_(route_if){}
void OctopusCallerBackend::CreateEndpoint(BaseContext *context,int fd){
	CHECK(route_if_);
	route_if_->OnAcceptConnection(context,fd);
}
OctopusCallerSocketFactory::OctopusCallerSocketFactory(OctopusRouteIf *route_if)
:route_if_(route_if){}
PhysicalSocketServer* OctopusCallerSocketFactory::CreateSocketServer(BaseContext *context){
	 std::unique_ptr<OctopusCallerBackend> backend(new OctopusCallerBackend(route_if_));
	 return new PhysicalSocketServer(context,std::move(backend));
}
void OctopusCalleeBackend::CreateEndpoint(BaseContext *context,int fd){
	OctopusHand *hand=new OctopusHand(context,fd,OCT_HAND_S,manager_,nullptr);
	UNUSED(hand);
}
PhysicalSocketServer* OctopusCalleeSocketFactory::CreateSocketServer(BaseContext *context){
    std::unique_ptr<OctopusCalleeBackend> backend(new OctopusCalleeBackend());
    return new PhysicalSocketServer(context,std::move(backend));
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
bool CheckIpExist(std::vector<IpAddress> &ip_vec, IpAddress &ele){
    bool found=false;
    for(int i=0;i<ip_vec.size();i++){
        if(ip_vec[i]==ele){
            found=true;
            break;
        }
    }
    return found;
}
}

