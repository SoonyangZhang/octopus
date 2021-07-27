#pragma once
#include <stdint.h>
namespace basic{
enum OctConnStatus:uint8_t{
    OCT_CONN_MIN,
    OCT_CONN_OK,
    OCT_CONN_TRYING,
    OCT_CONN_CLOSED,
};
typedef uint8_t OctSigCodeT;
const OctSigCodeT OCT_SIG_MIN=0;
const OctSigCodeT OCT_SIG_CONN_OK=1<<0;
const OctSigCodeT OCT_SIG_CONN_FAILED=1<<1; //asyn connect failure
const OctSigCodeT OCT_SIG_CONN_FIN=1<<2;
const OctSigCodeT OCT_SIG_CONN_FATAl=1<<3;
const OctSigCodeT OCT_SIG_DST_OK=1<<4;
const OctSigCodeT OCT_SIG_DST_FAILED=1<<5;
enum OctRole:uint8_t{
    OCT_HAND_C,
    OCT_HAND_S,
    OCT_DISPA_C,
    OCT_DISPA_S,
};
enum OctMessage:uint8_t{
    OCT_MSG_MIN,
    OCT_MSG_META,
    OCT_MSG_DST_OK,
    OCT_MSG_DST_FAILED,
    OCT_MSG_PING,
    OCT_MSG_PONG,
};
//Todo: design a tcp con for ping pong between proxies
enum OctMetaFlag:uint8_t{
    OCT_META_MIN_F,
    OCT_META_OK_F=0x01,
    OCT_META_ACK_F=0x02,
};
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
template<typename T>
T& create_null_ref() { return *static_cast<T*>(nullptr);}
}
