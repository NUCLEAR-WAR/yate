// Exercise the production resolver and message completion with deterministic DNS.
#include "../modules/ysipchan.cpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static std::vector<std::string> queries;
static bool dnsAvailable = true;
static unsigned checks = 0;

static void require(bool ok, const char* description)
{
    ++checks;
    if (!ok) {
        std::fprintf(stderr,"FAIL: %s\n",description);
        std::exit(1);
    }
}

static void word(std::vector<unsigned char>& data, unsigned value)
{
    data.push_back(value >> 8);
    data.push_back(value & 255);
}

static void name(std::vector<unsigned char>& data, const char* value)
{
    while (*value) {
        const char* dot = std::strchr(value,'.');
        unsigned len = dot ? dot - value : std::strlen(value);
        data.push_back(len);
        data.insert(data.end(),value,value + len);
        value += len;
        if (*value == '.')
            ++value;
    }
    data.push_back(0);
}

static void textField(std::vector<unsigned char>& data, const char* value)
{
    unsigned len = std::strlen(value);
    data.push_back(len);
    data.insert(data.end(),value,value + len);
}

// Override only the DNS query boundary; real Yate DNS parsing remains in use.
extern "C" int res_query(const char* query, int dnsClass, int type,
    unsigned char* answer, int answerLen)
{
    queries.push_back(std::string(query) + ":" + std::to_string(type));
    if (!dnsAvailable || dnsClass != ns_c_in)
        return -1;
    std::vector<unsigned char> rdata;
    if (type == ns_t_naptr && !std::strcmp(query,"ims.test.invalid")) {
        word(rdata,10);
        word(rdata,10);
        textField(rdata,"s");
        textField(rdata,"SIP+D2T");
        textField(rdata,"");
        name(rdata,"_sip._tcp.ims.test.invalid");
    }
    else if (type == ns_t_srv &&
        (!std::strcmp(query,"_sip._tcp.ims.test.invalid") ||
         !std::strcmp(query,"_sip._udp.ims.test.invalid"))) {
        word(rdata,0);
        word(rdata,0);
        word(rdata,6060);
        name(rdata,"next.test.invalid");
    }
    else
        return -1;
    std::vector<unsigned char> packet;
    word(packet,1);
    word(packet,0x8180);
    word(packet,0);
    word(packet,1);
    word(packet,0);
    word(packet,0);
    name(packet,query);
    word(packet,type);
    word(packet,ns_c_in);
    word(packet,0);
    word(packet,60);
    word(packet,rdata.size());
    packet.insert(packet.end(),rdata.begin(),rdata.end());
    if (packet.size() > (unsigned)answerLen)
        return -1;
    std::memcpy(answer,&packet[0],packet.size());
    return packet.size();
}

static void resolve(const char* value, const char* expectedHost, int expectedPort,
    int expectedTransport, unsigned expectedQueries)
{
    queries.clear();
    String host;
    int port = 0;
    int transport = ProtocolHolder::Unknown;
    require(sipResolveNextHop(URI(value),host,port,transport),value);
    require(host == expectedHost,"next-hop host");
    require(port == expectedPort,"next-hop port");
    require(transport == expectedTransport,"next-hop transport");
    require(queries.size() == expectedQueries,"DNS query count");
}

class TestParty : public SIPParty
{
public:
    TestParty(const char* proto) : SIPParty(!std::strcmp(proto,"TCP")), m_proto(proto)
    {
        setAddr("172.22.0.50",5080,true);
        setAddr("172.22.0.20",6060,false);
    }
    virtual bool transmit(SIPEvent*) { return true; }
    virtual const char* getProtoName() const { return m_proto.c_str(); }
    virtual bool setParty(const URI&) { return true; }
    virtual void* getTransport() { return 0; }
private:
    String m_proto;
};

class TestEngine : public SIPEngine
{
public:
    TestEngine() : SIPEngine("transport-regression") {}
    virtual bool buildParty(SIPMessage*) { return false; }
    virtual void allocTraceId(String&) {}
    virtual void traceMsg(SIPMessage*,bool) {}
};

static void contact(TestEngine& engine, const char* proto, const char* expected)
{
    TestParty* party = new TestParty(proto);
    SIPMessage* invite = new SIPMessage("INVITE","sip:08001234@172.22.0.50:5080");
    invite->setParty(party);
    invite->complete(&engine,"08001234");
    SIPMessage* reply = new SIPMessage(invite,200,"OK");
    reply->complete(&engine,"08001234",0,"test-tag");
    const MimeHeaderLine* header = reply->getHeader("Contact");
    require(header && *header == expected,"200 OK Contact");
    SIPMessage* trying = new SIPMessage(invite,100,"Trying");
    trying->complete(&engine,"08001234");
    require(!trying->getHeader("Contact"),"100 Trying has no Contact");
    SIPMessage* custom = new SIPMessage(invite,200,"OK");
    custom->addHeader("Contact","<sip:mgcf@mgcf.test.invalid>");
    custom->complete(&engine,"08001234");
    require(*custom->getHeader("Contact") == "<sip:mgcf@mgcf.test.invalid>",
        "explicit Contact preserved");
    TelEngine::destruct(custom);
    TelEngine::destruct(trying);
    TelEngine::destruct(reply);
    TelEngine::destruct(invite);
    TelEngine::destruct(party);
}

int main()
{
    s_rfc3263 = s_rfc3263Naptr = s_rfc3263Srv = true;
    resolve("sip:mo@172.22.0.20:6060;transport=tcp;lr;did=973.2211",
        "172.22.0.20",6060,ProtocolHolder::Tcp,0);
    resolve("sip:08001234@172.22.0.50:5080;transport=TCP",
        "172.22.0.50",5080,ProtocolHolder::Tcp,0);
    resolve("sip:08001234@172.22.0.50:5080",
        "172.22.0.50",5080,ProtocolHolder::Udp,0);
    resolve("sip:1001@[2001:db8::1];transport=tcp",
        "2001:db8::1",5060,ProtocolHolder::Tcp,0);
    resolve("sip:1001@ims.test.invalid:5080;transport=tcp",
        "ims.test.invalid",5080,ProtocolHolder::Tcp,0);
    resolve("sip:1001;transport=udp@172.22.0.20:6060;transport=tcp?x=transport=udp",
        "172.22.0.20",6060,ProtocolHolder::Tcp,0);

    resolve("sip:1001@ims.test.invalid;transport=tcp",
        "next.test.invalid",6060,ProtocolHolder::Tcp,1);
    require(queries[0] == "_sip._tcp.ims.test.invalid:33","explicit TCP uses TCP SRV");
    resolve("sip:1001@ims.test.invalid;transport=udp",
        "next.test.invalid",6060,ProtocolHolder::Udp,1);
    require(queries[0] == "_sip._udp.ims.test.invalid:33","explicit UDP uses UDP SRV");
    resolve("sip:1001@ims.test.invalid",
        "next.test.invalid",6060,ProtocolHolder::Tcp,2);
    require(queries[0] == "ims.test.invalid:35" &&
        queries[1] == "_sip._tcp.ims.test.invalid:33","NAPTR/SRV discovery retained");
    dnsAvailable = false;
    resolve("sip:1001@ims.test.invalid;transport=tcp",
        "ims.test.invalid",5060,ProtocolHolder::Tcp,1);
    dnsAvailable = true;
    s_rfc3263 = false;
    resolve("sip:1001@ims.test.invalid;transport=tcp",
        "ims.test.invalid",5060,ProtocolHolder::Tcp,0);
    s_rfc3263 = true;

    String host;
    int port, transport;
    require(!sipResolveNextHop(URI("sips:1001@ims.test.invalid"),host,port,transport),
        "SIPS cannot silently downgrade to UDP");
    require(!sipResolveNextHop(URI("sip:1001@ims.test.invalid;transport=ws"),host,port,transport),
        "unsupported transport cannot silently downgrade to UDP");

    SIPMessage* bye = new SIPMessage("BYE","sip:1001@192.168.199.103:58086;transport=tcp");
    bye->addHeader("Route","<sip:mo@172.22.0.20:6060;transport=tcp;lr>, <sip:other.test.invalid;lr>");
    String hop;
    bool fromRoute = false;
    require(getSipNextHopUri(bye,hop,fromRoute) && fromRoute,"BYE uses top Route");
    resolve(hop,"172.22.0.20",6060,ProtocolHolder::Tcp,0);
    require(bye->uri == "sip:1001@192.168.199.103:58086;transport=tcp",
        "next-hop resolution preserves Request-URI");
    SIPMessage* ack = new SIPMessage("ACK","sip:08001234@172.22.0.50:5080;transport=tcp");
    require(getSipNextHopUri(ack,hop,fromRoute) && !fromRoute,"ACK without Route uses Contact target");
    resolve(hop,"172.22.0.50",5080,ProtocolHolder::Tcp,0);
    TelEngine::destruct(bye);
    TelEngine::destruct(ack);

    TestEngine engine;
    contact(engine,"TCP","<sip:08001234@172.22.0.50:5080;transport=tcp>");
    contact(engine,"UDP","<sip:08001234@172.22.0.50:5080>");
    std::printf("PASS: %u SIP dialog transport checks\n",checks);
    return 0;
}
