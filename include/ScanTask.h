#include <iostream>
#include <QtWidgets>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <mutex>
#include <time.h>
#include "Utils.h"
#define SRC_PORT 6666
using namespace std;

struct PortState{
  const char* addr;
  uint16_t port;
  uint16_t state;
};
uint16_t getSign(const QString& scan_type);
class SendTask : public QObject,public QRunnable
{
    Q_OBJECT
public:
    SendTask(char* dev,const QList<QPair<QString,QPair<uint16_t, uint16_t>>>& port_ranges,const QString& scan_type) : m_dev(dev),
    m_port_ranges(port_ranges),m_type(scan_type),m_stopped(false),m_paused(false),m_rev_done(false) {}

    ~SendTask(){}
    void run() override;

public slots:
    // 暂停扫描
    void pause() { m_paused = true; }
    // 继续扫描
    void resume() { m_paused = false; }
    // 停止扫描
    void stop() { m_stopped = true; }
    void revEnd(){
        m_rev_done = true;
    }
    //发送RST/ACK
    void sendPacket(const string& dst_ip, uint16_t port, uint16_t sign);

signals:
    void error(const QString& err);
    void finished();
    void setCurrentIP(const QString& ip);
    void initError();
    //开始发送
    void startSend();
    //结束发送
    void endSend();


protected:
    bool initLibnet();
    void build_tcp(uint16_t port,uint16_t sign);
    void build_ipv4(const string& dst_ip);
    void build_send_packet(const string& dst_ip, uint16_t port, uint16_t sign);
    char* m_dev;
    bool m_stopped;
    bool m_paused;
    bool m_rev_done;
    string m_dst_ip; 
    string m_src_ip; 
    QString m_type;
    QList<QPair<QString,QPair<uint16_t, uint16_t>>> m_port_ranges;
    libnet_t* m_libnet_handle;
    libnet_ptag_t m_udp = 0, m_tcp = 0, m_ipv4 = 0;
    static std::mutex m_mutex;
    static std::mutex m_mutex1;
};  


class RevTask : public QObject,public QRunnable
{
    Q_OBJECT
public:
    RevTask(char* dev,const QString& scan_type) : m_dev(dev),m_type(scan_type),m_stopped(false),m_paused(false),m_start_rev(false),m_end_rev(false),m_send_init(true){}
    ~RevTask(){}
    // int initLibnet();
    void run() override;

public slots:
    // 暂停扫描
    void pause() { m_paused = true; }
    // 继续扫描
    void resume() { m_paused = false; }
    // 停止扫描
    void stop() { m_stopped = true; }
    //更新当前扫描IP
    void getCurrentIP(const QString& ip){
        
        m_current_ip = ip;
        cout << m_current_ip.toStdString()<<" "<<m_past_ip.toStdString()<<endl;
    };
    void initError(){
        m_send_init = false;
    }
    void startRev(){
        m_start_rev = true;
    }
    void endRev(){
        cout <<"end rev"<<endl;
        m_end_rev = true;
    }

signals:
    void sendPacket(const string& dst_ip, uint16_t port, uint16_t sign);
    void resultReady(const QString& dst_ip,uint16_t port, uint16_t open);
    void error(const QString& err);
    void finished();

protected:

    bool inintLibpcap();
    string creatFilter(const QString& ip);
    bool setFilter(const string& filter);
    struct PortState packet_handler (u_char * user, const struct pcap_pkthdr *header,const u_char * packet);
    char* m_dev;
    bool m_stopped;
    bool m_paused;
    pcap_t *m_pcap_handle;
    QString m_type;
    QString m_current_ip;
    QString m_past_ip;
    bool m_send_init;
    bool m_start_rev;
    bool m_end_rev;
};

// class ConnectScan : public SendTask
// {
// public:
//     ConnectScan(libnet_t* m_libnet_handle, const string& dst_ip,int start_port, int end_port): 
//         SendTask(m_libnet_handle, dst_ip,start_port,end_port) {
//             cout << m_dst_ip << endl;
//             m_filter = QString("(src host %1) and (tcp[13] == 0x14) or (tcp[13] == 0x12)").arg(dst_ip.c_str());
//         }
//     virtual ~ConnectScan() {}

//     virtual int scan(int port) override;
//     int packet_handler (u_char * user, const struct pcap_pkthdr *header,
//         const u_char * packet);
// };

// class SynScan : public SendTask {
// public:
//     SynScan(libnet_t* m_libnet_handle, const string& dst_ip,int start_port, int end_port): SendTask(m_libnet_handle, dst_ip,start_port,end_port) {
//         m_filter = QString("(src host %1) and (tcp[13] == 0x14) or (tcp[13] == 0x12)").arg(dst_ip.c_str());
//         cout << "ip"<< m_dst_ip <<"filter: "<< m_filter.toStdString() << endl;
//     }
//     virtual ~SynScan() {}

//     virtual int scan(int port) override;
//     int packet_handler (u_char * user, const struct pcap_pkthdr *header,
//         const u_char * packet);
// };

// class FinScan : public SendTask {
// public:
//     FinScan(libnet_t* m_libnet_handle, const string& dst_ip,int start_port, int end_port): SendTask(m_libnet_handle, dst_ip,start_port,end_port) {
//         m_filter = QString("(src host %1) and (tcp[13] == 0x14) or (tcp[13] == 0x12)").arg(dst_ip.c_str());
//     }
//     virtual ~FinScan() {}

//     virtual int scan(int port) override;
//     int packet_handler (u_char * user, const struct pcap_pkthdr *header,
//         const u_char * packet);
// };

// class NullScan : public SendTask {
// public:
//     NullScan(libnet_t* m_libnet_handle, const string& dst_ip,int start_port, int end_port): SendTask(m_libnet_handle, dst_ip,start_port,end_port) {
//         m_filter = QString("(src host %1) and (tcp[13] == 0x14) or (tcp[13] == 0x12)").arg(dst_ip.c_str());
//     }
//     virtual ~NullScan() {}

//     virtual int scan(int port) override ;
//     int packet_handler (u_char * user, const struct pcap_pkthdr *header,
//         const u_char * packet);
// };

// class XmasScan : public SendTask {
// public:
//     XmasScan(libnet_t* m_libnet_handle, const string& dst_ip,int start_port, int end_port): SendTask(m_libnet_handle, dst_ip,start_port,end_port) {
//         m_filter = QString("(src host %1) and (tcp[13] == 0x14) or (tcp[13] == 0x12)").arg(dst_ip.c_str());
//     }
//     virtual ~XmasScan() {}

//     virtual int scan(int port) override ;
//     int packet_handler (u_char * user, const struct pcap_pkthdr *header,
//         const u_char * packet);
// };

// class UdpScan : public SendTask {
// public:
//     UdpScan(libnet_t* m_libnet_handle, const string& dst_ip,int start_port, int end_port): SendTask(m_libnet_handle, dst_ip,start_port,end_port) {
//         m_filter = QString("(src host %1) and (tcp[13] == 0x14) or (tcp[13] == 0x12)").arg(dst_ip.c_str());
//     }
//     virtual ~UdpScan() {}

//     virtual int scan(int port) override ;
//     int packet_handler (u_char * user, const struct pcap_pkthdr *header,
//         const u_char * packet);
// };

