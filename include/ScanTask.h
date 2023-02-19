
#pragma once
#include <iostream>
#include <QtWidgets>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

class ScanTask : virtual public QObject
{
public:
    ScanTask(libnet_t* m_libnet_handle, const char* src_ip, const char* dst_ip,int start_port, int end_port) : m_libnet_handle(m_libnet_handle), src_ip(src_ip)
    , dst_ip(dst_ip),m_start_port(start_port),m_end_port(end_port),m_stopped(false),m_paused(false) {}
    ~ScanTask(){}
    void run()
    {
        //初始化抓包
        m_pcap_handle = pcap_open_live("any", 65535, 1, 1, NULL);  // 抓取所有网络接口上的数据包
        if (m_pcap_handle == NULL) {
          fprintf(stderr, "pcap_open_live() failed: %s\n", pcap_geterr(m_libnet_handle));
          exit(EXIT_FAILURE);
        }
        for (int port = m_start_port; port <= m_end_port; ++port) {
            if (m_stopped)
                return;
            // 暂停扫描
            while (m_paused) {
                QThread::msleep(100);
                if (m_stopped)
                {
                    pcap_close(m_pcap_handle);
                    return;
                }

            }
            if (scan(m_ip,port)) {
                emit resultReady(port, true); // 端口打开
            } else {
                emit resultReady(port, false);// 端口关闭
            }
        }
        pcap_close(m_pcap_handle);
        emit finished();
    }
    virtual bool scan(int port) = 0;

public slots:
    // 暂停扫描
    void pause() { m_paused = true; }
    // 继续扫描
    void resume() { m_paused = false; }
    // 停止扫描
    void stop() { m_stopped = true; }

signals:
    void resultReady(int port, bool open);
    void error(const QString err);
    void finished();

protected:

    bool m_stopped;
    bool m_paused;
    int m_start_port;
    int m_end_port;
    libnet_t* m_libnet_handle;
    pcap_t *m_pcap_handle;
    const char* m_src_ip;
    const char* m_dst_ip;

    void sendPacket() {
      int c = libnet_write(m_libnet_handle);
      if (c == -1) {
        fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(m_libnet_handle));
        exit(EXIT_FAILURE);
      }

      usleep(1000);  // 为了防止发送过快导致系统拒绝服务，每次发送后暂停一毫秒
    }

    virtual void handlePacket(const struct pcap_pkthdr* header, const u_char* packet) {}

    static void handlePacketWrapper(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
      reinterpret_cast<Scanner*>(user)->handlePacket(header, packet);
    }

    static bool isTcp(const u_char* packet) {
      const struct iphdr* ip_hdr = reinterpret_cast<const struct iphdr*>(packet + sizeof(struct ether_header));
      return ip_hdr->protocol == IPPROTO_TCP;
    }

    static bool isDstIp(const u_char* packet, const char* dst_ip) {
      const struct iphdr* ip_hdr = reinterpret_cast<const struct iphdr*>(packet + sizeof(struct ether_header));
      return ip_hdr->daddr == inet_addr(dst_ip);
    }
};  

class ConnectScan : public ScanTask
{
public:
    ConnectScan(libnet_t* m_libnet_handle, const char* src_ip, const char* dst_ip,int start_port, int end_port): ScanTask(m_libnet_handle, src_ip, dst_ip,start_port,end_port) {}
    virtual ~ConnectScan() {}

    virtual void scan(int port) override{
        // 使用 TCP Connect Scan 扫描指定 IP 地址的端口
    }
};

class SynScan : public ScanTask {
public:
    SynScan(libnet_t* m_libnet_handle, const char* src_ip, const char* dst_ip,int start_port, int end_port): ScanTask(m_libnet_handle, src_ip, dst_ip,start_port,end_port) {}
    virtual ~SynScan() {}

    virtual void scan(int port) override {
        // 使用 TCP SYN Scan 扫描指定 IP 地址的端口
    }
};

class FinScan : public ScanTask {
public:
    FinScan(libnet_t* m_libnet_handle, const char* src_ip, const char* dst_ip,int start_port, int end_port): ScanTask(m_libnet_handle, src_ip, dst_ip,start_port,end_port) {}
    virtual ~FinScan() {}

    virtual void scan(int port) override {
        // 使用 TCP FIN Scan 扫描指定 IP 地址的端口
    }
};

class NullScan : public ScanTask {
public:
    NullScan(libnet_t* m_libnet_handle, const char* src_ip, const char* dst_ip,int start_port, int end_port): ScanTask(m_libnet_handle, src_ip, dst_ip,start_port,end_port) {}
    virtual ~NullScan() {}

    virtual void scan(int port) override {
        // 使用 TCP NULL Scan 扫描指定 IP 地址的端口
    }
};

class XmasScan : public ScanTask {
public:
    XmasScan(libnet_t* m_libnet_handle, const char* src_ip, const char* dst_ip,int start_port, int end_port): ScanTask(m_libnet_handle, src_ip, dst_ip,start_port,end_port) {}
    virtual ~XmasScan() {}

    virtual void scan(int port) override {
        // 使用 TCP Xmas Scan 扫描指定 IP 地址的端口
    }
};

class UdpScan : public ScanTask {
public:
    UdpScan(libnet_t* m_libnet_handle, const char* src_ip, const char* dst_ip,int start_port, int end_port): ScanTask(m_libnet_handle, src_ip, dst_ip,start_port,end_port) {}
    virtual ~UdpScan() {}

    virtual void scan(int port) override {
        // 使用 UDP Scan 扫描指定 IP 地址的端口
    }
};
