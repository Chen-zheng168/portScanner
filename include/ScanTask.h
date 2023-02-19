
#pragma once
#include <QtWidgets>
#include <pcap.h>
#include <libnet.h>

class ScanTask : virtual public QRunnable
{
public:
    ScanTask(){}
    ~ScanTask(){}
    void run() override
    {
        for (int port = m_start_port; port <= m_end_port; ++port) {
            if (m_stopped)
                return;
            // 暂停扫描
            while (m_paused) {
                QThread::msleep(100);
                if (m_stopped)
                    return;
            }
            if (scan(m_ip,port)) {
                emit resultReady(port, true); // 端口打开
            } else {
                emit resultReady(port, false);// 端口关闭
            }
        }
    }

    virtual bool scan(QString& ip,int port);

public slots:
    // 暂停扫描
    void pause() { m_paused = true; }
    // 继续扫描
    void resume() { m_paused = false; }
    // 停止扫描
    void stop() { m_stopped = true; }

signals:
    void resultReady(int port, bool open);

protected:
    QString m_ip;
    int m_start_port;
    int m_end_port;
    bool m_stopped;
    bool m_paused;
    pcap_t* m_pcap_handle;
    libnet_t* m_libnet_handle;
};

class ConnectScan : public ScanTask
{
public:
    ConnectScan(pcap_t* pcap_handle,libnet_t* libnet_handle,const QString& ip, int start_port, int end_port)
    {
        m_pcap_handle = pcap_handle;
        m_libnet_handle = libnet_handle;
        m_ip = ip;
        m_start_port = start_port;
        m_end_port = end_port;
        m_stopped = false;
        m_paused = false;
    }
    virtual ~ConnectScan() {}

    virtual void scan(QString ip,int port) {
        // 使用 TCP Connect Scan 扫描指定 IP 地址的端口
    }
};

class SynScan : public ScanTask {
public:
    SynScan(pcap_t* pcap_handle,libnet_t* libnet_handle,const QString& ip, int start_port, int end_port)
    {
        m_pcap_handle = pcap_handle;
        m_libnet_handle = libnet_handle;
        m_ip = ip;
        m_start_port = start_port;
        m_end_port = end_port;
        m_stopped = false;
        m_paused = false;
    }
    virtual ~SynScan() {}

    virtual void scan(QString ip,int port) {
        // 使用 TCP SYN Scan 扫描指定 IP 地址的端口
    }
};

class FinScan : public ScanTask {
public:
    FinScan(pcap_t* pcap_handle,libnet_t* libnet_handle,const QString& ip, int start_port, int end_port)
    {
        m_pcap_handle = pcap_handle;
        m_libnet_handle = libnet_handle;
        m_ip = ip;
        m_start_port = start_port;
        m_end_port = end_port;
        m_stopped = false;
        m_paused = false;
    }
    virtual ~FinScan() {}

    virtual void scan(QString ip,int port) {
        // 使用 TCP FIN Scan 扫描指定 IP 地址的端口
    }
};

class NullScan : public ScanTask {
public:
    NullScan(pcap_t* pcap_handle,libnet_t* libnet_handle,const QString& ip, int start_port, int end_port)
    {
        m_pcap_handle = pcap_handle;
        m_libnet_handle = libnet_handle;
        m_ip = ip;
        m_start_port = start_port;
        m_end_port = end_port;
        m_stopped = false;
        m_paused = false;
    }
    virtual ~NullScan() {}

    virtual void scan(QString ip,int port) {
        // 使用 TCP NULL Scan 扫描指定 IP 地址的端口
    }
};

class XmasScan : public ScanTask {
public:
    XmasScan(pcap_t* pcap_handle,libnet_t* libnet_handle,const QString& ip, int start_port, int end_port)
    {
        m_pcap_handle = pcap_handle;
        m_libnet_handle = libnet_handle;
        m_ip = ip;
        m_start_port = start_port;
        m_end_port = end_port;
        m_stopped = false;
        m_paused = false;
    }
    virtual ~XmasScan() {}

    virtual void scan(QString ip,int port) {
        // 使用 TCP Xmas Scan 扫描指定 IP 地址的端口
    }
};

class UdpScan : public ScanTask {
public:
    UdpScan(pcap_t* pcap_handle,libnet_t* libnet_handle,const QString& ip, int start_port, int end_port)
    {
        m_pcap_handle = pcap_handle;
        m_libnet_handle = libnet_handle;
        m_ip = ip;
        m_start_port = start_port;
        m_end_port = end_port;
        m_stopped = false;
        m_paused = false;
    }
    virtual ~UdpScan() {}

    virtual void scan(QString ip,int port) {
        // 使用 UDP Scan 扫描指定 IP 地址的端口
    }
};
