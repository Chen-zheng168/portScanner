#pragma once
#include "PortScanner.h"

ScanTask* creatScanTask(const Qstring& type, pcap_t* pcap_handle,libnet_t* libnet_handle,
                        const Qstring&  ip, int start_port, int end_port){
    ScanTask *scanTask = NULL;
    if (type == "CON"){
        scanTask = new ConnectScan(pcap_handle,libnet_handle,ip, start_port,end_port)
    }else if (type == "SYN"){
        scanTask = new SynScan(pcap_handle,libnet_handle,ip, start_port,end_port)
    }else if (type == "NULL"){
        scanTask = new NullScan(pcap_handle,libnet_handle,ip, start_port,end_port)
    }else if (type == "FIN"){
        scanTask = new FinScan(pcap_handle,libnet_handle,ip, start_port,end_port)
    }else if (type == "UDP"){
        scanTask = new UdpScan(pcap_handle,libnet_handle,ip, start_port,end_port)
    }
    return scanTask;
}

PortScanner::PortScanner(QObject *parent = nullptr) : QObject(parent) 
{
    m_progress = 0;
}

bool PortScanner::initLibpcapLibnet()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        emit error(QString("Error finding default device: %1").arg(errbuf));
        return false;
    }

    bpf_u_int32 net, mask;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        emit error(QString("Error finding net and mask for device %1: %2").arg(dev).arg(errbuf));
        return false;
    }

    m_pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (m_pcap_handle == NULL) {
        emit error(QString("Error opening pcap device %1: %2").arg(dev).arg(errbuf));
        return false;
    }

    char libnet_errbuf[LIBNET_ERRBUF_SIZE];
    m_libnet_handle = libnet_init(LIBNET_RAW4, dev, libnet_errbuf);
    if (m_libnet_handle == NULL) {
        emit error(QString("Error initializing libnet: %1").arg(libnet_errbuf));
        return false;
    }

    struct in_addr src_ip;
    inet_aton(getLocalIpAddress().toStdString().c_str(), &src_ip);

    libnet_seed_prand(m_libnet_handle);
    libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, IPPROTO_TCP, src_ip.s_addr, m_ip_addr.toIPv4Address(), NULL, 0, m_libnet_handle);
    libnet_autobuild_tcp(libnet_get_prand(LIBNET_PRu16), m_start_port, libnet_get_prand(LIBNET_PRu16), 0, TH_SYN, 2048, NULL, 0, m_libnet_handle);

    return true;
}
void PortScanner::scan(const QString& ip, int start_port, int end_port)
{
    // 清除之前扫描的结果
    m_results.clear();
    m_progress = 0;

    if (!initLibpcapLibnet()){
        return
    }
    // 计算端口数量
    m_ports = end_port - start_port + 1;
    // 设置线程池大小为可用线程数
    int num_threads = QThreadPool::globalInstance()->maxThreadCount();
    int num_scan_threads = qMin(num_threads, m_ports);
    QThreadPool::globalInstance()->setMaxThreadCount(num_scan_threads);
    // 计算每个线程扫描的端口数量
    int num_ports_per_thread = m_ports / num_scan_threads;
    int num_remaining_ports = m_ports - num_ports_per_thread * num_scan_threads;
    // 生成每个线程需要扫描的端口范围
    QList<QPair<int, int>> port_ranges;
    int port = start_port;
    for (int i = 0; i < num_scan_threads; i++) {
        int num_ports_for_thread = num_ports_per_thread;
        if (i < num_remaining_ports) {
            num_ports_for_thread++;
        }
        port_ranges.append(qMakePair(port, port + num_ports_for_thread - 1));
        port += num_ports_for_thread;
    }
    // 启动每个线程
    for (const auto& range : port_ranges) {
        ScanTask* scanTask = creatScanTask(m_scanType, pcap_handle,libnet_handle;ip, range.first, range.second)
        // 连接信号槽
        connect(this,&PortScanner::pause,scanTask,&ScanTask::pause);
        connect(this,&PortScanner::resume,scanTask,&ScanTask::resume);
        connect(this,&PortScanner::stop,scanTask,&ScanTask::stop);
        connect(scanTask,&ScanTask::resultReady,this,&PortScanner::handleTask);
        QThreadPool::globalInstance()->start(scanTask);
    }
}