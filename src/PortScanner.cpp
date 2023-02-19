
#include "../include/PortScanner.h"
#include "../include/ScanTask.h"

ScanTask* creatScanTask(const QString& type,libnet_t* libnet_handle,
                        const char*  src_ip, const char* dst_ip, int start_port, int end_port){
    ScanTask *scanTask = NULL;
    if (type == "CON"){
        scanTask = new ConnectScan(libnet_handle,src_ip,dst_ip, start_port,end_port);
    }else if (type == "SYN"){
        scanTask = new SynScan(libnet_handle,src_ip,dst_ip, start_port,end_port);
    }else if (type == "NULL"){
        scanTask = new NullScan(libnet_handle,src_ip,dst_ip, start_port,end_port);
    }else if (type == "FIN"){
        scanTask = new FinScan(libnet_handle,src_ip,dst_ip, start_port,end_port);
    }else if (type == "UDP"){
        scanTask = new UdpScan(libnet_handle,src_ip,dst_ip, start_port,end_port);
    }
    return scanTask;
}


bool PortScanner::initLibnet()
{
    // char errbuf[PCAP_ERRBUF_SIZE];
    // char* dev = pcap_lookupdev(errbuf);
    // if (dev == NULL) {
    //     emit error(QString("Error finding default device: %1").arg(errbuf));
    //     return false;
    // }

    // bpf_u_int32 net, mask;
    // if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    //     emit error(QString("Error finding net and mask for device %1: %2").arg(dev).arg(errbuf));
    //     return false;
    // }

    // m_pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // if (m_pcap_handle == NULL) {
    //     emit error(QString("Error opening pcap device %1: %2").arg(dev).arg(errbuf));
    //     return false;
    // }

    char libnet_errbuf[LIBNET_ERRBUF_SIZE];
    m_libnet_handle = libnet_init(LIBNET_RAW4, dev, libnet_errbuf);
    if (m_libnet_handle == NULL) {
        emit error(QString("Error initializing libnet: %1\n").arg(libnet_errbuf));
        return false;
    }
    return true;
}


void PortScanner::scan(const char* dst_ip, int start_port, int end_port)
{
    const char *src_ip = "10.10.0.8";
    // 清除之前扫描的结果
    m_results.clear();
    m_progress = 0;

    if (!initLibnet()){
        return;
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
    // 创建线程池
    for (int i = 0; i < num_scan_threads; ++i) {
        QThread* thread = new QThread(this);
        thread->start();
        m_threads_pool.append(thread);
    }
    // 启动每个线程
    for (const auto& range : port_ranges) {
        ScanTask *scanTask = creatScanTask(m_scanType, m_ibnet_handle, src_ip,dst_ip, range.first, range.second);
        //加入子线程
        QThread* thread = m_threads_pool.at(thread_index);
        scanTask->moveToThread(thread);
        // 连接信号槽
        connect(this,&PortScanner::start,scanTask,&ScanTask::run);
        connect(this,&PortScanner::pause,scanTask,&ScanTask::pause);
        connect(this,&PortScanner::resume,scanTask,&ScanTask::resume);
        connect(this,&PortScanner::stop,scanTask,&ScanTask::stop);
        connect(scanTask,&ScanTask::resultReady,this,&PortScanner::handleTask);
        connect(scanTask,&ScanTask::error,this,&PortScanner::handleError);
        connect(scanTask, &ScanTask::finished, scanTask, &ScanTask::deleteLater);
        connect(thread, &QThread::finished, scanTask, &QObject::deleteLater);
        QThreadPool::globalInstance()->start(scanTask);
    }
    emit start();
}