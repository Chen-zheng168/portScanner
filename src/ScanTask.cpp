#include "../include/ScanTask.h"
std::mutex SendTask::m_mutex;
std::mutex SendTask::m_mutex1;
// std::mutex ScanTask::m_mutex;
// mutex ScanTask::m_mutex = mutex;

void SendTask::run()
{
    if (!initLibnet())
    {
        emit initError();
        return;
    }
    emit startSend();
    libnet_clear_packet(m_libnet_handle);
    QThread::msleep(100);
    for (auto port_range : m_port_ranges)
    {
        QString ip = port_range.first;
        cout <<"scaning "<< ip.toStdString()<<endl;
        setCurrentIP(ip);
        m_dst_ip = ip.toStdString();
        QPair<uint16_t, uint16_t> range = port_range.second;
        for (uint16_t port = range.first; port <= range.second; ++port)
        {
            if (m_stopped)
            {
                libnet_destroy(m_libnet_handle);
                return;
            }
            // 暂停扫描
            while (m_paused)
            {
                QThread::msleep(100);
                if (m_stopped)
                {
                    libnet_destroy(m_libnet_handle);
                    return;
                }
            }
            uint16_t sign = getSign(m_type);
            build_send_packet(m_dst_ip, port, sign);
            m_mutex.lock();
            ++scaned_ports;
            m_mutex.unlock();
        }
        usleep(1000*500);
    }
    cout << "send end"<<endl;
    emit endSend();
    while (!m_rev_done)
    {
        QThread::msleep(100);
    }
    libnet_destroy(m_libnet_handle);
}

void RevTask::run()
{
    // 发送未开始，阻塞
    while (!m_start_rev)
    {
        QThread::msleep(10);
        // 发送线程初始化错误，退出
        if (!m_send_init)
        {
            return;
        }
    }
    if (!inintLibpcap())
    {
        return;
    }
    int remain_time = 20;
    while (remain_time)
    {
        // remain_time--;
        // 父线程消息
        if (m_stopped)
        {
            pcap_close(m_pcap_handle);
            return;
        }
        // 暂停扫描
        while (m_paused)
        {
            QThread::msleep(100);
            if (m_stopped)
            {
                pcap_close(m_pcap_handle);
                return;
            }
        }
        // 收到发送结束信号，开始倒计时
        // m_end_rev = is_send_done.value(QString(m_dev));
        if (m_end_rev)
        {
            --remain_time;
        }
        // 发送线程更换IP
        // cout << m_current_ip.toStdString()<<" | "<<m_past_ip.toStdString()<< (m_current_ip != m_past_ip) << endl;
        if (m_current_ip != m_past_ip)
        {
            // 更新filter
            string filter = creatFilter(m_current_ip);
            setFilter(filter);
            m_past_ip = m_current_ip;
            cout <<"set filter success"<<endl;

        }
        // 抓取,解析数据包
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(m_pcap_handle, &header, &packet);
        if (res > 0)
        {
            struct PortState state = packet_handler(NULL, header, packet);
            emit resultReady(state.addr, state.port, state.state);
        }else if(res==0){
            usleep(1000);
        }
    }
    cout << "rev end"<<endl;
    emit finished();
    pcap_close(m_pcap_handle);
}
bool SendTask::initLibnet()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (m_dev == NULL)
    {
        m_dev = pcap_lookupdev(errbuf);
        if (m_dev == NULL)
        {
            emit error(QString("Error finding default device: %1").arg(errbuf));
            return false;
        }
    }
    is_send_done.insert(QString(m_dev),false);
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(m_dev, &net, &mask, errbuf) == -1)
    {
        emit error(QString("Error finding net and mask for device %1: %2").arg(m_dev).arg(errbuf));
        return false;
    }

    // 初始化libnet
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];
    m_libnet_handle = libnet_init(LIBNET_RAW4, m_dev, libnet_errbuf);
    if (m_libnet_handle == NULL)
    {
        emit error(QString("Error initializing libnet: %1\n").arg(libnet_errbuf));
        libnet_destroy(m_libnet_handle);
        return false;
    }
    u_int32_t ipaddr;
    if ((ipaddr = libnet_get_ipaddr4(m_libnet_handle)) == -1)
    {
        emit error(QString("Error getting IP: %1\n").arg(libnet_geterror(m_libnet_handle)));
        return false;
    }
    struct in_addr addr;
    addr.s_addr = ipaddr;
    m_src_ip = string(inet_ntoa(addr));
    cout << "linnet init success" << endl;
    return true;
}

// 非阻塞模式
//  if ((pcap_setnonblock (m_pcap_handle, 1, errbuf)) == -1)
//  {
//      fprintf (stderr, "Error setting nonblocking: %s\n", errbuf);
//      return false;
//  }
// 设置过滤器，只抓取目标IP和源端口为固定值的数据包
//  char filter[256];
//  snprintf(filter, sizeof(filter), "dst host %s and dst port %d", m_src_ip, SRC_PORT);

void SendTask::build_tcp(uint16_t port,uint16_t sign)
{
    // libnet_clear_packet(m_libnet_handle);
    // 构造TCP SYN数据包
    m_tcp = libnet_build_tcp(
        libnet_get_prand(LIBNET_PRu16), // 源端口
        port,                           // 目标端口
        0,                              // 序列号
        0,                              // 确认号
        sign,                         // 标志位
        8,                              // 窗口大小
        0,                              // 校验和，0表示由内核自动计算
        0,                              // 紧急指针
        LIBNET_TCP_H,                   // TCP头部长度
        nullptr,                        // 选项
        0,                              // 选项长度
        m_libnet_handle,                // libnet句柄
        m_tcp);                         // 新建一个libnet session
    // m_mutex.unlock();
    if (m_tcp == -1)
    {
        cout << "libnet_build_tcp f" << endl;
        emit error(QString("libnet_build_tcp() failed: %1\n").arg(libnet_geterror(m_libnet_handle)));
        exit(EXIT_FAILURE);
    }
    // cout << "build tcp" << endl;
}
void SendTask::build_ipv4(const string& dst_ip)
{
    // cout << m_dst_ip.c_str() << endl;
    m_ipv4 = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H,   // IP数据报长度
        0,                              // 服务类型
        libnet_get_prand(LIBNET_PRu16), // 标识
        0,                              // 片偏移
        64,                             // TTL
        IPPROTO_TCP,                    // 上层协议
        0,                              // 校验和，0表示由内核自动计算
        inet_addr(m_src_ip.c_str()),    // 源IP地址
        inet_addr(dst_ip.c_str()),    // 目标IP地址
        nullptr,                        // IP选项
        0,                              // IP选项长度
        m_libnet_handle,                // libnet句柄
        m_ipv4);                        // 新建一个libnet session
    if (m_ipv4 == -1)
    {
        cout << "libnet_build_ipv4 f" << endl;
        emit error(QString("libnet_build_ipv4() failed: %1\n").arg(libnet_geterror(m_libnet_handle)));
        exit(EXIT_FAILURE);
    }
    // cout << "build ip" << endl;
}

uint16_t getSign(const QString& scan_type)
{
    uint16_t sign;
    if (scan_type == "SYN" || scan_type == "FULL"){
        sign = TH_SYN;
    }else if (scan_type == "NULL"){
        sign = NULL;
    }else if (scan_type == "FIN"){
        sign = TH_FIN;
    }else if(scan_type == "Xmas"){
        sign = TH_FIN|TH_PUSH|TH_URG;
    }else if(scan_type == "TCP_WINDOW"){
        sign = TH_ACK;
    }
    return sign;
    // cout << "send" << endl;
}

void SendTask::build_send_packet(const string& dst_ip, uint16_t port, uint16_t sign){
    build_tcp(port,sign);
    build_ipv4(dst_ip);
    int c = libnet_write(m_libnet_handle);
    if (c == -1)
    {
        cout << "libnet_write f" << endl;
        fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(m_libnet_handle));
        exit(EXIT_FAILURE);
    }
    usleep(1000);
}

void SendTask::sendPacket(const string& dst_ip, uint16_t port, uint16_t sign){
    build_send_packet(dst_ip, port, sign);
}


PortState RevTask::packet_handler(u_char *user, const struct pcap_pkthdr *header,
                                  const u_char *packet)
{
    struct PortState state;
    struct tcphdr *tcp = (struct tcphdr *)(packet + LIBNET_IPV4_H + LIBNET_ETH_H);
    struct iphdr*ip = (struct iphdr*)(packet + LIBNET_ETH_H );
    // struct icmphdr* icmp = (struct icmphdr*)(+ LIBNET_IPV4_H + LIBNET_ETH_H);
    state.port = ntohs(tcp->th_sport);
    struct in_addr addr;
    addr.s_addr = ip->saddr;
    state.addr = inet_ntoa(addr);

    if (m_type == "SYN" || m_type == "FULL"){
        if (tcp->th_flags == 0x14){ 
            state.state = CLOSE;
            printf("Port %d appears to be closed\n", ntohs(tcp->th_sport));
        }else if (tcp->th_flags == 0x12){//
            state.state = OPEN;
            emit sendPacket(m_current_ip.toStdString(),state.port,m_type == "SYN"?TH_RST:TH_ACK);
            cout << "IP " << state.addr << " ";
            printf("Port %d appears to be open\n", ntohs(tcp->th_sport));
        }
    }else if (m_type == "NULL" || m_type == "FIN" || m_type == "Xmas"){
        if (tcp->th_flags == 0x04){
            state.state = CLOSE;
            cout << "IP " << state.addr << " ";
            printf("Port %d appears to be closed\n", ntohs(tcp->th_sport));
        }
    }else if(m_type == "TCP_WINDOW"){
        if (tcp->th_flags == 0x04){
            if (tcp->th_win > 0){
                state.state = OPEN;
                cout << "IP " << state.addr << " ";
                printf("Port %d appears to be open\n", ntohs(tcp->th_sport));
            }else{
                state.state = CLOSE;
                cout << "IP " << state.addr << " ";
                printf("Port %d appears to be closed\n", ntohs(tcp->th_sport));
            }

        }
    }
    
    return state;
}

bool RevTask::inintLibpcap()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (m_dev == NULL)
    {
        m_dev = pcap_lookupdev(errbuf);
        if (m_dev == NULL)
        {
            emit error(QString("Error finding default device: %1").arg(errbuf));
            return false;
        }
    }
    cout << m_dev << endl;
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(m_dev, &net, &mask, errbuf) == -1)
    {
        emit error(QString("Error finding net and mask for device %1: %2").arg(m_dev).arg(errbuf));
        return false;
    }
    m_pcap_handle = pcap_open_live(m_dev, BUFSIZ, 0, 100, errbuf);
    if (m_pcap_handle == NULL)
    {
        emit error(QString("Error opening pcap device %1: %2").arg(m_dev).arg(errbuf));
        return false;
    }
    if(pcap_setnonblock(m_pcap_handle,1,errbuf)==-1)
    {
        emit error(QString("Error set nonblock: %1").arg(errbuf));
        return false;
    }
    cout << "init success" << endl;
    return true;
}

bool RevTask::setFilter(const string& filter)
{
    struct bpf_program bpf;
    cout << "filter: "<< filter<< endl;
    if (pcap_compile(m_pcap_handle, &bpf, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        emit error(QString("pcap_compile() failed: %1\n").arg(pcap_geterr(m_pcap_handle)));
        pcap_freecode(&bpf);
        pcap_close(m_pcap_handle);
        return false;
    }

    if (pcap_setfilter(m_pcap_handle, &bpf) == -1)
    {
        emit error(QString("pcap_setfilter() failed: %1\n").arg(pcap_geterr(m_pcap_handle)));
        pcap_freecode(&bpf);
        pcap_close(m_pcap_handle);
        return false;
    }
    // pcap_freecode(&bpf);
}
string RevTask::creatFilter(const QString &ip)
{
    const char* src_ip = ip.toStdString().c_str();
    char filter[256];
    // cout << m_type.toStdString()<<endl;
    if (m_type == "SYN" || m_type == "FULL")
    {
        snprintf(filter, sizeof(filter), "(src host %s) && (tcp[13] == 0x14 || tcp[13] == 0x12)",src_ip); //RST|ACK=0x14,SYN|ACK=0x12
    }
    else if (m_type == "NULL" || m_type == "FIN"||m_type == "Xmas"||m_type == "TCP_WINDOW")
    {
        snprintf(filter, sizeof(filter), "(src host %s) && (tcp[13] == 0x04)",src_ip);//RST=0x04
    }
    cout <<filter<<endl;
    return string(filter);
}
