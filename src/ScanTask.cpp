#include "../include/ScanTask.h"

virtual void ConnectScan::scan(int port) {
    int a=0;
}

virtual void SynScan::scan(int port) {
    // 构造TCP SYN数据包
    libnet_ptag_t tcp_tag = libnet_build_tcp(
      SRC_PORT,  // 源端口
      port,      // 目标端口
      0,         // 序列号
      0,         // 确认号
      TH_SYN,    // 标志位
      1024,      // 窗口大小
      0,         // 校验和，0表示由内核自动计算
      0,         // 紧急指针
      LIBNET_TCP_H,  // TCP头部长度
      nullptr,    // 选项
      0,         // 选项长度
      m_libnet_handle,        // libnet句柄
      0);        // 新建一个libnet session

    if (tcp_tag == -1) {
        emit error(QString("libnet_build_tcp() failed: %1\n").arg(libnet_geterror(m_libnet_handle)));
        exit(EXIT_FAILURE);
    }
    libnet_ptag_t ipv4_tag = libnet_build_ipv4(
      LIBNET_IPV4_H + LIBNET_TCP_H,  // IP数据报长度
      0,                            // 服务类型
      0,                            // 标识
      0,                            // 片偏移
      64,                           // TTL
      IPPROTO_TCP,                  // 上层协议
      0,                            // 校验和，0表示由内核自动计算
      inet_addr(m_src_ip),            // 源IP地址
      inet_addr(dst_ip),            // 目标IP地址
      nullptr,                      // IP选项
      0,                            // IP选项长度
      m_libnet_handle,                           // libnet句柄
      0);                           // 新建一个libnet session
    if (ipv4_tag == -1) {
        emit error(QString("libnet_build_ipv4() failed: %1\n").arg(libnet_geterror(m_libnet_handle)));
        exit(EXIT_FAILURE);
    }

    // 发送数据包
    sendPacket();

    //抓包
    // 设置过滤器，只抓取目标IP和源端口为固定值的数据包
    char filter[256];
    snprintf(filter, sizeof(filter), "dst host %s and src port %d", m_src_ip, SRC_PORT);
    struct bpf_program bpf;
    if (pcap_compile(m_pcap_handle, &bpf, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        emit error(QString("pcap_compile() failed: %1\n").arg(pcap_geterr(m_pcap_handle)));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(m_pcap_handle, &bpf) == -1) {
        emit error(QString("pcap_setfilter() failed: %1\n").arg(pcap_geterr(m_pcap_handle)));
        exit(EXIT_FAILURE);
    }

    int timeout_ms = 100;  // 超时时间（毫秒）
    struct pcap_pkthdr header;
    const u_char* packet;
    //分析包数据
    while ((packet = pcap_next(m_pcap_handle, &header)) != NULL) {
      if (isTcp(packet) && isDstIp(packet, m_src_ip)) {
        const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        if (tcp_hdr->ack && tcp_hdr->syn) {
            return true;
            //   printf("%d open\n", port);
            //   break;
        }else if (tcp_hdr->rst) {
            return false;
        //   printf("%d closed\n", port);
        //   break;
        }
      }

      if (timeout_ms <= 0) {
        return;
      }
      usleep(1000);
      timeout_ms--;
    }
}


virtual void FinScan::scan(QString ip,int port) {
    int a=0;
}

virtual void NullScan::scan(QString ip,int port) {
    int a = 0;
}


virtual void UdpScan::scan(QString ip,int port) {
    int a = 0;
}

