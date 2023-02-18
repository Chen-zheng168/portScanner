#pragma once
#include "PortScanner.h"

void ConnectScan::scan(QString ip,int port) {

}

void SynScan::scan(pcap_t* pcap_handle, libnet_t* libnet_handle,QString ip,int port) {
    libnet_autobuild_tcp(libnet_get_prand(LIBNET_PRu16), m_port, libnet_get_prand(LIBNET_PRu16), 0, TH_SYN, 2048, NULL, 0, m_libnet_handle);
    int packet_size = libnet_write(m_libnet_handle);
    if (packet_size == -1) {
        emit resultReady(m_port, false);
        return;
    }
    pcap_pkthdr header;
    const u_char* packet_data;
    while ((packet_data = pcap_next(m_pcap_handle, &header)) != NULL) {
        if (checkPacket(packet_data, header.len)) {
            emit resultReady(m_port, true);
            return;
        }
    }

    // 构造TCP SYN数据包
    tcp_tag = libnet_build_tcp(
      SRC_PORT,              // 源端口
      0,                     // 目标端口（随机）
      libnet_get_prand(LIBNET_PRu32),  // 序列号
      libnet_get_prand(LIBNET_PRu32),  // 确认号
      TH_SYN,                // TCP标志位：SYN
      libnet_get_prand(LIBNET_PRu16),  // 窗口大小
      0,                     // 校验和（由内核自动计算）
      0,                     // 紧急指针
      LIBNET_TCP_H,          // TCP数据包总长度
      NULL,                  // TCP数据
      0,                     // TCP数据长度
      ln,                    // libnet句柄
      0                      // 新建TCP标志
    );
    if (tcp_tag == -1) {
      fprintf(stderr, "libnet_build_tcp() failed: %s\n", libnet_geterror(ln));
      exit(1);
    }

    // 设置TCP SYN数据包IP首部
    libnet_ptag_t ip_tag = libnet_build_ipv4(
      LIBNET_IPV4_H + LIBNET_TCP_H,  // IP数据包总长度
      0,                             // TOS
      libnet_get_prand(LIBNET_PRu16),// IP ID
      0,                             // IP fragmentation offset
      64,                            // TTL
      IPPROTO_TCP,                   // 上层协议
      0,                             // IP首部校验和（由内核自动计算）
      inet_addr(target_ip),          // 源IP
      inet_addr(target_ip),          // 目标IP
      NULL,                          // IP数据
      0,                             // IP数据长度
      ln,                            // libnet句柄
      0                              // 新建IP标志
    );
    if (ip_tag == -1) {
}

bool SynScan::checkPacket(const u_char* packet_data, int packet_size)
{
    if (packet_size < LIBNET_IPV4_H + LIBNET_TCP_H) {
        return false;
    }
    const struct libnet_ipv4_hdr* ip_hdr = reinterpret_cast<const struct libnet_ipv4_hdr*>(packet_data + LIBNET_ETH_H);
    const struct libnet_tcp_hdr* tcp_hdr = reinterpret_cast<const struct libnet_tcp_hdr*>(packet_data + LIBNET_ETH_H + LIBNET_IPV4_H);
    if (ip_hdr->ip_src.s_addr != m_ip_addr.toIPv4Address()) {
        return false;
    }
    if (tcp_hdr->th_sport != htons(m_port)) {
        return false;
    }
    if ((tcp_hdr->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        return true;
    }
    return false;
}

void FinScan::scan(QString ip,int port) {
    
}

void NullScan::scan(QString ip,int port) {
    
}


void UdpScan::scan(QString ip,int port) {
    
}

