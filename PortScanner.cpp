#pragma once
#include "PortScanner.h"

ScanTask* creatScanTask(const Qstring& type,const Qstring&  ip, int start_port, int end_port){
    ScanTask *scanTask = NULL;
    if (type == "SYN"){
        scanTask = new 
    }else if (type == "SYN"){
        scanTask = new 
    }else if (type == "SYN"){
        scanTask = new 
    }else if (type == "SYN"){
        scanTask = new 
    }else if (type == "SYN"){
        scanTask = new 
    }
    return scanTask;
}

PortScanner::PortScanner(QObject *parent = nullptr) : QObject(parent) 
{
    m_progress = 0;
}

void PortScanner::scan(const QString& ip, int start_port, int end_port)
{
    // 清除之前扫描的结果
    m_results.clear();
    m_progress = 0;
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
        ScanTask* scanTask = creatScanTask(m_scanType,ip, range.first, range.second)
        // 连接信号槽
        connect(this,&PortScanner::pause,scanTask,&ScanTask::pause);
        connect(this,&PortScanner::resume,scanTask,&ScanTask::resume);
        connect(this,&PortScanner::stop,scanTask,&ScanTask::stop);
        connect(scanTask,&ScanTask::resultReady,this,&PortScanner::handleTask);
        QThreadPool::globalInstance()->start(scanTask);
    }
}