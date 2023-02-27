
#include "../include/PortScanner.h"


void PortScanner::scan(const vector<string>& dst_ips, uint16_t start_port, uint16_t end_port)
{

    // m_src_ip = "10.10.0.8";
    // 清除之前扫描的结果
    m_scan_result.clear();
    m_scan_result += FillIn(QString("IP Address"),28,' ');
    m_scan_result += FillIn(QString("|  Port"),20,' ');
    m_scan_result += FillIn(QString("|  State"),20,' ').append('\n');
    m_scan_result += FillIn(QString(""),68,'-').append('\n');
    for (QMap<QString,QMap<uint16_t,uint16_t>>::iterator it=m_results.begin();it != m_results.end();++it){
        it->clear();
    }
    for (string dst_ip : dst_ips){
        //根据扫描技术和only_show_open来判断是否对每个端口赋初始状态
        QMap<uint16_t,uint16_t> port_map;
        if (m_scanType == "SYN" || m_scanType == "FULL" || m_scanType == "TCP_WINDOW"){
            if (!m_only_show_open){
                for(uint16_t i=start_port;i <= end_port;i++){
                    port_map.insert(i,FILTERED);
                }
            }
        }else{
            for(uint16_t i=start_port;i <= end_port;i++){
                port_map.insert(i ,OPEN|FILTERED);
            }
               
        }
        m_results.insert(QString::fromStdString(dst_ip),port_map);
    }
    scaned_ports  = 0;
    m_progress = 0;
    // char* filter = creatFilter(m_scanType,m_src_ip);

    
    // 计算端口数量
    m_ports = end_port - start_port + 1;
    m_total_ports = m_ports*dst_ips.size();
    // 设置线程池大小为可用线程数
    int num_threads = QThreadPool::globalInstance()->maxThreadCount();
    int num_scan_threads = qMin(num_threads, 2);
    // num_scan_threads = 1;
    QThreadPool::globalInstance()->setMaxThreadCount(num_scan_threads);
    QList<QPair<QString,QPair<uint16_t, uint16_t>>> port_ranges;
    for (auto dst_ip:dst_ips){
        port_ranges.append(qMakePair(QString::fromStdString(dst_ip),qMakePair(start_port,end_port)));
    }
    m_threads_pool.clear();

    char* dev = NULL;
    // 启动发送线程
    libnet_t* libnet_handle=NULL;
    SendTask* sendTask = new SendTask(dev,port_ranges,m_scanType);
    // 连接信号槽
    connect(this,&PortScanner::pause,sendTask,&SendTask::pause);
    connect(this,&PortScanner::resume,sendTask,&SendTask::resume);
    connect(this,&PortScanner::stop,sendTask,&SendTask::stop);
    connect(sendTask,&SendTask::error,this,&PortScanner::handleError);
    // connect(sendTask,&SendTask::resultReady,this,&PortScanner::handleTask);

    //启动接受线程
    RevTask* revTask = new RevTask(dev,m_scanType);
    connect(this,&PortScanner::pause,revTask,&RevTask::pause);
    connect(this,&PortScanner::resume,revTask,&RevTask::resume);
    connect(this,&PortScanner::stop,revTask,&RevTask::stop);
    connect(revTask,&RevTask::error,this,&PortScanner::handleError);
    connect(revTask,&RevTask::resultReady,this,&PortScanner::handleTask);
    connect(revTask,&RevTask::finished,this,&PortScanner::handleFinished);
    connect(revTask,&RevTask::finished,sendTask,&SendTask::revEnd);
    connect(sendTask,&SendTask::setCurrentIP,revTask,&RevTask::getCurrentIP);
    connect(sendTask,&SendTask::startSend,revTask,&RevTask::startRev);
    connect(sendTask,&SendTask::endSend,revTask,&RevTask::endRev);
    connect(sendTask,&SendTask::initError,revTask,&RevTask::initError);;
    m_start_time = clock();
    m_threads_pool.start(sendTask);
    m_threads_pool.start(revTask);
}

void PortScanner::handleTask(const QString& dst_ip,uint16_t port, uint16_t open)
{
    // m_mutex.lock();
    if ((m_only_show_open && open == OPEN) || !m_only_show_open){
        QMap<uint16_t,uint16_t> state_ = m_results.value(dst_ip);
        state_.insert(port, open);
        m_results.insert(dst_ip,state_);
    }
    // m_mutex.unlock();
    // emit resultReady(port, open);
    int progress_ = 100*scaned_ports / m_total_ports;
    // cout << scaned_ports << endl;
    if (m_progress != progress_){
        m_progress = progress_;
        emit progress(m_progress);
    }
}
void PortScanner::handleFinished(){
    cout << scaned_ports <<"  " << m_total_ports<<endl;
    if (scaned_ports == m_total_ports) {
        clock_t spend_time = clock()-m_start_time;
        for (QString dst_ip: m_results.keys()){
            QMap<uint16_t,uint16_t> state_   = m_results.value(dst_ip);
            for(QMap<uint16_t,uint16_t>::iterator it =  state_.begin(); it != state_.end();++it){
                m_scan_result += QString(dst_ip).leftJustified(30,' ');
                // cout << it.key() << endl;
                m_scan_result += QString("%1").arg(it.key()).leftJustified(20,' ');
                m_scan_result += QString("%1").arg(state(it.value())).leftJustified(18,' ').append('\n');
            }
        }
        m_scan_result += QString("spend time: %1 s").arg(double(spend_time)/CLOCKS_PER_SEC).append('\n');
        emit progress(100);
        emit finished();
        emit finalResult(m_scan_result);
    }
}

PortScanner::~PortScanner()
{
    m_threads_pool.clear();
}