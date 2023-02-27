#include <QObject>
#include <QThreadPool>
#include <QMap>
#include <QVector>
#include <iostream>
#include <time.h>
#include "ScanTask.h"
#include "Utils.h"

using namespace std;

class PortScanner : public QObject
{
    Q_OBJECT

public:
    explicit PortScanner(QObject *parent = nullptr) : QObject(parent) {
        m_progress = 0;
    }
    ~PortScanner();
    bool initLibnet(char* dev,libnet_t* libnet_handle);
    void scan(const vector<string>& dst_ips, uint16_t start_port, uint16_t end_port);

    // 获取扫描结果
    const QMap<QString,QMap<uint16_t,uint16_t>>& results() const { return m_results; }

    void setScanType(const QString& scanType){
        m_scanType = scanType;
    }
    void setShowType(bool showType){
        m_only_show_open = showType;
    }
    

public slots:
    //暂停扫描
    void paused(){
        emit pause();
    }
    //恢复扫描
    void resumed(){
        emit resume();
    }
    // 停止扫描
    void stoped()
    {
        // 终止所有线程
        m_threads_pool.clear();
        // 发送 stopped 信号
        emit stop();
    }
    void handleError(const QString& err){
        emit error(err);
    }
    void handleFinished();
    // 接收任务完成信号
    void handleTask(const QString& dst_ip,uint16_t port, uint16_t open);
signals:
    // 扫描结果更新信号
    void resultReady(int port, int open);
    // 扫描结果
    void finalResult(const QString& res);
    // 扫描结束信号
    void finished();
    //扫描进度信号
    void progress(int value);

    // 扫描停止信号
    void stop();
    // 扫描暂停信号
    void pause();
    // 扫描恢复信号
    void resume();
    void error(const QString& err);

private:
    QThreadPool m_threads_pool;
    QMap<QString,QMap<uint16_t,uint16_t>> m_results;// 扫描结果
    QString m_scanType;//扫描类型
    QMutex m_mutex;//锁
    QList<QPair<int, int>> m_port_range;//
    pcap_t* m_pcap_handle;
    int m_ports;
    int m_total_ports;
    const char* m_src_ip;
    int m_progress ;    
    bool m_only_show_open;
    clock_t m_start_time;
    QString m_scan_result;
};
