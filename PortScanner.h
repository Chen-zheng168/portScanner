

#include <QObject>
#include <QThreadPool>
#include <QMap>
#include "ScanTask.h"

class PortScanner : public QObject
{
    Q_OBJECT

public:
    explicit PortScanner(QObject *parent = nullptr) : QObject(parent) {
        m_progress = 0;
    }

    void scan(const QString &ip, int start_port, int end_port);

    // 获取扫描结果
    const QMap<int, bool>& results() const { return m_results; }

    void setScanType(const Qstring& scanType){
        m_scanType = scanType;
    }

public slots:
    //暂停扫描
    void pause(){
        emit pause();
    }
    //恢复扫描
    void resume(){
        emit resume();
    }
    // 停止扫描
    void stop()
    {
        // 终止所有线程
        QThreadPool::globalInstance()->clear();
        // 发送 stopped 信号
        emit stop();
    }

private slots:
    // 接收任务完成信号
    void handleTask(int port, bool open)
    {
        QMutexLocker locker(&m_mutex);
        m_results.insert(port, open);
        emit resultReady(port, open);
        int progress = 100 * m_results.size() / m_ports;
        if (m_progress != progress){
            m_progress = progress;
            emit progress(progress);
        }
        if (m_results.size() == m_ports) {
            emit finished();
        }
    }
signals:
    // 扫描结果更新信号
    void resultReady(int port, bool open);
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

private:
    // 扫描结果
    QMap<int, bool> m_results;
    Qstring m_scanType;
    QMutex m_mutex;
    QList<QPair<int, int>> m_port_range;
    int m_ports;
    int m_progress ;
};