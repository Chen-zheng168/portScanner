

#include <QMainWindow>
#include <QWidget>
#include <QThread>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QString>
#include <QSpinBox>
#include <QPushButton>
#include <QTextEdit>
#include <QThreadPool>
#include <QMutex>
#include "PortScanner.h"

using namespace std;

class Gui : public QWidget
{
    Q_OBJECT
public:
    Gui(QWidget *parent=nullptr);

public slots:
    // 开始扫描
    void startScan(QString ips, uint16_t start_port, uint16_t end_port);
    // 更新扫描结果
    void updateResult(int port, int open);
    //扫描结果
    void finalResult(const QString& res);
    // 停止扫描
    void stopScan();
    // 暂停/恢复扫描
    void pauseScan();
    //扫描进度
    void progress(int value);
    //扫描结束
    void finished();
    //扫描出错
    void error(const QString& err);
signals:
    // 扫描停止信号
    void stop();
    // 扫描暂停信号
    void pause();
    // 扫描恢复信号
    void resume();


private:
    // 控件

    QLineEdit* m_ipEdit;
    QSpinBox* m_startPortSpin;
    QSpinBox* m_endPortSpin;
    QPushButton* m_scanBtn;
    QPushButton* m_pauseBtn;
    QPushButton* m_stopBtn;
    QTextEdit* m_statusLabel;
    QProgressBar *m_progressBar;
    //扫描方式
    QComboBox* m_typeBox;
    QComboBox* m_showBox ;
    // 端口扫描器
    PortScanner* m_scanner;
};

