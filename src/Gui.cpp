#include "../include/Gui.h"



Gui::Gui(QWidget* parent) : QMainWindow(parent)
{
    // 创建控件
    m_typeBox = new QComboBox(this);
    QStringList strList;
    strList << "SYN"
            << "FULL";
    m_typeBox->addItems(strList);
    m_typeBox->setCurrentIndex(1);
    m_ipEdit = new QLineEdit("127.0.0.1", this);
    m_startPortSpin = new QSpinBox(this);
    m_startPortSpin->setRange(1, 65535);
    m_startPortSpin->setValue(1);
    m_endPortSpin = new QSpinBox(this);
    m_endPortSpin->setRange(1, 65535);
    m_endPortSpin->setValue(1000);
    m_scanBtn = new QPushButton("扫描", this);
    m_stopBtn = new QPushButton("暂停", this);
    m_stopBtn->setEnabled(false);
    QProgressBar *m_progressBar = new QProgressBar;
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_statusLabel = new QLabel(this);

    // 创建布局
    QGridLayout* layout = new QGridLayout(this);
    layout->addWidget(new QLabel("扫描技术:", this), 0, 0);
    layout->addWidget(m_typeBox, 0, 1);
    layout->addWidget(new QLabel("IP 地址:", this), 1, 0);
    layout->addWidget(m_ipEdit, 1, 1);
    layout->addWidget(new QLabel("开始端口:", this), 2, 0);
    layout->addWidget(m_startPortSpin, 2, 1);
    layout->addWidget(new QLabel("结束端口:", this), 3, 0);
    layout->addWidget(m_endPortSpin, 3, 1);
    layout->addWidget(m_scanBtn, 4, 0);
    layout->addWidget(m_stopBtn, 4, 1);
    layout->addWidget(m_progressBar);
    layout->addWidget(m_statusLabel, 6, 0, 1, 2);

    m_scanner = new PortScanner();
    // 连接信号槽
    connect(m_scanBtn, &QPushButton::clicked, this, [=]() {
        // 点击“Scan”按钮后开始扫描
        startScan(m_ipEdit->text(), m_startPortSpin->value(), m_endPortSpin->value());
    });

    connect(m_stopBtn, &QPushButton::clicked, this, &Gui::stopScan);
    connect(m_pauseBtn, &QPushButton::clicked, this, &Gui::pauseScan);
    connect(m_scanner, &PortScanner::error,this, &Gui::error);
    connect(this, &Gui::stop, m_scanner, &PortScanner::stoped);
    connect(this, &Gui::resume, m_scanner, &PortScanner::resumed);
    connect(this, &Gui::pause, m_scanner, &PortScanner::paused);
}

void Gui::startScan(const QString& ip, int start_port, int end_port)
{
    m_stopBtn->setEnabled(true);
    m_pauseBtn->setEnabled(true);
    m_statusLabel->setText("————————开始扫描————————\n");
    // 创建端口扫描器,根据扫描方式创建对应的扫描器
    m_scanner->setScanType(m_typeBox->currentText());
    // 连接端口扫描器的信号槽
    connect(m_scanner, &PortScanner::resultReady, this, &Gui::updateResult);
    connect(m_scanner, &PortScanner::progress, this, &Gui::progress);
    // 开始扫描
    m_scanner->scan(ip, start_port, end_port);
}

void Gui::pauseScan() 
{ 
    if (m_pauseBtn->text() == "暂停"){
        emit pause(); 
    }else if (m_pauseBtn->text() == "继续"){
        emit resume(); 
    }
}

void Gui::progress(int value){
    m_progressBar->setValue(value);
}

void Gui::updateResult(int port, bool open)
{
    // 在状态标签中显示扫描结果
    QString statusText = QString("Port %1 is %2\n").arg(port).arg(open ? "open" : "closed");
    m_statusLabel->setText(m_statusLabel->text() + statusText);
}

void Gui::error(const QString& err){
    // 在状态标签中显示错误
    m_statusLabel->setText(m_statusLabel->text() + err);
}

