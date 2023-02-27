#include "../include/Gui.h"


Gui::Gui(QWidget* parent):QWidget(parent)
{
    // 创建控件
    m_typeBox = new QComboBox;
    QStringList strList;
    strList << "SYN" <<"FULL" <<"NULL" << "FIN" << "Xmas" << "TCP_WINDOW";
    m_typeBox->addItems(strList);
    m_typeBox->setCurrentIndex(0);
    m_showBox = new QComboBox;
    QStringList stateList;
    stateList << "NO" << "YES";
    m_showBox->addItems(stateList);
    m_showBox->setCurrentIndex(1);
    m_ipEdit = new QLineEdit("127.0.0.1");
    m_startPortSpin = new QSpinBox;
    m_startPortSpin->setRange(1, 65535);
    m_startPortSpin->setValue(1);
    m_endPortSpin = new QSpinBox;
    m_endPortSpin->setRange(1, 65535);
    m_endPortSpin->setValue(1000);
    m_scanBtn = new QPushButton("扫描");
    m_stopBtn = new QPushButton("结束");
    m_stopBtn->setEnabled(false);
    m_pauseBtn = new QPushButton("暂停");
    m_pauseBtn->setEnabled(false);
    m_progressBar = new QProgressBar;
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_statusLabel = new QTextEdit;
    m_statusLabel->setMinimumSize(300,400);
    // QScrollArea * scrollArea = new QScrollArea;
    // 创建布局

    QGridLayout* layout = new QGridLayout;
    layout->addWidget(new QLabel("扫描技术:"), 0, 0,1,3);
    layout->addWidget(m_typeBox, 0, 3,1,3);
    layout->addWidget(new QLabel("只显示开放端口:"), 0, 6,1,3);
    layout->addWidget(m_showBox, 0, 9,1,3);
    layout->addWidget(new QLabel("IP 地址:"), 1, 0,1,3);
    layout->addWidget(m_ipEdit, 1, 3,1,9);
    layout->addWidget(new QLabel("开始端口:"), 2, 0,1,3);
    layout->addWidget(m_startPortSpin, 2, 3,1,3);
    layout->addWidget(new QLabel("结束端口:"), 2, 6,1,3);
    layout->addWidget(m_endPortSpin, 2, 9,1,3);
    layout->addWidget(m_scanBtn,3, 0,1,4);
    layout->addWidget(m_stopBtn,3, 4,1,4);
    layout->addWidget(m_pauseBtn,3,8,1,4);
    layout->addWidget(m_progressBar,4,0, 1, 12);
    layout->addWidget(m_statusLabel, 5, 0, 1, 12);
    setLayout(layout);
    m_scanner = new PortScanner();
    // 连接信号槽
    connect(m_scanBtn, &QPushButton::clicked, this, [=]() {
        // 点击“Scan”按钮后开始扫描
        startScan(m_ipEdit->text(), (uint16_t)m_startPortSpin->value(), (uint16_t)m_endPortSpin->value());
    });

    connect(m_stopBtn, &QPushButton::clicked, this, &Gui::stopScan);
    connect(m_pauseBtn, &QPushButton::clicked, this, &Gui::pauseScan);
    connect(m_scanner, &PortScanner::error,this, &Gui::error);
    connect(this, &Gui::stop, m_scanner, &PortScanner::stoped);
    connect(this, &Gui::resume, m_scanner, &PortScanner::resumed);
    connect(this, &Gui::pause, m_scanner, &PortScanner::paused);
}

void Gui::startScan(QString ips, uint16_t start_port, uint16_t end_port)
{
    m_stopBtn->setEnabled(true);
    m_pauseBtn->setEnabled(true);
    m_scanBtn->setDisabled(true);
    m_statusLabel->clear();
    ips.remove(QRegExp("\\s"));
    cout << ips.toStdString().length() << endl;
    QStringList ip_list = ips.split(',',QString::SkipEmptyParts);
    vector<string> ip_vector;
    for(QString ip : ip_list){
        try{
            vector<string>* ips = calculate_prefix(ip.toStdString());
            ip_vector.insert(ip_vector.end(),ips->begin(),ips->end());
            cout << ip_vector.size() << endl;
            delete ips;
        }catch (string e){
            m_statusLabel->append(e.c_str());
            return;
        }    
    }

    m_statusLabel->append("------------开始扫描------------\n");
    // 创建端口扫描器,根据扫描方式创建对应的扫描器
    m_scanner->setScanType(m_typeBox->currentText());
    m_scanner->setShowType(m_showBox->currentIndex());
    // 连接端口扫描器的信号槽
    connect(m_scanner, &PortScanner::resultReady, this, &Gui::updateResult);
    connect(m_scanner, &PortScanner::finalResult, this, &Gui::finalResult);
    connect(m_scanner, &PortScanner::progress, this, &Gui::progress);
    connect(m_scanner, &PortScanner::finished, this, &Gui::finished);
    // 开始扫描
    m_scanner->scan(ip_vector, start_port, end_port);
}

void Gui::pauseScan() 
{ 
    if (m_pauseBtn->text() == "暂停"){
        m_pauseBtn->setText("继续");
        emit pause(); 
    }else if (m_pauseBtn->text() == "继续"){
        m_pauseBtn->setText("暂停");
        emit resume(); 
    }
}

void Gui::progress(int value){
    m_progressBar->setValue(value);
}

void Gui::stopScan(){
    m_stopBtn->setDisabled(true);
    m_pauseBtn->setDisabled(true);
    m_scanBtn->setEnabled(true); 
    emit stop(); 
}
void Gui::finished(){
    m_stopBtn->setDisabled(true);
    m_pauseBtn->setDisabled(true);
    m_scanBtn->setEnabled(true); 
}

void Gui::finalResult(const QString& res){
    m_statusLabel->clear();
    m_statusLabel->append(res);
}
void Gui::updateResult(int port, int open)
{
    // 在状态标签中显示扫描结果
    QString statusText = QString("Port %1 is %2\n").arg(port).arg(state(open));
    m_statusLabel->append( statusText);
}

void Gui::error(const QString& err){
    // 在状态标签中显示错误
    m_statusLabel->append(err);
}

// Gui::~Gui(){
//     delete m_ipEdit;
//     delete m_startPortSpin;
//     delete m_endPortSpin;
//     delete m_scanBtn;
//     delete m_pauseBtn;
//     delete m_stopBtn;
//     delete m_statusLabel;
//     delete m_progressBar;
//     delete m_typeBox;
//     delete m_showBox ;
//     delete m_scanner;
// }
