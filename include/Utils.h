#include <QString>
#include <iostream>
#include <QMap>
#include <string>
#include <vector>
#include <stdexcept>
using namespace std;
#define CLOSE 0x01
#define OPEN 0x02
#define FILTERED 0x04
extern int scaned_ports;
extern QMap<QString,bool> is_send_done;
//判断端口状态
const char* state(int s);
//文字填充，格式化
QString FillIn(QString str,int maxLen,QChar c);
//校验IP
void validate_ip(string ip) throw(string);
//解析IP段
vector<string>* calculate_prefix(string ip) throw(string);