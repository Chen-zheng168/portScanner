#include<iostream>
#include<string>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <mutex>
using namespace std;




void test01(){
    uint16_t u0 = 1;
    int u1 = 1;
    cout <<ntohs(static_cast<uint16_t>(u1))<<"  " <<ntohs(2)<<endl;
    cout <<*((uint16_t*)&u1)<<endl;
}


int main(){
    string ip = string("127.23.1.32/24");
    int pos = ip.find('/',0);
    cout << pos << endl;
    test01();
}