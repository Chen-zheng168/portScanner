#include "../include/Utils.h"
#include <math.h>

using namespace std;
int scaned_ports = 0;
QMap<QString,bool> is_send_done = QMap<QString,bool>() ;
const char* state(int s){
    switch (s)
    {
    case OPEN:
        return "open";
    case CLOSE:
        return "closed";
    case FILTERED:
        return "filtered";
    case OPEN|FILTERED:
        return "open|filtered";
    
    }
}

QString FillIn(QString str,int maxLen,QChar c)
{
    int len = str.length();
    if(len < maxLen){
        for (int i=0; i < maxLen-len; i++){
            str += c;
        }
    }
    return str;
}

void validate_ip(string ip)throw(string)
{
    if(ip.find(".") == std::string::npos)
        throw string("invalid ip: ").append(ip);
    int count;
    int a,b,c,d;
    count = sscanf(ip.c_str(),"%d.%d.%d.%d", &a, &b, &c, &d);
    if (count!= 4)
        throw string("invalid ip: ").append(ip);

    if ( a <0 || a>255 ||b <0 ||b>255 ||c<0 || c>255 || d<0 || d>255)
        throw string("invalid ip: ").append(ip);
}

vector<string>* calculate_prefix(string ip) throw(string)
{
    int i,k,l,m;
    char* post;
    int pos,preRange,pos1;
    string ipPre, ipaddr;
    long double ip_num;
    vector<string>* ipAddress = NULL;

    if((pos = ip.find('/',0))==std::string::npos){
        try{
            validate_ip(ip);
            // cout << ip << endl;
            ipAddress = new vector<string>;
            ipAddress->push_back(ip);
            return ipAddress;
        }
        catch(string e){
            throw e;
        }
    }
    ipPre = ip.substr(0,pos);
    // cout << "/"<<ip << " %" << pos << endl;
    try{
        validate_ip(ipPre);
    }
    catch(string e){
        throw e;
    }
    
    ipAddress = new vector<string>;
    preRange = 32 - atoi(ip.substr(pos+1,ip.size()).c_str());
    ip_num = (int)pow(2.0,preRange);
    
    pos1 = -1;
    switch(preRange)
    {
        case 32:
            
            for(i=1;i<256;i++)
                for(k=0;k<256;k++)
                    for(l=0;l<256;l++)
                        for(m=1;m<255;m++)
                        {
                            sprintf(post,"%d.%d.%d.%d",i,k,l,m);
                            ipaddr=post;
                            ipAddress->push_back(ipaddr);
                            // validate_ip(ipaddr);
                        }
            break;
        case  8:
            
            for( i=0;i<3;i++)
            {
                pos1 = ip.find(".",pos1+1);
            }
            ipPre = ip.substr(0,pos1);
            for(i=1;i<255;i++)
            {
                sprintf(post,"%d",i);
                ipaddr=ipPre+"."+post;
                ipAddress->push_back(ipaddr);
                // validate_ip(ipaddr);
            }
            break;
        case 16:
            
            for(i=0;i<2;i++)
            {
                pos1 = ip.find(".",pos1+1);
            }
            ipPre = ip.substr(0,pos1);
            for(i=0;i<256;i++)
                for(k=0;k<256;k++)
                {
                    sprintf(post,"%d.%d",i,k);
                    ipaddr=ipPre+"."+post;
                    ipAddress->push_back(ipaddr);
                    // validate_ip(ipaddr);
                }
            break;
        case 24:
            
            for(i=0;i<1;i++)
            {
                pos1 = ip.find(".",pos1+1);
            }
            ipPre = ip.substr(0,pos1);
            for(i=0;i<256;i++)
                for(k=0;k<256;k++)
                    for(l=0;l<256;l++)
                    {
                        sprintf(post,"%d.%d.%d",i,k,l);
                        ipaddr=ipPre+"."+post;
                        ipAddress->push_back(ipaddr);
                        // validate_ip(ipaddr);
                    }
            break;
        default:
            throw string("Invalid prefix. IP: ").append(ip) ;  
    }
    return ipAddress;
}


