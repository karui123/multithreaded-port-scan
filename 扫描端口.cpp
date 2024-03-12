#include<WinSock2.h> 
#include<iostream>
#include<time.h>
#include<stdlib.h>
#include<thread>
#include<ctype.h>
#include<mutex>
#include<map>
#pragma comment(lib,"Ws2_32")
using namespace std;
int port_g;
struct node {
	int  port_start;
	int port_end;
	string start_ip_addr;
	string end_ip_addr;
};

//输出服务
string port_server(int port) {
    string temp = "unknow";
    map<int, string> server_map;
    server_map[21] = "FTP";
    server_map[22] = "SSH";
    server_map[23] = "Telnet";
    server_map[25] = "SMTP";
    server_map[53] = "DNS";
    server_map[69] = "TFTP";//简单文件传输协议
    server_map[80] = "HTTP";
    server_map[109] = "POP2";//POP2（Post Office Protocol Version 2，邮局协议2
    server_map[110] = "POP3";//邮件协议3
    server_map[443] = "HTTPS";
    server_map[3306] = "MYSQL";
    server_map[8080] = "WWW代理";
    if (server_map.find(port) != server_map.end()) {
        return server_map.find(port)->second;
    }
    else {
        return temp;
    }
}


//端口扫描
void scan(node N, mutex& port_lock) {
	int port_temp;
    string server;
	SOCKET s;
	while (1) {
		if (port_g > N.port_end) {
			break;
		}
		port_lock.lock();
		port_temp = port_g;
		port_g++;
		port_lock.unlock();
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET) {
			cout << "套接字创建失败" << endl;
			return;
		}
		sockaddr_in dest_com;
		dest_com.sin_family = AF_INET;
		dest_com.sin_port = htons(port_temp);
		dest_com.sin_addr.S_un.S_addr = inet_addr(N.start_ip_addr.c_str());
		int result = connect(s, (sockaddr*)&dest_com, sizeof(sockaddr_in));
		if (result == 0) {
			//cout << "检测到目标主机开放" << port_temp << "端口" << endl;//cout会输出混乱
            server = port_server(port_temp);
			printf("检测到目标主机开放%d端口   %s\n", port_temp,server.c_str());
		}
		closesocket(s);
	}
	return;
}

//PING
// IP数据包头结构
typedef struct iphdr
{
    unsigned int headLen : 4;//位域，headlen占第一字节的四位
    unsigned int version : 4;//version 占第一字节的后四位
    unsigned char tos;//8位服务类型TOS
    unsigned short totalLen;//16位总长度
    unsigned short ident;//16位标识
    unsigned short fragAndFlags;//标志位
    unsigned char ttl;//生存时间
    unsigned char proto;//8位协议
    unsigned short checkSum;//16位校验和
    unsigned int sourceIP;//32位源IP地址
    unsigned int destIP;//32位目的IP地址
}IpHeader;

// ICMP数据头结构
typedef struct ihdr
{
    unsigned char iType;
    unsigned char iCode;
    unsigned short iCheckSum;
    unsigned short iID;
    unsigned short iSeq;
    unsigned long  timeStamp;
}IcmpHeader;

// 计算ICMP包的校验和(发送前要用)
unsigned short checkSum(unsigned short* buffer, int size)
{
    unsigned long ckSum = 0;

    while (size > 1)
    {
        ckSum += *buffer++;
        size -= sizeof(unsigned short);
    }

    if (size)
    {
        ckSum += *(unsigned char*)buffer;
    }

    ckSum = (ckSum >> 16) + (ckSum & 0xffff);
    ckSum += (ckSum >> 16);

    return unsigned short(~ckSum);
}

// 填充ICMP请求包的具体参数
void fillIcmpData(char* icmpData, int dataSize)
{
    IcmpHeader* icmpHead = (IcmpHeader*)icmpData;
    icmpHead->iType = 8;  // 8表示请求包
    icmpHead->iCode = 0;
    icmpHead->iID = (unsigned short)GetCurrentThreadId();
    icmpHead->iSeq = 0;
    icmpHead->timeStamp = GetTickCount();
    char* datapart = icmpData + sizeof(IcmpHeader);
    memset(datapart, 'x', dataSize - sizeof(IcmpHeader)); // 数据部分为xxx..., 实际上有32个x
    icmpHead->iCheckSum = checkSum((unsigned short*)icmpData, dataSize); // 千万要注意，这个一定要放到最后
}

// 对返回的IP数据包进行解析，定位到ICMP数据
int decodeResponse(char* buf, int bytes, struct sockaddr_in* from, int tid)
{
    IpHeader* ipHead = (IpHeader*)buf;
    unsigned short ipHeadLen = ipHead->headLen * 4;
    if (bytes < ipHeadLen + 8) // ICMP数据不完整, 或者不包含ICMP数据
    {
        return -1;
    }

    IcmpHeader* icmpHead = (IcmpHeader*)(buf + ipHeadLen);  // 定位到ICMP包头的起始位置
    if (icmpHead->iType != 0)   // 0表示回应包
    {
        return -2;
    }

    if (icmpHead->iID != (unsigned short)tid) // 理应相等
    {
        return -3;
    }

    int time = GetTickCount() - (icmpHead->timeStamp); // 返回时间与发送时间的差值
    if (time >= 0)
    {
        return time;
    }

    return -4; // 时间错误
}

// ping操作
int ping(const char* ip, unsigned int timeout)
{
    // 网络初始化
    WSADATA wsaData;
    WSAStartup(MAKEWORD(1, 1), &wsaData);
    unsigned int sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);  // icmp
    setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));  // 设置套接字的接收超时选项
    setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));  // 设置套接字的发送超时选项

    // 准备要发送的数据
    int  dataSize = sizeof(IcmpHeader) + 32; // 内容共32个x
    char icmpData[1024] = { 0 };
    fillIcmpData(icmpData, dataSize);
    unsigned long startTime = ((IcmpHeader*)icmpData)->timeStamp;

    // 远程通信端
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    struct hostent* hp = gethostbyname(ip);
    memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
    dest.sin_family = hp->h_addrtype;

    // 发送数据
    sendto(sockRaw, icmpData, dataSize, 0, (struct sockaddr*)&dest, sizeof(dest));


    int iRet = -1;
    struct sockaddr_in from;
    int fromLen = sizeof(from);
    while (1)
    {
        // 接收数据
        char recvBuf[1024] = { 0 };
        int iRecv = recvfrom(sockRaw, recvBuf, 1024, 0, (struct sockaddr*)&from, &fromLen);
        int time = decodeResponse(recvBuf, iRecv, &from, GetCurrentThreadId());
        if (time >= 0)
        {
            iRet = 0;   // alive
            break;
        }
        else if (GetTickCount() - startTime >= timeout || GetTickCount() < startTime)
        {
            iRet = -1;  // ping超时
            break;
        }
    }

    // 释放
    closesocket(sockRaw);
    WSACleanup();

    return iRet;
}

//IP存活扫描
void ip_addf_scan(string start_ip_addr,string end_ip_addr) {
    string ip_all[255];
    unsigned start_ip, end_ip, index, i = 0;
    start_ip = htonl(inet_addr(start_ip_addr.c_str()));
    index = start_ip;
    end_ip = htonl(inet_addr(end_ip_addr.c_str()));
    struct in_addr temp;//用于转化
    for (index = start_ip;index <= end_ip;index++) {
        temp.S_un.S_addr = ntohl(index);
        ip_all[i] = inet_ntoa(temp);//inet_ntoa转化后的是char*型
        i++;
    }
    for (int j = 0;j < i;j++) {
        int p_result = ping(ip_all[j].c_str(), 3000);
        if (p_result == 0) {
            cout << ip_all[j] << " 目标主机已开启" << endl;
        }
    }
}


int main() {
	node N;
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
	int thread_count;
	mutex port_lock;//互斥锁
	thread* mythread = new thread[2000];//线程数组
	time_t start_time, end_time;
	int function;
    double time_pay;


	cout << "**********************"<<endl;
	cout << "1、全连接端口扫描" << endl;
    cout << "2、扫描IP存活" << endl;
	cout << "0、退出" << endl;
    cout << "**********************" << endl;
key:
    cout << "选择功能" << endl;
	cin >> function;
	switch (function)
	{
	case 1:
		cout << "输入要扫描的IP地址" << endl;
		cin >> N.start_ip_addr;
		cout << "输入扫描的端口范围" << endl;
		cin >> N.port_start >> N.port_end;
		cout << "输入要开启的线程数（最大1500）" << endl;
		cin >> thread_count;
		port_g = N.port_start;
		start_time = clock();
		for (int i = 0;i < thread_count;i++) {
			mythread[i] = thread(scan, N, ref(port_lock));
		}
		for (int i = 0;i < thread_count;i++) {
			mythread[i].join();
		}
		delete[]mythread;
		end_time = clock();
		time_pay = double(end_time - start_time) / CLOCKS_PER_SEC;
		cout << "花费时间" << time_pay << "s"<<endl;
		goto key;
    case 2:
        cout<<"输入你想扫描的网段(开始IP~终止IP)"<<endl;
        cin >> N.start_ip_addr >> N.end_ip_addr;
        ip_addf_scan(N.start_ip_addr,N.end_ip_addr);
        goto key;
    
	case 0:
		break;
	}
	return 0;
}