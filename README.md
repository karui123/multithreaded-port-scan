### 1、全连接端口扫描功能

与指定端口进行三次握手通信，如果能够成功连接则说明目标端口开放，如果没有目标主机会返回RST/ACK，证明端口没有开放。全连接端口扫描的准确度很高，但却非常容易被检测到然后使用的IP极易被拉入黑名单。

![img](D:\screen shout\typora\clip_image002.jpg)

### 2、多线程

在main函数中创建一个线程数组，并赋予一定的初始值。当使用时先输入线程数，再使用for循环依次初始线程，使用结构体进行传参，并加上互斥锁。在线程调用的函数中对端口进行上锁，使线程读取端口号时不会发生冲突，避免出现一个端口被多次扫描的现象。
 在输出结果时，开始使用cout进行输出，出现输出格式不正确的现象，搜索资料得知cout不是原子操作，向输出缓冲区中加入数据时不会马上刷新到页面上。使用printf，输入数据完数据在跳转到其他线程时可以即使的刷新输出流，把数据更新到界面。

### 3、输出服务

首先自定义一个map，里面存储常用的服务以及对应的端口号。在输出时即使使用printf也出现了乱码的情况，在搜索相关资料后，发现要先将字符串转化为字符型，再输出。

### 4、扫描IP地址段

最初打算先根据点将IP地址各段分离单独取出，转为整数，在逐渐加一再转化回字符串类型拼接起来直到IP地址为终止地址。但是这个方法过于麻烦，于是打算使用htnol(inet_addr(ip))将IP地址转化为无符号长整型，进行加操作后再转化为字符串型IP数组。节省了许多中间过程。使用ping来确定目标主机是否可以通信。ping 使用的是ICMP协议，它发送ICMP回送请求消息给目的主机。ICMP协议规定：目的主机必须返回ICMP回送应答消息给源主机。如果源主机在一定时间内收到应答，则认为主机可达。ICMP协议通过IP协议发送的，IP协议是一种无连接的，不可靠的数据包协议。Windows中ping程序的ICMP序列号是没有规律，所以这里使用线程id作为ICMP的序列号。

### 5、半连接

由于syn端口扫描需要取得root权限，所以我在kali Linux下实现这一功能，虽然windows下C++和Linux下C++大体相同，但由于对LinuxC++编程的不熟悉，我本想在Linux上依葫芦画瓢。考虑到半连接扫描端口的效率高，就没有使用线程。并且考虑到Linux下大多数命令都是直接在其后加参数运行，所以在main函数中使用了形参，依次是IP地址，起始端口，终止端口。

![img](D:\screen shout\typora\clip_image004.jpg)

### 6、计时

在全连接端口扫描上进行了计时，IP网段扫描以及半连接因为消耗的时间较短，所以不计时。因为clock()是以毫秒为单位，要将其转化为秒，强制转化成double类型并除以CLOCKS_PER_SEC。CLOCKS_PER_SEC表示一秒钟cpu运行的时钟周期数。