#include <pcap/pcap.h>
#include <sys/socket.h>
#include <pcapplusplus/PcapFilter.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/SSLLayer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/FtpLayer.h>
#include <iostream>
#include <fstream>
#include <regex>
#include "net_headers.h"
#include <postgresql/libpq-fe.h>
#include "convert.h"
std::string IP_serv ;

  int count=0;
#define SERVER_ADRESS "127.0.0.1"
#define SERVER_PORT 3425  


struct Packet{
    char src_ip[12];
    char dst_ip[12];
    int src_port;
    int dst_port;
    std::string data="";
    std::string dataHex="";
    bool protocols;
};

struct Rule{
    std::string src_ip;
    std::string dst_ip;
    std::string src_port;
    std::string dst_port;
    std::regex reg;
    std::regex regHex;
    std::string protocol;
};



#define UNUSED(x) ((void)(x))
// std::string  filter = "not ether proto \\stp and not ether proto \\arp and not proto \\icmp and not (icmp6[icmp6type] != icmp6-echo and icmp6[icmp6type] != icmp6-echoreply)";
//std::string filter1 = "net 192.168.3.0/24 and not port 5672 and not port 3306 and not port 5432";
std::string filter1 = " not port 5672 and not port 3306 and not port 5432";
#define PRINT_BYTES_PER_LINE 16

// функция для отправки собранной информации на сборщик


//функция для вывода информации о всем трафике в консоль(в основном проекте ее не будет, это для быстрой проверки)
static void print_data_hex(const uint8_t *data, int size)
{
    int offset = 0;
    int nlines = size / PRINT_BYTES_PER_LINE;
    if (nlines * PRINT_BYTES_PER_LINE < size)
        nlines++;

    printf("        ");

    for (int i = 0; i < PRINT_BYTES_PER_LINE; i++)
        printf("%02X ", i);

    printf("\n\n");

    for (int line = 0; line < nlines; line++)
    {
        printf("%04X    ", offset);
        for (int j = 0; j < PRINT_BYTES_PER_LINE; j++)
        {
            if (offset + j >= size)
                printf("   ");
            else
                printf("%02X ", data[offset + j]);
        }

        printf("   ");

        for (int j = 0; j < PRINT_BYTES_PER_LINE; j++)
        {
            if (offset + j >= size)
                printf(" ");
            else if (data[offset + j] > 31 && data[offset + j] < 127)
                printf("%c", data[offset + j]);
            else
                printf(".");
        }

        offset += PRINT_BYTES_PER_LINE;
        printf("\n");
    }
}







bool GoodPacket(Rule rule, Packet packet){

 if (std::regex_search(packet.data, rule.reg)) {
       return false;
    }

    return true;
}




//обработка пакета
static void handlePacket(uint8_t *user, const struct pcap_pkthdr *hdr, const uint8_t *bytes)
{
    int protoBefore=0;
    int proto=0;
    //+2 т.к прослушиваем все устройства
    struct iphdr *ip_header = (struct iphdr *)(bytes + 2 + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;

    Packet packet;
    Rule rule;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    char source_ip[128];
    char dest_ip[128];
    strncpy(source_ip, inet_ntoa(source.sin_addr), sizeof(source_ip));
    strncpy(dest_ip, inet_ntoa(dest.sin_addr), sizeof(dest_ip));

    int source_port = 0;
    int dest_port = 0;
    int data_size = 0;
    int ip_header_size = ip_header->ihl * 4;
    char *next_header = (char *)ip_header + ip_header_size;

    //определяем протокол транспортного уровня
    if (ip_header->protocol == IP_HEADER_PROTOCOL_TCP)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)next_header;
        source_port = ntohs(tcp_header->source);
        dest_port = ntohs(tcp_header->dest);
        int tcp_header_size = tcp_header->doff * 4;
        data_size = hdr->len - sizeof(struct ethhdr) - ip_header_size - tcp_header_size;
    }
    else if (ip_header->protocol == IP_HEADER_PROTOCOL_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)next_header;
        source_port = ntohs(udp_header->source);
        dest_port = ntohs(udp_header->dest);
        data_size = hdr->len - sizeof(struct ethhdr) - ip_header_size - sizeof(struct udphdr);
    }

    printf("\n%s:%d -> %s:%d, %d (0x%x) bytes\n\n",
           source_ip, source_port, dest_ip, dest_port,
           data_size, data_size);
    int headers_size = 0;
    if (data_size > 0)
    {
        headers_size = hdr->len - data_size;
        print_data_hex(bytes + headers_size, data_size);
    }

    strncpy(packet.dst_ip, dest_ip, sizeof(dest_ip));
    strncpy(packet.src_ip, source_ip, sizeof(source_ip));
    packet.dst_port = dest_port;
    packet.src_port = source_port;
    

    std::string dataForInf=" ";
    std::string dataForInf2;
    timeval tm;
    gettimeofday(&tm, NULL);
    pcpp::RawPacket rawPacket((uint8_t *)bytes + 2, hdr->len, tm, false, pcpp::LinkLayerType::LINKTYPE_ETHERNET);
    pcpp::Packet parsedPacket(&rawPacket);

        for (int j = 0; j < data_size; j++)
        {
            if ((bytes + headers_size)[j] > 31 && (bytes + headers_size)[j] < 127 && j < 1024)
                dataForInf = dataForInf + (char)(bytes + headers_size)[j];
        }
packet.data=dataForInf;

  //  PGconn *connPost = PQconnectdb("user=postgres port=5432 password=password host=localhost dbname=test");
  PGconn *connPost = PQconnectdb("user=postgres port=5432 password=postgres host=localhost dbname=SOV");
    if (PQstatus(connPost) != CONNECTION_OK)
    {
        std::cout << PQerrorMessage(connPost) << std::endl;
        fprintf(stderr, "%s", PQerrorMessage(connPost));
           PQfinish(connPost);
    exit(1);
    }


    std::string query = "SELECT * FROM rules;";

     PGresult *res = PQexec(connPost, query.c_str());

  if (PQntuples(res) != 0)
     {
        for (size_t i = 0; i < PQntuples(res); i++)
        {
            rule.src_ip = PQgetvalue(res,i,0);
            rule.dst_ip = PQgetvalue(res,i,1);
            rule.src_port = PQgetvalue(res,i,2);
            rule.dst_port = PQgetvalue(res,i,3);
            rule.reg = PQgetvalue(res,i,4);
            rule.regHex = PQgetvalue(res,i,5);
            rule.protocol = PQgetvalue(res,i,6);

            if (!GoodPacket(rule,packet))
            {
                std::cout <<"BAD"<<std::endl;
            }
            
            
        }
        
     }

/*
for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
{

    proto= getProtocolTypeAsNum(curLayer->getProtocol());
    if (proto==39)
    {
        continue;
    }

    if (proto==38&&inf.isSMB==true)
    {
        proto=40;
        inf.protocols[proto]=true;
        inf.dataSize[proto]+=  curLayer->getHeaderLen();
        continue;
    }

    if (proto==38)
    {
        inf.dataSize[protoBefore]+= curLayer->getHeaderLen();
        continue;
    }
    
    if (inf.protocols[proto]==true)
    {
        inf.tunnel=true;
    }
    
    inf.protocols[proto]=true;
    if (proto==0)
    {
        inf.dataSize[0]= curLayer->getDataLen();
    }else{
        inf.dataSize[proto]= curLayer->getHeaderLen();   
    }

}*/

}

int main()
{
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];

    std::ifstream fin("/opt/soa/ip.txt");
	fin>>IP_serv;
	fin.close();

    pcap_t *pcap = pcap_open_live("any", 65535, 1, 100, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    //убрали трафик к коллектору
    //  filter = filter + " and not net ";
    //   filter = filter + SERVER_ADRESS;
    filter1 = filter1 + " and not port ";
    filter1 = filter1 + std::to_string(SERVER_PORT);

    struct bpf_program filterprog;
    res = pcap_compile(pcap, &filterprog, filter1.c_str(), 0, PCAP_NETMASK_UNKNOWN);
    if (res != 0)
    {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return 1;
    }

    res = pcap_setfilter(pcap, &filterprog);
    if (res != 0)
    {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return 1;
    }
    // pcap файл для проверки в wireshsrk
    pcap_dumper_t *dumper = pcap_dump_open(pcap, "output.pcap");

    printf("Listening all device");
    //-1- не записывать в файл
    res = pcap_loop(pcap,-1, handlePacket, (unsigned char *)dumper);
    printf("pcap_loop returned %d\n", res);

    pcap_close(pcap);
    return 0;
}