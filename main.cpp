#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <string>
#include <vector>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "mac.h"
#define REDIRECT_MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

void usage() {
    std::cout << "syntax : tcp-block <interface> <pattern>\n";
    std::cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n";
}

Mac local_mac;

uint16_t calc_checksum(uint16_t* data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t*)data;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

Mac get_mac(const std::string& iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

void send_rst_to_server(pcap_t* handle, const EthHdr* eth, const IpHdr* ip, const TcpHdr* tcp, int payload_len) {
    int ip_len = ip->header_len();
    int tcp_len = tcp->header_len();
    int total_len = sizeof(EthHdr) + ip_len + tcp_len;

    uint8_t pkt[1500] = {};
    EthHdr* eth_new = (EthHdr*)pkt;
    *eth_new = *eth;
    eth_new->smac_ = local_mac;

    IpHdr* ip_new = (IpHdr*)(pkt + sizeof(EthHdr));
    std::memcpy(ip_new, ip, ip_len);
    ip_new->sip_ = ip->sip_;
    ip_new->dip_ = ip->dip_;
    ip_new->ttl = 128;
    ip_new->total_length = htons(ip_len + tcp_len);
    ip_new->checksum = 0;
    ip_new->checksum = calc_checksum((uint16_t*)ip_new, ip_len);

    TcpHdr* tcp_new = (TcpHdr*)((uint8_t*)ip_new + ip_len);
    std::memcpy(tcp_new, tcp, tcp_len);
    tcp_new->sport_ = tcp->sport_;
    tcp_new->dport_ = tcp->dport_;
    tcp_new->seq_ = htonl(ntohl(tcp->seq_) + payload_len);
    tcp_new->flags_ = TcpHdr::RST | TcpHdr::ACK;
    tcp_new->win_ = 0;
    tcp_new->urp_ = 0;
    tcp_new->sum_ = 0;

    pseudo_header phdr = {};
    phdr.source_address = ip_new->sip_;
    phdr.dest_address = ip_new->dip_;
    phdr.protocol = IPPROTO_TCP;
    phdr.tcp_length = htons(tcp_len);

    std::vector<uint8_t> buf(sizeof(phdr) + tcp_len);
    std::memcpy(buf.data(), &phdr, sizeof(phdr));
    std::memcpy(buf.data() + sizeof(phdr), tcp_new, tcp_len);
    tcp_new->sum_ = calc_checksum((uint16_t*)buf.data(), buf.size());

    pcap_sendpacket(handle, pkt, total_len);
}

void send_redirect_to_client(const IpHdr* ip, const TcpHdr* tcp, int payload_len) {
    const char* msg = REDIRECT_MSG;
    int ip_len = ip->header_len();
    int tcp_len = tcp->header_len();
    int msg_len = strlen(msg);
    int total_len = ip_len + tcp_len + msg_len;

    uint8_t buffer[1500] = {};
    IpHdr* ip_new = (IpHdr*)buffer;
    std::memcpy(ip_new, ip, ip_len);
    ip_new->sip_ = ip->dip_;
    ip_new->dip_ = ip->sip_;
    ip_new->ttl = 128;
    ip_new->total_length = htons(total_len);
    ip_new->checksum = 0;
    ip_new->checksum = calc_checksum((uint16_t*)ip_new, ip_len);

    TcpHdr* tcp_new = (TcpHdr*)(buffer + ip_len);
    std::memcpy(tcp_new, tcp, tcp_len);
    tcp_new->sport_ = tcp->dport_;
    tcp_new->dport_ = tcp->sport_;
    tcp_new->seq_ = tcp->ack_;
    tcp_new->ack_ = htonl(ntohl(tcp->seq_) + payload_len);
    tcp_new->flags_ = TcpHdr::FIN | TcpHdr::ACK;
    tcp_new->win_ = htons(60000);
    tcp_new->urp_ = 0;
    tcp_new->sum_ = 0;

    std::memcpy(buffer + ip_len + tcp_len, msg, msg_len);

    pseudo_header phdr = {};
    phdr.source_address = ip_new->sip_;
    phdr.dest_address = ip_new->dip_;
    phdr.protocol = IPPROTO_TCP;
    phdr.tcp_length = htons(tcp_len + msg_len);

    std::vector<uint8_t> buf(sizeof(phdr) + tcp_len + msg_len);
    std::memcpy(buf.data(), &phdr, sizeof(phdr));
    std::memcpy(buf.data() + sizeof(phdr), tcp_new, tcp_len);
    std::memcpy(buf.data() + sizeof(phdr) + tcp_len, buffer + ip_len + tcp_len, msg_len);
    tcp_new->sum_ = calc_checksum((uint16_t*)buf.data(), buf.size());

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in sin = {};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip_new->dip_;
    sendto(sock, buffer, total_len, 0, (sockaddr*)&sin, sizeof(sin));
    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc != 3) { usage(); return -1; }
    std::string dev = argv[1], pattern = argv[2];
    local_mac = get_mac(dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, errbuf);
    if (!handle) return -1;

    struct pcap_pkthdr* header;
    const u_char* pkt;

    while (true) {
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res != 1) continue;

        const EthHdr* eth = (EthHdr*)pkt;
        if (ntohs(eth->type_) != EthHdr::Ip4) continue;
        const IpHdr* ip = (IpHdr*)(pkt + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        int ip_len = ip->header_len();
        const TcpHdr* tcp = (TcpHdr*)((uint8_t*)ip + ip_len);
        int tcp_len = tcp->header_len();

        int total_len = ntohs(ip->total_length);
        int payload_len = total_len - ip_len - tcp_len;
        if (payload_len <= 0) continue;

        const char* data = (const char*)((uint8_t*)tcp + tcp_len);
        if (payload_len < 3 || std::memcmp(data, "GET", 3) != 0) continue;
        if (std::string(data, payload_len).find(pattern) == std::string::npos) continue;

        std::printf("Blocking pattern '%s'\n", pattern.c_str());
        send_rst_to_server(handle, eth, ip, tcp, payload_len);
        send_redirect_to_client(ip, tcp, payload_len);
    }
    pcap_close(handle);
    return 0;
}

