#include <pcap.h>
#include <stdio.h>
//#include "libnet-headers.h"
#include "myheader.h"
#include <string.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1]; //interface/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];/* Error string */
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);/* Session handle */
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }	

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); //start buffer
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);


    /* ethernet headers are always exactly 14 bytes */
    #define SIZE_ETHERNET 14
        const struct sniff_ethernet *ethernet; /* The ethernet header */
        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */
        const unsigned char *payload; /* Packet payload */

        u_int size_ip;
        u_int size_tcp;

        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return 1;
        }
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return 1;
        }
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        int total_header_size = SIZE_ETHERNET + size_ip + size_tcp;
        int payload_size= (header->caplen - total_header_size);

        /*Ethernet*/
        unsigned char* es = (u_char*)ethernet->ether_shost;
        unsigned char* ed = (u_char*)ethernet->ether_dhost;
        printf("#Ethernet_src : %02x:%02x:%02x:%02x:%02x:%02x \n",es[0],es[1],es[2],es[3],es[4],es[5]);
        printf("#Ethernet_dst : %02x:%02x:%02x:%02x:%02x:%02x \n",ed[0],ed[1],ed[2],ed[3],ed[4],ed[5]);

        /*IP*/
        char ip_s[100];
        char ip_d[100];
        strcpy(ip_s,inet_ntoa(ip->ip_src));
        strcpy(ip_d,inet_ntoa(ip->ip_dst));
        printf("#Ip_src : %s\n", ip_s);
        printf("#Ip_dst : %s\n", ip_d);

        /*TCP*/
        u_long tcp_s = ntohs(tcp->th_sport);
        u_long tcp_d = ntohs(tcp->th_dport);
        printf("#TCP_sport : %ld\n", tcp_s);
        printf("#TCP_dport : %ld\n", tcp_d);

        /*payload*/
        printf("#paload: ");
        if(payload_size>16){
            for(int i=0; i<8;i++){
                printf("%02x / ", payload[i]);
            }
            printf("\n");
        }else if(payload_size<=0){
            printf("X");
        }
        else if(payload_size<=16){
            for(int i=0; i<payload_size;i++){
                 printf("%02x / ", payload[i]);
            }
        }
        printf("\n-------------------------------------\n");
    }
    pcap_close(handle); /* And close the session */
}
