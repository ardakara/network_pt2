#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

int main(int argc, char* argv[]) {
  printf("Opening pcap file %s...\n", argv[1]);
  char err[1024];
  pcap_t* p = pcap_open_offline(argv[1], err);
  struct pcap_pkthdr hdr;
  const u_char* packet = NULL;
  while ((packet = pcap_next(p, &hdr)) != NULL) {
    struct ip* ip_hdr = (struct ip*) (packet+14);
    struct tcphdr* tcp_hdr = (struct tcphdr*) (packet+14+ip_hdr->ip_hl*4);
    char source_ip[512];
    char dest_ip[512];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), source_ip, 512);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dest_ip, 512);    
    printf("Source IP: %s, Destination IP: %s, SYN: %d\n", source_ip, dest_ip, tcp_hdr->th_flags & TH_SYN);
  }
  return 0;
}
