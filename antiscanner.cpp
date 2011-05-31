#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <map>
#include <string>

using namespace std;

struct counts {
  int syns;
  int syn_acks;
};

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("No pcap file!\n");
    return 1;
  }

  // open pcap file
  char err[1024];
  pcap_t* p = pcap_open_offline(argv[1], err);

  struct pcap_pkthdr hdr;
  const u_char* packet = NULL;

  // initialize map of src/dest IPs to syn/synack counts
  map<string, struct counts> count_map;

  while ((packet = pcap_next(p, &hdr)) != NULL) {
    // read headers
    struct ip* ip_hdr = (struct ip*) (packet+14);
    struct tcphdr* tcp_hdr = (struct tcphdr*) (packet+14+ip_hdr->ip_hl*4);
    // convert IPs to strings
    char source_ip[512];
    char dest_ip[512];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), source_ip, 512);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dest_ip, 512);    
    int syn = tcp_hdr->th_flags & TH_SYN;
    int synack = (tcp_hdr->th_flags & TH_ACK) && syn;

    string key;
    if (synack) {
      key = string(dest_ip).append(" ").append(string(source_ip));
    } else if (syn) {
      key = string(source_ip).append(" ").append(string(dest_ip));
    }
    struct counts c = count_map[key];
    if (synack) {
      c.syn_acks++;
    } else if (syn) {
      c.syns++;
    }
    count_map[key] = c;
  }

  printf("Source-IP Destination-IP\n");
  map<string, struct counts>::iterator end = count_map.end();
  for (map<string, struct counts>::iterator it = count_map.begin(); it != end; ++it) {
    printf("%s %d %d\n", it->first.c_str(), it->second.syns, it->second.syn_acks);
    struct counts c = it->second;
    if ((c.syn_acks == 0 && c.syns >= 3) || (c.syn_acks > 0 && c.syns / c.syn_acks > 3.0)) {
      //      printf("%s\n", it->first.c_str());
    }
  }
  

  return 0;
}
