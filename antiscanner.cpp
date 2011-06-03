#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include <sstream>
#include <netinet/in.h>

using namespace std;

struct counts {
  int syns;
  int syn_acks;
};

/* Returns a string with the following format:
IP:PORT#SEQNO
for example,
127.0.0.1:80#1234
Subtracts one from seqno if ack is true.
*/
string get_ip_str(string ip, u_short port, tcp_seq seqno, bool ack) {
  stringstream ss;
  ss << ntohs(port) << "#" << (ack ? ntohl(seqno) - 1 : ntohl(seqno));
  return ip.append(":").append(ss.str());
}

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

  /* Initialize a map (count_map) of raw syn and syn_ack counts.
     This map has keys of the following form:
    SRCIP:SRCPORT#SEQNO DESTIP:DESTPORT#SEQNO
    It maps each key to a count of SYNs and SYN/ACKs that we've seen for this key.
    ratios_map keeps track of the counts of SYNs and SYN/ACKs that we actually
    use to compute the ratio, and it has keys of the form:
    SRCIP DESTIP
    We only increment the SYN/ACK count for a SRCIP/DESTIP pair once in ratios_map
    per sequence number. This is so that if a destination resends a SYN/ACK because
    it has not received an ACK, resent SYN/ACKs do not get counted in the ratio.
   */
  map<string, struct counts> count_map;
  map<string, struct counts> ratios_map;

  while ((packet = pcap_next(p, &hdr)) != NULL) {
    // read headers
    struct ip* ip_hdr = (struct ip*) (packet+14);

    if (ip_hdr->ip_p == 6) { // only use TCP packets
      struct tcphdr* tcp_hdr = (struct tcphdr*) (packet+14+ip_hdr->ip_hl*4);

      // convert IPs to strings
      char source_ip[512];
      char dest_ip[512];
      inet_ntop(AF_INET, &(ip_hdr->ip_src), source_ip, 512);
      inet_ntop(AF_INET, &(ip_hdr->ip_dst), dest_ip, 512);    

      // is this packet a SYN or SYN/ACK or neither?
      int syn = tcp_hdr->th_flags & TH_SYN;
      int synack = (tcp_hdr->th_flags & TH_ACK) && syn;

      // construct the keys to index into count_map and ratios_map
      string count_key, ratio_key;      
      if (synack) {
       	count_key = get_ip_str(dest_ip, tcp_hdr->th_dport, tcp_hdr->th_ack, true).append(" ").append(get_ip_str(source_ip, tcp_hdr->th_sport, tcp_hdr->th_ack, true));
	ratio_key = string(dest_ip).append(" ").append(string(source_ip));
      } else if (syn) {
	count_key = get_ip_str(source_ip, tcp_hdr->th_sport, tcp_hdr->th_seq, false).append(" ").append(get_ip_str(dest_ip, tcp_hdr->th_dport, tcp_hdr->th_seq, false));
	ratio_key = string(source_ip).append(" ").append(string(dest_ip));
      }

      // get the SYN and SYN/ACK counts for this key and increment if necessary
      if (syn || synack) {
	//	printf("syn: %d, synack: %d\n", syn, synack);
	// printf("count key: %s, ratio key: %s\n", count_key.c_str(), ratio_key.c_str());
	struct counts c = count_map[count_key];
	if (synack) {
	  c.syn_acks++;
	} else if (syn) {
	  c.syns++;
	}
	count_map[count_key] = c;

	struct counts r = ratios_map[ratio_key];

	// only increment SYN/ACK count in ratios_map once per sequence number
      	if (synack && c.syn_acks == 1) r.syn_acks += 1;
	//if (synack) r.syn_acks += c.syn_acks;
	else if (syn) r.syns += c.syns;
	ratios_map[ratio_key] = r;
	
      }
    }
  }

  // One more pass through ratios_map to print the output
  printf("Source-IP Destination-IP\n");
  map<string, struct counts>::iterator end = ratios_map.end();
  for (map<string, struct counts>::iterator it = ratios_map.begin(); it != end; ++it) {
    struct counts r = ratios_map[it->first];
    // printf("%s %d %d\n", it->first.c_str(), r.syns, r.syn_acks);
    if (it->first.compare("0 0") != 0) {
      if ((r.syn_acks == 0 && r.syns > 0) || (r.syn_acks > 0 && r.syns / r.syn_acks > 3.0)) {
	printf("%s\n", it->first.c_str());
      }
    }
  }

  return 0;
}
