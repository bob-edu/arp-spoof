#include "attack.h"

Mac get_source_mac(const char* dev)
{
	struct ifreq ifr;
	int sockfd;
	Mac source_mac;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("Failed to get interface MAC address - socket() failed - %m\n");
		exit(1);
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Failed to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		exit(1);
	}

	memcpy(&source_mac, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

	close(sockfd);

	return source_mac;
}

Ip get_source_ip(const char* dev)
{
	struct ifreq ifr;
	int sockfd;
	Ip source_ip;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("Failed to get interface IP address - socket() failed - %m\n");
		exit(1);
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
		printf("Failed to get interface IP address - ioctl(SIOCSIFADDR) failed - %m\n");
		close(sockfd);
		exit(1);
	}

	memcpy(&source_ip, ifr.ifr_addr.sa_data + 2, sizeof(struct sockaddr));

	close(sockfd);

	return ntohl(source_ip);
}

EthArpPacket config_packet(Mac eth_dmac, Mac eth_smac, uint16_t arp_op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = arp_op;
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = arp_sip;
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = arp_tip;

	return packet;
}

Mac get_mac_adress(pcap_t* handle, Mac eth_dmac, Mac eth_smac, uint16_t arp_op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{
	EthArpPacket arp_request = config_packet(eth_dmac, eth_smac, arp_op, arp_smac, arp_sip, arp_tmac, arp_tip);
	Mac mac_addr;

	int send_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_request), sizeof(EthArpPacket));
	if (send_res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send_res, pcap_geterr(handle));
		exit(1);
	}

	struct pcap_pkthdr *header;
	const u_char *packet;

	while (true)
	{
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(1);
		}

		EthArpPacket* reply_packet_from_sender = (EthArpPacket *)(packet);
		if (reply_packet_from_sender->eth_.type() != EthHdr::Arp ||
		reply_packet_from_sender->arp_.op() != ArpHdr::Reply ||
		reply_packet_from_sender->eth_.dmac_ != eth_smac)
			continue;

		mac_addr = reply_packet_from_sender->arp_.smac();

		return mac_addr;
	}
}