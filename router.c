#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define ARP_INIT 10

#define TTL_SIZE 64

#define ARP_CODE 0x0806
#define IP_CODE 0x0800

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_ETHER 1

#define HLEN 6
#define PLEN 4

struct pkt
{
	char buf[MAX_PACKET_LEN];
	int len;
}__attribute__((packed));

int is_prefix_match(uint32_t ip, uint32_t prefix, uint32_t mask) {
    return (prefix == (ip & mask));
}

struct route_table_entry *best_rentry_recursive(uint32_t ip, int left, int right, struct route_table_entry *route_table) {
    if (left > right) {
        return NULL;
    }

    int mid = left + ((right - left) / 2);

    if (is_prefix_match(ip, route_table[mid].prefix, route_table[mid].mask)) {
        struct route_table_entry *best_match = best_rentry_recursive(ip, mid + 1, right, route_table);
        if (best_match == NULL || ntohl(best_match->mask) < ntohl(route_table[mid].mask)) {
            return &route_table[mid];
        }
        return best_match;
    }
    else {
        if (ntohl(route_table[mid].prefix) < ntohl(ip)) {
            return best_rentry_recursive(ip, mid + 1, right, route_table);
        }
        else {
            return best_rentry_recursive(ip, left, mid - 1, route_table);
        }
    }
}

struct route_table_entry *best_rentry(uint32_t ip, int rt_len, struct route_table_entry *route_table) {
    return best_rentry_recursive(ip, 0, rt_len - 1, route_table);
}

uint8_t *get_arp_entry_recursive(uint32_t ip, int arp_len, struct arp_table_entry *arp_table, int index) {
    if (index >= arp_len) {
        return NULL;
    }

    if (memcmp(&arp_table[index].ip, &ip, sizeof(ip)) == 0) {
        return arp_table[index].mac;
    }

    return get_arp_entry_recursive(ip, arp_len, arp_table, index + 1);
}

uint8_t *get_arp_entry(uint32_t ip, int arp_len, struct arp_table_entry *arp_table) {
    return get_arp_entry_recursive(ip, arp_len, arp_table, 0);
}


int index_tabela_arp(uint32_t ip, int arp_len, struct arp_table_entry *arp_table) {
    
    uint8_t *mac = get_arp_entry_recursive(ip, arp_len, arp_table, 0);

    if (mac != NULL) {
        size_t entry_size = sizeof(struct arp_table_entry);
        return (mac - (uint8_t*)&(arp_table[0].mac)) / entry_size;
    }

    return -1;
}


int rtable_compare(const void *a, const void *b)
{
	struct route_table_entry *prima = (struct route_table_entry *)a;
	struct route_table_entry *doua = (struct route_table_entry *)b;


	if (prima->prefix != doua->prefix)
	{
		if (prima->prefix < doua->prefix)
		{
			return -1;
		}
		else
		{
			return 1;
		}
	}
	else
	{
		if (prima->mask > doua->mask)
			return 1;
		else
		if(prima->mask == doua->mask)
			return 0;
		else
			return -1;
	}
}

struct route_table_entry *init_tabela_rutare()
{
    struct route_table_entry *rt = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * 80000);
    DIE(rt == NULL, "alocarea a esuat");
    return rt;
}

struct arp_table_entry *init_tabela_arp()
{
    struct arp_table_entry *arp_table = (struct arp_table_entry *)malloc(sizeof(struct arp_table_entry) * 10);
    DIE(arp_table == NULL, "alocarea a esuat");
    return arp_table;
}

void send_arp_request(int interface, struct ether_header *eth_hdr, char buf[MAX_PACKET_LEN], struct arp_header *arp_hdr, size_t len, struct arp_table_entry *arp_table, int arp_len)
{

	for (int i = 0; i < sizeof(eth_hdr->ether_dhost); ++i) {
        eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
    }

	get_interface_mac(interface, eth_hdr->ether_shost);

	eth_hdr->ether_type = htons(ARP_CODE);

	arp_hdr->htype = htons(ARP_ETHER);
	arp_hdr->ptype = htons(IP_CODE);
	arp_hdr->op = htons(ARP_REPLY);
	arp_hdr->hlen = HLEN;
	arp_hdr->plen = PLEN;

	// Preluarea adreselor MAC din eth_hdr
	uint8_t *source_mac = eth_hdr->ether_shost;
    uint8_t *destination_mac = eth_hdr->ether_dhost;

    // Copierea adresei MAC a destinației în arp_hdr->tha
    for (int i = 0; i < sizeof(arp_hdr->tha); ++i) {
        arp_hdr->tha[i] = destination_mac[i];
    }

	// Copierea adresei MAC a sursei în arp_hdr->sha
    for (int i = 0; i < sizeof(arp_hdr->sha); ++i) {
        arp_hdr->sha[i] = source_mac[i];
    }

	uint32_t tmp = arp_hdr->spa;
	uint32_t interface_ip = inet_addr(get_interface_ip(interface));
  	arp_hdr->spa = interface_ip;
	arp_hdr->tpa = tmp;

	send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
}

struct pkt *dequeue_packet(struct queue *pkt_queue) {
    return (struct pkt *)queue_deq(pkt_queue);
}

struct ether_header *extract_eth_hdr(struct pkt *pkt) {
    return (struct ether_header *)pkt->buf;
}

struct iphdr *extract_ip_hdr(struct pkt *pkt) {
    return (struct iphdr *)(pkt->buf + sizeof(struct ether_header));
}


void empty_queue1(struct ether_header *eth_hdr, queue pkt_queue, int rt_len, struct route_table_entry *route_table, int current_arp_entry, struct arp_table_entry *arp_table, char buf[MAX_PACKET_LEN]) {
	if (ntohs(((struct arp_header *)(buf + sizeof(struct ether_header)))->op) == 2) {
		if (!queue_empty(pkt_queue)) {
			struct pkt *pkt = (struct pkt *)queue_deq(pkt_queue);
			struct ether_header *eth_hdr_pkt = (struct ether_header *)pkt->buf;
			struct iphdr *ip_hdr_pkt = (struct iphdr *)(pkt->buf + sizeof(struct ether_header));

			struct route_table_entry *best = best_rentry(ip_hdr_pkt->daddr, rt_len, route_table);
			uint8_t *new_mac = arp_table[index_tabela_arp(best->next_hop, current_arp_entry + 1, arp_table)].mac;

			if (new_mac == NULL) {
				queue_enq(pkt_queue, pkt);
				empty_queue1(eth_hdr, pkt_queue, rt_len, route_table, current_arp_entry, arp_table, buf);
			} else {
				for (int i = 0; i < sizeof(eth_hdr->ether_dhost); i++) {
					eth_hdr_pkt->ether_dhost[i] = new_mac[i];
				}
				for (int i = 0; i < 6 * sizeof(uint8_t); i++) {
					eth_hdr_pkt->ether_shost[i] = new_mac[i];
				}
				eth_hdr_pkt->ether_type = htons(0x0800);

				send_to_link(best->interface, pkt->buf, pkt->len);
				free(pkt);

				empty_queue1(eth_hdr, pkt_queue, rt_len, route_table, current_arp_entry, arp_table, buf);
			}
		}
	}
}


void initializare_iphdr(struct iphdr *ip_hdr)
{
	ip_hdr->version = 4;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->ttl = TTL_SIZE;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->frag_off = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
}

void get_interface_mac_from_ip(int interface, uint8_t* ether_shost) {
    // Obținem adresa IP a interfeței
    char* ip_address_str = get_interface_ip(interface);

    // Convertim adresa IP într-un format numeric (uint32_t)
    uint32_t ip_address = inet_addr(ip_address_str);

    // Obținem adresa MAC folosind metode specifice sistemului de operare
    // Aici ar trebui să adaugi codul specific pentru sistemul de operare
    // pentru a obține adresa MAC corespunzătoare adresei IP date
    // Pentru exemplificare, vom folosi o adresă MAC fixă
    uint8_t default_mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    // Copiem adresa MAC în câmpul ether_shost al structurii ether_header
    memcpy(ether_shost, default_mac, sizeof(default_mac));
}

void icmp_with_type(struct iphdr *ip_hdr, int interface, struct ether_header *eth_hdr, char buf[MAX_PACKET_LEN], int len)
{
	initializare_iphdr(ip_hdr);

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				
	get_interface_mac_from_ip(interface, eth_hdr->ether_shost);

	send_to_link(interface, buf, len);
}

void send_icmp(struct ether_header *eth_hdr, char buf[MAX_PACKET_LEN], int interface, struct iphdr *ip_hdr, int contor, size_t len)
{
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	if(contor == 3)
		{
			icmp_hdr->type = 3;
			icmp_hdr->code = 0;
		}
	else
	if(contor == 0)
		{
			icmp_hdr->type = 0;
			icmp_hdr->code = 0;
		}
	else
		{
			icmp_hdr->type = 11;
			icmp_hdr->code = 0;
		}

	size_t new_len = 0;
	if(contor == 0)
		{
			new_len = len - sizeof(struct ether_header) - sizeof(struct iphdr);
		}
	else
		{
			new_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
		}	

	icmp_hdr->checksum = 0;
	if(contor == 0)
		{
			icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, new_len));
		}
	else
		{
			icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));
		}
	
	struct ether_header * eth_icmp = calloc(1,sizeof(struct ether_header));
	memcpy(eth_icmp->ether_dhost,eth_hdr->ether_shost,6*sizeof(uint8_t));
	eth_icmp->ether_type = htons(0x0800);
	memcpy(buf, eth_icmp, sizeof(struct ether_header));

	if(contor)
		{
			icmp_with_type(ip_hdr, interface, eth_hdr, buf, new_len);
		}
	else
		{
			icmp_with_type(ip_hdr, interface, eth_hdr, buf, len);
		}
}

struct ether_header *init_eth(char buf[MAX_PACKET_LEN])
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	return eth_hdr;
}

struct arp_header *init_arp(char buf[MAX_PACKET_LEN])
{
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	return arp_hdr;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	struct route_table_entry *route_table;
	int rt_len;

	struct arp_table_entry *arp_table;
	int arp_len;

	route_table = init_tabela_rutare();
	rt_len = read_rtable(argv[1], route_table);

	arp_table = init_tabela_arp();
	arp_len = ARP_INIT;

	int current_arp_entry = 0;

	queue pkt_queue = queue_create();
	DIE(pkt_queue == NULL, "cannot create queue");


	for (int i = 0; i < rt_len; i++)
		{
			route_table[i].mask = ntohl(route_table[i].mask);
			route_table[i].prefix = ntohl(route_table[i].prefix);
		}
	qsort(route_table, rt_len, sizeof(struct route_table_entry), rtable_compare);
	for (int i = 0; i < rt_len; i++)
		{
			route_table[i].mask = ntohl(route_table[i].mask);
			route_table[i].prefix = ntohl(route_table[i].prefix);
		}

	// Do not modify this line
	init(argc - 2, argv + 2);


	while (1)
	{
		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);

		struct ether_header *eth_hdr = init_eth(buf);
		struct arp_header *arp_hdr = init_arp(buf);
		if (eth_hdr->ether_type == htons(ARP_CODE))
		{

			if (arp_hdr->op == htons(ARP_REPLY))

			{

				int i;
				char ip_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(arp_hdr->spa), ip_str, INET_ADDRSTRLEN);
				uint32_t ip = inet_addr(ip_str);
  				for (i = 0; i < current_arp_entry; i++)
  				{
    				if (ip == arp_table[i].ip)
    				{
						break;
    				}
  				}

				struct arp_table_entry *arp_entry = (struct arp_table_entry *)calloc(1, sizeof(struct arp_table_entry));
				arp_entry->ip = arp_hdr->spa;

				for (int i = 0; i < sizeof(arp_table[current_arp_entry].mac); ++i) {
    				arp_table[current_arp_entry].mac[i] = arp_hdr->sha[i];
				}

				arp_table[current_arp_entry].ip = arp_entry->ip;
				current_arp_entry++;

				if (current_arp_entry == arp_len)
				{
					struct arp_table_entry *new_arp_table = malloc(arp_len * sizeof(struct arp_table_entry));
					if (new_arp_table == NULL) {
    					exit(EXIT_FAILURE);
					}
					memcpy(new_arp_table, arp_table, arp_len * sizeof(struct arp_table_entry));
					free(arp_table);
					arp_table = new_arp_table;
				}

				empty_queue1(eth_hdr, pkt_queue, rt_len, route_table, current_arp_entry, arp_table, buf);
			}
			else
			{
				send_arp_request(interface, eth_hdr, buf, arp_hdr, len, arp_table, arp_len);
			}
		}
		else if (ntohs(eth_hdr->ether_type) == IP_CODE)
		{
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			uint16_t chs = ip_hdr->check;

			struct ether_header *eth_hdrIcmp = malloc(sizeof(struct ether_header));
			
			for (int i = 0; i < sizeof(eth_hdr->ether_shost); i++) {
    			eth_hdrIcmp->ether_dhost[i] = eth_hdr->ether_shost[i];
    			eth_hdrIcmp->ether_shost[i] = eth_hdr->ether_dhost[i];
			}
			eth_hdrIcmp->ether_type = htons(0x0800);

			if (ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))))
			{
				continue;
			}

			
			if (ip_hdr->ttl <= 1)
			{
				int contor = 11;
				send_icmp(eth_hdr, buf, interface, ip_hdr, 11, len);

				continue;
			}

			char ipDaddrString[16];
			inet_ntop(2, &ip_hdr->daddr, ipDaddrString, sizeof(ipDaddrString));
			struct icmphdr *icmp_hdr1 = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

			if (strcmp(get_interface_ip(interface), ipDaddrString) == 0 && icmp_hdr1->type == 8)
			{

				send_icmp(eth_hdr, buf, interface, ip_hdr, 0, len);

				continue;
			}

			ip_hdr->ttl--;

			uint16_t chss = ~(~chs + ~((uint16_t)(ip_hdr->ttl + 1)) + (uint16_t)(ip_hdr->ttl)) - 1;
			ip_hdr->check = chss;

			struct route_table_entry *best = best_rentry(ip_hdr->daddr, rt_len, route_table);

			char* ipInterface = calloc(4,sizeof(char));
			DIE(ipInterface == NULL, "Calloc ipDestination was faild\n");
			ipInterface = get_interface_ip(interface);

			if(best == NULL)
			{

				send_icmp(eth_hdr, buf, interface, ip_hdr, 3, len);

				continue;
			}

			struct pkt *arp_pkt = malloc(sizeof(struct pkt));
			//unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
			unsigned char *broadcast_mac = (unsigned char *)malloc(6 * sizeof(unsigned char));
		if (broadcast_mac == NULL) {
    		exit(EXIT_FAILURE);
		}

		for (int i = 0; i < 6; i++) {
    		broadcast_mac[i] = 0xff;
		}

			uint8_t *new_mac = get_arp_entry(best->next_hop, arp_len, arp_table);
			if (new_mac == NULL)
			{
				struct pkt *new_pkt = malloc(sizeof(struct pkt));

				memcpy(new_pkt->buf, buf, len);
				new_pkt->len = len;

				queue_enq(pkt_queue, new_pkt);

				struct arp_header *new_arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

				new_arp_hdr->htype = htons(ARP_ETHER);
				new_arp_hdr->ptype = htons(IP_CODE);
				new_arp_hdr->op = htons(ARP_REQUEST);
				new_arp_hdr->hlen = HLEN;
				new_arp_hdr->plen = PLEN;
				eth_hdr->ether_type = htons(ARP_CODE);

				get_interface_mac(best->interface, eth_hdr->ether_shost);
				get_interface_mac(best->interface, new_arp_hdr->sha);

				uint8_t macMeu[6];
				get_interface_mac(best->interface, macMeu);
				char *ipMeuChar = get_interface_ip(best->interface);
				uint32_t ipMeu = inet_addr(ipMeuChar);
				memcpy(new_arp_hdr->sha, macMeu, 6);
				new_arp_hdr->spa = ipMeu;
				memset(new_arp_hdr->tha, 0, 6);
				new_arp_hdr->tpa = best->next_hop;

				memcpy(eth_hdr->ether_dhost, broadcast_mac, sizeof(eth_hdr->ether_dhost));

				memset(arp_pkt->buf, 0, MAX_PACKET_LEN);
				memcpy(arp_pkt->buf, eth_hdr, sizeof(struct ether_header));
				memcpy(arp_pkt->buf + sizeof(struct ether_header), new_arp_hdr, sizeof(struct arp_header));

				send_to_link(best->interface, arp_pkt->buf, sizeof(struct ether_header) + sizeof(struct arp_header));

				continue;
			}

			memcpy(eth_hdr->ether_dhost, new_mac, sizeof(eth_hdr->ether_dhost));

			send_to_link(best->interface, buf, len);
		}
	}
}