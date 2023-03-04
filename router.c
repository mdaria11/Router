#include "skel.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//functie de comparare pentru qsort
int cmpfunc(const void *a, const void *b)
{
	struct route_table_entry *aa= (struct route_table_entry *) a;
	struct route_table_entry *bb= (struct route_table_entry *) b;

	if(aa->prefix == bb->prefix)
	{
		if(ntohl(aa->mask) < ntohl(bb->mask))
		{
			return 1;
		}
		else if(ntohl(aa->mask) > ntohl(bb->mask))
		{
			return -1;
		}
		else
		{
			return 0;
		}
	}
	else if (ntohl(aa->prefix)<ntohl(bb->prefix))
	{
		return -1;
	}
	else
	{
		return 1;
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	//Parsare ARP_Table 
	struct arp_entry *arp_table= malloc(sizeof(struct arp_entry)*100);
	int arptablesize = parse_arp_table("arp_table.txt", arp_table);

	//Parsare Tabela de Rutare
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int rtablesize = read_rtable(argv[1], rtable);

	//LPM qsort care probabil nu face ce trebuie
	//qsort(rtable, rtablesize, sizeof(struct route_table_entry), cmpfunc);

	//Adresa de Broadcast 
	uint8_t *broadcast_mac_address=malloc(sizeof(char)*6);
	int bc=hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_mac_address); 

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		//ether headerul pachetului
		struct ether_header *ether_hdr = (struct ether_header *) m.payload;

		//luam adresa MAC a interfetei pe care a fost trimis pachetul
		uint8_t *received_mac_address=malloc(sizeof(char)*6);
		get_interface_mac(m.interface, received_mac_address);

		//cazul in care pachetul nu trebuia sa ajunga la router si nici nu e pachet de broadcast
		if (memcmp(ether_hdr->ether_dhost, received_mac_address, 6)!=0 && memcmp(ether_hdr->ether_dhost, broadcast_mac_address, 6)!=0)
		{
			free(received_mac_address);
			continue;
		}

		if(ntohs(ether_hdr->ether_type)==ETHERTYPE_IP) //IP HEADER
		{
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header)); //IP header

			//adresa IP a interfetei de pe care a venit pachetul
			struct in_addr *inp= malloc(sizeof(struct in_addr));
			inet_aton(get_interface_ip(m.interface), inp);

			//pachet ICMP destinat routerului (echo-request)
			if (ip_hdr->daddr == inp->s_addr)
			{
				//schimbam adresele de sursa si destinatie intre ele pentru echo-reply
				uint32_t aux= ip_hdr->daddr;
				ip_hdr->daddr=ip_hdr->saddr;
				ip_hdr->saddr=aux;

				//refacem checksum
				ip_hdr->check=0;
				ip_hdr->check=ip_checksum(ip_hdr,sizeof(struct iphdr));

				//ICMP header
				struct icmphdr *icmp_hdr=(struct icmphdr *)(m.payload+sizeof(struct ether_header)+ sizeof(struct iphdr));

				//schimbam type-ul mesajului si recalculam checksum 
				icmp_hdr->type=0;
				icmp_hdr->checksum=0;
				icmp_hdr->checksum=htons(icmp_checksum(icmp_hdr, sizeof(struct icmphdr)));

				//cautam in tabela de rutare next-hop
				struct route_table_entry *bestroute=NULL;

				for (int i=0; i<rtablesize; i++) 
				{
					if ((ip_hdr->daddr & rtable[i].mask) == rtable[i].prefix) 
					{
						if (bestroute==NULL)
						{
							bestroute=&rtable[i];
						}
						else if (ntohl(bestroute->mask) < ntohl(rtable[i].mask))
						{
							bestroute=&rtable[i];
						}
					}
				}

				//adresa MAC a interfetei pe care trebuie sa trimitem pachetul
				uint8_t *source_mac_address=malloc(sizeof(char)*6);
				get_interface_mac(bestroute->interface, source_mac_address);

				memcpy(ether_hdr->ether_shost, source_mac_address, 6);

				//cautam in tabela statica adresa MAC a urmatorului hop
				for(int i=0; i<arptablesize; i++)
				{
					if (arp_table[i].ip==bestroute->next_hop)
					{
						memcpy(ether_hdr->ether_dhost, arp_table[i].mac, 6);
						break;
					}
				}

				//trimitem pachetul pe interfata corespunzatoare
				m.interface= bestroute->interface;
				send_packet(&m);

				free(received_mac_address);
				free(inp);
				free(source_mac_address);
				
				continue;
			}

			if (ntohs(ip_checksum(ip_hdr,sizeof(struct iphdr))) != 0) //checksum este corupt -> drop
			{
				free(received_mac_address);
				free(inp);
				continue;
			}

			//TTL 1 sau 0 -> mesaj TCMP "TIME EXCEEDED"
			if (ip_hdr->ttl<=1)
			{
				//avem un pachet nou cu ether, ip, icmp headers si 64 de octeti din datele pachetului vechi
				packet newpacket;
				newpacket.len=sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct icmphdr)+64;

				//ETHER HEADER 
				struct ether_header *ether_new_hdr= (struct ether_header *) newpacket.payload;
				ether_new_hdr->ether_type=htons(ETHERTYPE_IP);

				//construim IP header-ul pachetului nou
				struct iphdr *ip_new_hdr= (struct iphdr *) (newpacket.payload + sizeof(struct ether_header));

				ip_new_hdr->version=4;
				ip_new_hdr->ihl=5;
				ip_new_hdr->tos=0;
				ip_new_hdr->daddr=ip_hdr->saddr;
				ip_new_hdr->protocol=1;
				ip_new_hdr->tot_len=htons(84);
				ip_new_hdr->ttl=64;
				ip_new_hdr->id=ip_hdr->id;
				ip_new_hdr->frag_off= ip_hdr->frag_off;

				//ICMP header cu type si code corespunzatoare
				struct icmphdr *icmp_new_hdr=(struct icmphdr *)(newpacket.payload+sizeof(struct ether_header)+ sizeof(struct iphdr));

				icmp_new_hdr->type=11;
				icmp_new_hdr->code=0; 
				icmp_new_hdr->checksum=0;
				icmp_new_hdr->checksum=htons(icmp_checksum(icmp_new_hdr, sizeof(struct icmphdr)));

				//copiem cei 64 de octeti din datele pachetului vechi
				memcpy(newpacket.payload +sizeof(struct ether_header)+ sizeof(struct iphdr)+ sizeof(struct icmphdr), m.payload+sizeof(struct ether_header) + sizeof(struct iphdr), 64);

				//cautam next-hop
				struct route_table_entry *bestroute=NULL;

				for (int i=0; i<rtablesize; i++) 
				{
					if ((ip_new_hdr->daddr & rtable[i].mask) == rtable[i].prefix) 
					{
						if (bestroute==NULL)
						{
							bestroute=&rtable[i];
						}
						else if (ntohl(bestroute->mask) < ntohl(rtable[i].mask))
						{
							bestroute=&rtable[i];
						}
					}
				}

				//adresa IP a interfetei de pe care vom trimite pachetul
				struct in_addr *inp_new= malloc(sizeof(struct in_addr));
				inet_aton(get_interface_ip(bestroute->interface), inp_new);

				ip_new_hdr->saddr=inp_new->s_addr;

				ip_new_hdr->check=0;
				ip_new_hdr->check=ip_checksum(ip_new_hdr,sizeof(struct iphdr));

				//adresa MAC a interfetei pe care trebuie sa trimitem pachetul
				uint8_t *source_mac_address=malloc(sizeof(char)*6);
				get_interface_mac(bestroute->interface, source_mac_address);

				memcpy(ether_new_hdr->ether_shost, source_mac_address, 6);

				//adresa MAC a urmatorului hop
				for(int i=0; i<arptablesize; i++)
				{
					if (arp_table[i].ip==bestroute->next_hop)
					{
						memcpy(ether_new_hdr->ether_dhost, arp_table[i].mac, 6);
						break;
					}
				}

				//trimitem pachetul pe interfata corespunzatoare
				newpacket.interface= bestroute->interface;
				send_packet(&newpacket);

				free(received_mac_address);
				free(inp);
				free(source_mac_address);
				free(inp_new);
				
				continue;
			}

			//actualizare TTL
			ip_hdr->ttl--;

			//cautam next-hop
			struct route_table_entry *bestroute=NULL;

			for (int i=0; i<rtablesize; i++) //luam toate intrarile din tabelul de rutare
			{
				if ((ip_hdr->daddr & rtable[i].mask) == rtable[i].prefix) //am gasit un match
				{
					if (bestroute==NULL)
					{
						bestroute=&rtable[i];
					}
					else if (ntohl(bestroute->mask) < ntohl(rtable[i].mask)) //luam match-ul cu masca cea mai mare
					{
						bestroute=&rtable[i];
					}
				}
			}
		

			if (bestroute==NULL)
			{
				//mesaj ICMP "DESTINATION UNREACHABLE", identic cu "TIME EXCEEDED" in afara de type-ul mesajului in headerul ICMP
				packet newpacket;
				newpacket.len=sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct icmphdr)+64;

				struct ether_header *ether_new_hdr= (struct ether_header *) newpacket.payload;
				ether_new_hdr->ether_type=htons(ETHERTYPE_IP);

				struct iphdr *ip_new_hdr= (struct iphdr *) (newpacket.payload + sizeof(struct ether_header));

				ip_new_hdr->version=4;
				ip_new_hdr->ihl=5;
				ip_new_hdr->tos=0;
				ip_new_hdr->daddr=ip_hdr->saddr;
				ip_new_hdr->protocol=1;
				ip_new_hdr->tot_len=htons(84);
				ip_new_hdr->ttl=64;
				ip_new_hdr->id=ip_hdr->id;
				ip_new_hdr->frag_off= ip_hdr->frag_off;

				struct icmphdr *icmp_new_hdr=(struct icmphdr *)(newpacket.payload+sizeof(struct ether_header)+ sizeof(struct iphdr));

				icmp_new_hdr->type=3;
				icmp_new_hdr->code=0; 
				icmp_new_hdr->checksum=0;
				icmp_new_hdr->checksum=htons(icmp_checksum(icmp_new_hdr, sizeof(struct icmphdr)));

				memcpy(newpacket.payload +sizeof(struct ether_header)+ sizeof(struct iphdr)+ sizeof(struct icmphdr), m.payload+sizeof(struct ether_header) + sizeof(struct iphdr), 64);

				struct route_table_entry *bestroute=NULL;

				for (int i=0; i<rtablesize; i++) 
				{
					if ((ip_new_hdr->daddr & rtable[i].mask) == rtable[i].prefix) 
					{
						if (bestroute==NULL)
						{
							bestroute=&rtable[i];
						}
						else if (ntohl(bestroute->mask) < ntohl(rtable[i].mask))
						{
							bestroute=&rtable[i];
						}
					}
				}

				struct in_addr *inp_new= malloc(sizeof(struct in_addr));
				inet_aton(get_interface_ip(bestroute->interface), inp_new);

				ip_new_hdr->saddr=inp_new->s_addr;

				ip_new_hdr->check=0;
				ip_new_hdr->check=ip_checksum(ip_new_hdr,sizeof(struct iphdr));

				uint8_t *source_mac_address=malloc(sizeof(char)*6);
				get_interface_mac(bestroute->interface, source_mac_address);

				memcpy(ether_new_hdr->ether_shost, source_mac_address, 6);

				for(int i=0; i<arptablesize; i++)
				{
					if (arp_table[i].ip==bestroute->next_hop)
					{
						memcpy(ether_new_hdr->ether_dhost, arp_table[i].mac, 6);
						break;
					}
				}

				newpacket.interface= bestroute->interface;
				send_packet(&newpacket);

				free(received_mac_address);
				free(inp);
				free(source_mac_address);
				free(inp_new);
				continue;
			}

			//recalculare checksum
			ip_hdr->check=0;
			ip_hdr->check=ip_checksum(ip_hdr,sizeof(struct iphdr));

			//adresa MAC a interfetei pe care trebuie sa trimitem pachetul
			uint8_t *send_mac_address=malloc(sizeof(char)*6);
			get_interface_mac(bestroute->interface, send_mac_address);

			memcpy(ether_hdr->ether_shost, send_mac_address, 6);

			//cautam in tabela statica adresa MAC a urmatorului hop
			for(int i=0; i<arptablesize; i++)
			{
				if (arp_table[i].ip==bestroute->next_hop)
				{
					memcpy(ether_hdr->ether_dhost, arp_table[i].mac, 6);
					break;
				}
			}

			//trimitem pachetul pe interfata corespunzatoare
			m.interface=bestroute->interface; 
			send_packet(&m);

			free(send_mac_address);
			free(inp);

		}
		else if(ntohs(ether_hdr->ether_type)==ETHERTYPE_ARP) //ARP HEADER
		{
			//skip for now...
			free(received_mac_address);
			continue;
		}
		else
		{
			continue;
		}

		free(received_mac_address);
	}
	free(broadcast_mac_address);
	free(arp_table);
	free(rtable);
}
