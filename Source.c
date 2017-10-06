/*
*	Project 1		*****
*	Author			Pavol Grofèík
*	Date			5.10
*	Year			2017
*	Subject			Computer and communication networks
*/

#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <pcap.h>

//Definovanie pre vıpis riadku po 16 B
#define LINE_LEN 16 





//Funkcia zobrazí podrobné informácie o packete - protokoly,IP/MAC adresy ...
void print_pckt(pcap_t *f, const u_char *pkt_data, struct pcap_pkthdr *hdr, FILE *r, int *count) {

	int i;
	int c, comm = 1,
		type;

	//Listujeme celım  linked list
	while ((pcap_next_ex(f, &hdr, &pkt_data)) > 0) {


		//Urèenie typu IP || ARP
		if (pkt_data[12] == 8) {

			//IP 08 00
			if (pkt_data[13] == 0) {
				printf("Ramec: %d\n", ++(*count));
				printf("Dlzka ramca poskytnuta pcap API: %ld B\n", hdr->caplen);

				printf("Dlzka ramca prenasana po mediu: %ld B\n", hdr->len < 60 ? 64 : hdr->len + 4);		


				if (pkt_data[12] >= 6) {

					//Naèítanie zo súboru - typ linkovej vrstvy
					fscanf(r, "%d ", &type);

					while ((c = getc(r)) != EOF) {
						putchar(c);
					}
					putchar('\n');
					rewind(r);

					//Src Mac
					printf("Zdrojova MAC adresa: ");

					for (i = 6; i < 12; i++) {
						printf("%.2x ", pkt_data[i]);
					}
					putchar('\n');

					//Dest Mac
					printf("Cielova MAC adresa: ");
					for (i = 0; i < 6; i++) {
						printf("%.2x ", pkt_data[i]);
					}
					putchar('\n');

					//IPv4 - sietova vrstva
					if (pkt_data[14] >= 64 && pkt_data[14] <= 96) {	
						printf("IPv4\n");
					}
					else
					{
						printf("IPv6\n");
					}

					//Src IP
					printf("Zdrojova IP adresa: ");
					for (i = 26; i <= 29; i++) {
						if (i == 29) {
							printf("%d\n", pkt_data[i]);
							break;
						}
						printf("%d.", pkt_data[i]);
					}

					//Dst IP
					printf("Cielova IP adresa: ");
					for (i = 30; i <= 33; i++) {
						if (i == 33) {
							printf("%d\n", pkt_data[i]);
							break;
						}
						printf("%d.", pkt_data[i]);
					}


					//PORTY - transportná vrstva
					switch (pkt_data[23]) {
					case 1: printf("%s\n", "ICMP"); break;
					case 2: printf("%s\n", "IGMP"); break;
					case 6: printf("%s\n", "TCP"); break;
					case 9: printf("%s\n", "IGRP"); break;
					case 17: printf("%s\n", "UDP"); break;
					}

					//source port
					printf("Zdrojovy port: %d\n", pkt_data[34] * 256 + pkt_data[35]);
					//destination port
					printf("Cielovy port: %d\n", pkt_data[36] * 256 + pkt_data[37]);
				}
			}

			//ARP komunikácia 08 06
			else if (pkt_data[12] == 8 && pkt_data[13] == 6) {
				// comm = 1 request, 0 -reply
				if (comm == 1) {
					printf("Komunikacia c: %d\n", comm);
				
					comm = 0;
					printf("ARP - %s, ", pkt_data[21] == 1 ? "Request" : "Reply");

					//IP
					printf("IP adresa: ");
					for (i = 38; i <= 41; i++) {
						if (i == 41) {
							printf("%d, ", pkt_data[i]);
							break;
						}
						printf("%d.", pkt_data[i]);
					}

					//Zobrazenie zdrojovej IP 
					printf("MAC adresa: ???\n");
					printf("Zdrojova IP: ");

					for (i = 28; i <= 31; i++) {
						if (i == 31) {
							printf("%d, ", pkt_data[i]);
							break;
						}
						printf("%d.", pkt_data[i]);
					}

					//Zobrazenie cielovej IP
					printf("Cielova IP: ");

					for (i = 38; i <= 41; i++) {
						if (i == 41) {
							printf("%d\n", pkt_data[i]);
							break;
						}
						printf("%d.", pkt_data[i]);
					}

					//ARP komunikácia sa ráta tie do celkového rámcu (count = all)
					(*count)++;
					//Zobrazíme podrobnejšie informácie o komunikácii
					printf("Ramec: %d\n", (*count));
					printf("Dlzka ramca poskytnuteho pcap API: %d\n", hdr->caplen);
					printf("Dlza ramca prenasaneho po mediu: %d\n", hdr->len < 60 ? 64 : hdr->len + 4);
					
					//Naèítanie zo súboru - typ
					fscanf(r, "%d ", &type);

					while ((c = getc(r)) != EOF) {
						putchar(c);
					}
					putchar('\n');
					rewind(r);

					//Src Mac
					printf("Zdrojova MAC adresa: ");

					for (i = 6; i <= 11; i++) {
						printf("%.2x ", pkt_data[i]);
					}

					putchar('\n');

					//Dst MAc
					printf("Cielova MAC adresa: ");
					for (i = 0; i <= 5; i++) {
						printf("%.2x ", pkt_data[i]);
					}

					putchar('\n');

				}
				else
				{

					//ARP reply

					printf("ARP - %s, ", pkt_data[21] == 1 ? "Request" : "Reply");

					//Src IP
					printf("IP adresa: ");
					for (i = 28; i <= 31; i++) {
						if (i == 31) {
							printf("%d, ", pkt_data[i]);
							break;
						}
						printf("%d.", pkt_data[i]);
					}
					
					//MAC
					printf("MAC adresa: ");
					for (i = 6; i <= 11; i++) {
						if (i == 11) {
							printf("%.2x\n", pkt_data[i]);
							break;
						}
						printf("%.2x ", pkt_data[i]);
					}

					//Src IP
					printf("Zdrojova IP: ");
					for (i = 28; i <= 31; i++) {
						if (i == 31) {
							printf("%d, ", pkt_data[i]);
							break;
						}
						printf("%d.", pkt_data[i]);
					}

					//Dst IP
					printf("Cielova IP: ");
					for (i = 38; i <= 41; i++) {
						if (i == 41) {
							printf("%d\n", pkt_data[i]);
							break;
						}
						printf("%d.", pkt_data[i]);
					}

					//Zobrazenie podrobnosti o danom rámci
					(*count)++;
					printf("Ramec: %d\n", (*count));
					printf("Dlzka ramca poskytnuteho pcap API: %d\n", hdr->caplen);
					printf("Dlza ramca prenasaneho po mediu: %d\n", hdr->len < 60 ? 64 : hdr->len + 4);

					//Naèítanie zo súboru o akı typ ide
					fscanf(r, "%d ", &type);

					while ((c = getc(r)) != EOF) {
						putchar(c);
					}
					putchar('\n');
					rewind(r);

					//Zdrojova MAC 
					printf("Zdrojova MAC adresa: ");
					for (i = 0; i <= 5; i++) {
						if (i == 5) {
							printf("%.2x\n", pkt_data[i]);
							break;
						}
						printf("%.2x ", pkt_data[i]);
					}


					//Cielova MAC
					printf("Cielova MAC adresa: ");
					for (i = 6; i <= 11; i++) {
						if (i == 11) {
							printf("%.2x\n", pkt_data[i]);
							break;
						}
						printf("%.2x ", pkt_data[i]);
					}

				}
			}
		}


		else	//Vıpis pre typ - IEEE 802.3
		{
			printf("IEEE 802-3 ");

			//ff ff 
			if (pkt_data[14] == 255) {
				printf("- Raw\n");
			}
			//aa aa 
			else if (pkt_data[14] == 170)
			{
				printf("- LLC-SNAP\n");
			}
			else
			{
				printf("- LLC\n");
			}

			//Ráta sa aj typ 802.3
			(*count)++;
		}

		//Za kadım nasleduje vıpis packetu v Hexadec s.

		for (i = 1; i <= hdr->caplen; i++) {

			printf("%.2x ", pkt_data[i - 1]);

			if (i % LINE_LEN == 8) {
				printf("  ");
			}
			else if (i % LINE_LEN == 0) {
				printf("\n");
			}
		}
		//Odriakovanie
		printf("\n\n");									
	}
}


int main(void) {

	char errbuff[PCAP_ERRBUF_SIZE];
	int count = 0;										//Udáva poradové èíslo rámca ,poèet všetkıch rámcov nachádzajúcich sa v súbore
	pcap_t *f = NULL;									//Smerník na spájanı zoznam
	const u_char *pktdata = NULL;
	struct pcap_pkthdr *header = NULL;

	FILE *r = NULL;


	
	if ((f = (pcap_open_offline("newsample.pcap", errbuff))) == NULL ||
		(r = fopen("Linkframe.txt", "r")) == NULL) {

		//Ak nastane chyba otvorenia súborov, program sa ukonèí
		printf("Subor sa nepodarilo otvorit\n");
		printf("%s\n", errbuff);									
		return -1;
	}
	else
	{
		//Funkcia zobrazí podrobné informáce
		print_pckt(f, pktdata, header, r, &count);	

		//Po dokonèení je nutné súbory zavrie
		pcap_close(f);

		if (fclose(r) == EOF) {
			printf("Subor sa nepodarilo zatvorit\n");
		}
	}

	return 0;
}