/*
*	Project 1		*****
*	Author			Pavol Grof��k
*	Date			5.10
*	Year			2017
*	Subject			Computer and communication networks
*/

#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <pcap.h>

//Definovanie pre v�pis riadku po 16 B
#define LINE_LEN 16 
#define ARRAY_LEN 2

//�trukt�ra p�rov pre port + n�zov
typedef struct  pairs {
	int num;
	char name[16];
}Pairs;

//�trukt�ra pre UDP
typedef struct udp {
	char name[4];		//UDP
	int s_port;			//Src port
	int d_port;			//Dst port
	int len;			//Ve�kost� portov
	int udp_value;		//Poz�cia UDP
	Pairs ports[1];		//Hodnota portov s n�zvom
}Udp;

typedef struct icmp {
	char name[5];		//ICMP
	int type;			//Poz�cia protokolu
	int len;			//Dlzka
	int icmp_value;		//Poz�cia ICMP
	Pairs code[6];		//Hodnoty protokolov s nazvom
}Icmp;
//�trukt�ra pre ARP
typedef struct arp {
	char name[4];		//ARP
	int operation;		//Poz�cia - operation
	int len;			//Dlzka operacie
	Pairs echo[2];		//Echo - Reply/Request
}Arp;

//�trukt�ra pre TCP
typedef struct tcp {
	char name[4];		//TCP
	int s_port;			//Src port
	int d_port;			//Dst port
	int len_p;			//Ve�kos� portov(Bytes)
	int tcp_value;		//Pozicia TCP 
	Pairs ports[6];		//Hodnota portu + n�zov
}Tcp;

//�trukt�ra pre IP
typedef struct ip {
	int name_p;			//Verzia 4/6
	char name[5];		//IP
	int s_ip;			//Src ip
	int d_ip;			//Dst ip
	int len;			//Ve�kos� Ip adresy(Bytes)
	int prot_pos;		//Poz�cia �al�ieho protokolu
	Tcp tcp[1];			//Vnoren� protokol TCP
	Icmp icmp[1];		//Vnoren� protokol ICMP
	Udp udp[1];			//Vnoren� protokol UDP
}IP;

//Definovanie vlastnej �truktury pre Ethernet a 802.3
typedef struct prot {
	char name[11];		//nazov
	int dest;			//destination
	int src;			//source
	int len;			//type
	int arr[3];			//sub protokoly
	struct prot *next;	//Ukazovatel na dalsiu strukturu
	Arp arp[1];
	IP ip[1];

}Protocol;

//Na��tanie protokolov a �pecifik�ci� zo s�boru
void nacitaj(Protocol **first, FILE *f) {

	Protocol *akt = NULL,
		*pom = NULL;
	int c, i;

	if ((*first) == NULL) {

		//Alok�cia pamati
		if ((*first = (Protocol*)malloc(sizeof(Protocol))) == NULL) {
			printf("Nedostatok pamate\n");
			return;
		}
		//Nasmerovanie smern�ka do NULL
		(*first)->next = NULL;

		//nac�tanie zo s�boru
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s ", (*first)->name);
			printf("%s\n", (*first)->name);

			fscanf(f, "%d", &(*first)->dest);
			fscanf(f, "%d", &(*first)->src);
			fscanf(f, "%d", &(*first)->len);
			fscanf(f, "%d", &(*first)->arr[0]);
			fscanf(f, "%d", &(*first)->arr[1]);
			fscanf(f, "%d", &(*first)->arr[2]);

		}
		//na��tanie potrebn�ch �dajov do subprotokolov pre IP/ARP
		//arp v Ethernete
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->arp->name);
			fscanf(f, "%d", &(*first)->arp->operation);
			fscanf(f, "%d", &(*first)->arp->len);
			fscanf(f, "%d", &(*first)->arp->echo[0].num);
			fscanf(f, "%s", (*first)->arp->echo[0].name);
			fscanf(f, "%d", &(*first)->arp->echo[1].num);
			fscanf(f, "%s", (*first)->arp->echo[1].name);

		}

		//na��tanie IP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->name);
			fscanf(f, "%d", &(*first)->ip->name_p);
			fscanf(f, "%d", &(*first)->ip->s_ip);
			fscanf(f, "%d", &(*first)->ip->d_ip);
			fscanf(f, "%d", &(*first)->ip->len);
			fscanf(f, "%d", &(*first)->ip->prot_pos);
			printf("Position of protocol in ip %d\n", (*first)->ip->prot_pos);

		}

		//na��tanie TCP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->tcp->name);
			//printf("tcp name: %s\n", (*first)->ip->tcp->name);		//vypis IP nazov
			fscanf(f, "%d", &(*first)->ip->tcp->s_port);
			fscanf(f, "%d", &(*first)->ip->tcp->d_port);
			fscanf(f, "%d", &(*first)->ip->tcp->len_p);
			fscanf(f, "%d", &(*first)->ip->tcp->tcp_value);
			//spravi� cez for loop
			fscanf(f, "%d", &(*first)->ip->tcp->ports[0].num);
			fscanf(f, "%s", (*first)->ip->tcp->ports[0].name);
			fscanf(f, "%d", &(*first)->ip->tcp->ports[1].num);
			fscanf(f, "%s", (*first)->ip->tcp->ports[1].name);
			fscanf(f, "%d", &(*first)->ip->tcp->ports[2].num);
			fscanf(f, "%s", (*first)->ip->tcp->ports[2].name);
			fscanf(f, "%d", &(*first)->ip->tcp->ports[3].num);
			fscanf(f, "%s", (*first)->ip->tcp->ports[3].name);
			fscanf(f, "%d", &(*first)->ip->tcp->ports[4].num);
			fscanf(f, "%s", (*first)->ip->tcp->ports[4].name);
			fscanf(f, "%d", &(*first)->ip->tcp->ports[5].num);
			fscanf(f, "%s", (*first)->ip->tcp->ports[5].name);
		}

		//na��tanie UDP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->udp->name);
			printf("UDP name: %s\n", (*first)->ip->udp->name);
			fscanf(f, "%d", &(*first)->ip->udp->s_port);
			fscanf(f, "%d", &(*first)->ip->udp->d_port);
			fscanf(f, "%d", &(*first)->ip->udp->len);
			fscanf(f, "%d", &(*first)->ip->udp->udp_value);
			fscanf(f, "%d", &(*first)->ip->udp->ports[0].num);
			fscanf(f, "%s", (*first)->ip->udp->ports[0].name);
		}

		//Na��tanie ICMP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->icmp->name);
			fscanf(f, "%d", &(*first)->ip->icmp->type);
			fscanf(f, "%d", &(*first)->ip->icmp->len);
			fscanf(f, "%d", &(*first)->ip->icmp->icmp_value);
			printf("ICMP value: %d\n", (*first)->ip->icmp->icmp_value);
			for (i = 0; i <= 5; i++) {
				fscanf(f, "%d", &(*first)->ip->icmp->code[i].num);
				fscanf(f, "%s", (*first)->ip->icmp->code[i].name);
				printf("NUM: %d\n", (*first)->ip->icmp->code[i].num);
			}
		}


		akt = (*first);
		//akt = akt->next;

		//Na��tanie IEE 802.3
		if (akt->next == NULL) {
			akt->next = (Protocol*)malloc(sizeof(Protocol));
			akt = akt->next;
			akt->next = NULL;
			//nacitanie konca riadku

			while ((c = getc(f)) != EOF) {
				ungetc(c, f);
				fscanf(f, "%s ", (akt)->name);
				printf("IEEE -%s\n", (akt)->name);

				fscanf(f, "%d", &(akt)->dest);
				fscanf(f, "%d", &(akt)->src);
				fscanf(f, "%d", &(akt)->len);
				fscanf(f, "%d", &(akt)->arr[0]);
				fscanf(f, "%d", &(akt)->arr[1]);
				fscanf(f, "%d", &(akt)->arr[2]);
			}
		}

	}


}

//Pomocn� v�pis
void vypis_prot(Protocol *first) {
	Protocol *akt = NULL;
	akt = first;
	while (akt != NULL) {

		printf("Name: %s\n", (akt)->name);
		printf("Dest: %d\n", (akt)->dest);
		printf("Src: %d\n", (akt)->src);
		printf("Len: %d\n", (akt)->len);
		printf("Min: %d\n", (akt)->arr[0]);
		printf("IP: %d\n", akt->arr[1]);
		printf("Arp: %d\n", akt->arr[2]);
		akt = akt->next;
	}
}

//Zmazanie sp�jan�ho zoznamu
void delete_list(Protocol *f) {
	Protocol *akt = NULL,
		*pom = NULL;
	pom = f;

	while (pom) {
		akt = pom;
		pom = pom->next;
		free(akt);
	}
	
}

//Funkcia sl��iaca na v�pis k bodu �. 1
void Point_1(pcap_t *f, struct pcap_pkthdr *hdr, const u_char *pkt_data, int *count, Protocol *first) {

	//Pomocn� premenn�
	Protocol *akt = NULL;
	int i, pom, num = 0;

	//nasmerovanie na za�iatok
	akt = first;

	if (akt == NULL) {
		return;
	}
	

	while ((pcap_next_ex(f, &hdr, &pkt_data)) >= 0) {

		//Z�kladn� inform�cie o packete
		printf("Ramec: %d\n", ++(num));
		printf("Dlzka ramca poskytnuteho pcap API: %d\n", hdr->caplen);
		printf("Dlza ramca prenasaneho po mediu: %d\n", hdr->len < 60 ? 64 : hdr->len + 4);
		//nasmerovanie na za�iatok Linked list-u
		pom = akt->dest + akt->src;	//12
		akt = first;

		//Ur�enie typu na Linkovej vrstve
		if (pkt_data[pom] >= akt->arr[0] / 100) {
			printf("%s\n", akt->name);						//Ethernet II
		}
		else
		{
			akt = akt->next;
			printf("%s -", akt->name);						//IEEE 802.3
			pom += akt->len;

			if (pkt_data[pom] == akt->arr[0]) {				//ff ff (Raw)
				printf("Raw\n");
			}
			else if (pkt_data[pom] == akt->arr[1]) {
				printf("LLC/SNAP\n");						//aa aa (SNAP)
			}
			else
			{
				printf("LLC\n");							//LLC
			}
		}

		//V�pis MAC adries
		printf("Zdrojova MAC adresa: ");
		for (i = akt->dest; i < akt->dest + akt->src; i++) {
			if (i == 11) {
				printf("%.2x\n", pkt_data[i]);
				break;
			}
			printf("%.2x ", pkt_data[i]);
		}

		printf("Cielova MAC adresa: ");
		for (i = 0; i < akt->dest; i++) {
			if (i == 5) {
				printf("%.2x\n", pkt_data[i]);
				break;
			}
			printf("%.2x ", pkt_data[i]);
		}

		//Vypis cel�ho packetu
		for (i = 1; i <= hdr->caplen; i++) {

			printf("%.2x ", pkt_data[i - 1]);

			if (i % LINE_LEN == 8) {
				printf("  ");
			}
			else if (i % LINE_LEN == 0) {
				printf("\n");
			}
		}

		//Odriakovanie pre lep�iu �itate�nost
		printf("\n\n");
	}
	(*count) = num;									//Po�et v�etk�ch r�mcov v danom s�bore
}


void Vypis_ip(pcap_t *f, Protocol *first, struct pcap_pkthdr *hdr, const u_char *pkt_data,int n) {

	Protocol *akt = first;
	int i, j = 0, max = 0,delimiter;
	char errbuff[20];
	int count = 0, frame, tmp = 0;

	int **arr = NULL;
	int *space = NULL;

	//Hranica (src) IP adrey 
	delimiter = akt->ip->s_ip + 4;

	//Alok�cia 2d po�a na ur�enie max ve�kosti bajtov
	if ((arr = (int**)malloc(n * sizeof(int*))) == NULL) {
		printf("Nedostatok pamate\n");
		return;
	}

	for (i = 0; i < 30; i++) {
		space = (int *)calloc(ARRAY_LEN*n,sizeof(int));
	}

	//Nasmerovanie po�a smernikov �vonz�kov
	for (i = 0; i < n; ++i) {
		arr[i] = space + i*ARRAY_LEN;
	}


	printf("IP adresy vysielajucich uzlov:\n");
	//Len Src Ip adresy
	while ((pcap_next_ex(f, &hdr, &pkt_data)) >= 0) {

		count++;

		/*if (max < hdr->caplen) {
			max = hdr->caplen;
			frame = count;
		}*/

		for (i = akt->ip->s_ip; i < delimiter; i++) {
			if (i == (delimiter-1)) {
				tmp += pkt_data[i];
				//arr[j] = tmp;
				printf("%d\n", pkt_data[i]);
				break;
			}
			tmp += pkt_data[i];
			printf("%d. ", pkt_data[i]);
		}
		
		//Priradenie IP s velkostou
		arr[count - 1][0] = tmp;			//IP adresa
		arr[count - 1][1] = hdr->caplen;	//Hodnota po mediu(Bajty)

		tmp = 0;
	}


	frame= arr[0][0];						//Default IP adresa
	delimiter = arr[0][1];					//Default hodnota bajtov
	for (i = 1; i < n; i++) {
		if (arr[i][0] == frame) {			//def ip
			delimiter += arr[i][1];			//def max
		}
	}

	for (i = 1; i < n; i++) {
		max = arr[i][1];
		tmp = arr[i][0];
		for (j = i + 1; j < n; j++) {
			if (arr[j][0] == tmp) {
				max += arr[j][1];
			}
		}
		if (max > delimiter) {
			delimiter = max;
			frame = tmp;
		}
	}

	//Odriakovanie pre v�pis
	putchar('\n');

	//Rewindovanie pcap_t (f)
	pcap_close(f);
	f = (pcap_open_offline("eth-9.pcap", errbuff));
	count = 0;

	//Hranica IP
	max = akt->ip->len + akt->ip->s_ip;
	printf("Adresa uzla s najvacsim poctom odvysielanych bajtov:\n");

	//Cykl�me na zistenie IP adresy pre dan� velkost
	while ((pcap_next_ex(f, &hdr, &pkt_data)) >= 0) {

	
			for (i = akt->ip->s_ip; i < max; i++) {
				count += pkt_data[i];
			}
			if (count == frame) {

				//vypis Ip
				for (i = akt->ip->s_ip; i < max; i++) {
					if (i == (max - 1)) {
						printf("%d", pkt_data[i]);
						printf("\t %d Bajtov\n", delimiter);
						j = 1;
						break;
					}
					printf("%d. ", pkt_data[i]);
				}
				break;
			}
			count = 0;
	}

	//Dealokacia - vr�tenie "po�i�an�ch" bajtov OS

	for (i = 0; i < n; i++) {
		arr[i] = NULL;
	}
	free(space);
	free(arr);
	arr = NULL;

}


//V�pis pre HTTP komunik�cie
void Vypis_HTTP(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, int count, Protocol *first) {
	
	int i, position, prot_pos, tmp=0, pom = 0;
	int delimiter, delimiter2;
	int http_val;
	Protocol *akt = first;

	//nastavenie poz�ci� 
	position = akt->dest + akt->src;//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	http_val = akt->ip->tcp->ports[4].num;			//�. portu - 80 (Dec)

	//Prechadzanie paketmi a ur�enie HTTP
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
	
		tmp++;																				//��slo r�mca
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1])) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve podprotokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {
				
				//Hodnota cieloveho portu mus� by� 80(https) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port+1] == http_val || pktdata[akt->ip->tcp->s_port +1] == http_val) {
					printf("Ramec: %d\n", tmp);
					printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
					printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
					printf("%s\n", akt->name);

					//MAC adresy
					printf("Zdrojova MAC adresa: ");
					for (i = akt->dest; i < akt->dest + akt->src; i++) {
						if (i == 11) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					printf("Cielova MAC adresa: ");
					for (i = 0; i < akt->dest; i++) {
						if (i == 5) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					//IPv4
					printf("%s\n", akt->ip->name);
					//Src IP
					printf("Zdrojova IP adresa: ");
					for (i = akt->ip->s_ip; i < delimiter; i++) {
						if (i == delimiter - 1) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}
					//Dst IP
					printf("Cielova IP adresa: ");
					for (i = delimiter; i < delimiter + akt->ip->len; i++) {
						if (i == (delimiter + akt->ip->len -1)) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}

					//TCP name
					printf("%s\n", akt->ip->tcp->name);

					//Porty
					//Src Port
					pom = 0;
					printf("Zdrojovy port: ");
					for (i = akt->ip->tcp->s_port; i < delimiter2; i++) {
						if (i == akt->ip->tcp->s_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);
					//Dst Port
					printf("Cielovy port: ");
					for (i = delimiter2; i < delimiter2 + 2; i++) {
						if (i == akt->ip->tcp->d_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);

					//Vypis Bytov(packetu)
					for (i = 1; i <= header->caplen; i++) {

						printf("%.2x ", pktdata[i - 1]);

						if (i % LINE_LEN == 8) {
							printf("  ");
						}
						else if (i % LINE_LEN == 0) {
							printf("\n");
						}
					}
					putchar('\n');
					putchar('\n');
				}
			}
		}
	}
}

//Vypis HTTPS komunik�ci�
void Vypis_HTTPS(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, int count, Protocol *first) {

	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2;
	Protocol *akt = first;
	int https_val;

	//nastavenie poz�cie na 12 B (za�iatok Ipv4)
	position = akt->dest + akt->src;						//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	https_val = akt->ip->tcp->ports[5].num;					//443 - HTTPS

	//Prechadzanie paketmi a ur�enie HTTPS
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1])) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 443(https) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == https_val || pktdata[akt->ip->tcp->s_port+1] == https_val) {
					printf("Ramec: %d\n", tmp);
					printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
					printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
					printf("%s\n", akt->name);

					printf("Zdrojova MAC adresa: ");
					for (i = akt->dest; i < akt->dest + akt->src; i++) {
						if (i == 11) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					printf("Cielova MAC adresa: ");
					for (i = 0; i < akt->dest; i++) {
						if (i == 5) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					//IPv4
					printf("%s\n", akt->ip->name);
					printf("Zdrojova IP adresa: ");
					//Src IP
					for (i = akt->ip->s_ip; i < delimiter; i++) {
						if (i == delimiter - 1) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}
					//Dst IP
					printf("Cielova IP adresa: ");
					for (i = delimiter; i < delimiter + akt->ip->len; i++) {
						if (i == (delimiter + akt->ip->len - 1)) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}

					//TCP
					printf("%s\n", akt->ip->tcp->name);

					//Porty
					//Src
					pom = 0;
					printf("Zdrojovy port: ");
					for (i = akt->ip->tcp->s_port; i < delimiter2; i++) {
						if (i == akt->ip->tcp->s_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);
					//Dst
					printf("Cielovy port: ");
					for (i = delimiter2; i < delimiter2 + 2; i++) {
						if (i == akt->ip->tcp->d_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);			//Cielov� port
					//Vypis Bytov(packetu)
					for (i = 1; i <= header->caplen; i++) {

						printf("%.2x ", pktdata[i - 1]);

						if (i % LINE_LEN == 8) {
							printf("  ");
						}
						else if (i % LINE_LEN == 0) {
							printf("\n");
						}
					}
					putchar('\n');
					putchar('\n');
				}
			}
		}
	}
}

//V�pis Telnet komunik�ci�
void Vypis_Telnet(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first) {
	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2;
	Protocol *akt = first;
	int telnet_val;

	//nastavenie poz�cie na 12 B (za�iatok Ipv4)
	position = akt->dest + akt->src;					//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	telnet_val = akt->ip->tcp->ports[3].num;			//23 - TELNET

	//Prechadzanie paketmi a ur�enie HTTPS
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1])) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 23(TELNET) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == telnet_val || pktdata[delimiter2 -1] == telnet_val) {
					printf("Ramec: %d\n", tmp);
					printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
					printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
					printf("%s\n", akt->name);

					printf("Zdrojova MAC adresa: ");
					for (i = akt->dest; i < akt->dest + akt->src; i++) {
						if (i == 11) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					printf("Cielova MAC adresa: ");
					for (i = 0; i < akt->dest; i++) {
						if (i == 5) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					//IPv4
					printf("%s\n", akt->ip->name);
					printf("Zdrojova IP adresa: ");
					//Src IP
					for (i = akt->ip->s_ip; i < delimiter; i++) {
						if (i == delimiter - 1) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}
					//Dst IP
					printf("Cielova IP adresa: ");
					for (i = delimiter; i < delimiter + akt->ip->len; i++) {
						if (i == (delimiter + akt->ip->len - 1)) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}

					//TCP
					printf("%s\n", akt->ip->tcp->name);

					//Porty
					//Src
					pom = 0;
					printf("Zdrojovy port: ");
					for (i = akt->ip->tcp->s_port; i < delimiter2; i++) {
						if (i == akt->ip->tcp->s_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);
					//Dst
					printf("Cielovy port: ");
					for (i = delimiter2; i < delimiter2 + 2; i++) {
						if (i == akt->ip->tcp->d_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);

					//Vypis Bytov(packetu)
					for (i = 1; i <= header->caplen; i++) {

						printf("%.2x ", pktdata[i - 1]);

						if (i % LINE_LEN == 8) {
							printf("  ");
						}
						else if (i % LINE_LEN == 0) {
							printf("\n");
						}
					}
					putchar('\n');
					putchar('\n');
				}
			}
		}
	}
}

//V�pis pre SSH komunik�ciu
void Vypis_SSH(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first) {
	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2;
	Protocol *akt = first;
	int SSH_val;

	//nastavenie poz�cie na 12 B (za�iatok Ipv4)
	position = akt->dest + akt->src;								//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	SSH_val = akt->ip->tcp->ports[2].num;							//22 - SSH

	//Prechadzanie paketmi a ur�enie HTTPS
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1])) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 80(https) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == SSH_val || pktdata[delimiter2-1] == SSH_val) {
					printf("Ramec: %d\n", tmp);
					printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
					printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
					printf("%s\n", akt->name);

					printf("Zdrojova MAC adresa: ");
					for (i = akt->dest; i < akt->dest + akt->src; i++) {
						if (i == 11) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					printf("Cielova MAC adresa: ");
					for (i = 0; i < akt->dest; i++) {
						if (i == 5) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					//IPv4
					printf("%s\n", akt->ip->name);
					printf("Zdrojova IP adresa: ");
					//Src IP
					for (i = akt->ip->s_ip; i < delimiter; i++) {
						if (i == delimiter - 1) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}
					//Dst IP
					printf("Cielova IP adresa: ");
					for (i = delimiter; i < delimiter + akt->ip->len; i++) {
						if (i == (delimiter + akt->ip->len - 1)) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}

					//TCP
					printf("%s\n", akt->ip->tcp->name);

					//Porty - v�etky su preveden� do Decim�lnej s�stavy
					//Src Port
					pom = 0;
					printf("Zdrojovy port: ");
					for (i = akt->ip->tcp->s_port; i < delimiter2; i++) {
						if (i == akt->ip->tcp->s_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);
					//Dst Port
					printf("Cielovy port: ");
					for (i = delimiter2; i < delimiter2 +2; i++) {
						if (i == akt->ip->tcp->d_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);

					//Vypis Bytov(packetu)
					for (i = 1; i <= header->caplen; i++) {

						printf("%.2x ", pktdata[i - 1]);

						if (i % LINE_LEN == 8) {
							printf("  ");
						}
						else if (i % LINE_LEN == 0) {
							printf("\n");
						}
					}
					putchar('\n');
					putchar('\n');
				}
			}
		}
	}
}

//V�pis pre FTP riadiacu komunik�ciu - port �:	21(FTP-Control)
void Vypis_FTP_Control(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first) {
	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2;
	Protocol *akt = first;
	int ftp_val;

	//nastavenie poz�cie na 12 B (za�iatok Ipv4)
	position = akt->dest + akt->src;//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	ftp_val = akt->ip->tcp->ports[1].num;

	//Prechadzanie paketmi a ur�enie HTTPS
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1])) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 80(https) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == ftp_val || pktdata[delimiter2-1] == ftp_val) {
					printf("Ramec: %d\n", tmp);
					printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
					printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
					printf("%s\n", akt->name);

					printf("Zdrojova MAC adresa: ");
					for (i = akt->dest; i < akt->dest + akt->src; i++) {
						if (i == 11) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					printf("Cielova MAC adresa: ");
					for (i = 0; i < akt->dest; i++) {
						if (i == 5) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					//IPv4
					printf("%s\n", akt->ip->name);
					printf("Zdrojova IP adresa: ");
					//Src IP
					for (i = akt->ip->s_ip; i < delimiter; i++) {
						if (i == delimiter - 1) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}
					//Dst IP
					printf("Cielova IP adresa: ");
					for (i = delimiter; i < delimiter + akt->ip->len; i++) {
						if (i == (delimiter + akt->ip->len - 1)) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}

					//TCP
					printf("%s\n", akt->ip->tcp->name);

					//Porty
					//Src
					pom = 0;
					printf("Zdrojovy port: ");
					for (i = akt->ip->tcp->s_port; i < delimiter2; i++) {
						if (i == akt->ip->tcp->s_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);
					//Dst
					printf("Cielovy port: ");
					for (i = delimiter2; i < delimiter2 +2; i++) {
						if (i == akt->ip->tcp->d_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);
					//Vypis Bytov(packetu)
					for (i = 1; i <= header->caplen; i++) {

						printf("%.2x ", pktdata[i - 1]);

						if (i % LINE_LEN == 8) {
							printf("  ");
						}
						else if (i % LINE_LEN == 0) {
							printf("\n");
						}
					}
					putchar('\n');
					putchar('\n');
				}
			}
		}
	}
}

//V�pis pre FTP d�tov� komunik�ciu
void Vypis_FTP_Data(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first) {
	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2;
	Protocol *akt = first;
	int ftpd_val;

	//nastavenie poz�cie na 12 B (za�iatok Ipv4)
	position = akt->dest + akt->src;//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	ftpd_val = akt->ip->tcp->ports[0].num;

	//Prechadzanie paketmi a ur�enie HTTPS
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1])) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 20(ftp - data) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == ftpd_val || pktdata[delimiter2-1] == ftpd_val) {
					printf("Ramec: %d\n", tmp);
					printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
					printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
					printf("%s\n", akt->name);

					printf("Zdrojova MAC adresa: ");
					for (i = akt->dest; i < akt->dest + akt->src; i++) {
						if (i == 11) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					printf("Cielova MAC adresa: ");
					for (i = 0; i < akt->dest; i++) {
						if (i == 5) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					//IPv4
					printf("%s\n", akt->ip->name);
					printf("Zdrojova IP adresa: ");
					//Src IP
					for (i = akt->ip->s_ip; i < delimiter; i++) {
						if (i == delimiter - 1) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}
					//Dst IP
					printf("Cielova IP adresa: ");
					for (i = delimiter; i < delimiter + akt->ip->len; i++) {
						if (i == (delimiter + akt->ip->len - 1)) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}

					//TCP
					printf("%s\n", akt->ip->tcp->name);

					//Porty
					//Src
					pom = 0;
					printf("Zdrojovy port: ");
					for (i = akt->ip->tcp->s_port; i < delimiter2; i++) {
						if (i == akt->ip->tcp->s_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);
					//Dst
					printf("Cielovy port: ");
					for (i = delimiter2; i < delimiter2+2; i++) {
						if (i == akt->ip->tcp->d_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);

					//Vypis Bytov(packetu)
					for (i = 1; i <= header->caplen; i++) {

						printf("%.2x ", pktdata[i - 1]);

						if (i % LINE_LEN == 8) {
							printf("  ");
						}
						else if (i % LINE_LEN == 0) {
							printf("\n");
						}
					}
					putchar('\n');
					putchar('\n');
				}
			}
		}
	}
}

//V�pis pre TFTP komunik�ciu
void Vypis_TFTP(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first) {
	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2;
	Protocol *akt = first;
	int def_port = 0;			//port pod�a ktor�ho budeme sledova� cel� ftp komunik�ciu

	//nastavenie poz�cie na 12 B (za�iatok Ipv4)
	position = akt->dest + akt->src;//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;

	//Prechadzanie paketmi a ur�enie UDP(69-TFTP)
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1])) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - UDP(17) (x11)
			if (pktdata[prot_pos] == akt->ip->udp->udp_value) {

				//Hodnota cieloveho portu mus� by� 69(tftp) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->udp->d_port+1] == akt->ip->udp->ports[0].num ||
					((pktdata[akt->ip->udp->s_port] * 256 + pktdata[akt->ip->udp->s_port + 1]) == def_port) ||
					((pktdata[akt->ip->udp->d_port] * 256 + pktdata[akt->ip->udp->d_port + 1]) == def_port)) {
					
					printf("Ramec: %d\n", tmp);
					printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
					printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
					printf("%s\n", akt->name);

					//def port podla ktor�ho src portu budeme sledova� celu komunik�ciu(tftp server ma rozne portu ale rovnanke dst porty)
					def_port = pktdata[akt->ip->udp->s_port] * 256 + pktdata[akt->ip->udp->s_port + 1];

					printf("Zdrojova MAC adresa: ");
					for (i = akt->dest; i < akt->dest + akt->src; i++) {
						if (i == 11) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					printf("Cielova MAC adresa: ");
					for (i = 0; i < akt->dest; i++) {
						if (i == 5) {
							printf("%.2x\n", pktdata[i]);
							break;
						}
						printf("%.2x ", pktdata[i]);
					}

					//IPv4
					printf("%s\n", akt->ip->name);
					printf("Zdrojova IP adresa: ");
					//Src IP
					for (i = akt->ip->s_ip; i < delimiter; i++) {
						if (i == delimiter - 1) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}
					//Dst IP
					printf("Cielova IP adresa: ");
					for (i = delimiter; i < delimiter + akt->ip->len; i++) {
						if (i == (delimiter + akt->ip->len - 1)) {
							printf("%d\n", pktdata[i]);
							break;
						}
						printf("%d. ", pktdata[i]);
					}

					//UDP
					printf("%s\n", akt->ip->udp->name);

					//Porty
					//Src
					pom = 0;
					printf("Zdrojovy port: ");
					for (i = akt->ip->udp->s_port; i < akt->ip->udp->d_port; i++) {
						if (i == akt->ip->tcp->s_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);
					//Dst
					printf("Cielovy port: ");
					for (i = akt->ip->udp->d_port; i < akt->ip->udp->d_port+2; i++) {
						if (i == akt->ip->tcp->d_port) {
							pom = pktdata[i] * 256;
						}
						else
						{
							pom += pktdata[i];
						}
					}
					printf("%d\n", pom);

					//Vypis Bytov(packetu)
					for (i = 1; i <= header->caplen; i++) {

						printf("%.2x ", pktdata[i - 1]);

						if (i % LINE_LEN == 8) {
							printf("  ");
						}
						else if (i % LINE_LEN == 0) {
							printf("\n");
						}
					}
					putchar('\n');
					putchar('\n');
				}
			}
		}
	}
}


//V�pis pre komunik�ciu ICMP
void Vypis_ICMP(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first) {
	//urobi� v�pis protocolov cez switch

	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2;
	Protocol *akt = first;


	//nastavenie poz�cie na 12 B (za�iatok Ipv4)
	position = akt->dest + akt->src;		//12. B
	prot_pos = akt->ip->prot_pos;			//14. B
	delimiter = akt->ip->d_ip;				//30. B

	//Prechadzanie paketmi a ur�enie UDP(TFTP)
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {

		tmp++;		//��slo r�mca
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1])) {

			//Protokol ICMP sa nach�dza na na transportnej vrtsve protokolu IP - ICMP  - 1 (x11)
			if (pktdata[prot_pos] == akt->ip->icmp->icmp_value) {

				//V�pis komunik�cie pod�a ICMP - code operation
				//Overenie �i sa jedn� o platn� k�d v r�mc ICMP
					for (i = 0; i < 6; i++) {
						if (pktdata[akt->ip->icmp->type] == akt->ip->icmp->code[i].num) {
							printf("Ramec: %d\n", tmp);
							printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
							printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
							printf("%s\n", akt->name);


							//MAC Adresy
							printf("Zdrojova MAC adresa: ");
							for (i = akt->dest; i < akt->dest + akt->src; i++) {
								if (i == 11) {
									printf("%.2x\n", pktdata[i]);
									break;
								}
								printf("%.2x ", pktdata[i]);
							}

							printf("Cielova MAC adresa: ");
							for (i = 0; i < akt->dest; i++) {
								if (i == 5) {
									printf("%.2x\n", pktdata[i]);
									break;
								}
								printf("%.2x ", pktdata[i]);
							}

							//IPv4
							printf("%s\n", akt->ip->name);
							printf("Zdrojova IP adresa: ");
							//Src IP
							for (i = akt->ip->s_ip; i < delimiter; i++) {
								if (i == delimiter - 1) {
									printf("%d\n", pktdata[i]);
									break;
								}
								printf("%d. ", pktdata[i]);
							}
							//Dst IP
							printf("Cielova IP adresa: ");
							for (i = delimiter; i < delimiter + akt->ip->len; i++) {
								if (i == (delimiter + akt->ip->len - 1)) {
									printf("%d\n", pktdata[i]);
									break;
								}
								printf("%d. ", pktdata[i]);
							}

							//ICMP name
							printf("%s\n", akt->ip->icmp->name);

							//Code -operation Echo, Time exceeded Reply .... decimalna s�stava(bajty packetu)
							switch (pktdata[akt->ip->icmp->type]) {
							case 0: printf("%s\n", akt->ip->icmp->code[0].name); break;
							case 3: printf("%s\n", akt->ip->icmp->code[1].name); break;
							case 5: printf("%s\n", akt->ip->icmp->code[2].name); break;
							case 8: printf("%s\n", akt->ip->icmp->code[3].name); break;
							case 11: printf("%s\n", akt->ip->icmp->code[4].name); break;
							case 30: printf("%s\n", akt->ip->icmp->code[5].name); break;
							}
							//V�pis packetu
							for (i = 1; i <= header->caplen; i++) {

								printf("%.2x ", pktdata[i - 1]);

								if (i % LINE_LEN == 8) {
									printf("  ");
								}
								else if (i % LINE_LEN == 0) {
									printf("\n");
								}
							}
							putchar('\n');
							putchar('\n');
							//Zbyto�ne u� necyklujeme ke� sme u� vyp�sali
							break;
						}
					}
				}
			}
		}
	}


// Ak otvara� in� s�bor mus� zmenit v main,switch-rewind point 1 a vypis-IP

int main(void) {

	char errbuff[PCAP_ERRBUF_SIZE];
	int c, count = 0;										//Ud�va poradov� ��slo r�mca ,po�et v�etk�ch r�mcov nach�dzaj�cich sa v s�bore

	pcap_t *f = NULL;										//Smern�k na sp�jan� zoznam packetov zo s�boru
	const u_char *pktdata = NULL;
	struct pcap_pkthdr *header = NULL;

	FILE *r = NULL;
	Protocol *first = NULL;


	//Otvorenie s�borov na anal�zu
	if ((f = (pcap_open_offline("eth-9.pcap", errbuff))) == NULL ||
		(r = fopen("Linkframe.txt", "r")) == NULL) {

		//Ak nastane chyba otvorenia s�borov, program sa ukon��
		printf("Subor sa nepodarilo otvorit\n");
		printf("%s\n", errbuff);
		return -1;
	}
	else
	{
		//Na��tanie protokolov a inform�ci� do sp�jan�ho zoznamu
		nacitaj(&first, r);

		//kontroln� v�pis
		//vypis_prot(first);

		while ((c = getchar()) != 'k') {

			switch (c) {
				//Bod c. 1
			case '1':Point_1(f, header, pktdata, &count, first),
				pcap_close(f),
				(f = (pcap_open_offline("eth-9.pcap", errbuff))),
				Vypis_ip(f, first, header, pktdata, count);
				break;

				//Bod 3 - HTTP
			case 'a':Vypis_HTTP(f, header, pktdata, count, first); break;			//V�pis pre HTTP
			case 'b':Vypis_HTTPS(f, header, pktdata, count, first); break;			//V�pis pre HTTPS
			case 'c':Vypis_Telnet(f, header, pktdata, first); break;				//V�pis pre TELNET
			case 'd':Vypis_SSH(f, header, pktdata, first); break;					//V�pis pre SSH
			case 'e':Vypis_FTP_Control(f, header, pktdata, first); break;			//V�pis pre FTP-Control
			case 'f':Vypis_FTP_Data(f, header, pktdata, first); break;				//V�pis pre FTP-Data
			case 'g':Vypis_TFTP(f, header, pktdata, first); break;					//V�pis pre TFTP
			case 'h':Vypis_ICMP(f, header, pktdata, first); break;					//V�pis pre ICMP

			}

			//rewindovanie
			pcap_close(f);
			f = (pcap_open_offline("eth-9.pcap", errbuff));
	
		}


		pcap_close(f);

		if (fclose(r) == EOF) {
			printf("Subor sa nepodarilo zatvorit\n");
		}

		//Vr�tenie alokovanej pamate OS
		delete_list(first);
		//free(pktdata, header);
		first = NULL;
		return 0;
	}

}