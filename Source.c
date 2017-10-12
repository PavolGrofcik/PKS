/*
*	Project 1		*****
*	Author			Pavol Grof��k
*	Date			5.10
*	Year			2017
*	Subject			Computer and communication networks
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
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

//�trukt�ra pre DNS
typedef struct dns {
	char name[4];		//DNS
	Pairs q_res[2];		//Querry/response
	Pairs op_code[3];	//Opera�n� k�d
	Pairs res_code[6];	//Response cod
	int position[3];	//Poz�cie pre dan� kod� 0 -q_res 1 - op_code 2 - res_code
}Dns;

//�trukt�ra pre UDP
typedef struct udp {
	char name[4];		//UDP
	int s_port;			//Src port
	int d_port;			//Dst port
	int len;			//Ve�kost� portov
	int udp_value;		//Poz�cia UDP
	Pairs ports[2];		//Hodnota portov s n�zvom
	Dns dns[1];			//DNS v UDP
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
	int op_len;			//Dlzka operacie
	int src_mac;		//Src MAC pozicia
	int src_ip;			//Src IP pozicia
	int dst_mac;		//Dst MAC pozicia
	int dst_ip;			//Dst IP pozicia
	int mac_len;		//Dlzka MAC adresy
	int ip_len;			//Dlzka IP adresy
	Pairs echo[2];		//Echo - Reply/Request
}Arp;

//�trukt�ra pre TCP
typedef struct tcp {
	char name[4];		//TCP
	int s_port;			//Src port
	int d_port;			//Dst port
	int len_p;			//Ve�kos� portov(Bytes)
	int tcp_value;		//Pozicia TCP 
	Pairs ports[7];		//Hodnota portu + n�zov
	Dns dns[1];			//DNS v TCP
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

	Protocol *akt = NULL;
	int c, i;

	if ((*first) == NULL) {

		//Alok�cia pamati
		if ((*first = (Protocol*)malloc(sizeof(Protocol))) == NULL) {
			printf("Nedostatok pamate\n");
			return;
		}
		//Nasmerovanie smern�ka do NULL
		(*first)->next = NULL;

		//na��tanie Ethernet protokolu zo s�boru
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s ", (*first)->name);
			fscanf(f, "%d", &(*first)->dest);
			fscanf(f, "%d", &(*first)->src);
			fscanf(f, "%d", &(*first)->len);
			fscanf(f, "%d", &(*first)->arr[0]);
			fscanf(f, "%d", &(*first)->arr[1]);
			fscanf(f, "%d", &(*first)->arr[2]);

		}
		//na��tanie ARP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->arp->name);
			fscanf(f, "%d", &(*first)->arp->operation);
			fscanf(f, "%d", &(*first)->arp->op_len);
			fscanf(f, "%d", &(*first)->arp->src_mac);
			fscanf(f, "%d", &(*first)->arp->src_ip);
			fscanf(f, "%d", &(*first)->arp->dst_mac);
			fscanf(f, "%d", &(*first)->arp->dst_ip);
			fscanf(f, "%d", &(*first)->arp->mac_len);
			fscanf(f, "%d", &(*first)->arp->ip_len);
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
			for (i = 0; i < 7; i++) {
				fscanf(f, "%d", &(*first)->ip->tcp->ports[i].num);
				fscanf(f, "%s", (*first)->ip->tcp->ports[i].name);
			}
		}

		//na��tanie UDP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->udp->name);
			fscanf(f, "%d", &(*first)->ip->udp->s_port);
			fscanf(f, "%d", &(*first)->ip->udp->d_port);
			fscanf(f, "%d", &(*first)->ip->udp->len);
			fscanf(f, "%d", &(*first)->ip->udp->udp_value);
			fscanf(f, "%d", &(*first)->ip->udp->ports[0].num);
			fscanf(f, "%s", (*first)->ip->udp->ports[0].name);
			fscanf(f, "%d", &(*first)->ip->udp->ports[1].num);
			fscanf(f, "%s", (*first)->ip->udp->ports[1].name);
		}

		//Na��tanie ICMP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->icmp->name);
			fscanf(f, "%d", &(*first)->ip->icmp->type);
			fscanf(f, "%d", &(*first)->ip->icmp->len);
			fscanf(f, "%d", &(*first)->ip->icmp->icmp_value);
			for (i = 0; i <= 5; i++) {
				fscanf(f, "%d", &(*first)->ip->icmp->code[i].num);
				fscanf(f, "%s", (*first)->ip->icmp->code[i].name);
			}
		}

		//Na��tanie DNS

		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->udp->dns->name);
			for (i = 0; i < 3; i++) {
				fscanf(f, "%d", &(*first)->ip->udp->dns->position[i]);
			}
			for (i = 0; i < 2; i++) {
				fscanf(f, "%d", &(*first)->ip->udp->dns->q_res[i].num);
				fscanf(f, "%s", (*first)->ip->udp->dns->q_res[i].name);

			}
			for (i = 0; i < 3; i++) {
				fscanf(f, "%d", &(*first)->ip->udp->dns->op_code[i].num);
				fscanf(f, "%s", (*first)->ip->udp->dns->op_code[i].name);

			}
			for (i = 0; i < 6; i++) {
				fscanf(f, "%d", &(*first)->ip->udp->dns->res_code[i].num);
				fscanf(f, "%s", (*first)->ip->udp->dns->res_code[i].name);

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


void Vypis_ip(pcap_t *f, Protocol *first, struct pcap_pkthdr *hdr, const u_char *pkt_data, int n, char path[]) {

	Protocol *akt = first;
	int i, j = 0, max = 0, delimiter;
	char errbuff[20];
	int count = 0, frame, tmp = 0;

	int **arr = NULL;
	int *space = NULL;

	//Hranica (src) IP adrey 
	delimiter = akt->ip->s_ip + 4;

	//Alok�cia 2D po�a na ur�enie max ve�kosti bajtov
	if ((arr = (int**)malloc(n * sizeof(int*))) == NULL) {
		printf("Nedostatok pamate\n");
		return;
	}

	for (i = 0; i < 30; i++) {
		space = (int *)calloc(ARRAY_LEN*n, sizeof(int));
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
			if (i == (delimiter - 1)) {
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


	frame = arr[0][0];						//Default IP adresa
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
	f = (pcap_open_offline(path, errbuff));
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

	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2;
	int http_val;
	Protocol *akt = first;

	//nastavenie poz�ci� 
	position = akt->dest + akt->src;				//12. B
	prot_pos = akt->ip->prot_pos;					//14. B
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	http_val = akt->ip->tcp->ports[4].num;			//�. portu - 80 (Dec)

	//Prechadzanie paketmi a ur�enie HTTP
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {

		tmp++;																				//��slo r�mca
		//Zistenie �i sa jedn� o IPv4 (0800) && IPv4
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve podprotokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 80(https) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == http_val || pktdata[akt->ip->tcp->s_port + 1] == http_val) {
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
						if (i == (delimiter + akt->ip->len - 1)) {
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
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 443(https) Dst port(pozicia druha tj(36+1)==37
				if ((pktdata[akt->ip->tcp->d_port + 1] + pktdata[akt->ip->tcp->d_port] * 256) == https_val ||
					(pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256) == https_val) {
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

	//Prechadzanie paketmi a ur�enie Telnet
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800) && IPv4
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 23(TELNET) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == telnet_val || pktdata[delimiter2 - 1] == telnet_val) {
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
	prot_pos = akt->ip->prot_pos;									//14. B
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	SSH_val = akt->ip->tcp->ports[2].num;							//22 - SSH

	//Prechadzanie paketmi a ur�enie SSHs
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800) && IPv4
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 80(https) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == SSH_val || pktdata[delimiter2 - 1] == SSH_val) {
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

	//Prechadzanie paketmi a ur�enie FTP
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800)
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 80(https) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == ftp_val || pktdata[delimiter2 - 1] == ftp_val) {
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

	//Prechadzanie paketmi a ur�enie FTP - data
	while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
		tmp++;
		//Zistenie �i sa jedn� o IPv4 (0800) && IPv4
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - TCP(06)
			if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

				//Hodnota cieloveho portu mus� by� 20(ftp - data) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->tcp->d_port + 1] == ftpd_val || pktdata[delimiter2 - 1] == ftpd_val) {
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
		//Zistenie �i sa jedn� o IPv4 (0800) && IPv4
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

			//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - UDP(17) (x11)
			if (pktdata[prot_pos] == akt->ip->udp->udp_value) {

				//Hodnota cieloveho portu mus� by� 69(tftp) Dst port(pozicia druha tj(36+1)==37
				if (pktdata[akt->ip->udp->d_port + 1] == akt->ip->udp->ports[0].num ||
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
					for (i = akt->ip->udp->d_port; i < akt->ip->udp->d_port + 2; i++) {
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
		//Zistenie �i sa jedn� o IPv4 (0800) && IPv4
		if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

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

void Print_info(struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first, int arr[], int pom,int flag) {

	int i, count, delimiter;
	Protocol *akt = first;

	delimiter = akt->arp->dst_ip + akt->arp->ip_len;						//Hranica dest IP(iter�cia)

	printf("%s - %s, ", akt->arp->name, pktdata[akt->arp->operation] == 1 ? "Request" : "Reply");

	printf("IP adresa: ");													//Dst IP adresa
	for (i = akt->arp->dst_ip; i < delimiter; i++) {
		if (i == delimiter - 1) {
			printf("%d ,", pktdata[i]);
			break;
		}
		printf("%d. ", pktdata[i]);
	}
	if (flag == 0) {
		printf("MAC adresa: ???\n");
	}
	else
	{
		printf("MAC adresa: ");
		//V�pis n�jdenej MAC adresy
		for (i = akt->dest; i < akt->dest + akt->src; i++) {
			if (i == 11) {
				printf("%.2x\n", pktdata[i]);
				break;
			}
			printf("%.2x ", pktdata[i]);
		}
	}
	
	printf("Zdrojova IP adresa: ");											//Src IP	
	for (i = akt->arp->src_ip; i < akt->arp->dst_mac; i++) {
		if (i == akt->arp->dst_mac - 1) {
			printf("%d ,", pktdata[i]);
			break;
		}
		printf("%d. ", pktdata[i]);
	}

	printf("Cielova IP: ");													//Dst Ip
	for (i = akt->arp->dst_ip; i < delimiter; i++) {
		if (i == delimiter - 1) {
			printf("%d\n", pktdata[i]);
			break;
		}
		printf("%d. ", pktdata[i]);
	}
	printf("Ramec: %d\n", arr[pom]);										//Poz�cia v poli(r�mec)
	printf("Dlzka ramca poskytnuteho pcap API: %d\n", header->caplen);
	printf("Dlza ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
	printf("%s\n", akt->name);												//Ethernet II

																			//V�pis MAC adries
	printf("Zdrojova MAC adresa: ");
	for (i = akt->dest; i < akt->dest + akt->src; i++) {
		if (i == 11) {
			printf("%.2x\n", pktdata[i]);
			break;
		}
		printf("%.2x ", pktdata[i]);
	}

	printf("Cielova MAC adresa: ");
	for (i = akt->arp->dst_mac; i < akt->arp->dst_ip; i++) {
		if (i == akt->arp->dst_ip - 1) {
			printf("%.2x\n", pktdata[i]);
			break;
		}
		printf("%.2x ", pktdata[i]);
	}
	//Vypis cel�ho obsahu packetu
	for (i = 1; i <= header->caplen; i++) {

		printf("%.2x ", pktdata[i - 1]);

		if (i % LINE_LEN == 8) {
			printf("  ");
		}
		else if (i % LINE_LEN == 0) {
			printf("\n");
		}
	}
	printf("\n\n");															//Odriadkovanie
	return;
}

//V�pis pre ARP komunik�ciu
void Vypis_Arp(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, int frames, Protocol *first, char path[]) {

	int Arp_count, Arp_position;
	int *arr = NULL;
	int tmp, pom, i, delimiter, count, comm;	//pomocn� premenn�
	int j, pom2, count2, comm2;
	int flag;									//Pr�znak potrebn� k v�pisu
	char errbuff[10];
	Protocol *akt = first;

	Arp_count = 0;
	Arp_position = akt->dest + akt->src;

	while (pcap_next_ex(f, &header, &pktdata) > 0) {

		//Arp protocol je v Ethernet type: 0806
		if (pktdata[Arp_position] * 100 + pktdata[Arp_position + 1] == akt->arr[2]) {
			Arp_count++;
		}
	}

	if (Arp_count) {

		//Alokujeme pole, do ktor�ho ulo��me poradov� ��slo r�mca
		if ((arr = (int*)malloc(Arp_count * sizeof(int))) == NULL) {
			printf("Nepodarilo sa alokova� pamat\n");
			return;
		}

		pcap_close(f);
		f = pcap_open_offline(path, errbuff);

		//napln�me pole 
		tmp = 0;
		pom = 0;
		while (pcap_next_ex(f, &header, &pktdata) > 0) {
			tmp++;
			if (pktdata[Arp_position] * 100 + pktdata[Arp_position + 1] == akt->arr[2]) {			//O�etrenie �e sa jedn� o r�mec s ARP
				//zapamatanie �. r�mca
				arr[pom] = tmp;
				pom++;
			}
		}

		pcap_close(f);
		f = pcap_open_offline(path, errbuff);

		tmp = 0;
		pom = 0;
		count = 0;
		comm = 0;
		printf("Arp count je %d\n", Arp_count);
		i = j = pom2 = count2 = comm2 = 0;
		count2 = Arp_count - 20;
		delimiter = Arp_count - 20;			//Za�iatok poz�cie (posl 10.)
		comm2 = delimiter;
		//Po�et r�mcov je vy��� ne� 20 (req +rep =2)
		if (Arp_count / 2 > 20) {
			while (pcap_next_ex(f, &header, &pktdata) > 0) {
				tmp++;
				if (tmp == arr[pom] && i < 20) {
					if (count % 2 == 0) {
						flag = 0;
						comm++;
						printf("Komunikacia c: %d\n", comm);
						Print_info(header, pktdata, first, arr, pom,flag);
						pom++;
						count++;
						i++;
					}
					else
					{
						flag = 0;
						Print_info(header, pktdata, first, arr, pom,flag);
						pom++;
						count++;
						i++;
					}
				}
				else if (tmp == arr[delimiter] && j < 20) {


					if (count2 % 2 == 0) {
						comm2++;
						printf("Komunikacia c: %d\n", comm);
						Print_info(header, pktdata, first, arr, pom2,flag);
						pom2++;
						count2++;
						j++;
					}
					else
					{
						Print_info(header, pktdata, first, arr, pom2,flag);
						pom2++;
						count2++;
						j++;
					}
				}
			}
		}
		else
		{
			i = 0;
			tmp = 1;															//R�mec
			pom = 0;															//Index pola arr[pom]
			count = 0;															//Komunik�cia
			while (pcap_next_ex(f, &header, &pktdata) > 0) {
				if (tmp == arr[pom] && count < 20) {
					if (count % 2 == 0) {
						i++;													//��slo komunik�cie
						flag = 0;
						printf("Komunikacia c: %d\n", i);
						Print_info(header, pktdata, first, arr, pom,flag);
						pom++;
						count++;
					}
					else {
						if (pktdata[akt->arp->operation] == akt->arp->echo[0].num) {
							flag = 0;
							Print_info(header, pktdata, first, arr, pom,flag);		//Zobraz� inform�cie o danej komunik�cii
							pom++;												//Sl��i na posunutie poz�cie v poli o +1 dopredu
						}
						else
						{
							//ARP reply only => flag == 1 (V�pis reply namiesto ????)
							flag = 1;
							Print_info(header, pktdata, first, arr, pom,flag);
							pom++;
							count++;											////Sl��i na ur�enie ��sla komunik�cie
						
						}
					}
				}
				tmp++;
			}
		}

		free(arr);																//Uvo�nenie alokovan�ho po�a
		return;
	}
	else
	{
		//V subore *.pcap nie s� �iadne protokoly ARP
		return;
	}
}


//Zobraz� z�kladn� inform�cie o programe a k���ov� slov�
void Intro() {

	printf("Zadajte operaciu: \n");
	printf("1: Bod c. 1\n");
	printf("a: Vypis pre http komunikaciu\n");
	printf("b: Vypis pre https komunikaciu\n");
	printf("c: Vypis pre Telnet komunikaciu\n");
	printf("d: Vypis pre SSH komunikaciu\n");
	printf("e: Vypis pre FTP - control komunikaciu\n");
	printf("f: Vypis pre FTP - data komunikaciu\n");
	printf("g: Vypis pre TFTP komunikaciu\n");
	printf("h: Vypis pre ICMP komunikaciu\n");
	printf("i: Vypis pre ARP komunikaciu\n");
	printf("j: Vypis pre DNS komunik�ciu UDP\n");
	printf("k: Koniec programu\n");

}

void Dns_udp(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first) {
		int i, position, prot_pos, tmp = 0, pom = 0;
		int delimiter, delimiter2;
		Protocol *akt = first;
		int def_port = 0;							//port pod�a ktor�ho budeme sledova� cel� ftp komunik�ciu

													//nastavenie poz�cie na 12 B (za�iatok Ipv4)
		position = akt->dest + akt->src;//12. B
		prot_pos = akt->ip->prot_pos;
		delimiter = akt->ip->d_ip;

		//Prechadzanie paketmi a ur�enie UDP(69-TFTP)
		while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
			tmp++;
			//Zistenie �i sa jedn� o IPv4 (0800) && IPv4
			if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

				//Protokol HTTP sa nach�dza na na rela�nej vrtsve protokolu - UDP(17) (x11)
				if (pktdata[prot_pos] == akt->ip->udp->udp_value) {

					//Hodnota cieloveho portu mus� by� 53(domain) Dst port(pozicia druha tj(36+1)==37
					if (pktdata[akt->ip->udp->d_port + 1] == akt->ip->udp->ports[1].num ||
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
						for (i = akt->ip->udp->d_port; i < akt->ip->udp->d_port + 2; i++) {
							if (i == akt->ip->tcp->d_port) {
								pom = pktdata[i] * 256;
							}
							else
							{
								pom += pktdata[i];
							}
						}
						printf("%d\n", pom);

						//Response/querry
						pom = 0;
						for (i = akt->ip->udp->dns->position[2]; i < akt->ip->udp->dns->position[2] + 2; i++) {
							if (i == akt->ip->udp->dns->position[2]) {
								pom = pktdata[i] * 256;
							}
							else
							{
								pom += pktdata[i];
							}
						}
						printf("%s\n", pom >> 15 == 1 ? "Response" : "Querry");
						/*		//Dorobi� selekciu 4 posledn�ch bitov!!!
						pom = 0;
						for (i = akt->ip->udp->dns->position[2]; i < akt->ip->udp->dns->position[2] + 2; i++) {
							if (i == akt->ip->udp->dns->position[2]) {
								pom = pktdata[i] * 256;
							}
							else
							{
								pom += pktdata[i];
							}
						}
						
						switch (pom) {
							case 
						}
						*/
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


int main(void) {

	char errbuff[PCAP_ERRBUF_SIZE];
	char path[] = "C:\\Users\\Pavol Grof��k\\Documents\\Visual Studio 2017\\Projects\\Winpcap\\Winpcap\\trace-2.pcap";
	int c, count = 0;													//Ud�va poradov� ��slo r�mca ,po�et v�etk�ch r�mcov nach�dzaj�cich sa v s�bore

	pcap_t *f = NULL;													//Smern�k na sp�jan� zoznam packetov zo s�boru
	const u_char *pktdata = NULL;
	struct pcap_pkthdr *header = NULL;

	FILE *r = NULL;
	Protocol *first = NULL;


	//Otvorenie s�borov na anal�zu
	if ((f = (pcap_open_offline(path, errbuff))) == NULL ||
		(r = fopen("Linkframe.txt", "r")) == NULL) {

		//Ak nastane chyba otvorenia s�borov, program sa ukon��
		printf("Subor sa nepodarilo otvorit\n");
		printf("%s\n", errbuff);
		return -1;
	}
	else
	{

		time_t t = time(NULL);
		struct tm *tm = localtime(&t);
		char s[64];

		printf("Vitajte!\n");
		//printf("Dnes: ");
		strftime(s, sizeof(s), "%c", tm);
		printf("%s\n\n", s);
		tm = NULL;
		//Zobrazenie domovskej obrazovky
		Intro();
		//Na��tanie protokolov a inform�ci� do sp�jan�ho zoznamu
		nacitaj(&first, r);


		while ((c = getchar()) != 'k') {

			switch (c) {
				//Bod c. 1
			case '1':Point_1(f, header, pktdata, &count, first),					//O�etri� len pre ipv4 pozor na IIEE 802.3 len pre Ethernet II, porobi� bod a do f cez jednu funkciu
				pcap_close(f),
				(f = (pcap_open_offline(path, errbuff))),
				Vypis_ip(f, first, header, pktdata, count, path);
				break;

			//Bod c. 3 
			case 'a':Vypis_HTTP(f, header, pktdata, count, first); break;			//V�pis pre HTTP
			case 'b':Vypis_HTTPS(f, header, pktdata, count, first); break;			//V�pis pre HTTPS
			case 'c':Vypis_Telnet(f, header, pktdata, first); break;				//V�pis pre TELNET
			case 'd':Vypis_SSH(f, header, pktdata, first); break;					//V�pis pre SSH
			case 'e':Vypis_FTP_Control(f, header, pktdata, first); break;			//V�pis pre FTP-Control
			case 'f':Vypis_FTP_Data(f, header, pktdata, first); break;				//V�pis pre FTP-Data
			case 'g':Vypis_TFTP(f, header, pktdata, first); break;					//V�pis pre TFTP
			case 'h':Vypis_ICMP(f, header, pktdata, first); break;					//V�pis pre ICMP
			case 'i':Vypis_Arp(f, header, pktdata, count, first, path); break;		//V�pis pre ARP 
			case 'j':Dns_udp(f, header, pktdata, first); break;						//V�pis DND pre UDP

			}
			f = (pcap_open_offline(path, errbuff));									//Rewind pcap_t *f

		}

		pcap_close(f);

		if (fclose(r) == EOF) {
			printf("Subor sa nepodarilo zatvorit\n");
		}

		//Vr�tenie alokovanej pamate OS
		delete_list(first);
		free(pktdata, header);
		first = NULL;
		return 0;
	}
}