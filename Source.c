/*
*	Project 1		*****
*	Author			Pavol GrofËÌk
*	Date			5.10
*	Year			2017
*	Subject			Computer and communication networks
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <WinSock2.h>
#include <pcap.h>

//Definovanie pre v˝pis riadku po 16 B
#define LINE_LEN 16 
#define ARRAY_LEN 2

//ätrukt˙ra p·rov pre port + n·zov
typedef struct  pairs {
	int num;
	char name[16];
}Pairs;

//ätrukt˙ra pre DNS
typedef struct dns {
	char name[4];		//DNS
	Pairs q_res[2];		//Querry/response
	Pairs op_code[3];	//OperaËn˝ kÛd
	Pairs res_code[6];	//Response cod
	int position[3];	//PozÌcie pre danÈ kod˝ 0 -q_res 1 - op_code 2 - res_code
}Dns;

//ätrukt˙ra pre UDP
typedef struct udp {
	char name[4];		//UDP
	int s_port;			//Src port
	int d_port;			//Dst port
	int len;			//Veækostù portov
	int udp_value;		//PozÌcia UDP
	Pairs ports[2];		//Hodnota portov s n·zvom
	Dns dns[1];			//DNS v UDP
}Udp;

typedef struct icmp {
	char name[5];		//ICMP
	int type;			//PozÌcia protokolu
	int len;			//Dlzka
	int icmp_value;		//PozÌcia ICMP
	Pairs code[6];		//Hodnoty protokolov s nazvom
}Icmp;
//ätrukt˙ra pre ARP
typedef struct arp {
	char name[4];		//ARP
	int operation;		//PozÌcia - operation
	int op_len;			//Dlzka operacie
	int src_mac;		//Src MAC pozicia
	int src_ip;			//Src IP pozicia
	int dst_mac;		//Dst MAC pozicia
	int dst_ip;			//Dst IP pozicia
	int mac_len;		//Dlzka MAC adresy
	int ip_len;			//Dlzka IP adresy
	Pairs echo[2];		//Echo - Reply/Request
}Arp;

//ätrukt˙ra pre TCP
typedef struct tcp {
	char name[4];		//TCP
	int s_port;			//Src port
	int d_port;			//Dst port
	int len_p;			//Veækosù portov(Bytes)
	int tcp_value;		//Pozicia TCP 
	Pairs ports[7];		//Hodnota portu + n·zov
	Dns dns[1];			//DNS v TCP
}Tcp;

//ätrukt˙ra pre IP
typedef struct ip {
	int name_p;			//Verzia 4/6
	char name[5];		//IP
	int s_ip;			//Src ip
	int d_ip;			//Dst ip
	int len;			//Veækosù Ip adresy(Bytes)
	int prot_pos;		//PozÌcia Ôalöieho protokolu
	Tcp tcp[1];			//Vnoren˝ protokol TCP
	Icmp icmp[1];		//Vnoren˝ protokol ICMP
	Udp udp[1];			//Vnoren˝ protokol UDP
}IP;

//Definovanie vlastnej ötruktury pre Ethernet a 802.3
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

//NaËÌtanie protokolov a öpecifik·ciÌ zo s˙boru
void nacitaj(Protocol **first, FILE *f) {

	Protocol *akt = NULL;
	int c, i;

	if ((*first) == NULL) {

		//Alok·cia pamati
		if ((*first = (Protocol*)malloc(sizeof(Protocol))) == NULL) {
			printf("Nedostatok pamate\n");
			return;
		}
		//Nasmerovanie smernÌka do NULL
		(*first)->next = NULL;

		//naËÌtanie Ethernet protokolu zo s˙boru
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
		//naËÌtanie ARP
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

		//naËÌtanie IP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->name);
			fscanf(f, "%d", &(*first)->ip->name_p);
			fscanf(f, "%d", &(*first)->ip->s_ip);
			fscanf(f, "%d", &(*first)->ip->d_ip);
			fscanf(f, "%d", &(*first)->ip->len);
			fscanf(f, "%d", &(*first)->ip->prot_pos);
		}

		//naËÌtanie TCP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->tcp->name);
			//printf("tcp name: %s\n", (*first)->ip->tcp->name);		//vypis IP nazov
			fscanf(f, "%d", &(*first)->ip->tcp->s_port);
			fscanf(f, "%d", &(*first)->ip->tcp->d_port);
			fscanf(f, "%d", &(*first)->ip->tcp->len_p);
			fscanf(f, "%d", &(*first)->ip->tcp->tcp_value);
			//spraviù cez for loop
			for (i = 0; i < 7; i++) {
				fscanf(f, "%d", &(*first)->ip->tcp->ports[i].num);
				fscanf(f, "%s", (*first)->ip->tcp->ports[i].name);
			}
		}

		//naËÌtanie UDP
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

		//NaËÌtanie ICMP
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

		//NaËÌtanie DNS
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

		//NaËÌtanie IEE 802.3
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

//Zmazanie sp·janÈho zoznamu
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

//Funkcia sl˙ûiaca na v˝pis k bodu Ë. 1
void Point_1(pcap_t *f, struct pcap_pkthdr *hdr, const u_char *pkt_data, int *count, Protocol *first) {

	//PomocnÈ premennÈ
	Protocol *akt = NULL;
	int i, pom, num = 0;

	//nasmerovanie na zaËiatok
	akt = first;

	if (akt == NULL) {
		return;
	}

	while ((pcap_next_ex(f, &hdr, &pkt_data)) >= 0) {

		//Z·kladnÈ inform·cie o packete
		printf("Ramec: %d\n", ++(num));
		printf("Dlzka ramca poskytnuteho pcap API: %d\n", hdr->caplen);
		printf("Dlza ramca prenasaneho po mediu: %d\n", hdr->len < 60 ? 64 : hdr->len + 4);
		//nasmerovanie na zaËiatok Linked list-u
		pom = akt->dest + akt->src;	//12
		akt = first;

		//UrËenie typu na Linkovej vrstve
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

		//V˝pis MAC adries
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

		//Vypis celÈho packetu
		for (i = 1; i <= hdr->caplen; i++) {

			printf("%.2x ", pkt_data[i - 1]);

			if (i % LINE_LEN == 8) {
				printf("  ");
			}
			else if (i % LINE_LEN == 0) {
				printf("\n");
			}
		}

		//Odriakovanie pre lepöiu Ëitateænost
		printf("\n\n");
	}
	(*count) = num;									//PoËet vöetk˝ch r·mcov v danom s˙bore
}


void Vypis_ip(pcap_t *f, Protocol *first, struct pcap_pkthdr *hdr, const u_char *pkt_data, int n, char path[]) {

	Protocol *akt = first;
	int i, j = 0, max = 0, delimiter;
	char errbuff[20];
	int count = 0, frame, tmp = 0;
	int arr_count = 0, pom = 0;

	int **arr = NULL;
	int *space = NULL;

	//Hranica (src) IP adrey 
	delimiter = akt->ip->s_ip + 4;
	//PoËet IPv4 protokolov v s˙bore
	while (pcap_next_ex(f, &hdr, &pkt_data) > 0) {
		count++;
		if ((pkt_data[akt->src + akt->dest] * 256 + pkt_data[akt->src + akt->dest + 1])
			== 2048) {
			arr_count++;
		}
	}
	f = pcap_open_offline(path, errbuff);
	//Alok·cia 2D poæa na urËenie max veækosti bajtov
	if ((arr = (int**)malloc(arr_count * sizeof(int*))) == NULL) {
		printf("Nedostatok pamate\n");
		return;
	}

	//alok·cia pomocnÈho poæa
	space = (int *)calloc(ARRAY_LEN*arr_count, sizeof(int));
	
	//Nasmerovanie poæa smernikov ûvonzÌkov
	for (i = 0; i < arr_count; ++i) {
		arr[i] = space + i*ARRAY_LEN;
	}


	count = 0;
	printf("IP adresy vysielajucich uzlov:\n");
	//Len Src Ip adresy
	while ((pcap_next_ex(f, &hdr, &pkt_data)) > 0) {

		count++;
		//Len pre Ethernet II(0800)
		if ((pkt_data[akt->src + akt->dest] * 256 + pkt_data[akt->src + akt->dest + 1])
			== 2048) {
			//PoËet odvysielan˝ch bajtov src adresa
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
			arr[pom][0] = tmp;			//IP adresa
			arr[pom][1] = hdr->caplen;	//Hodnota po mediu(Bajty)

			pom++;
			tmp = 0;
		}
	}


	frame = arr[0][0];						//Default IP adresa
	delimiter = arr[0][1];					//Default hodnota bajtov
	for (i = 1; i < arr_count; i++) {
		if (arr[i][0] == frame) {			//def ip
			delimiter += arr[i][1];			//def max
		}
	}

	for (i = 1; i < arr_count; i++) {
		max = arr[i][1];
		tmp = arr[i][0];
		for (j = i + 1; j < arr_count; j++) {
			if (arr[j][0] == tmp) {
				max += arr[j][1];
			}
		}
		if (max > delimiter) {
			delimiter = max;
			frame = tmp;
		}
	}

	//Odriakovanie pre v˝pis
	putchar('\n');

	//Rewindovanie pcap_t (f)
	pcap_close(f);
	f = (pcap_open_offline(path, errbuff));
	count = 0;

	//Hranica IP
	max = akt->ip->len + akt->ip->s_ip;
	printf("Adresa uzla s najvacsim poctom odvysielanych bajtov:\n");

	//CyklÌme na zistenie IP adresy pre dan˝ velkost
	while ((pcap_next_ex(f, &hdr, &pkt_data)) > 0) {


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
	//Dealokacia - vr·tenie "poûiËan˝ch" bajtov OS

	for (i = 0; i < arr_count; i++) {
		arr[i] = NULL;
	}
	free(space);
	free(arr);
	arr = NULL;
	space = NULL;
}

void vypis(Protocol *first, struct pcap_pkthdr *header, const u_char *pktdata, int frame) {
	int i, pom, delimiter, delimiter2;
	Protocol *akt = first;

	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;

	printf("Ramec: %d\n", frame);
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
	akt = NULL;
}


//V˝pis pre  komunik·cie
void Print_Protocol(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, int count, Protocol *first, char s[],char path[]) {

	int i, position, prot_pos, tmp =0, n, k = 11;
	int delimiter, delimiter2;
	int prot_val;
	char errbuff[10];
	int *arr = NULL, *more = NULL;
	int flag, arrpos = 0;
	Protocol *akt = first;

	position = akt->dest + akt->src;				//12. B
	prot_pos = akt->ip->prot_pos;					//14. B
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;

	if (!strcmp("http", s)) {
		prot_val = akt->ip->tcp->ports[4].num;
	}
	else if (!strcmp("https", s)) {
		prot_val = akt->ip->tcp->ports[5].num;
	}
	else if (!strcmp("ftpc", s)) {
		prot_val = akt->ip->tcp->ports[1].num;
	}
	else if (!strcmp("ftpd", s)) {
		prot_val = akt->ip->tcp->ports[0].num;
	}
	else if (!strcmp("ssh", s)) {
		prot_val = akt->ip->tcp->ports[2].num;
	}
	else if (!strcmp("telnet", s)) {
		prot_val = akt->ip->tcp->ports[3].num;
	}

	arr = (int *)malloc(sizeof(int));
	flag = n = arrpos = 0;
	//Prejdenie zoznamu a vyhladanie poËtu danej komunik·cie
	while (pcap_next_ex(f, &header, &pktdata) > 0) {
		flag++;
		if ((pktdata[akt->ip->tcp->d_port + 1] + pktdata[akt->ip->tcp->d_port] * 256) == prot_val ||
			(pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256) == prot_val) {
			
			//ner·tam tu zvyöne porty ako podla wiresharku
			arr[n] = flag;								//Hodnota r·mca - t.j ËÌslo
			n++;
			more = realloc(arr, (n+1)*sizeof(int));		//PoËet prvkov poæa je vûdy o jedna v‰ËöÌ treba Ìsù o -2 pozÌcie
			arr = more;
		}
	}
	//printf("Pocet n je :%d\n", n);						//Kontroln˝ v˝pis

	f = pcap_open_offline(path, errbuff);
	tmp = flag = 0;
	if (n + 1 >= 20) {												//PoËet komunik·cii je viac neû 20

		while ((pcap_next_ex(f, &header, &pktdata)) > 0) {
			tmp++;
			if (arr[arrpos] == tmp && flag < 10) {					//V˝pis prv˝ch 10
				arrpos++;											//PozÌcia v poli
				flag++;												//PrÌznak
				vypis(first, header, pktdata, tmp);
			}
			else if(arr[n-k+1] == tmp && k>1 )
			{
				k--;
				vypis(first, header, pktdata, tmp);
			}
		}
	}
	else
	{
		//Prechadzanie paketmi a urËenie protokolu
		while ((pcap_next_ex(f, &header, &pktdata)) > 0) {

			tmp++;																				//»Ìslo r·mca
			//Zistenie Ëi sa jedn· o IPv4 (0800) && IPv4
			if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

				//Protokol  sa nach·dza na na relaËnej vrtsve podprotokolu - TCP(06)
				if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

					//Hodnoty cieloveho portu
					if ((pktdata[akt->ip->tcp->d_port + 1] + pktdata[akt->ip->tcp->d_port] * 256) == prot_val ||
						(pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256) == prot_val) {
						vypis(first, header, pktdata, tmp);
					}
				}
			}
		}
	}
	free(arr);	//uvolnenie poæa
}

void vypis_tftp(Protocol *first, struct pcap_pkthdr *header, const u_char *pktdata, int frame) {
	int i, pom, delimiter;
	Protocol *akt = first;

	delimiter = akt->ip->d_ip;

	printf("Ramec: %d\n", frame);
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
	akt = NULL;
}

//V˝pis pre TFTP komunik·ciu
void Vypis_TFTP(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first, char path[]) {
	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter;
	Protocol *akt = first;
	int def_port = 69;																					//port podæa ktorÈho budeme sledovaù cel˙ ftp komunik·ciu
	int *arr = NULL, *more = NULL;
	int flag, n, arrpos, k = 11;
	char errbuff[10];

	//nastavenie pozÌcie na 12 B (zaËiatok Ipv4)
	position = akt->dest + akt->src;//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;

	arr = (int *)malloc(sizeof(int));
	flag = n = arrpos = 0;

	while (pcap_next_ex(f, &header, &pktdata) > 0) {
		flag++;
		if ((pktdata[akt->ip->tcp->d_port + 1] + pktdata[akt->ip->tcp->d_port] * 256) == def_port ||
			(pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256) == def_port) {

			def_port = pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256;			//cel· komunik·cia podæa wireshark
			arr[n] = flag;																				//Hodnota r·mca - t.j ËÌslo
			n++;
			more = realloc(arr, (n + 1) * sizeof(int));													//PoËet prvkov poæa je vûdy o jedna v‰ËöÌ treba Ìsù o -2 pozÌcie
			arr = more;
		}
	}

	flag = 0;
	f = pcap_open_offline(path, errbuff);
	//Prechadzanie paketmi a urËenie UDP(69-TFTP)
	if (n + 1 >= 20) {
		while ((pcap_next_ex(f, &header, &pktdata)) > 0) {
			tmp++;

			if (arr[arrpos] == tmp && flag < 10) {
				flag++;
				arrpos++;
				vypis_tftp(first, header, pktdata, tmp);
			}
			else if (arr[n - k] == tmp && k > 1) {
				k--;
				vypis_tftp(first, header, pktdata, tmp);
				}
			}
	}
	else
	{
		while ((pcap_next_ex(f, &header, &pktdata)) > 0) {
			tmp++;

			if (pktdata[akt->ip->udp->d_port + 1] == akt->ip->udp->ports[0].num ||
				((pktdata[akt->ip->udp->s_port] * 256 + pktdata[akt->ip->udp->s_port + 1]) == def_port) ||
				((pktdata[akt->ip->udp->d_port] * 256 + pktdata[akt->ip->udp->d_port + 1]) == def_port)) {
				vypis_tftp(first, header, pktdata, tmp);
			}
		}
	}
	free(arr);
}

void Vypis_pre_icmp(Protocol *first, struct pcap_pkthdr *header, const u_char *pktdata, int frame) {

	int i, delimiter;
	Protocol *akt = first;

	delimiter = akt->ip->d_ip;

	for (i = 0; i < 6; i++) {
		if (pktdata[akt->ip->icmp->type] == akt->ip->icmp->code[i].num ||
			pktdata[70] == akt->ip->icmp->code[i].num) {

			printf("Ramec: %d\n", frame);
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

			//ICMP name
			printf("%s\n", akt->ip->icmp->name);

			//Code -operation Echo, Time exceeded Reply .... decimalna s˙stava(bajty packetu)
			switch (pktdata[akt->ip->icmp->type]) {
			case 0: printf("%s\n", akt->ip->icmp->code[0].name); break;
			case 3: printf("%s\n", akt->ip->icmp->code[1].name); break;
			case 5: printf("%s\n", akt->ip->icmp->code[2].name); break;
			case 8: printf("%s\n", akt->ip->icmp->code[3].name); break;
			case 11: printf("%s\n", akt->ip->icmp->code[4].name); break;
			case 30: printf("%s\n", akt->ip->icmp->code[5].name); break;
			}
			//V˝pis packetu
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
			//ZbytoËne uû necyklujeme keÔ sme uû vypÌsali
			break;
		}
	}
	akt = NULL;
}

//V˝pis pre komunik·ciu ICMP
void Vypis_ICMP(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first, char path[]) {
	//urobiù v˝pis protocolov cez switch

	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2,
		flag, n, arrpos, k;
	int *arr = NULL, *more = NULL;
	char errbuff[10];
	Protocol *akt = first;


	//nastavenie pozÌcie na 12 B (zaËiatok Ipv4)
	position = akt->dest + akt->src;		//12. B
	prot_pos = akt->ip->prot_pos;			//14. B
	delimiter = akt->ip->d_ip;				//30. B

	arr = (int *)malloc(sizeof(int));
	flag = n = arrpos = 0;

	while (pcap_next_ex(f, &header, &pktdata) > 0) {
		tmp++;
		if (pktdata[akt->ip->prot_pos] == akt->ip->icmp->icmp_value) {
			arr[n] = tmp;
			n++;
			more = realloc(arr, (n + 1) * sizeof(int));
			arr = more;
		}
	}

	f = pcap_open_offline(path, errbuff);

	flag = pom = 0;
	k = 10;
	tmp = 0;
	if ((n + 1) >= 20) {
		while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
			tmp++;
			if (arr[flag] == tmp && pom < 10) {
				pom++;
				flag++;
				Vypis_pre_icmp(akt, header, pktdata, tmp);
			}
			else if (arr[n - k] == tmp && k > 0) {
				k--;
				Vypis_pre_icmp(akt, header, pktdata, tmp);
			}
		}
	}
	else {
		while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
			tmp++;
			if (arr[flag] == tmp) {
				flag++;
				Vypis_pre_icmp(akt, header, pktdata, tmp);
			}
		}
	}

	free(arr);
	arr = NULL;
	more = NULL;
}

void Print_info(struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first, int arr[], int pom,int flag) {

	int i, count, delimiter;
	Protocol *akt = first;

	delimiter = akt->arp->dst_ip + akt->arp->ip_len;						//Hranica dest IP(iterÌcia)

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
		//V˝pis n·jdenej MAC adresy
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
	printf("Ramec: %d\n", arr[pom]);										//PozÌcia v poli(r·mec)
	printf("Dlzka ramca poskytnuteho pcap API: %d\n", header->caplen);
	printf("Dlza ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
	printf("%s\n", akt->name);												//Ethernet II

																			//V˝pis MAC adries
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
	//Vypis celÈho obsahu packetu
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

//V˝pis pre ARP komunik·ciu
void Vypis_Arp(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, int frames, Protocol *first, char path[]) {

	int Arp_count, Arp_position;
	int *arr = NULL;
	int tmp, pom, i, delimiter, count, comm;	//pomocnÈ premennÈ
	int j, pom2, count2, comm2;
	int flag, arp_reply = 0;									//PrÌznak potrebn˝ k v˝pisu
	char errbuff[10];
	Protocol *akt = first;

	Arp_count = 0;
	Arp_position = akt->dest + akt->src;

	while (pcap_next_ex(f, &header, &pktdata) > 0) {

		//Arp protocol je v Ethernet type: 0806
		if (pktdata[Arp_position] * 100 + pktdata[Arp_position + 1] == akt->arr[2] ) {																					//poËÌtame koæko je reply(ak viac ako 20 v poriadku)
			Arp_count++;
			if (pktdata[akt->arp->operation] == akt->arp->echo[1].num) {
				arp_reply++;
			}
		}
	}

	if (Arp_count) {

		//Alokujeme pole, do ktorÈho uloûÌme poradovÈ ËÌslo r·mca
		if ((arr = (int*)malloc(Arp_count * sizeof(int))) == NULL) {
			printf("Nepodarilo sa alokovaù pamat\n");
			return;
		}

		pcap_close(f);
		f = pcap_open_offline(path, errbuff);

		//naplnÌme pole 
		tmp = 0;
		pom = 0;
		while (pcap_next_ex(f, &header, &pktdata) > 0) {
			tmp++;
			if (pktdata[Arp_position] * 100 + pktdata[Arp_position + 1] == akt->arr[2]) {			//Oöetrenie ûe sa jedn· o r·mec s ARP (806)
				//zapamatanie Ë. r·mca
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
		printf("Arp count je %d\n", arp_reply);
		i = j = pom2 = count2 = comm2 = 0;
		count2 = Arp_count - 20;
		delimiter = Arp_count - 20;			//ZaËiatok pozÌcie (posl 10.)
		comm2 = delimiter;
		//PoËet r·mcov je vyööÌ neû 20 (req +rep =2)
		if (arp_reply > 20) {
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
			tmp = 1;															//R·mec
			pom = 0;															//Index pola arr[pom]
			count = 0;															//Komunik·cia
			while (pcap_next_ex(f, &header, &pktdata) > 0) {
				if (tmp == arr[pom] && count < 20) {
					if (count % 2 == 0) {
						i++;													//»Ìslo komunik·cie
						flag = 0;
						printf("Komunikacia c: %d\n", i);
						Print_info(header, pktdata, first, arr, pom,flag);
						pom++;
						count++;
					}
					else {
						if (pktdata[akt->arp->operation] == akt->arp->echo[0].num) {
							flag = 0;
							Print_info(header, pktdata, first, arr, pom,flag);		//ZobrazÌ inform·cie o danej komunik·cii
							pom++;													//Sl˙ûi na posunutie pozÌcie v poli o +1 dopredu
						}
						else
						{
							//ARP reply only => flag == 1 (V˝pis reply namiesto ????)
							flag = 1;
							Print_info(header, pktdata, first, arr, pom,flag);
							pom++;
							count++;											////Sl˙ûi na urËenie ËÌsla komunik·cie
						}
					}
				}
				tmp++;
			}
		}

		free(arr);																//Uvoænenie alokovanÈho poæa
		arr = NULL;

	}
	else
	{
		//V subore *.pcap nie s˙ ûiadne protokoly ARP
		return;
	}
}


//ZobrazÌ z·kladnÈ inform·cie o programe a kæ˙ËovÈ slov·
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
	printf("j: Vypis pre DNS komunikaciu UDP\n");
	printf("k: Koniec programu\n");
}

void Dns_udp(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first) {
		int i, position, prot_pos, tmp = 0, pom = 0;
		int delimiter, delimiter2;
		Protocol *akt = first;
		int def_port = 0;							//port podæa ktorÈho budeme sledovaù cel˙ ftp komunik·ciu

													//nastavenie pozÌcie na 12 B (zaËiatok Ipv4)
		position = akt->dest + akt->src;//12. B
		prot_pos = akt->ip->prot_pos;
		delimiter = akt->ip->d_ip;

		//Prechadzanie paketmi a urËenie UDP(69-TFTP)
		while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
			tmp++;
			//Zistenie Ëi sa jedn· o IPv4 (0800) && IPv4
			if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

				//Protokol HTTP sa nach·dza na na relaËnej vrtsve protokolu - UDP(17) (x11)
				if (pktdata[prot_pos] == akt->ip->udp->udp_value) {

					//Hodnota cieloveho portu musÌ byù 53(domain) Dst port(pozicia druha tj(36+1)==37
					if (pktdata[akt->ip->udp->d_port + 1] == akt->ip->udp->ports[1].num ||
						((pktdata[akt->ip->udp->s_port] * 256 + pktdata[akt->ip->udp->s_port + 1]) == def_port) ||
						((pktdata[akt->ip->udp->d_port] * 256 + pktdata[akt->ip->udp->d_port + 1]) == def_port)) {

						printf("Ramec: %d\n", tmp);
						printf("Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
						printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
						printf("%s\n", akt->name);

						//def port podla ktorÈho src portu budeme sledovaù celu komunik·ciu(tftp server ma rozne portu ale rovnanke dst porty)
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
						/*		//Dorobiù selekciu 4 posledn˝ch bitov!!!
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
	char path[] = "C:\\Users\\Pavol GrofËÌk\\Documents\\Visual Studio 2017\\Projects\\Winpcap\\Winpcap\\eth-8.pcap";
	int c, count = 0;													//Ud·va poradovÈ ËÌslo r·mca ,poËet vöetk˝ch r·mcov nach·dzaj˙cich sa v s˙bore

	pcap_t *f = NULL;													//SmernÌk na sp·jan˝ zoznam packetov zo s˙boru
	const u_char *pktdata = NULL;
	struct pcap_pkthdr *header = NULL;

	FILE *r = NULL;
	Protocol *first = NULL;


	//Otvorenie s˙borov na anal˝zu
	if ((f = (pcap_open_offline(path, errbuff))) == NULL ||
		(r = fopen("Linkframe.txt", "r")) == NULL) {

		//Ak nastane chyba otvorenia s˙borov, program sa ukonËÌ
		printf("Subor sa nepodarilo otvorit\n");
		printf("%s\n", errbuff);
		return -1;
	}
	else
	{

		time_t t = time(NULL);
		struct tm *tm = localtime(&t);
		char s[64];

	
		printf("Vitajte: ");
		strftime(s, sizeof(s), "%c", tm);
		printf("%s\n\n", s);
		tm = NULL;
		//Zobrazenie domovskej obrazovky
		Intro();
		//NaËÌtanie protokolov a inform·ciÌ do sp·janÈho zoznamu
		nacitaj(&first, r);

	
		while ((c = getchar()) != 'k') {

			switch (c) {
				//Bod c. 1
			case '1':Point_1(f, header, pktdata, &count, first),										//Oöetriù len pre ipv4 pozor na IIEE 802.3 len pre Ethernet II, porobiù bod a do f cez jednu funkciu
				pcap_close(f),
				(f = (pcap_open_offline(path, errbuff))),
				Vypis_ip(f, first, header, pktdata, count, path);
				break;

			case 'a':Print_Protocol(f, header, pktdata, count, first,"http",path); break;				//V˝pis pre HTTP
			case 'b':Print_Protocol(f, header, pktdata, count, first,"https",path); break;				//V˝pis pre HTTPS
			case 'c':Print_Protocol(f, header, pktdata, count, first,"telnet",path); break;				//V˝pis pre TELNET
			case 'd':Print_Protocol(f, header, pktdata, count, first,"ssh",path); break;				//V˝pis pre SSH
			case 'e':Print_Protocol(f, header, pktdata, count, first,"ftpc",path); break;				//V˝pis pre FTP-Control
			case 'f':Print_Protocol(f, header, pktdata, count, first,"ftpd",path); break;				//V˝pis pre FTP-Data
			case 'g':Vypis_TFTP(f, header, pktdata, first,path); break;									//V˝pis pre TFTP
			case 'h':Vypis_ICMP(f, header, pktdata, first,path); break;									//V˝pis pre ICMP
			case 'i':Vypis_Arp(f, header, pktdata, count, first, path); break;							//V˝pis pre ARP 
			case 'j':Dns_udp(f, header, pktdata, first); break;											//V˝pis DND pre UDP
			}

			f = (pcap_open_offline(path, errbuff));														//Rewind pcap_t *f
		}

		pcap_close(f);

		if (fclose(r) == EOF) {
			printf("Subor sa nepodarilo zatvorit\n");
		}

		//Vr·tenie alokovanej pamate OS
		delete_list(first);
		free(pktdata, header);
		first = NULL;
		return 0;
	}
}