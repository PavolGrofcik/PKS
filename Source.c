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
void bod_c_1(pcap_t *f, struct pcap_pkthdr *hdr, const u_char *pkt_data, int *count, Protocol *first, FILE *fw) {

	Protocol *akt = NULL;
	int i, pom, num = 0;

	akt = first;

	if (akt == NULL) {
		return;
	}
	/*Prech�dzanie s�borom a n�sledn� v�pis*/
	while ((pcap_next_ex(f, &hdr, &pkt_data)) > 0) {

		//Z�kladn� inform�cie o packete
		fprintf(fw, "Ramec :%d\n", (++num));
		fprintf(fw, "Dlzka ramca poskytnuteho pcap API: %d\n", hdr->caplen);
		fprintf(fw, "Dlzka ramca prenasaneho po mediu: %d\n", hdr->len < 60 ? 64 : hdr->len + 4);

		pom = akt->dest + akt->src;
		akt = first;

		//Ur�enie typu na Linkovej vrstve - Ethernet II vs IEEE 802.3
		if (pkt_data[pom] >= akt->arr[0] / 100) {
			fprintf(fw, "%s\n", akt->name);
		}
		else
		{
			akt = akt->next;

			fprintf(fw, "%s -", akt->name);
			pom += akt->len;

			if (pkt_data[pom] == akt->arr[0]) {
				fprintf(fw, "Raw\n");
			}
			else if (pkt_data[pom] == akt->arr[1]) {
				fprintf(fw, "LLC/SNAP\n");
			}
			else
			{
				fprintf(fw, "LLC\n");
			}
		}

		/*V�pis MAC adries*/
		fprintf(fw, "Zdrojova MAC adresa: ");
		for (i = akt->dest; i < akt->dest + akt->src; i++) {
			if (i == 11) {
				fprintf(fw, "%.2x\n", pkt_data[i]);
				break;
			}
			fprintf(fw, "%.2x ", pkt_data[i]);
		}

		fprintf(fw, "Cielova MAC adresa: ");
		for (i = 0; i < akt->dest; i++) {
			if (i == 5) {
				fprintf(fw, "%.2x\n", pkt_data[i]);
				break;
			}
			fprintf(fw, "%.2x ", pkt_data[i]);

		}

		/*Vypis cel�ho packetu*/
		for (i = 1; i <= hdr->caplen; i++) {
			fprintf(fw, "%.2x ", pkt_data[i - 1]);

			if (i % LINE_LEN == 8) {
				fprintf(fw, "  ");
			}
			else if (i % LINE_LEN == 0) {
				fprintf(fw, "\n");
			}
		}

		/*Odriadkovanie obsahu*/
		fprintf(fw, "\n\n");
	}
	/*Po�et v�etk�ch r�mcov v s�bore*/
	(*count) = num;
}

//Funkcia vyp�e v�etky IP adresy uzlov a najv��iu s po�tom odoslan�ch Bajtov
void Vypis_ip(pcap_t *f, Protocol *first, struct pcap_pkthdr *hdr, const u_char *pkt_data, int n, char path[],FILE *fw) {

	Protocol *akt = first;
	int i, j = 0, max = 0, delimiter;
	char errbuff[20];
	int count = 0, frame, tmp = 0;
	int arr_count = 0, pom = 0;

	int **arr = NULL;
	int *space = NULL;

	delimiter = akt->ip->s_ip + akt->ip->len;

	/*H�adanie IPv4 protokolov*/
	while (pcap_next_ex(f, &hdr, &pkt_data) > 0) {
		/*Overenie IPv4(0x800)*/
		if ((pkt_data[akt->src + akt->dest] * 256 + pkt_data[akt->src + akt->dest + 1])
			== 2048) {
			arr_count++;
		}
	}
	/*Rewind pcap_t */
	f = pcap_open_offline(path, errbuff);

	/*Alok�cia 2D po�a pre Ip adresu a ve�kos�*/
	if ((arr = (int**)malloc(arr_count * sizeof(int*))) == NULL) {
		printf("Nedostatok pamate\n");
		return;
	}

	space = (int *)calloc(ARRAY_LEN*arr_count, sizeof(int));
	
	/*Nasmerovanie po�a smernikov*/
	for (i = 0; i < arr_count; ++i) {
		arr[i] = space + i*ARRAY_LEN;
	}

	fprintf(fw, "IP adresy vysielajucich uzlov:\n");

	/*Rie�ime len pre IPv4 adresy*/
	while ((pcap_next_ex(f, &hdr, &pkt_data)) > 0) {
		count++;

		/*Ethernet II - IPv4*/
		if ((pkt_data[akt->src + akt->dest] * 256 + pkt_data[akt->src + akt->dest + 1])
			== 2048) {
			/*V�pis IP adries*/
			for (i = akt->ip->s_ip; i < delimiter; i++) {
				if (i == (delimiter - 1)) {
					tmp += pkt_data[i];
					fprintf(fw, "%d\n", pkt_data[i]);
					break;
				}
				tmp += pkt_data[i];
				fprintf(fw, "%d. ", pkt_data[i]);
			}

			//Priradenie IP s velkostou
			arr[pom][0] = tmp;			//IP adresa
			arr[pom][1] = hdr->caplen;	//Hodnota B po mediu

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

	/*Odriadkovanie pre �itate�nos�*/
	fputc('\n', fw);

	/*Rewind pcap_t f*/
	pcap_close(f);
	f = (pcap_open_offline(path, errbuff));
	count = 0;

	max = akt->ip->len + akt->ip->s_ip;
	fprintf(fw, "Adresa uzla s najvacsim poctom odvysielanych bajtov:\n");

	/*Zistenie danej adresy s najv���m po�tom Bajtov*/
	while ((pcap_next_ex(f, &hdr, &pkt_data)) > 0) {


		for (i = akt->ip->s_ip; i < max; i++) {
			count += pkt_data[i];
		}
		if (count == frame) {

			/*V�pis adresy s najv���m po�tom Bajtov*/
			for (i = akt->ip->s_ip; i < max; i++) {
				if (i == (max - 1)) {
					fprintf(fw, "%d", pkt_data[i]);
					fprintf(fw, "\t %d Bajtov\n", delimiter);
					break;
				}
				fprintf(fw, "%d. ", pkt_data[i]);
			}
			break;
		}
		count = 0;
	}
	/*Dealok�cia po�a*/
	for (i = 0; i < arr_count; i++) {
		arr[i] = NULL;
	}
	free(space);
	free(arr);
	arr = NULL;
	space = NULL;
}

//Funkcia vyp�e jednotliv� protokoly
void vypis(Protocol *first, struct pcap_pkthdr *header, const u_char *pktdata, int frame,FILE *fw) {
	int i, pom, delimiter, delimiter2;
	Protocol *akt = first;

	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;
	/*Z�kladn� inform�cie o pakete*/
	fprintf(fw, "Ramec: %d\n", frame);
	fprintf(fw, "Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
	fprintf(fw, "Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
	fprintf(fw, "%s\n", akt->name);

	/*V�pis MAC adries*/
	fprintf(fw, "Zdrojova MAC adresa: ");
	for (i = akt->dest; i < akt->dest + akt->src; i++) {
		if (i == 11) {
			fprintf(fw, "%.2x\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%.2x ", pktdata[i]);
	}

	fprintf(fw, "Cielova MAC adresa: ");
	for (i = 0; i < akt->dest; i++) {
		if (i == 5) {
			fprintf(fw, "%.2x\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%.2x ", pktdata[i]);
	}

	/*IPv4*/
	fprintf(fw, "%s\n", akt->ip->name);

	fprintf(fw, "Zdrojova IP adresa: ");
	for (i = akt->ip->s_ip; i < delimiter; i++) {
		if (i == delimiter - 1) {
			fprintf(fw, "%d\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%d. ", pktdata[i]);
	}

	fprintf(fw, "Cielova IP adresa: ");
	for (i = delimiter; i < delimiter + akt->ip->len; i++) {
		if (i == (delimiter + akt->ip->len - 1)) {
			fprintf(fw, "%d\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%d. ", pktdata[i]);
	}

	/*TCP name*/
	fprintf(fw, "%s\n", akt->ip->tcp->name);

	/*Porty*/
	pom = 0;

	fprintf(fw, "Zdrojovy port: ");
	for (i = akt->ip->tcp->s_port; i < delimiter2; i++) {
		if (i == akt->ip->tcp->s_port) {
			pom = pktdata[i] * 256;
		}
		else
		{
			pom += pktdata[i];
		}
	}
	fprintf(fw, "%d\n", pom);

	fprintf(fw, "Cielovy port: ");
	for (i = delimiter2; i < delimiter2 + 2; i++) {
		if (i == akt->ip->tcp->d_port) {
			pom = pktdata[i] * 256;
		}
		else
		{
			pom += pktdata[i];
		}
	}
	fprintf(fw, "%d\n", pom);

	/*V�pis obsahu paketu*/
	for (i = 1; i <= header->caplen; i++) {
		fprintf(fw, "%.2x ", pktdata[i - 1]);

		if (i % LINE_LEN == 8) {
			fprintf(fw, "  ");
		}
		else if (i % LINE_LEN == 0) {
			fprintf(fw, "\n");
		}
	}
	fprintf(fw, "%\n\n");
	akt = NULL;
}


//V�pis pre  komunik�cie
void Print_Protocol(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, int count, Protocol *first, char s[],char path[],FILE *fw) {

	int i, position, prot_pos, tmp =0, n, k = 11;
	int delimiter, delimiter2;
	int prot_val;
	char errbuff[10];
	int *arr = NULL, *more = NULL;
	int flag, arrpos = 0;
	Protocol *akt = first;

	position = akt->dest + akt->src;
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;
	delimiter2 = akt->ip->tcp->d_port;

	if (!strcmp("http", s)) {
		prot_val = akt->ip->tcp->ports[4].num;
		fprintf(fw, "HTTP\n");
	}
	else if (!strcmp("https", s)) {
		prot_val = akt->ip->tcp->ports[5].num;
		fprintf(fw, "HTTPS\n");
	}
	else if (!strcmp("ftpc", s)) {
		prot_val = akt->ip->tcp->ports[1].num;
		fprintf(fw, "FTP - Control\n");
	}
	else if (!strcmp("ftpd", s)) {
		prot_val = akt->ip->tcp->ports[0].num;
		fprintf(fw, "FTP - Data\n");
	}
	else if (!strcmp("ssh", s)) {
		prot_val = akt->ip->tcp->ports[2].num;
		fprintf(fw, "SSH\n");
	}
	else if (!strcmp("telnet", s)) {
		prot_val = akt->ip->tcp->ports[3].num;
		fprintf(fw, "TELNET\n");
	}

	arr = (int *)malloc(sizeof(int));
	flag = n = arrpos = 0;
	//Prejdenie zoznamu a vyhladanie po�tu danej komunik�cie
	while (pcap_next_ex(f, &header, &pktdata) > 0) {
		flag++;
		if ((pktdata[akt->ip->tcp->d_port + 1] + pktdata[akt->ip->tcp->d_port] * 256) == prot_val ||
			(pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256) == prot_val) {
			
			//ner�tam tu zvy�ne porty ako podla wiresharku
			arr[n] = flag;												//Hodnota r�mca - t.j ��slo
			n++;
			more = realloc(arr, (n+1)*sizeof(int));						//Po�et prvkov po�a je v�dy o jedna v��� treba �s� o -2 poz�cie
			arr = more;
		}
	}
	//printf("Pocet n je :%d\n", n);									//Kontroln� v�pis

	f = pcap_open_offline(path, errbuff);
	tmp = flag = 0;
	if (n + 1 >= 20) {													//Po�et komunik�cii je viac ne� 20

		while ((pcap_next_ex(f, &header, &pktdata)) > 0) {
			tmp++;
			if (arr[arrpos] == tmp && flag < 10) {						//V�pis prv�ch 10
				arrpos++;												//Poz�cia v poli
				flag++;													//Pr�znak
				vypis(first, header, pktdata, tmp,fw);
			}
			else if(arr[n-k+1] == tmp && k>1 )
			{
				k--;
				vypis(first, header, pktdata, tmp,fw);
			}
		}
	}
	//Po�et je men�� ne� 20
	else
	{
		//Prechadzanie paketmi a ur�enie protokolu
		while ((pcap_next_ex(f, &header, &pktdata)) > 0) {

			tmp++;														//��slo r�mca
			//Zistenie �i sa jedn� o IPv4 (0800) && IPv4
			if (akt->arr[1] == (pktdata[position] * 100 + pktdata[position + 1]) && pktdata[akt->ip->name_p] / 10 == 6) {

				//Protokol  sa nach�dza na na rela�nej vrtsve podprotokolu - TCP(06)
				if (pktdata[prot_pos] == akt->ip->tcp->tcp_value) {

					//Hodnoty cieloveho portu
					if ((pktdata[akt->ip->tcp->d_port + 1] + pktdata[akt->ip->tcp->d_port] * 256) == prot_val ||
						(pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256) == prot_val) {
						vypis(first, header, pktdata, tmp,fw);
					}
				}
			}
		}
	}
	/*Dealokovanie po�a*/
	free(arr);
	fprintf(fw, "******\n");
}

//Funkcia vyp�e TFTP komunik�cie
void vypis_tftp(Protocol *first, struct pcap_pkthdr *header, const u_char *pktdata, int frame, FILE *fw) {
	int i, pom, delimiter;
	Protocol *akt = first;

	delimiter = akt->ip->d_ip;

	fprintf(fw, "Ramec: %d\n", frame);
	fprintf(fw, "Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
	fprintf(fw, "Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
	fprintf(fw, "%s\n", akt->name);

	fprintf(fw, "Zdrojova MAC adresa: ");
	for (i = akt->dest; i < akt->dest + akt->src; i++) {
		if (i == 11) {
			fprintf(fw, "%.2x\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%.2x ", pktdata[i]);
	}

	fprintf(fw, "Cielova MAC adresa: ");
	for (i = 0; i < akt->dest; i++) {
		if (i == 5) {
			fprintf(fw, "%.2x\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%.2x ", pktdata[i]);
	}

	/*IPv4*/
	fprintf(fw, "%s\n", akt->ip->name);
	/*IP adresy*/
	fprintf(fw, "Zdrojova IP adresa: ");
	for (i = akt->ip->s_ip; i < delimiter; i++) {
		if (i == delimiter - 1) {
			fprintf(fw, "%d\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%d. ", pktdata[i]);
	}

	fprintf(fw, "Cielova IP adresa: ");
	for (i = delimiter; i < delimiter + akt->ip->len; i++) {
		if (i == (delimiter + akt->ip->len - 1)) {
			fprintf(fw, "%d\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%d. ", pktdata[i]);
	}

	/*UDP*/
	fprintf(fw, "%s\n", akt->ip->udp->name);
	
	/*Porty*/
	pom = 0;
	fprintf(fw, "Zdrojovy port: ");
	for (i = akt->ip->udp->s_port; i < akt->ip->udp->d_port; i++) {
		if (i == akt->ip->tcp->s_port) {
			pom = pktdata[i] * 256;
		}
		else
		{
			pom += pktdata[i];
		}
	}
	fprintf(fw, "%d\n", pom);

	fprintf(fw, "Cielovy port: ");
	for (i = akt->ip->udp->d_port; i < akt->ip->udp->d_port + 2; i++) {
		if (i == akt->ip->tcp->d_port) {
			pom = pktdata[i] * 256;
		}
		else
		{
			pom += pktdata[i];
		}
	}
	fprintf(fw, "%d\n", pom);

	/*Vypis Bytov(packetu)*/
	for (i = 1; i <= header->caplen; i++) {

		fprintf(fw, "%.2x ", pktdata[i - 1]);

		if (i % LINE_LEN == 8) {
			fprintf(fw, "  ");
		}
		else if (i % LINE_LEN == 0) {
			fprintf(fw, "\n");
		}
	}
	/*Odriakovanie*/
	fprintf(fw, "\n\n");
	akt = NULL;
}

//V�pis pre TFTP komunik�ciu
void Vypis_TFTP(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first, char path[], FILE *fw) {
	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter;
	Protocol *akt = first;
	int def_port = 69;																					//Port pod�a ktor�ho budeme sledova� cel� ftp komunik�ciu
	int *arr = NULL, *more = NULL;
	int flag, n, arrpos, k = 11;
	char errbuff[10];

	//Nastavenie poz�cie na 12 B (za�iatok Ipv4)
	position = akt->dest + akt->src;//12. B
	prot_pos = akt->ip->prot_pos;
	delimiter = akt->ip->d_ip;

	arr = (int *)malloc(sizeof(int));
	flag = n = arrpos = 0;

	while (pcap_next_ex(f, &header, &pktdata) > 0) {
		flag++;
		if ((pktdata[akt->ip->tcp->d_port + 1] + pktdata[akt->ip->tcp->d_port] * 256) == def_port ||
			(pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256) == def_port) {

			def_port = pktdata[akt->ip->tcp->s_port + 1] + pktdata[akt->ip->tcp->s_port] * 256;			
			arr[n] = flag;																				//Hodnota r�mca - t.j ��slo
			n++;
			more = realloc(arr, (n + 1) * sizeof(int));													//Po�et prvkov po�a je v�dy o jedna v��� treba �s� o -2 poz�cie
			arr = more;
		}
	}
	fprintf(fw,"TFTP\n");

	flag = 0;
	f = pcap_open_offline(path, errbuff);
	//Prechadzanie paketmi a ur�enie UDP(69-TFTP)
	if (n + 1 >= 20) {
		while ((pcap_next_ex(f, &header, &pktdata)) > 0) {
			tmp++;

			if (arr[arrpos] == tmp && flag < 10) {
				flag++;
				arrpos++;
				vypis_tftp(first, header, pktdata, tmp,fw);
			}
			else if (arr[n - k] == tmp && k > 1) {
				k--;
				vypis_tftp(first, header, pktdata, tmp,fw);
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
				vypis_tftp(first, header, pktdata, tmp,fw);
			}
		}
	}
	fprintf(fw, "******\n");
	/*Dealok�cia*/
	free(arr);
	arr = NULL;
	more = NULL;
}

void Vypis_pre_icmp(Protocol *first, struct pcap_pkthdr *header, const u_char *pktdata, int frame,FILE *fw) {

	int i, delimiter;
	Protocol *akt = first;

	delimiter = akt->ip->d_ip;

	for (i = 0; i < 6; i++) {
		if (pktdata[akt->ip->icmp->type] == akt->ip->icmp->code[i].num ||
			pktdata[70] == akt->ip->icmp->code[i].num) {

			fprintf(fw,"Ramec: %d\n", frame);
			fprintf(fw, "Dlzka ramca poskytnuta pcap API: %d\n", header->caplen);
			fprintf(fw, "Dlzka ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
			fprintf(fw, "%s\n", akt->name);

			/*MAC adresy*/
			fprintf(fw, "Zdrojova MAC adresa: ");
			for (i = akt->dest; i < akt->dest + akt->src; i++) {
				if (i == 11) {
					fprintf(fw, "%.2x\n", pktdata[i]);
					break;
				}
				fprintf(fw, "%.2x ", pktdata[i]);
			}

			fprintf(fw, "Cielova MAC adresa: ");
			for (i = 0; i < akt->dest; i++) {
				if (i == 5) {
					fprintf(fw, "%.2x\n", pktdata[i]);
					break;
				}
				fprintf(fw, "%.2x ", pktdata[i]);
			}

			//IPv4
			fprintf(fw, "%s\n", akt->ip->name);
			//Src IP
			fprintf(fw, "Zdrojova IP adresa: ");
			for (i = akt->ip->s_ip; i < delimiter; i++) {
				if (i == delimiter - 1) {
					fprintf(fw, "%d\n", pktdata[i]);
					break;
				}
				fprintf(fw, "%d. ", pktdata[i]);
			}
			//Dst IP
			fprintf(fw, "Cielova IP adresa: ");
			for (i = delimiter; i < delimiter + akt->ip->len; i++) {
				if (i == (delimiter + akt->ip->len - 1)) {
					fprintf(fw, "%d\n", pktdata[i]);
					break;
				}
				fprintf(fw, "%d. ", pktdata[i]);
			}

			//ICMP name
			fprintf(fw, "%s\n", akt->ip->icmp->name);

			//Code -operation Echo, Time exceeded Reply .... decimalna s�stava(bajty packetu)
			switch (pktdata[akt->ip->icmp->type]) {
			case 0: fprintf(fw, "%s\n", akt->ip->icmp->code[0].name); break;
			case 3: fprintf(fw, "%s\n", akt->ip->icmp->code[1].name); break;
			case 5: fprintf(fw, "%s\n", akt->ip->icmp->code[2].name); break;
			case 8: fprintf(fw, "%s\n", akt->ip->icmp->code[3].name); break;
			case 11: fprintf(fw, "%s\n", akt->ip->icmp->code[4].name); break;
			case 30: fprintf(fw, "%s\n", akt->ip->icmp->code[5].name); break;
			}
			//V�pis packetu
			for (i = 1; i <= header->caplen; i++) {

				fprintf(fw, "%.2x ", pktdata[i - 1]);

				if (i % LINE_LEN == 8) {
					fprintf(fw, "  ");
				}
				else if (i % LINE_LEN == 0) {
					fprintf(fw, "\n");
				}
			}
			fprintf(fw, "\n\n");
			//Zbyto�ne u� necyklujeme ke� sme u� vyp�sali
			break;
		}
	}
	akt = NULL;
}

//V�pis pre komunik�ciu ICMP
void Vypis_ICMP(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first, char path[], FILE *fw) {

	int i, position, prot_pos, tmp = 0, pom = 0;
	int delimiter, delimiter2,
		flag, n, arrpos, k;
	int *arr = NULL, *more = NULL;
	char errbuff[10];
	Protocol *akt = first;

	/*Nastavenie poz�ci� na ur�en� miesto*/
	position = akt->dest + akt->src;		//12. B
	prot_pos = akt->ip->prot_pos;			//14. B
	delimiter = akt->ip->d_ip;				//30. B
	fprintf(fw, "ICMP\n");

	arr = (int *)malloc(sizeof(int));
	flag = n = arrpos = 0;

	/*Ur�enie po�tu protokolov ICMP*/
	while (pcap_next_ex(f, &header, &pktdata) > 0) {
		tmp++;
		if (pktdata[akt->ip->prot_pos] == akt->ip->icmp->icmp_value) {
			arr[n] = tmp;
			n++;
			more = realloc(arr, (n + 1) * sizeof(int));
			arr = more;
		}
	}
	/*Rewind pcap_t *f*/
	f = pcap_open_offline(path, errbuff);
	/*V�pis protokolov*/
	flag = pom = 0;
	k = 10;
	tmp = 0;
	if ((n + 1) >= 20) {
		while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
			tmp++;
			if (arr[flag] == tmp && pom < 10) {
				pom++;
				flag++;
				Vypis_pre_icmp(akt, header, pktdata, tmp,fw);
			}
			else if (arr[n - k] == tmp && k > 0) {
				k--;
				Vypis_pre_icmp(akt, header, pktdata, tmp,fw);
			}
		}
	}
	else {
		while ((pcap_next_ex(f, &header, &pktdata)) >= 0) {
			tmp++;
			if (arr[flag] == tmp) {
				flag++;
				Vypis_pre_icmp(akt, header, pktdata, tmp, fw);
			}
		}
	}
	/*Dealok�cia*/
	free(arr);
	arr = NULL;
	more = NULL;
	fprintf(fw, "******\n");
}

void Print_info(struct pcap_pkthdr *header, const u_char *pktdata, Protocol *first, int arr[], int pom,int flag, FILE *fw) {

	int i, count, delimiter;
	Protocol *akt = first;

	delimiter = akt->arp->dst_ip + akt->arp->ip_len;						//Hranica dest IP(iter�cia)

	fprintf(fw, "%s - %s, ", akt->arp->name, pktdata[akt->arp->operation] == 1 ? "Request" : "Reply");

	fprintf(fw, "IP adresa: ");													//Dst IP adresa
	for (i = akt->arp->dst_ip; i < delimiter; i++) {
		if (i == delimiter - 1) {
			fprintf(fw, "%d ,", pktdata[i]);
			break;
		}
		fprintf(fw, "%d. ", pktdata[i]);
	}
	if (flag == 0) {
		fprintf(fw, "MAC adresa: ???\n");
	}
	else
	{
		fprintf(fw, "MAC adresa: ");
		//V�pis n�jdenej MAC adresy
		for (i = akt->dest; i < akt->dest + akt->src; i++) {
			if (i == 11) {
				fprintf(fw, "%.2x\n", pktdata[i]);
				break;
			}
			fprintf(fw, "%.2x ", pktdata[i]);
		}
	}
	
	fprintf(fw, "Zdrojova IP adresa: ");											//Src IP	
	for (i = akt->arp->src_ip; i < akt->arp->dst_mac; i++) {
		if (i == akt->arp->dst_mac - 1) {
			fprintf(fw, "%d ,", pktdata[i]);
			break;
		}
		fprintf(fw, "%d. ", pktdata[i]);
	}

	fprintf(fw, "Cielova IP: ");													//Dst Ip
	for (i = akt->arp->dst_ip; i < delimiter; i++) {
		if (i == delimiter - 1) {
			fprintf(fw, "%d\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%d. ", pktdata[i]);
	}
	fprintf(fw, "Ramec: %d\n", arr[pom]);										//Poz�cia v poli(r�mec)
	fprintf(fw, "Dlzka ramca poskytnuteho pcap API: %d\n", header->caplen);
	fprintf(fw, "Dlza ramca prenasaneho po mediu: %d\n", header->len < 60 ? 64 : header->len + 4);
	fprintf(fw, "%s\n", akt->name);												//Ethernet II

																			//V�pis MAC adries
	fprintf(fw, "Zdrojova MAC adresa: ");
	for (i = akt->dest; i < akt->dest + akt->src; i++) {
		if (i == 11) {
			fprintf(fw, "%.2x\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%.2x ", pktdata[i]);
	}

	fprintf(fw, "Cielova MAC adresa: ");
	for (i = akt->arp->dst_mac; i < akt->arp->dst_ip; i++) {
		if (i == akt->arp->dst_ip - 1) {
			fprintf(fw, "%.2x\n", pktdata[i]);
			break;
		}
		fprintf(fw, "%.2x ", pktdata[i]);
	}
	//Vypis cel�ho obsahu packetu
	for (i = 1; i <= header->caplen; i++) {

		fprintf(fw, "%.2x ", pktdata[i - 1]);

		if (i % LINE_LEN == 8) {
			fprintf(fw, "  ");
		}
		else if (i % LINE_LEN == 0) {
			fprintf(fw, "\n");
		}
	}
	fprintf(fw, "\n\n");															//Odriadkovanie
	return;
}

//V�pis pre ARP komunik�ciu
void Vypis_Arp(pcap_t *f, struct pcap_pkthdr *header, const u_char *pktdata, int frames, Protocol *first, char path[], FILE *fw) {

	int Arp_count, Arp_position;
	int *arr = NULL;
	int tmp, pom, i, delimiter, count, comm;	//pomocn� premenn�
	int j, pom2, count2, comm2;
	int flag, arp_reply = 0;									//Pr�znak potrebn� k v�pisu
	char errbuff[10];
	Protocol *akt = first;

	Arp_count = 0;
	Arp_position = akt->dest + akt->src;

	fprintf(fw, "ARP\n");
	while (pcap_next_ex(f, &header, &pktdata) > 0) {

		//Arp protocol je v Ethernet type: 0806
		if (pktdata[Arp_position] * 100 + pktdata[Arp_position + 1] == akt->arr[2] ) {																					//po��tame ko�ko je reply(ak viac ako 20 v poriadku)
			Arp_count++;
			if (pktdata[akt->arp->operation] == akt->arp->echo[1].num) {
				arp_reply++;
			}
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

		//Napln�me pole 
		tmp = 0;
		pom = 0;
		while (pcap_next_ex(f, &header, &pktdata) > 0) {
			tmp++;
			if (pktdata[Arp_position] * 100 + pktdata[Arp_position + 1] == akt->arr[2]) {			//O�etrenie �e sa jedn� o r�mec s ARP (806)
				//Zapamatanie �. r�mca
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
		delimiter = Arp_count - 20;			//Za�iatok poz�cie (posl 10.)
		comm2 = delimiter;
		//Po�et r�mcov je vy��� ne� 20 (req +rep =2)
		if (arp_reply > 20) {
			while (pcap_next_ex(f, &header, &pktdata) > 0) {
				tmp++;
				if (tmp == arr[pom] && i < 20) {
					if (count % 2 == 0) {
						flag = 0;
						comm++;
						fprintf(fw, "Komunikacia c: %d\n", comm);
						Print_info(header, pktdata, first, arr, pom,flag,fw);
						pom++;
						count++;
						i++;
					}
					else
					{
						flag = 0;
						Print_info(header, pktdata, first, arr, pom,flag,fw);
						pom++;
						count++;
						i++;
					}
				}
				else if (tmp == arr[delimiter] && j < 20) {


					if (count2 % 2 == 0) {
						comm2++;
						fprintf(fw, "Komunikacia c: %d\n", comm);
						Print_info(header, pktdata, first, arr, pom2,flag,fw);
						pom2++;
						count2++;
						j++;
					}
					else
					{
						Print_info(header, pktdata, first, arr, pom2,flag,fw);
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
			tmp = 1;																//R�mec
			pom = 0;																//Index pola arr[pom]
			count = 0;																//Komunik�cia
			while (pcap_next_ex(f, &header, &pktdata) > 0) {
				if (tmp == arr[pom] && count < 20) {
					if (count % 2 == 0) {
						i++;														//��slo komunik�cie
						flag = 0;	
						fprintf(fw, "Komunikacia c: %d\n", i);
						Print_info(header, pktdata, first, arr, pom,flag,fw);
						pom++;
						count++;
					}
					else {
						if (pktdata[akt->arp->operation] == akt->arp->echo[0].num) {
							flag = 0;
							Print_info(header, pktdata, first, arr, pom,flag,fw);		//Zobraz� inform�cie o danej komunik�cii
							pom++;													//Sl��i na posunutie poz�cie v poli o +1 dopredu
						}
						else
						{
							flag = 1;
							Print_info(header, pktdata, first, arr, pom,flag,fw);
							pom++;
							count++;												//Sl��i na ur�enie ��sla komunik�cie
						}
					}
				}
				tmp++;
			}
		}

		free(arr);																	//Uvo�nenie alokovan�ho po�a
		arr = NULL;

	}
	else
	{
		//V subore *.pcap nie s� �iadne protokoly ARP
		return;
	}
	fprintf(fw, "******\n");
}


//Zobraz� z�kladn� inform�cie o programe a k���ov� slov�
void uvodne_zobrazenie() {

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
	printf("j: Vypis pre DNS komunikacie UDP\n");
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
	char path[] = "C:\\Users\\Pavol Grof��k\\Documents\\Visual Studio 2017\\Projects\\Winpcap\\Winpcap\\eth-8.pcap";
	/*count sl��i na ur�enie po�tu r�mcov*/
	int c, count = 0;													

	pcap_t *f = NULL;
	const u_char *pktdata = NULL;
	struct pcap_pkthdr *header = NULL;

	FILE *r = NULL, *fw = NULL;
	Protocol *first = NULL;


	//Otvorenie s�borov na anal�zu
	if ((f = (pcap_open_offline(path, errbuff))) == NULL ||
		(r = fopen("Linkframe.txt", "r")) == NULL || 
		(fw = fopen("Out.txt", "w"))==NULL) {

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

		uvodne_zobrazenie();

		//Na��tanie protokolov a inform�ci� do sp�jan�ho zoznamu
		nacitaj(&first, r);
	
		while ((c = getchar()) != 'k') {

			switch (c) {
			case '1':fprintf(fw,"******\n"),
				bod_c_1(f, header, pktdata, &count, first, fw),												//V�pis bod �. 1
				pcap_close(f),
				(f = (pcap_open_offline(path, errbuff))),
				Vypis_ip(f, first, header, pktdata, count, path,fw);
				fprintf(fw, "******\n");
				break;

			case 'a':Print_Protocol(f, header, pktdata, count, first,"http",path,fw); break;				//V�pis pre HTTP
			case 'b':Print_Protocol(f, header, pktdata, count, first,"https",path,fw); break;				//V�pis pre HTTPS
			case 'c':Print_Protocol(f, header, pktdata, count, first,"telnet",path,fw); break;				//V�pis pre TELNET
			case 'd':Print_Protocol(f, header, pktdata, count, first,"ssh",path,fw); break;					//V�pis pre SSH
			case 'e':Print_Protocol(f, header, pktdata, count, first,"ftpc",path,fw); break;				//V�pis pre FTP-Control
			case 'f':Print_Protocol(f, header, pktdata, count, first,"ftpd",path,fw); break;				//V�pis pre FTP-Data
			case 'g':Vypis_TFTP(f, header, pktdata, first,path,fw); break;										//V�pis pre TFTP
			case 'h':Vypis_ICMP(f, header, pktdata, first,path,fw); break;										//V�pis pre ICMP
			case 'i':Vypis_Arp(f, header, pktdata, count, first, path,fw); break;								//V�pis pre ARP 
			case 'j':Dns_udp(f, header, pktdata, first); break;												//V�pis DND pre UDP
			}

			f = (pcap_open_offline(path, errbuff));															//Rewind pcap_t *f
		}

		pcap_close(f);

		if (fclose(r) == EOF || fclose(fw)==EOF) {
			printf("Jeden zo suborov sa nepodarilo zatvorit\n");
		}

		/*Dealokovanie zoznamu*/
		delete_list(first);
		free(pktdata);
		free(header);
		first = NULL;
		return 0;
	}
}