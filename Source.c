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
	char name[15];
}Pairs;

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
	Pairs ports[6];		//Hodnota portu + n�zov
}Tcp;

//�trukt�ra pre IP
typedef struct ip {
	int name_p;			//Verzia 4/6
	char name[5];		//IP
	int s_ip;			//Src ip
	int d_ip;			//Dst ip
	int len;			//Ve�kos� Ip adresy(Bytes)
	Tcp tcp[1];			//Vnoren� protokol TCP
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
	int c;

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

		}

		//na��tanie TCP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->tcp->name);
			//printf("tcp name: %s\n", (*first)->ip->tcp->name);		//vypis IP nazov
			fscanf(f, "%d", &(*first)->ip->tcp->s_port);
			fscanf(f, "%d", &(*first)->ip->tcp->d_port);
			fscanf(f, "%d", &(*first)->ip->tcp->len_p);
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


		akt = (*first);
		//akt = akt->next;

		if (akt->next == NULL) {
			akt->next = (Protocol*)malloc(sizeof(Protocol));
			akt = akt->next;
			akt->next = NULL;
			//nacitanie konca riadku

			while ((c = getc(f)) != EOF) {
				ungetc(c, f);
				fscanf(f, "%s ", (akt)->name);
				printf("%s\n", (akt)->name);

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
			printf("%s\n", akt->name);
		}
		else
		{
			akt = akt->next;
			printf("%s -", akt->name);
			pom += akt->len;

			if (pkt_data[pom] == akt->arr[0]) {
				printf("Raw\n");
			}
			else if (pkt_data[pom] == akt->arr[1]) {
				printf("LLC/SNAP\n");
			}
			else
			{
				printf("LLC\n");
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

		//Odriakovanie
		printf("\n\n");
	}
	printf("Num %d\n", num);
	(*count) = num;
}


void Vypis_ip(pcap_t *f, Protocol *first, struct pcap_pkthdr *hdr, const u_char *pkt_data,int n) {

	Protocol *akt = first;
	int i, j = 0, max = 0,delimiter;
	char errbuff[20];
	int count = 0, frame, tmp = 0;

	int **arr = NULL;
	int *space = NULL;


	delimiter = akt->ip->s_ip + 4;

	if ((arr = (int**)malloc(n * sizeof(int*))) == NULL) {
		printf("Nedostatok pamate\n");
		return;
	}

	for (i = 0; i < 30; i++) {
		space = (int *)calloc(ARRAY_LEN*n,sizeof(int));
	}

	//nasmerujeme pole smernikov �vonz�kov
	for (i = 0; i < n; ++i) {
		printf("I je %d\n", i);
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
		arr[count - 1][1] = hdr->caplen;	//Hodnota po mediu

		tmp = 0;

	}

	frame= arr[0][0];		//ip adresa
	delimiter = arr[0][1];	//hodnota bajtov
	for (i = 1; i < n; i++) {
		if (arr[i][0] == frame) {			//def ip
			delimiter += arr[i][1];		//def max
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
	putchar('\n');

	//rewindovanie pcap_t (f)
	pcap_close(f);
	f = (pcap_open_offline("eth-8.pcap", errbuff));
	count = 0;
	j = 0;
	//Hranica IP
	max = akt->ip->len + akt->ip->s_ip;
	printf("Adresa uzla s najvacsim poctom odvysielanych bajtov:\n");

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

	//Dealokacia

	for (i = 0; i < n; i++) {
		arr[i] = NULL;
	}
	free(space);
	free(arr);
	arr = NULL;
	
	//Rewindovanie sp�janeho zoznamu na za�iatok
	pcap_close(f);
	f = (pcap_open_offline("eth-8.pcap", errbuff));

}


//Hlavn� funkcia main
int main(void) {

	char errbuff[PCAP_ERRBUF_SIZE];
	int c, count = 0;										//Ud�va poradov� ��slo r�mca ,po�et v�etk�ch r�mcov nach�dzaj�cich sa v s�bore
	pcap_t *f = NULL;										//Smern�k na sp�jan� zoznam packetov zo s�boru
	const u_char *pktdata = NULL;
	struct pcap_pkthdr *header = NULL;

	FILE *r = NULL;
	Protocol *first = NULL;


	//Otvorenie s�borov na anal�zu
	if ((f = (pcap_open_offline("eth-8.pcap", errbuff))) == NULL ||
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
				(f = (pcap_open_offline("eth-8.pcap", errbuff))),
				Vypis_ip(f, first, header, pktdata, count);
				break;

				//Bod 3 - a:i
			case 'a':printf("Hello world guys!\n"); break;
			}
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