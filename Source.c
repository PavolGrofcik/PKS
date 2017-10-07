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

//Definovanie pre výpis riadku po 16 B
#define LINE_LEN 16 

//Štruktúra párov pre port + názov
typedef struct  pairs {
	int num;
	char name[15];
}Pairs;

//Štruktúra pre ARP
typedef struct arp {
	char name[4];		//ARP
	int operation;		//Pozícia - operation
	int len;			//Dlzka operacie
	Pairs echo[2];			//Echo - Reply/Request
}Arp;

//Štruktúra pre TCP
typedef struct tcp {
	char name[4];		//TCP
	int s_port;			//Src port
	int d_port;			//Dst port
	int len_p;			//Ve¾kos portov(Bytes)
	Pairs ports[6];		//Hodnota portu + názov
}Tcp;

//Štruktúra pre IP
typedef struct ip {
	int name_p;			//Verzia 4/6
	char name[5];		//IP
	int s_ip;			//Src ip
	int d_ip;			//Dst ip
	int len;			//Ve¾kos Ip adresy(Bytes)
	Tcp tcp[1];			//Vnorený protokol TCP
}IP;

//Definovanie vlastnej štruktury pre Ethernet a 802.3
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

//Naèítanie protokolov a špecifikácií zo súboru
void nacitaj(Protocol **first, FILE *f) {

	Protocol *akt = NULL,
		*pom = NULL;
	int c;

	if ((*first) == NULL) {

		//Alokácia pamati
		if ((*first = (Protocol*)malloc(sizeof(Protocol))) == NULL) {
			printf("Nedostatok pamate\n");
			return;
		}
		//Nasmerovanie smerníka do NULL
		(*first)->next = NULL;

		//nacítanie zo súboru
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
		//naèítanie potrebných údajov do subprotokolov pre IP/ARP
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

		//naèítanie IP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->name);
			fscanf(f, "%d", &(*first)->ip->name_p);
			fscanf(f, "%d", &(*first)->ip->s_ip);
			fscanf(f, "%d", &(*first)->ip->d_ip);
			fscanf(f, "%d", &(*first)->ip->len);

		}

		//naèítanie TCP
		while ((c = getc(f)) != '\n') {
			ungetc(c, f);
			fscanf(f, "%s", (*first)->ip->tcp->name);
			printf("tcp name: %s\n", (*first)->ip->tcp->name);		//vypis
			fscanf(f, "%d", &(*first)->ip->tcp->s_port);
			fscanf(f, "%d", &(*first)->ip->tcp->d_port);
			fscanf(f, "%d", &(*first)->ip->tcp->len_p);
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

//Pomocný výpis
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

//Zmazanie spájaného zoznamu
void delete(Protocol *f) {
	Protocol *akt;

	while (f) {
		akt = f;
		f = f->next;
		free(akt);
	}
}

//Funkcia slúžiaca na výpis k bodu è. 1
void Point_1(pcap_t *f, struct pcap_pkthdr *hdr, const u_char *pkt_data, int *count, Protocol *first) {

	//Pomocné premenné
	Protocol *akt = NULL;
	int i, pom;

	//nasmerovanie na zaèiatok
	akt = first;

	if (akt == NULL) {
		return;
	}
	else if ((*count) != 0) {
		(*count) = 0;
	}

	while ((pcap_next_ex(f, &hdr, &pkt_data)) >= 0) {

		//Základné informácie o packete
		printf("Ramec: %d\n", ++(*count));
		printf("Dlzka ramca poskytnuteho pcap API: %d\n", hdr->caplen);
		printf("Dlza ramca prenasaneho po mediu: %d\n", hdr->len < 60 ? 64 : hdr->len + 4);
		//nasmerovanie na zaèiatok Linked list-u
		pom = akt->dest + akt->src;	//12
		akt = first;

		//Urèenie typu na Linkovej vrstve
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


		//Výpis MAC adries
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




		//Vypis celého packetu
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

void vypis_ip(pcap_t *f, Protocol *first, struct pcap_pkthdr *hdr, const u_char *pkt_data) {

	Protocol *akt = first;
	int i, j = 0, max = 0, pom, delimiter;
	char errbuff[20];
	int count = 0, frame;

	pom = akt->ip->d_ip + akt->ip->len;
	delimiter = akt->ip->s_ip + 4;


	printf("IP adresy vysielajucich uzlov:\n");

	while ((pcap_next_ex(f, &hdr, &pkt_data)) >= 0) {
		count++;
		if (max < hdr->caplen) {
			max = hdr->caplen;
			frame = count;
		}
		for (i = akt->ip->s_ip; i < pom; i++) {
			if (i == delimiter) {
				printf("\n");
			}
			printf("%d. ", pkt_data[i]);
		}
		printf("\n....\n");

	}

	//rewindovanie f
	pcap_close(f);
	f = (pcap_open_offline("eth-8.pcap", errbuff));
	count = 0;

	printf("Adresa uzla s najvacsim poctom odvysielanych bajtov:\n");

	//najdi bug
	while ((pcap_next_ex(f, &hdr, &pkt_data)) >= 0) {
		count++;
		if (count == frame) {
			for (i = akt->ip->s_ip; i < delimiter; i++) {
				printf("%d. ", pkt_data[i]);
			}
			printf("%d Bajtov\n", max);
			putchar('\n');
		}
	}

}


//Hlavná funkcia main
int main(void) {

	char errbuff[PCAP_ERRBUF_SIZE];
	int c, count = 0;										//Udáva poradové èíslo rámca ,poèet všetkých rámcov nachádzajúcich sa v súbore
	pcap_t *f = NULL;										//Smerník na spájaný zoznam packetov zo súboru
	const u_char *pktdata = NULL;
	struct pcap_pkthdr *header = NULL;

	FILE *r = NULL;
	Protocol *first = NULL
		;



	if ((f = (pcap_open_offline("eth-8.pcap", errbuff))) == NULL ||
		(r = fopen("Linkframe.txt", "r")) == NULL) {

		//Ak nastane chyba otvorenia súborov, program sa ukonèí
		printf("Subor sa nepodarilo otvorit\n");
		printf("%s\n", errbuff);
		return -1;
	}
	else
	{
		//Naèítanie protokolov a informácií do spájaného zoznamu
		nacitaj(&first, r);


		//kontrolný výpis
		vypis_prot(first);
		while ((c = getchar()) != 'k') {

			switch (c) {
				//Bod c. 1
			case '1':Point_1(f, header, pktdata, &count, first), pcap_close(f),
				f = (pcap_open_offline("eth-8.pcap", errbuff)); vypis_ip(f, first, header, pktdata);
				break;
				//Bod 3 - a:i
			case 'a':printf("Hello world guys!\n");
			}

			//rewindovanie Packetov
			//pcap_close(f);
			//f = (pcap_open_offline("eth.8.pcap", errbuff));
		}

		//Po dokonèení je nutné súbory správne zavrie
		pcap_close(f);

		if (fclose(r) == EOF) {
			printf("Subor sa nepodarilo zatvorit\n");
		}

		//Vrátenie alokovanej pamate OS
		delete(first);
		free(pktdata, header);
	}

	return 0;
}