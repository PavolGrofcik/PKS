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

//Definovanie vlastnej štruktury
typedef struct prot {
	char name[11];		//nazov
	int dest;			//destination
	int src;			//source
	int len;			//type
	int arr[3];			//sub protokoly
	struct prot *next;	//iny ne na danej úrovni
	struct prot *sub;	//podprotokolo vyššej vrstvy

}Protocol;


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
		(*first)->next = NULL;
		(*first)->sub = NULL;

		//nacítanie zo súboru
		while ((c = getc(f)) != '\n' ) {
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
		akt = (*first);
		//akt = akt->next;

		if (akt->next == NULL) {
			akt->next = (Protocol*)malloc(sizeof(Protocol));
			akt = akt->next;
			akt->sub = NULL;
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

void delete(Protocol *f) {
	Protocol *akt;

	while (f) {
		akt = f;
		f = f->next;
		free(akt);
	}
}

void point_1(pcap_t *f, struct pcap_pkthdr *hdr, const u_char *pkt_data, int *count, Protocol *first) {

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

		printf("Ramec: %d\n", ++(*count));
		printf("Dlzka ramca poskytnuteho pcap API: %d\n", hdr->caplen);
		printf("Dlza ramca prenasaneho po mediu: %d\n", hdr->len < 60 ? 64 : hdr->len + 4);
		pom = akt->dest + akt->src;	//12

		if (pkt_data[pom] >= akt->arr[0]/100) {
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

		

		printf("Zdrojova MAC adresa: ");
		for (i = 0; i < akt->dest; i++) {
			if (i == 5) {
				printf("%.2x\n", pkt_data[i]);
				break;
			}
			printf("%.2x ", pkt_data[i]);
		}

		printf("Cielova MAC adresa: ");
		for (i = akt->dest; i < akt->dest + akt->src; i++) {
			if (i == 11) {
				printf("%.2x\n", pkt_data[i]);
				break;
			}
			printf("%.2x ", pkt_data[i]);
		}





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
	int c,count = 0;										//Udáva poradové èíslo rámca ,poèet všetkıch rámcov nachádzajúcich sa v súbore
	pcap_t *f = NULL;									//Smerník na spájanı zoznam
	const u_char *pktdata = NULL;
	struct pcap_pkthdr *header = NULL;

	FILE *r = NULL;
	Protocol *first = NULL
		;



	if ((f = (pcap_open_offline("newsample.pcap", errbuff))) == NULL ||
		(r = fopen("Linkframe.txt", "r")) == NULL) {

		//Ak nastane chyba otvorenia súborov, program sa ukonèí
		printf("Subor sa nepodarilo otvorit\n");
		printf("%s\n", errbuff);
		return -1;
	}
	else
	{
		//naèítanie protokolov do spájaného zoznamu
		nacitaj(&first, r);

		
		//kontrolnı vıpis
		vypis_prot(first);
		while((c=getchar())!='k'){

			switch (c) {
			case '1':point_1(f, header, pktdata, &count, first), pcap_close(f),
				f = (pcap_open_offline("newsample.pcap", errbuff)); break;
			case 'a':printf("Hello world guys!\n");
			}

		}
		
		//Po dokonèení je nutné súbory zavrie
		pcap_close(f);

		if (fclose(r) == EOF) {
			printf("Subor sa nepodarilo zatvorit\n");
		}

		delete(first);
	}

	return 0;
}