/*	Zadanie		PKS 1
*	Autor		Pavol GrofËÌk
*	D·tum		13.9.2018
*/


#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <pcap.h>



#define FILENAME "trace-20.pcap"				//N·zov analyzovanÈho pcap s˙boru
#define FILEOUTPUT "data.txt"				//N·zov v˝stupnÈho s˙boru pri presmerovanÌ 1> data.txt
#define PROTOCOLS "protocols.txt"		//N·zov zdrojovÈho s˙buru pre pozÌcie MAC,IP,Ports ... 

#define NAME_LEN	16
#define BUFF	512

FILE *fw = NULL;							//Glob·ln˝ pointer pre z·pis v˝stupu do s˙boru
FILE *fr = NULL;							//-||- pointer na ËÌtanie protocols.txt s˙boru
pcap_t *fpc = NULL;							//-||- pointer na ËÌtanie .pcap s˙boru
int Mode;									//MÛd pre v˝stup programu


//ätrukt˙ra pre ËÌslo protokola - status a jeho n·zov
typedef struct pairs {
	int number;
	char name[NAME_LEN];
}Pairs;

typedef struct datalink {
	char eth[NAME_LEN];
	char iee[NAME_LEN];

	int positions[3];			//PozÌcie MAC adresy,type/len
	int boundary;				//Hranica pre ETH II (0600 DEC)
	Pairs pairs[4];				//Hodnota:par e.g 0800 IPv4
}DataLink;

//Funkcia naËÌta jednotlivÈ protokoly zo s˙boru
void read_protocols(FILE **fr, DataLink *link) {

	char buff[BUFF];
	int c;

	if (*fr == NULL) {
		if ((*fr = fopen(PROTOCOLS, "r")) == NULL) {
			printf("Subor %s sa nepodarilo otvorit\n", PROTOCOLS);
			return;
		}
		
	}

	while (!feof(*fr)) {

		if ((c = getc(*fr)) == '#') {
			fgets(buff, BUFF, *fr);
		}
		else {

			ungetc(c, *fr);
			fgets(link->eth, 13, *fr);
			fgets(link->iee, 12, *fr);

			for (int i = 0; i < 3; i++) {
				fscanf(*fr, "%d", &link->positions[i]);
			}

			fscanf(*fr, "%d", &link->boundary);

			for (int i = 0; i < 4; i++) {
				fscanf(*fr, "%d", &link->pairs[i].number);
				fscanf(*fr, "%s", link->pairs[i].name);
			}
			break;
		}
	}
}

//Funkcia inicializuje potrebnÈ d·ta na analyzovanie vzoriek
int init(DataLink **link) {
	char errbuff[BUFF];

	printf("Zadajte mod  pre vystup\n");
	printf("0 - Konzola\t1 - Subor\n");
	scanf("%d", &Mode);

	if (Mode) {
		if ((fw = fopen(FILEOUTPUT, "w")) == NULL) {
			printf("Subor %s sa nepodarilo otvorit\n", FILENAME);
			return -1;
		}
	}

	*link = (DataLink*)malloc(sizeof(DataLink));		//Alokovanie pam‰te pre ötrukt˙ru DataLink

	read_protocols(&fr, *link);							//NaËÌtanie protokolov zo s˙boru PROTOCOLS
	
	return 1;
}

//Funkcia uvoænÌ alokovan˙ pam‰ù
void dealloc(DataLink *link) {
	free(link);
}

//Funkcia vypÌöe d·ta r·mcu
void print_pkt_data(u_char *pktdata, struct pcap_pkthdr *header) {
	if (Mode) {
		for (int i = 1; i < header->len + 1; i++) {
			fprintf(fw,"%.2x ", pktdata[i - 1]);
			if (i % 16 == 0) {
				fputc('\n', fw);
			}
			else if (i % 8 == 0) {
				fputc(' ', fw);
			}
		}
		fputc('\n', fw);
	}
	else {
		for (int i = 1; i < header->len + 1; i++) {
			printf("%.2x ", pktdata[i - 1]);
			if (i % 16 == 0) {
				putchar('\n');
			}
			else if (i % 8 == 0) {
				putchar(' ');
			}
		}
		putchar('\n');
	}
}

void print_datalink(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link) {

	if (Mode) {
		fprintf(fw, "Dlzka ramca poskytnuteho pcap API: %d\n", header->len);								//Header-> len == caplen rovnakÈ
		fprintf(fw, "Dlzka ramca prenasaneho po mediu: %d\n", header->len < 64 ? 64 : header->len + 4);	//FCS + 4B
		int protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

		fprintf(fw, "Protocol je %d\n", protocol);

		if (protocol < link->boundary) {			//IEEE 802.3
			fprintf(fw, "%s- ", link->iee);
			if (pktdata[link->positions[2]] == 255) {
				fprintf(fw, "%s\n", link->pairs[3].name);
			}
			else if (pktdata[link->positions[2]] == 170) {
				fprintf(fw, "%s\n", link->pairs[2].name);
			}
			else
			{
				fprintf(fw, "%s", "LLC\n");
			}
		}
		else {
			fprintf(fw, "%s\n", link->eth);
		}

		//SRC MAC
		fprintf(fw, "Zdrojova MAC adresa: ");
		for (int i = link->positions[0]; i < link->positions[1]; i++) {
			fprintf(fw, "%.2x ", pktdata[i]);
		}
		fputc('\n', fw);

		//DST MAC
		fprintf(fw, "Cielova MAC adresa: ");
		for (int i = 0; i < link->positions[0]; i++) {
			fprintf(fw, "%.2x ", pktdata[i]);
		}
		fputc('\n', fw);
	}
	else {

		printf("Dlzka ramca poskytnuteho pcap API: %d\n", header->len);								//Header-> len == caplen rovnakÈ
		printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 64 ? 64 : header->len + 4);	//FCS + 4B
		int protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

		printf("Protocol je %d\n", protocol);

		if (protocol < link->boundary) {			//IEEE 802.3
			printf("%s- ", link->iee);
			if (pktdata[link->positions[2]] == 255) {
				printf("%s\n", link->pairs[3].name);
			}
			else if (pktdata[link->positions[2]] == 170) {
				printf("%s\n", link->pairs[2].name);
			}
			else
			{
				printf("%s", "LLC\n");
			}
		}
		else {
			printf("%s\n", link->eth);
		}

		//SRC MAC
		printf("Zdrojova MAC adresa: ");
		for (int i = link->positions[0]; i < link->positions[1]; i++) {
			printf("%.2x ", pktdata[i]);
		}
		putchar('\n');

		//DST MAC
		printf("Cielova MAC adresa: ");
		for (int i = 0; i < link->positions[0]; i++) {
			printf("%.2x ", pktdata[i]);
		}
		putchar('\n');
	}
}

//Funkcia k bodu Ë.1
void print_communications(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link) {
	char errbuff[BUFF];
	int counter;

	//Rewind, otvorenie s˙boru
	fpc = pcap_open_offline(FILENAME, errbuff);
	if (fpc == NULL) {
		printf("Doslo k chybe pri otvarani suboru %s\n", FILENAME);
		return;
	}

	counter = 0;

	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {

		//Podæa zvolenÈho modu: 0 = konzola	1 = s˙bor
		if (Mode) {
			fprintf(fw, "Ramec %d\n", ++counter);
		}
		else {
			printf("Ramec %d\n", ++counter);
		}
		//Datalink info
		print_datalink(header, pktdata, link);

		//Packet data
		print_pkt_data(pktdata, header);
	}
}

int main(void) {

	DataLink *link = NULL;

	const u_char *pktdata = NULL;
	struct pcap_pkthdr* header = NULL;

	if (init(&link) <= 0) {
		printf("Inicializacia neuspesna\n");
		return -1;
	}

	print_communications(header,pktdata,link);

	dealloc(link);

	return 0;
}