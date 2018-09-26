/*	Zadanie		PKS 1	Network Analyzer
*	Autor		Pavol GrofËÌk
*	D·tum		13.9.2018
*/


#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <pcap.h>


#define FILENAME	"trace-16.pcap"			//N·zov analyzovanÈho pcap s˙boru
#define FILEOUTPUT	"data.txt"				//N·zov v˝stupnÈho s˙boru
#define PROTOCOLS	"protocols.txt"			//N·zov zdrojovÈho s˙boru pre protokoly

#define NAME_LEN	25						//Max dÂûka pre n·zov protokolov
#define BUFF		512						//Max dÂûka pre buffer
#define IP4_LEN		4						//DÂûka IPv4 adresy u_char
#define PORT_LEN	2						//Dlûka portov v bytoch
#define HASH_SIZE	10000					//Veækosù hash tabuæky na v˝pis IP 


FILE *fw = NULL;							//Glob·ln˝ pointer pre z·pis v˝stupu do s˙boru
FILE *fr = NULL;							//-||- pointer na ËÌtanie protocols.txt s˙boru
pcap_t *fpc = NULL;							//-||- pointer na ËÌtanie .pcap s˙boru

int Mode;									//MÛd pre v˝stup programu	1 File 0 STDOUT


//Pomocn· ötrukt˙ra pre v˝pis IP adries
typedef struct ip_addr {
	int bytes;					//PoËet odvysielan˝ch bajtov
	u_char addr[4];				//Ip adresa uzla
}Ip_addr;

//ätrukt˙ra pre protokoly - status a jeho n·zov
typedef struct pairs {
	int number;					//Status
	char name[NAME_LEN];		//N·zov
}Pairs;

//ätrukt˙ra pre ARP
typedef struct arp {
	char name[NAME_LEN];		//N·zov
	int positions[3];			//PozÌcie protokolov pre ARP

	Pairs opcode[2];			//Typ ARP operaËnÈho kÛdu
}Arp;

//ätrukt˙ra pre Linkov˙ vrstvu
typedef struct datalink {
	char eth[NAME_LEN];			//Ethernet II
	char iee[NAME_LEN];			//IEEE-802.3

	int positions[3];			//PozÌcie MAC adresy,type/len
	int boundary;				//Hranica pre ETH II (0600 DEC)
	Pairs pairs[4];				//Hodnota:par e.g 0800 IPv4
}DataLink;

//ätrukt˙ra pre sieùov˙ vrstvu
typedef struct ip {
	char name[NAME_LEN];		//IPv4

	int positions[4];			//PozÌcia IHL,Protocol, Src, Dst IP
	Pairs pairs[3];				//Protocoly a hodnoty
}Ip;

//ätrukt˙ra pre transportn˙ vrstvu
typedef struct tcp {
	char name[NAME_LEN];		//TCP

	int positions[2];			//PozÌcie portov
	Pairs pairs[7];				//P·r port + n·zov
}Tcp;

//ätrukt˙ra pre transportn˙ vrstvu
typedef struct upd {
	char name[NAME_LEN];		//ICMP

	int positions[2];			//PozÌcia Type/Code
	Pairs pairs[3];				//P·r port + n·zov
}Udp;

//ätrukt˙ra pre transportn˙ vrstvu ICMP
typedef struct icmp {
	char name[NAME_LEN];		//ICMP

	int positions[2];			//PozÌcia Type/Code
	Pairs pairs[6];				//P·r port + n·zov
}Icmp;


//Funkcia naËÌta jednotlivÈ protokoly zo s˙boru
void read_protocols(FILE **fr, DataLink *link, Arp *arp, Ip *ip, Tcp *tcp, Icmp *icmp, Udp *udp) {

	char buff[BUFF];
	int c;

	if (*fr == NULL) {
		if ((*fr = fopen(PROTOCOLS, "r")) == NULL) {
			printf("Subor %s sa nepodarilo otvorit\n", PROTOCOLS);
			return;
		}
		
	}

	//»Ìtanie protokolov
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

			getc(*fr);
			if ((c = getc(*fr)) == '#') {
				fgets(buff, BUFF, *fr);
			}
			

			//NaËitanie arp
			fscanf(*fr, "%s", arp->name);
			for (int i = 0; i < 3; i++) {
				fscanf(*fr, "%d", &arp->positions[i]);
			}

			for (int i = 0; i < 2; i++) {
				fscanf(*fr, "%d", &arp->opcode[i].number);
				fscanf(*fr, "%s", arp->opcode[i].name);
			}
			getc(*fr);
			if ((c = getc(*fr)) == '#') {
				fgets(buff, BUFF, *fr);
			}

			//NaËÌtanie IP
			fscanf(*fr, "%s", ip->name);

			for (int i = 0; i < 4; i++) {
				fscanf(*fr, "%d", &ip->positions[i]);
			}

			for (int i = 0; i < 3; i++) {
				fscanf(*fr, "%d", &ip->pairs[i].number);
				fscanf(*fr, "%s", ip->pairs[i].name);
			}
			
			//NaËÌtanie TCP
			getc(*fr);
			if ((c = getc(*fr)) == '#') {
				fgets(buff, BUFF, *fr);
			}

			fscanf(*fr, "%s", tcp->name);

			for (int i = 0; i < 2; i++) {
				fscanf(*fr, "%d", &tcp->positions[i]);
			}

			for (int i = 0; i < 7; i++) {
				fscanf(*fr, "%d", &tcp->pairs[i].number);
				fscanf(*fr, "%s", tcp->pairs[i].name);
			}

			//NaËÌtanie ICMP
			getc(*fr);
			if ((c = getc(*fr)) == '#') {
				fgets(buff, BUFF, *fr);
			}

			fscanf(*fr, "%s", icmp->name);

			for (int i = 0; i < 2; i++) {
				fscanf(*fr, "%d", &icmp->positions[i]);
			}

			for (int i = 0; i < 6; i++) {
				fscanf(*fr, "%d", &icmp->pairs[i].number);
				fscanf(*fr, "%s", icmp->pairs[i].name);
			}

			//NaËÌtanie UDP
			getc(*fr);
			if ((c = getc(*fr)) == '#') {
				fgets(buff, BUFF, *fr);
			}

			fscanf(*fr, "%s", udp->name);

			for (int i = 0; i < 2; i++) {
				fscanf(*fr, "%d", &udp->positions[i]);
			}

			for (int i = 0; i < 3; i++) {
				fscanf(*fr, "%d", &udp->pairs[i].number);
				fscanf(*fr, "%s", udp->pairs[i].name);
			}

			break;
		}
	}
}

//Funkcia inicializuje potrebnÈ d·ta na analyzovanie vzoriek
int init(DataLink **link, Arp **arp, Ip **ip, Tcp **tcp, Icmp **icmp, Udp **udp) {
	char errbuff[BUFF];

	//⁄vodnÈ okno
	printf("^^^^^^^^^^^########################^^^^^^^^^^^\n");
	printf("\t Vitaje v Network Analyser\n");
	printf("^^^^^^^^^^^########################^^^^^^^^^^^\n");
	printf("Zadajte mod  pre vystup\n");
	printf("0 - Konzola\n1 - Subor\n");
	scanf("%d", &Mode);

	if (Mode) {
		if ((fw = fopen(FILEOUTPUT, "w")) == NULL) {
			printf("Subor %s sa nepodarilo otvorit\n", FILENAME);
			return -1;
		}
	}

	//Alok·cia protokolov
	*link = (DataLink*)malloc(sizeof(DataLink));		
	*arp = (Arp*)malloc(sizeof(Arp));					
	*ip = (Ip*)malloc(sizeof(Ip));
	*tcp = (Tcp*)malloc(sizeof(Tcp));
	*icmp = (Icmp*)malloc(sizeof(Icmp));
	*udp = (Udp*)malloc(sizeof(Udp));

	//NaËÌtanie protokolov zo s˙boru PROTOCOLS
	read_protocols(&fr, *link, *arp, *ip, *tcp,  *icmp, *udp);					
	
	return 1;
}

//Funkcia otvorÌ alebo rewind .pcap s˙bor 
int filename_open() {
	char errbuff[BUFF];

	if (!fpc) {
		fpc = pcap_open_offline(FILENAME, errbuff);
	}
	else {
		//Rewind fpc
		pcap_close(fpc);
		fpc = pcap_open_offline(FILENAME, errbuff);
	}

	if (!fpc) {
		printf("Error %s\n", errbuff);
		return 0;		//On Failure
	}
	else {
		return 1;		//On Success
	}
	}

//Funkcia uvoænÌ alokovan˙ pam‰ù
void dealloc(DataLink *link, Arp *arp, Ip *ip, Tcp *tcp, Icmp *icmp, Udp *udp) {
	free(link);
	free(arp);
	free(ip);
	free(tcp);
	free(icmp);
	free(udp);
}

//Funkcia vypÌöe Ë.ramca buÔ na stdin/stdout
void print_frame_number(int frame) {
	if (Mode) {
		fprintf(fw, "Ramec c. %d\n", frame);
	}
	else {
		printf("Ramec c. %d\n", frame);
	}
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
		//Odriadkovanie
		putchar('\n');
		putchar('\n');
	}
}

//Funkcia vypÌöe konkrÈtne inform·cie MAC,Type/Len linkovej vrstvy
void print_datalink(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link) {

	if (Mode) {
		fprintf(fw, "Dlzka ramca poskytnuteho pcap API: %d\n", header->len);								//Header-> len == caplen
		fprintf(fw, "Dlzka ramca prenasaneho po mediu: %d\n", header->len < 64 ? 64 : header->len + 4);		//FCS + 4B
		int protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];


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

		printf("Dlzka ramca poskytnuteho pcap API: %d\n", header->len);								//Header-> len == caplen 
		printf("Dlzka ramca prenasaneho po mediu: %d\n", header->len < 64 ? 64 : header->len + 4);	//FCS + 4B
		int protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

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

//Funkcia vypÌöe IP adresu podæa statusu 1 SRC 2 DST pre ARP protokol
void print_ip_addr(u_char *pktdata, Arp *arp, int status) {

	if (Mode) {
		//SRC
		if (status == 1) {
			for (int i = arp->positions[0]; i < arp->positions[0] + IP4_LEN; i++) {
				if ((i + 1) == (arp->positions[0] + IP4_LEN)) {
					fprintf(fw, "%d ", pktdata[i]);
				}
				else {
					fprintf(fw, "%d.", pktdata[i]);
				}
			}
		}
		//DST
		else {
			for (int i = arp->positions[1]; i < arp->positions[1] + IP4_LEN; i++) {
				if ((i + 1) == (arp->positions[1] + IP4_LEN)) {
					fprintf(fw, "%d ", pktdata[i]);
				}
				else {
					fprintf(fw, "%d.", pktdata[i]);
				}
			}
		}
	}
	else {
		//SRC
		if (status == 1) {
			for (int i = arp->positions[0]; i < arp->positions[0] + IP4_LEN; i++) {
				if ((i + 1) == (arp->positions[0] + IP4_LEN)) {
					printf("%d ", pktdata[i]);
				}
				else {
					printf("%d.", pktdata[i]);
				}
			}
		}
		//DST
		else {
			for (int i = arp->positions[1]; i < arp->positions[1] + IP4_LEN; i++) {
				if ((i + 1) == (arp->positions[1] + IP4_LEN)) {
					printf("%d ", pktdata[i]);
				}
				else {
					printf("%d.", pktdata[i]);
				}
			}
		}
	}
}

//Funkcia vypÌöe obsah Ip adresy pre funkciu print_ip_addresses
void print_address(u_char *pktdata, Ip *ip, int flag) {
	if (Mode) {
		if (flag == 0) {
			//SRC IP
			for (int i = ip->positions[2]; i < ip->positions[3]; i++) {
				if (i == (ip->positions[3] - 1)) {
					fprintf(fw, "%d\n", pktdata[i]);
				}
				else {
					fprintf(fw, "%d.", pktdata[i]);
				}
			}
		}
		else {
			//DST IP
			for (int i = ip->positions[3]; i < ip->positions[3] + IP4_LEN; i++) {
				if (i == (ip->positions[3] + 3)) {
					fprintf(fw, "%d\n", pktdata[i]);
				}
				else {
					fprintf(fw, "%d.", pktdata[i]);
				}
			}
		}
	}
	else {
		if (flag == 0) {
			//SRC IP
			for (int i = ip->positions[2]; i < ip->positions[3]; i++) {
				if (i == (ip->positions[3] - 1)) {
					printf("%d\n", pktdata[i]);
				}
				else {
					printf("%d.", pktdata[i]);
				}
			}
		}
		else {
			//DST IP
			for (int i = ip->positions[3]; i < ip->positions[3] + IP4_LEN; i++) {
				if (i == (ip->positions[3] + 3)) {
					printf("%d\n", pktdata[i]);
				}
				else {
					printf("%d.", pktdata[i]);
				}
			}
		}
	}
}

//Funkcia vypÌöe obsah Ip adresy s poËtom max odvysielan˝ch bajtov
void print_max_ip_address(Ip_addr ip_addr, int max) {
	if (Mode) {
		fprintf(fw, "Adresa uzla s najvacsim poctom odvysielanych bajtov:\n");
		for (int i = 0; i < IP4_LEN; i++) {
			if (i == IP4_LEN - 1) {
				fprintf(fw, "%d\t", ip_addr.addr[i]);
			}
			else {
				fprintf(fw, "%d.", ip_addr.addr[i]);
			}
		}
		fprintf(fw, "%d bajtov\n", max < 64 ? 64 : max);
	}
	else {
		printf("Adresa uzla s najvacsim poctom odvysielanch bajtov:\n");
		for (int i = 0; i < IP4_LEN; i++) {
			if (i == IP4_LEN - 1) {
				printf("%d\t", ip_addr.addr[i]);
			}
			else {
				printf("%d.", ip_addr.addr[i]);
			}
		}
		printf("%d bajtov\n", max < 64 ? 64 : max);
	}
}

//Funkcia doplnok k bodu 1 - v˝pis IP adries s max poËtom odvysielan˝ch bajtov
void print_ip_addresses(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Ip  *ip) {
	int ip_counter, hash, offset,
		position, j, max;
	Ip_addr *ptr = NULL;

	//Rewind
	filename_open();

	ip_counter = 0;

	//SpoËÌtanie poËtu v˝skyt rÙznych IP adries (Max)
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {

		int protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

		if (protocol == link->pairs[0].number) {
			ip_counter++;
		}
	}

	filename_open();

	//Alokovanie pomocnÈho poæa na anal˝zu Ip adries
	if ((ptr = (Ip_addr*)calloc(HASH_SIZE, sizeof(Ip_addr))) == NULL) {
		printf("Nedostatok pamate na analyzu IP adries\n");
		return;
	}
	int packet_counter = 0;

	//Prech·dzanie .pcap s˙borom a spoËÌtanie poËtu odvysielan˝ch bajtov
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {

		int protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

		if (protocol == link->pairs[0].number) {
			hash = 0;
			offset = 3;

			//Zahashovanie O(1)
			//Pri kolÌzi·ch zv˝ö HASH_SIZE!
			for (int i = ip->positions[2]; i < ip->positions[3]; i++) {	
				if (i + 3 >= ip->positions[3]) {
					hash += pktdata[i] << offset;
					offset += 3;
				}

				hash += pktdata[i];
			}

			//Naplnenie poæa Ip adries
			position = hash % HASH_SIZE;
			

			j = 0;
			for (int i = ip->positions[2]; i < ip->positions[3]; i++) {
				ptr[position].addr[j] = pktdata[i];
				j++;
			}
			ptr[position].bytes += header->len;

			//V˝pis 0 - SRC IP adresy
			print_address(pktdata, ip, 0);	
		}
	}

	position = max = 0;

	//Prech·dzanie poæom a hæadanie max IP adresy odvysielan˝ch bajtov
	for (int i = 0; i < HASH_SIZE; i++) {
		if (ptr[i].bytes > 0 && ptr[i].bytes > max) {
			position = i;
			max = ptr[i].bytes;
		}
	}
	print_max_ip_address(ptr[position], max);

	free(ptr);
}

//Funkcia k vypÌöe komunik·cie bod Ë.1
void print_communications(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Ip *ip) {
	char errbuff[BUFF];
	u_char ip_addr[IP4_LEN];

	int max_bytes = 0;
	int counter;

	//Rewind s˙boru
	filename_open();

	counter = 0;
	//Prech·dzanie .pcap s˙borom
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

		//Frame data
		print_pkt_data(pktdata, header);
	}

	if (Mode) {
		fprintf(fw, "Ip adresy odosielajucich uzlov:\n");
	}
	else {
		printf("Ip adresy odosielajucich uzlov:\n");
	}

	//Anal˝za IP adries
	print_ip_addresses(header, pktdata, link, ip);
}

//Funkcia vypÌöe inform·cie k ARP komunik·ciam
void print_arp_info(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Arp *arp, int flag,
	int com, int com_number, int frame_number) {
	//Flag 0 - arp req
	//Flag 1 - arp rep

	if (Mode) {
		//S˙bor
		if (com == 1) {
			fprintf(fw, "Komunikacia c. %d\n", com_number);
			return;
		}
		else {
			if (flag == 1) {
				fprintf(fw,"%s - %s, ", arp->name, arp->opcode[0].name);
				fprintf(fw,"Ip adresa: ");
				print_ip_addr(pktdata, arp, 2);

				fprintf(fw,"MAC adresa: ???\n");


			}
			else {
				//Arp reply
				fprintf(fw,"%s - %s, ", arp->name, arp->opcode[1].name);
				fprintf(fw,"Ip adresa: ");
				print_ip_addr(pktdata, arp, 1);
				fprintf(fw,"MAC adresa: ");

				//V˝pis SRC MAC
				for (int i = link->positions[0]; i < link->positions[1]; i++) {
					fprintf(fw,"%.2x ", pktdata[i]);
				}
				fputc('\n',fw);
			}
			fprintf(fw, "Zdrojova IP: ");
			print_ip_addr(pktdata, arp, 1);
			fprintf(fw, " Cielova IP: ");
			print_ip_addr(pktdata, arp, 2);
			fprintf(fw, "\nRamec c. %d\n", frame_number);

			print_datalink(header, pktdata, link);
			print_pkt_data(pktdata, header);
		}
	}
	else {
		//Konzola
		if (com == 1){
			printf("Komunikacia c. %d\n", com_number);
			return;
		}
		else {
			//Arp req
			if (flag == 1) {
				printf("%s - %s, ", arp->name, arp->opcode[0].name);
				printf("Ip adresa: ");
				print_ip_addr(pktdata, arp, 2);

				printf("MAC adresa: ???\n");


			}
			else {
				//Arp reply
				printf("%s - %s, ", arp->name, arp->opcode[1].name);
				printf("Ip adresa: ");
				print_ip_addr(pktdata, arp, 1);
				printf("MAC adresa: ");

				//V˝pis SRC MAC
				for (int i = link->positions[0]; i < link->positions[1]; i++) {
					printf("%.2x ", pktdata[i]);
				}
				putchar('\n');
			}
			printf("Zdrojova IP: ");
			print_ip_addr(pktdata, arp, 1);
			printf(" Cielova IP: ");
			print_ip_addr(pktdata, arp, 2);
			printf("\nRamec c. %d\n", frame_number);

			print_datalink(header, pktdata, link);
			print_pkt_data(pktdata, header);
		}

	}
}

//Funkcia k v˝pisu tcp/icmp komunik·ciÌ
void print_tcp_icmp_info(struct pcap_pkthdr *header, u_char *pktdata, Ip *ip, Tcp *tcp, Icmp *icmp, int icmp_flag) {
	if (Mode) {
		fprintf(fw,"%s\n", ip->name);
		fprintf(fw, "Zdrojova IP adresa: ");
		print_address(pktdata, ip, 0);
		fprintf(fw, "Cielova IP adresa: ");
		print_address(pktdata,ip,1);
		fprintf(fw, "%s\n", tcp->name);

		int ihl = pktdata[ip->positions[0]] & 0xF;		//IHL pre IP je od 5(20) po F(60)
		ihl = (ihl - 5) * 4;

		if (icmp_flag == 1) {

			int tmp = pktdata[icmp->positions[0] + ihl];
			switch (tmp) {
			case 0:fprintf(fw, "Type: %s\n", icmp->pairs[0].name); break;
			case 3:fprintf(fw, "Type: %s\n", icmp->pairs[1].name); break;
			case 4:fprintf(fw, "Type: %s\n", icmp->pairs[2].name); break;
			case 5:fprintf(fw, "Type: %s\n", icmp->pairs[3].name); break;
			case 8:fprintf(fw, "Type: %s\n", icmp->pairs[4].name); break;
			case 10:fprintf(fw, "Type: %s\n", icmp->pairs[5].name); break;
			}
		}
		else {

			fprintf(fw, "Zdrojovy port: %d\n", (pktdata[tcp->positions[0] + ihl] << 8) + pktdata[tcp->positions[0] + ihl + 1]);
			fprintf(fw, "Cielovy port %d\n", (pktdata[tcp->positions[1] + ihl] << 8) + pktdata[tcp->positions[1] + ihl + 1]);
		}
	}
	else {
		printf("%s\n", ip->name);
		printf("Zdrojova IP adresa: ");
		print_address(pktdata, ip, 0);
		printf("Cielova IP adresa: ");
		print_address(pktdata, ip, 1);
		printf("%s\n", tcp->name);

		int ihl = pktdata[ip->positions[0]] & 0xF;		//IHL pre IP je od 5(20) po F(60)
		ihl = (ihl - 5) * 4;
		

		if (icmp_flag == 1) {
			int tmp = pktdata[icmp->positions[0] + ihl];
			switch (tmp) {
			case 0:printf("Type: %s\n", icmp->pairs[0].name); break;
			case 3:printf("Type: %s\n", icmp->pairs[1].name); break;
			case 4:printf("Type: %s\n", icmp->pairs[2].name); break;
			case 5:printf("Type: %s\n", icmp->pairs[3].name); break;
			case 8:printf("Type: %s\n", icmp->pairs[4].name); break;
			case 10:printf("Type: %s\n", icmp->pairs[5].name); break;
			}
		}
		else {

			printf("Zdrojovy port: %d\n", (pktdata[tcp->positions[0] + ihl] << 8) + pktdata[tcp->positions[0] + ihl + 1]);		
			printf("Cielovy port %d\n", (pktdata[tcp->positions[1] + ihl] << 8) + pktdata[tcp->positions[1] + ihl + 1]);
		}
	}
}

//Funkcia k v˝pisu udp komunik·cii
void print_udp_info(struct pcap_pkthdr *header, u_char *pktdata, Ip *ip, Udp *udp, int com_type) {
	if (Mode) {
		fprintf(fw, "%s\n", ip->name);
		fprintf(fw, "Zdrojova IP adresa: ");
		print_address(pktdata, ip, 0);
		fprintf(fw, "Cielova IP adresa: ");
		print_address(pktdata, ip, 1);
		fprintf(fw, "%s\n", udp->name);

		int ihl = pktdata[ip->positions[0]] & 0xF;		//IHL pre IP je od 5(20) po F(60)
		ihl = (ihl - 5) * 4;
		int prot = (pktdata[udp->positions[0] + ihl] << 8) + pktdata[udp->positions[0] + ihl + 1];		//UrËenie protokolu a jeho typu

		fprintf(fw, "Zdrojovy port: %d\n", (pktdata[udp->positions[0] + ihl] << 8) + pktdata[udp->positions[0] + ihl + 1]);
		fprintf(fw, "Cielovy port %d\n", (pktdata[udp->positions[1] + ihl] << 8) + pktdata[udp->positions[1] + ihl + 1]);

		if(com_type == 2) fprintf(fw, "%s\n", udp->pairs[2].name);		//com_type 2 TFTP
		else if (com_type == 1) fprintf(fw, "%s\n", udp->pairs[1].name);		//com_type 2 DNS

	}
	else {
		printf("%s\n", ip->name);
		printf("Zdrojova IP adresa: ");
		print_address(pktdata, ip, 0);
		printf("Cielova IP adresa: ");
		print_address(pktdata, ip, 1);
		printf("%s\n", udp->name);

		int ihl = pktdata[ip->positions[0]] & 0xF;		//IHL pre IP je od 5(20) po F(60)
		ihl = (ihl - 5) * 4;

		printf("Zdrojovy port: %d\n", (pktdata[udp->positions[0] + ihl] << 8) + pktdata[udp->positions[0] + ihl + 1]);
		printf("Cielovy port %d\n", (pktdata[udp->positions[1] + ihl] << 8) + pktdata[udp->positions[1] + ihl + 1]);

		int prot = (pktdata[udp->positions[0] + ihl] << 8) + pktdata[udp->positions[0] + ihl + 1];		//UrËenie protokolu a jeho typu
		
		if (com_type == 2) printf("%s\n", udp->pairs[2].name);		//com_type 2 TFTP
		else if (com_type == 1) printf("%s\n", udp->pairs[1].name);		//com_type 2 DNS
	}
}

//Funkcia analyzuje ARP komunik·cie
void analyse_arp(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Arp *arp) {

	int counter, arp_reply, i, j, protocol, opcode,
		com_number, flag, first, last;
	int **ptr = NULL;

	//Rewind
	filename_open();

	//Zistenie poËtu arp komunik·cii
	counter = arp_reply = 0;
	protocol = link->pairs[1].number;

	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {

		com_number = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

		//PoËet ARP protokolov
		if (com_number == protocol) {
			counter++;
			if (pktdata[arp->positions[2]] == arp->opcode[1].number) {			//ARP reply
				arp_reply++;
			}
		}
	}

	//Rewind
	filename_open();

	//Pre prÌpad ûe neexistuj˙ ARP komunik·cie
	if (counter == 0) {
		if (Mode) {
			fprintf(fw, "\nZiadne ARP komunikacie\n");
		}
		else {

			printf("\nZiadne ARP komunikacie\n");
		}
		return;
	}

	//Alok·cia pomocnÈho poæa
	ptr = (int**)malloc(counter * sizeof(int*));

	for (i = 0; i < counter; i++) {
		ptr[i] = (int*)calloc(2, sizeof(int));
	}
	j = i = 0;

	//Naplnenie poæa ARP protokolmi
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		i++;

		com_number = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];			//UrËenie protokolu na linkovej vrstves

		if (com_number == protocol) {
			if (pktdata[arp->positions[2]] == arp->opcode[1].number) {						//ARP reply
				ptr[j][0] = i;
				ptr[j][1] = 2;
			}
			else {
				ptr[j][0] = i;		//»Ìslo r·mca
				ptr[j][1] = 1;		//OperaËn˝ kÛd 1 = request : 2 = reply
			}
			j++;
		}
	}

	//Anal˝za + v˝pis
	j = i = 0;
	flag = -1;			//Pre v˝pis prvej komunik·cie
	com_number = 0;		//Counter pre Ë. komunik·cii
	filename_open();	//Rewind s˙boru

	first = 10;
	last = arp_reply - 10;

	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		i++;

		if (i == ptr[j][0] && arp_reply <= 20) {
				if (com_number == 0 && flag == -1) {			//Prv· komunik·cia
					com_number++;
					print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
				}
				
				//UrËenie status
				if (ptr[j][1] == 2)		//Reply
					flag = 0;
				else
					flag = 1;			//Request

				if (flag == 0) {		//UrËenie
					com_number++;
				}

				print_arp_info(header, pktdata, link, arp, flag, 0 , com_number, i);

				//V˝pis - komunik·cia Ë....
				if (flag == 0 && (j + 1 < counter)) {
					print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
				}
	
			j++;
			//Ak boli uû analyzovanÈ vöetk˝ komunik·cie
			if (j >= counter) {
				break;
			}
		}
		//UrËenie prv˝ch a posledn˝ch 10
		else if (i == ptr[j][0] ){
			
			if (com_number == 0) {
				com_number++;
				print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
			}

			if (ptr[j][1] == 2)		//Reply
				flag = 0;
			else
				flag = 1;			//Request

			if (flag == 0) {		//UrËenie prÌznaku
				com_number++;
			}
			
			//Prv˝ch 10
			if (j < first) {
				print_arp_info(header, pktdata, link, arp, flag, 0, com_number, i);
				if (flag == 0 && (j + 1 < counter)) {
					print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
				}
			}

			//V˝pis komunik·cie pre posl. 10-teho
			if (j == last) {
				print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);	
			}

			//Posledn˝ch 10
			if (j >= last && j < counter) {
				print_arp_info(header, pktdata, link, arp, flag, 0, com_number, i);
				if (flag == 0 && (j + 1 < counter)) {
					print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
				}
			}

			j++;
			if (j >= counter) {
				break;
			}
		}
	}

	//Uvoænenie prostriedkov
	for (i = 0; i < counter; i++) {
		free(ptr[i]);
	}
}

//Funkcia analyzuje TCP komunik·cie
void analyse_tcp(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Ip *ip, Tcp *tcp, char *port_name) {

	int communication, protocol, tcp_val, port, counter, n,i, tmp, tmp2;
	int *arr=NULL, *pom=NULL;

	//UrËenie analyzovanej komunik·cie
	if (!strcmp(port_name, "ftp-data")) {
		communication = tcp->pairs[0].number;
	}
	else if (!strcmp(port_name, "ftp-control")) {
		communication = tcp->pairs[1].number;
	}
	else if (!strcmp(port_name, "ssh")) {
		communication = tcp->pairs[2].number;
	}
	else if (!strcmp(port_name, "telnet")) {
		communication = tcp->pairs[3].number;
	}
	else if (!strcmp(port_name, "http")) {
		communication = tcp->pairs[4].number;
	}
	else if (!strcmp(port_name, "https")) {
		communication = tcp->pairs[5].number;
	}
	else if (!strcmp(port_name, "dns")) {
		communication = tcp->pairs[6].number;
	}

	filename_open();		//Rewind s˙boru
	n = i = counter = 0;

	arr = (int*)malloc(sizeof(int));		//Alokovanie na zapam‰tanie Ë.r·mcov

	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		counter++;

		protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];		//IPv4 = 2048

		if (protocol == link->pairs[0].number) {
			tcp_val = pktdata[ip->positions[1]];			//TCP = 6
			//UrËÌme hodnoty portov
			tmp = (pktdata[tcp->positions[1]] << 8) + pktdata[tcp->positions[1] + 1];
			tmp2 = (pktdata[tcp->positions[0]] << 8) + pktdata[tcp->positions[0] + 1];

			if((communication == tmp || communication == tmp2)) {
				arr[i] = counter;
				i++;
				n++;
				arr = realloc(arr,(n +1)* sizeof(int));			//Zapam‰tanie si Ë.r·mcov pre dan˙ kom
			}
		}
	}

	filename_open();

	//Pomocn˝ v˝pis
	if (n > 0) {
		if (Mode) {
			fprintf(fw, "Komunikacie %s\n", port_name);
		}
		else {
			printf("Komunikacie %s\n", port_name);
		}
	}
	else {
		if (Mode) {
			fprintf(fw,"Ziadne %s komunikacie\n", port_name);
			return;
		}
		else {
			printf("Ziadne %s komunikacie\n", port_name);
			return;
		}
	}

	//V˝pis segmentov
	i = counter = tmp = 0;
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		counter++;

		if (n > 20 && arr[i] == counter ) {
			if (i < 10) {
				print_frame_number(counter);
				print_datalink(header, pktdata, link);
				print_tcp_icmp_info(header, pktdata, ip, tcp,NULL,0);
				print_pkt_data(pktdata, header);
			}
			else if( counter>= arr[n-10]){
				print_frame_number(counter);
				print_datalink(header, pktdata, link);
				print_tcp_icmp_info(header, pktdata, ip, tcp,NULL,0);
				print_pkt_data(pktdata, header);
			}
			i++;
		}
		else if(arr[i]==counter && n <= 20) {
			print_frame_number(counter);
			print_datalink(header, pktdata, link);
			print_tcp_icmp_info(header, pktdata, ip, tcp,NULL,0);
			print_pkt_data(pktdata, header);
			i++;
		}

		if (counter > arr[n - 1]) {
			break;
		}
	}
	free(arr);
}

//Funkcia analyzuje ICMP komunik·cie
void analyse_icmp(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Ip *ip, Tcp *tcp, Icmp *icmp) {
	int counter, protocol, communication, tmp, tmp2, i, n,
		icmp_val;
	int *arr = NULL;


	filename_open();		//Rewind s˙boru

	arr = (int*)malloc(sizeof(int));

	i = n = counter = 0;
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		counter++;

		protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];		

		if (protocol == link->pairs[0].number) {			//IPv4 = 2048
			icmp_val = pktdata[ip->positions[1]];			//ICMP = 6
															//UrËÌme hodnoty portov
			//UrËi si type

			if ((icmp_val == ip->pairs[0].number)) {
				arr[i] = counter;
				i++;
				n++;
				arr = realloc(arr, (n + 1) * sizeof(int));			//Zapam‰tanie si Ë.r·mcov pre dan˙ kom
			}
		}
	}

	//Pomocn˝ v˝pis
	if (n > 0) {
		if (Mode) {
			fprintf(fw, "Komunikacie %s\n", icmp->name);
		}
		else {
			printf("Komunikacie %s\n", icmp->name);
		}
	}
	else {
		if (Mode) {
			fprintf(fw, "Ziadne %s komunikacie\n", icmp->name);
			return;
		}
		else {
			printf("Ziadne %s komunikacie\n", icmp->name);
			return;
		}
	}

	filename_open();

	//V˝pis ICMP
	i = counter = tmp = 0;
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		counter++;

		if (n > 20 && arr[i] == counter) {
			if (i < 10) {
				print_frame_number(counter);
				print_datalink(header, pktdata, link);
				print_tcp_icmp_info(header, pktdata, ip, tcp, icmp, 1);
				print_pkt_data(pktdata, header);
			}
			else if (counter >= arr[n - 10]) {
				print_frame_number(counter);
				print_datalink(header, pktdata, link);
				print_tcp_icmp_info(header, pktdata, ip, tcp, icmp, 1);
				print_pkt_data(pktdata, header);
			}
			i++;
		}
		else if (arr[i] == counter && n <= 20) {
			print_frame_number(counter);
			print_datalink(header, pktdata, link);
			print_tcp_icmp_info(header, pktdata, ip, tcp, icmp, 1);
			print_pkt_data(pktdata, header);
			i++;
		}

		if (counter > arr[n - 1]) {
			break;
		}
	}


	free(arr);

}

//Funkcia analyzuje UDP komunik·cie
void analyse_udp(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Ip *ip, Udp *udp, int com_type) {

	int counter, protocol, tmp, i, n, udp_val;
	int *arr = NULL;

	filename_open();		//Rewind s˙boru
	arr = (int*)malloc(sizeof(int));

	counter = i = n = 0;
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		counter++;

		protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];		//IPv4 = 2048

		if (protocol == link->pairs[0].number) {
			udp_val = pktdata[ip->positions[1]];			//UDP = 17(11)
															//UrËÌme hodnoty portov

			int ihl = pktdata[ip->positions[0]] & 0xF;		//IHL pre IP je od 5(20) po F(60)
			ihl = (ihl - 5) * 4;
			int prot = (pktdata[udp->positions[0] + ihl] << 8) + pktdata[udp->positions[0] + ihl + 1];		//UrËenie protokolu a jeho typu
			int prot2 = (pktdata[udp->positions[1] + ihl] << 8) + pktdata[udp->positions[1] + ihl + 1];

			if (udp_val == ip->pairs[2].number && (prot == udp->pairs[com_type].number
				|| prot2 == udp->pairs[com_type].number)) {					//com_type 2 TFTP	1 DNS
				arr[i] = counter;
				i++;
				n++;
				arr = realloc(arr, (n + 1) * sizeof(int));			//Zapam‰tanie si Ë.r·mcov pre dan˙ kom
			}
		}
	}


	//Pomocn˝ v˝pis
	if (n > 0) {
		if (Mode) {
			fprintf(fw, "Komunikacie %s\n", udp->name);
		}
		else {
			printf("Komunikacie %s\n", udp->name);
		}
	}
	else {
		if (Mode) {
			fprintf(fw, "Ziadne %s komunikacie\n", udp->name);
			return;
		}
		else {
			printf("Ziadne %s komunikacie\n", udp->name);
			return;
		}
	}

	filename_open();

	//V˝pis datagramov TFTP/DNS
	i = counter = tmp = 0;
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		counter++;

		if (n > 20 && arr[i] == counter) {
			if (i < 10) {
				print_frame_number(counter);
				print_datalink(header, pktdata, link);
				print_udp_info(header, pktdata, ip, udp, com_type);
				print_pkt_data(pktdata, header);
			}
			else if (counter >= arr[n - 10]) {
				print_frame_number(counter);
				print_datalink(header, pktdata, link);
				print_udp_info(header, pktdata, ip, udp, com_type);
				print_pkt_data(pktdata, header);
			}
			i++;
		}
		else if (arr[i] == counter && n <= 20) {
			print_frame_number(counter);
			print_datalink(header, pktdata, link);
			print_udp_info(header, pktdata, ip, udp, com_type);
			print_pkt_data(pktdata, header);
			i++;
		}

		if (counter > arr[n - 1]) {
			break;
		}
	}

	free(arr);
}

//Funkcia pre moûnosù analyzy protokolov
void User_interface() {

	printf("\nZadajte operaciu: \n");
	printf("1: Vypis komunikacii\n");
	printf("a: Vypis pre http komunikaciu\n");
	printf("b: Vypis pre https komunikaciu\n");
	printf("c: Vypis pre Telnet komunikaciu\n");
	printf("d: Vypis pre SSH komunikaciu\n");
	printf("e: Vypis pre FTP - control komunikaciu\n");
	printf("f: Vypis pre FTP - data komunikaciu\n");
	printf("g: Vypis pre TFTP komunikaciu\n");
	printf("h: Vypis pre ICMP komunikaciu\n");
	printf("i: Vypis pre DNS komunikacie UDP\n");
	printf("j: Vypis pre ARP komunikaciu\n");
	printf("k: Koniec programu\n");
}





int main(void) {

	//Protokoly
	DataLink *link = NULL;			
	Arp *arp = NULL;
	Ip	*ip = NULL;
	Tcp *tcp = NULL;
	Icmp *icmp = NULL;
	Udp *udp = NULL;

	//Pcap 
	const u_char *pktdata = NULL;
	struct pcap_pkthdr* header = NULL;
	char c;

	//Inicializ·cia protokolov
	if (init(&link, &arp, &ip, &tcp, &icmp, &udp) < 1) {
		printf("Inicializacia neuspesna\n");
		return -1;
	}
	
	User_interface();
	getc(stdin);	


	/*ZobrazÌ menu na analyzu protokolov*/
	while ((c = getc(stdin))!= 'k') {
		if (c == '1') print_communications(header, pktdata, link, ip);
		else if (c == 'a') analyse_tcp(header, pktdata, link, ip, tcp, "http");
		else if (c == 'b') analyse_tcp(header, pktdata, link, ip, tcp, "https");
		else if (c == 'c') analyse_tcp(header, pktdata, link, ip, tcp, "telnet");
		else if (c == 'd') analyse_tcp(header, pktdata, link, ip, tcp, "ssh");
		else if (c == 'e') analyse_tcp(header, pktdata, link, ip, tcp, "ftp-control");
		else if (c == 'f') analyse_tcp(header, pktdata, link, ip, tcp, "ftp-data");
		else if (c == 'g') analyse_udp(header, pktdata, link, ip, udp, 2);
		else if (c == 'h') analyse_icmp(header, pktdata, link, ip, tcp, icmp);
		else if (c == 'i') analyse_udp(header, pktdata, link, ip, udp, 1);
		else if (c == 'j') analyse_arp(header, pktdata, link, arp);
		else if (c == 'k' || c == 'K') break;

		if (!Mode) {
			User_interface();
		}
		
		getc(stdin);
	}

	//Uvoænenie prostriedkov
	dealloc(link, arp, ip, tcp, icmp, udp);
	
	if (fpc != NULL) {
		pcap_close(fpc);
	}

	return 0;
}
