/*	Zadanie		PKS 1
*	Autor		Pavol Grof��k
*	D�tum		13.9.2018
*/


#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <pcap.h>



#define FILENAME	"eth-4.pcap"			//N�zov analyzovan�ho pcap s�boru
#define FILEOUTPUT	"data.txt"				//N�zov v�stupn�ho s�boru
#define PROTOCOLS	"protocols.txt"			//N�zov zdrojov�ho s�boru pre poz�cie MAC,IP,Ports ... 

#define NAME_LEN	16						//Max d�ka pre n�zov protokolov
#define BUFF		512						//Max d�ka pre buffer
#define IP4_LEN		4						//D�ka IPv4 adresy u_char
#define PORT_LEN	2						//Dl�ka portu v bytoch
#define ARP_DEL		10						//Delimiter pre prv�ch a posledn�ch 10 komunik�cii ARP
#define HASH_SIZE	10000					//Ve�kos� hash tabu�ky


FILE *fw = NULL;							//Glob�ln� pointer pre z�pis v�stupu do s�boru
FILE *fr = NULL;							//-||- pointer na ��tanie protocols.txt s�boru
pcap_t *fpc = NULL;							//-||- pointer na ��tanie .pcap s�boru
int Mode;									//M�d pre v�stup programu


//Pomocn� �trukt�ra pre v�pis IP adries
typedef struct ip_addr {
	int bytes;					//Po�et odvysielan�ch bajtov
	u_char addr[4];				//Ip adresa uzla
}Ip_addr;

//�trukt�ra pre protokoly - status a jeho n�zov
typedef struct pairs {
	int number;					//Status
	char name[NAME_LEN];		//N�zov
}Pairs;

typedef struct arp {
	char name[NAME_LEN];		//N�zov
	int positions[3];			//Poz�cie protokolov pre ARP

	Pairs opcode[2];			//Typ ARP opera�n�ho k�du
}Arp;

typedef struct datalink {
	char eth[NAME_LEN];
	char iee[NAME_LEN];

	int positions[3];			//Poz�cie MAC adresy,type/len
	int boundary;				//Hranica pre ETH II (0600 DEC)
	Pairs pairs[4];				//Hodnota:par e.g 0800 IPv4
}DataLink;

typedef struct ip {
	char name[NAME_LEN];		//N�zov

	int positions[4];			//Poz�cia IHL,Protocol, Src, Dst IP
	Pairs pairs[3];				//Protocoly a hodnoty
}Ip;

typedef struct tcp {
	char name[NAME_LEN];		//TCP

	int positions[2];			//Poz�cie portov
	Pairs pairs[7];				//P�r port + n�zov
}Tcp;

//Funkcia na��ta jednotliv� protokoly zo s�boru
void read_protocols(FILE **fr, DataLink *link, Arp *arp, Ip *ip, Tcp *tcp) {

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

			//Prerobi� na f-ciu
			getc(*fr);
			if ((c = getc(*fr)) == '#') {
				fgets(buff, BUFF, *fr);
			}
			

			//Na�itanie arp
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

			//Na��tanie IP
			fscanf(*fr, "%s", ip->name);

			for (int i = 0; i < 4; i++) {
				fscanf(*fr, "%d", &ip->positions[i]);
			}

			for (int i = 0; i < 3; i++) {
				fscanf(*fr, "%d", &ip->pairs[i].number);
				fscanf(*fr, "%s", ip->pairs[i].name);
			}
			
			//Na��tanie TCP
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
			break;
		}
	}
}

//Funkcia inicializuje potrebn� d�ta na analyzovanie vzoriek
int init(DataLink **link, Arp **arp, Ip **ip, Tcp **tcp) {
	char errbuff[BUFF];

	printf("Zadajte mod  pre vystup\n");
	printf("0 - Konzola\n1 - Subor\n");
	scanf("%d", &Mode);

	if (Mode) {
		if ((fw = fopen(FILEOUTPUT, "w")) == NULL) {
			printf("Subor %s sa nepodarilo otvorit\n", FILENAME);
			return -1;
		}
	}

	*link = (DataLink*)malloc(sizeof(DataLink));		//Alokovanie pam�te pre �trukt�ru DataLink
	*arp = (Arp*)malloc(sizeof(Arp));					//Alokovanie pam�te pre -||- Arp
	*ip = (Ip*)malloc(sizeof(Ip));
	*tcp = (Tcp*)malloc(sizeof(Tcp));

	read_protocols(&fr, *link, *arp, *ip, *tcp);					//Na��tanie protokolov zo s�boru PROTOCOLS
	
	return 1;
}

//Funkcia otvor� alebo rewind .pcap s�bor 
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

//Funkcia uvo�n� alokovan� pam�
void dealloc(DataLink *link, Arp *arp, Ip *ip, Tcp *tcp) {
	free(link);
	free(arp);
	free(ip);
	free(tcp);
}
//Funkcia vyp�e �.ramca bu� na stdin/stdout
void print_frame_number(int frame) {
	if (Mode) {
		fprintf(fw, "Ramec c. %d\n", frame);
	}
	else {
		printf("Ramec c. %d\n", frame);
	}
}

//Funkcia vyp�e d�ta r�mcu
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

//Funkcia vyp�e konkr�tne inform�cie MAC,Type/Len linkovej vrstvy
void print_datalink(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link) {

	if (Mode) {
		fprintf(fw, "Dlzka ramca poskytnuteho pcap API: %d\n", header->len);								//Header-> len == caplen rovnak�
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

		printf("Dlzka ramca poskytnuteho pcap API: %d\n", header->len);								//Header-> len == caplen rovnak�
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

//Funkcia vyp�e IP adresu pod�a statusu 1 SRC 2 DST pre ARP protokol
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

//Funkcia vyp�e obsah Ip adresy pre funkciu print_ip_addresses
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
					fprintf(fw, "%d", pktdata[i]);
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
					printf("%d", pktdata[i]);
				}
				else {
					printf("%d.", pktdata[i]);
				}
			}
		}
	}
}

//Funkcia vyp�e obsah Ip adresy s po�tom max odvysielan�ch bajtov
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

//Funkcia doplnok k bodu 1 - v�pis IP adries s max po�tom odvysielan�ch bajtov
void print_ip_addresses(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Ip  *ip) {
	int ip_counter, hash, offset,
		position, j, max;
	Ip_addr *ptr = NULL;

	//Rewind
	filename_open();

	ip_counter = 0;

	//Spo��tanie po�tu v�skyt r�znych IP adries (Max)
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {

		int protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

		if (protocol == link->pairs[0].number) {
			ip_counter++;
		}
	}

	filename_open();

	//Alokovanie pomocn�ho po�a na anal�zu Ip adries
	if ((ptr = (Ip_addr*)calloc(HASH_SIZE, sizeof(Ip_addr))) == NULL) {
		printf("Nedostatok pamate na analyzu IP adries\n");
		return;
	}
	int packet_counter = 0;

	//Prech�dzanie .pcap s�borom a spo��tanie po�tu odvysielan�ch bajtov
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {

		int protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

		if (protocol == link->pairs[0].number) {
			hash = 0;
			offset = 3;

			//Zahashovanie O(1)
			//Pri kol�zi�ch zv�� HASH_SIZE!
			for (int i = ip->positions[2]; i < ip->positions[3]; i++) {	
				if (i + 3 >= ip->positions[3]) {
					hash += pktdata[i] << offset;
					offset += 3;
				}

				hash += pktdata[i];
			}

			//Naplnenie po�a Ip adries
			position = hash % HASH_SIZE;

			j = 0;
			for (int i = ip->positions[2]; i < ip->positions[3]; i++) {
				ptr[position].addr[j] = pktdata[i];
				j++;
			}
			ptr[position].bytes += header->len;

			//V�pis 0 - SRC IP adresy
			print_address(pktdata, ip, 0);	
		}
	}

	position = max = 0;

	//Prech�dzanie po�om a h�adanie max IP adresy odvysielan�ch bajtov
	for (int i = 0; i < HASH_SIZE; i++) {
		if (ptr[i].bytes > 0 && ptr[i].bytes > max) {
			position = i;
			max = ptr[i].bytes;
		}
	}
	print_max_ip_address(ptr[position], max);

	free(ptr);
}

//Funkcia k vyp�e komunik�cie bod �.1
void print_communications(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Ip *ip) {
	char errbuff[BUFF];
	u_char ip_addr[IP4_LEN];

	int max_bytes = 0;
	int counter;

	//Rewind s�boru
	filename_open();

	counter = 0;
	//Prech�dzanie .pcap s�borom
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {

		//Pod�a zvolen�ho modu: 0 = konzola	1 = s�bor
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

	//Anal�za IP adries
	print_ip_addresses(header, pktdata, link, ip);
}

//Funkcia vyp�e inform�cie k ARP komunik�ciam
void print_arp_info(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Arp *arp, int flag,
	int com, int com_number, int frame_number) {
	//Flag 0 - arp req
	//Flag 1 - arp rep

	if (Mode) {
		//S�bor
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

				//V�pis SRC MAC
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

				//V�pis SRC MAC
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

//Funkcia k v�pisu tcp komunik�ci�
void print_tcp_info(struct pcap_pkthdr *header, u_char *pktdata, Ip *ip, Tcp *tcp) {
	if (Mode) {
		fprintf(fw,"%s\n", tcp->name);
		fprintf(fw, "Zdrojova IP adresa: ");
		print_address(pktdata, ip, 0);
		fprintf(fw, "\nCielova IP adresa: ");
		print_address(pktdata,ip,1);
		fprintf(fw,"%s\n", ip->name);
		fprintf(fw,"Zdrojovy port: %d\n", (pktdata[tcp->positions[0]] << 8) + pktdata[tcp->positions[0] + 1]);		//IHL???
		fprintf(fw,"Cielovy port %d\n", (pktdata[tcp->positions[1]] << 8) + pktdata[tcp->positions[1] + 1]);
	}
	else {
		printf("%s\n", tcp->name);
		printf("Zdrojova IP adresa: ");
		print_address(pktdata, ip, 0);
		printf("Cielova IP adresa: ");
		print_address(pktdata, ip, 1);
		printf("%s\n", ip->name);
		printf("Zdrojovy port: %d\n",(pktdata[tcp->positions[0]] << 8) + pktdata[tcp->positions[0] + 1]);		//IHL???
		printf("Cielovy port %d\n", (pktdata[tcp->positions[1]] << 8) + pktdata[tcp->positions[1] + 1]);
	}
}

//Funkcia analyzuje ARP komunik�cie
void analyse_arp(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Arp *arp) {

	int counter, arp_reply, i, j, protocol, opcode,
		com_number, flag, first, last;
	int **ptr = NULL;

	//Rewind
	filename_open();

	//Zistenie po�tu arp komunik�cii
	counter = arp_reply = 0;
	protocol = link->pairs[1].number;

	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {

		com_number = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];

		//Po�et ARP protokolov
		if (com_number == protocol) {
			counter++;
			if (pktdata[arp->positions[2]] == arp->opcode[1].number) {			//ARP reply
				arp_reply++;
			}
		}
	}

	//Rewind
	filename_open();

	//Pre pr�pad �e neexistuj� ARP komunik�cie
	if (counter == 0) {
		if (Mode) {
			fprintf(fw, "\nZiadne ARP komunikacie\n");
		}
		else {

			printf("\nZiadne ARP komunikacie\n");
		}
		return;
	}

	//Alok�cia pomocn�ho po�a
	ptr = (int**)malloc(counter * sizeof(int*));

	for (i = 0; i < counter; i++) {
		ptr[i] = (int*)calloc(2, sizeof(int));
	}
	j = i = 0;

	//Naplnenie po�a ARP protokolmi
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		i++;

		com_number = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];			//Ur�enie protokolu na linkovej vrstves

		if (com_number == protocol) {
			if (pktdata[arp->positions[2]] == arp->opcode[1].number) {						//ARP reply
				ptr[j][0] = i;
				ptr[j][1] = 2;
			}
			else {
				ptr[j][0] = i;		//��slo r�mca
				ptr[j][1] = 1;		//Opera�n� k�d 1 = request : 2 = reply
			}
			j++;
		}
	}

	//Anal�za + v�pis
	j = i = 0;
	flag = -1;			//Pre v�pis prvej komunik�cie
	com_number = 0;		//Counter pre �. komunik�cii
	filename_open();	//Rewind s�boru

	first = 10;
	last = arp_reply - 10;

	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		i++;

		if (i == ptr[j][0] && arp_reply <= 20) {
				if (com_number == 0 && flag == -1) {			//Prv� komunik�cia
					com_number++;
					print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
				}
				
				//Ur�enie status
				if (ptr[j][1] == 2)		//Reply
					flag = 0;
				else
					flag = 1;			//Request

				if (flag == 0) {		//Ur�enie
					com_number++;
				}

				print_arp_info(header, pktdata, link, arp, flag, 0 , com_number, i);

				//V�pis - komunik�cia �....
				if (flag == 0 && (j + 1 < counter)) {
					print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
				}
	
			j++;
			//Ak boli u� analyzovan� v�etk� komunik�cie
			if (j >= counter) {
				break;
			}
		}
		//Ur�enie prv�ch a posledn�ch 10
		else if (i == ptr[j][0] ){
			
			if (com_number == 0) {
				com_number++;
				print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
			}

			if (ptr[j][1] == 2)		//Reply
				flag = 0;
			else
				flag = 1;			//Request

			if (flag == 0) {		//Ur�enie pr�znaku
				com_number++;
			}
			
			//Prv�ch 10
			if (j < first) {
				print_arp_info(header, pktdata, link, arp, flag, 0, com_number, i);
				if (flag == 0 && (j + 1 < counter)) {
					print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);
				}
			}

			//V�pis komunik�cie pre posl. 10-teho
			if (j == last) {
				print_arp_info(header, pktdata, link, arp, flag, 1, com_number, i);	
			}

			//Posledn�ch 10
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

	//Uvo�nenie prostriedkov
	for (i = 0; i < counter; i++) {
		free(ptr[i]);
	}
}

void analyse_tcp(struct pcap_pkthdr *header, u_char *pktdata, DataLink *link, Ip *ip, Tcp *tcp, char *port_name) {

	int communication, protocol, tcp_val, port, counter, n,i, tmp, tmp2;
	int *arr=NULL, *pom=NULL;

	//Ur�enie analyzovanej komunik�cie
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

	filename_open();		//Rewind s�boru
	n = i = counter = 0;

	arr = (int*)malloc(sizeof(int));		//Alokovanie na zapam�tanie �.r�mcov

	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		counter++;

		protocol = (pktdata[link->positions[1]] << 8) + pktdata[link->positions[1] + 1];		//IPv4 = 2048

		if (protocol == link->pairs[0].number) {
			tcp_val = pktdata[ip->positions[1]];			//TCP = 6
			//Ur��me hodnoty portov
			tmp = (pktdata[tcp->positions[1]] << 8) + pktdata[tcp->positions[1] + 1];
			tmp2 = (pktdata[tcp->positions[0]] << 8) + pktdata[tcp->positions[0] + 1];

			if((communication == tmp || communication == tmp2)) {
				arr[i] = counter;
				i++;
				n++;
				arr = realloc(arr,(n +1)* sizeof(int));			//Zapam�tanie si �.r�mcov pre dan� kom
			}
		}
	}

	filename_open();

	//Pomocn� v�pis
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
		}
		else {
			printf("Ziadne %s komunikacie\n", port_name);
		}
	}

	//V�pis segmentov
	i = counter = tmp = 0;
	while (pcap_next_ex(fpc, &header, &pktdata) > 0) {
		counter++;

		if (n > 20 && arr[i] == counter ) {
			if (i < 10) {
				print_frame_number(counter);
				print_datalink(header, pktdata, link);
				print_tcp_info(header, pktdata, ip, tcp);
				print_pkt_data(pktdata, header);
			}
			else if( counter>= arr[n-10]){
				print_frame_number(counter);
				print_datalink(header, pktdata, link);
				print_tcp_info(header, pktdata, ip, tcp);
				print_pkt_data(pktdata, header);
			}
			i++;
		}
		else if(arr[i]==counter && n <= 20) {
			print_frame_number(counter);
			print_datalink(header, pktdata, link);
			print_tcp_info(header, pktdata, ip, tcp);
			print_pkt_data(pktdata, header);
			i++;
		}

		if (counter > arr[n - 1]) {
			break;
		}
	}
	free(arr);
}

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

	DataLink *link = NULL;			
	Arp *arp = NULL;
	Ip	*ip = NULL;
	Tcp *tcp = NULL;

	const u_char *pktdata = NULL;
	struct pcap_pkthdr* header = NULL;
	char c;

	if (init(&link, &arp, &ip, &tcp) < 1) {
		printf("Inicializacia neuspesna\n");
		return -1;
	}
	
	User_interface();
	getc(stdin);	

	while ((c = getc(stdin))!= 'k') {
		if (c == '1') print_communications(header, pktdata, link, ip);
		else if (c == 'a') analyse_tcp(header, pktdata, link, ip, tcp, "http");
		else if (c == 'b') analyse_tcp(header, pktdata, link, ip, tcp, "https");
		else if (c == 'c') analyse_tcp(header, pktdata, link, ip, tcp, "telnet");
		else if (c == 'd') analyse_tcp(header, pktdata, link, ip, tcp, "ssh");
		else if (c == 'e') analyse_tcp(header, pktdata, link, ip, tcp, "ftp-control");
		else if (c == 'f') analyse_tcp(header, pktdata, link, ip, tcp, "ftp-data");
		else if (c == 'g') printf("TFTP\n");
		else if (c == 'h') printf("ICMP\n");
		else if (c == 'i') printf("DNS\n");								//Len pre UDP
		else if (c == 'j') analyse_arp(header, pktdata, link, arp);
		else if (c == 'k' || c == 'K') break;

		if (!Mode) {
			User_interface();
		}
		
		getc(stdin);
	}

	dealloc(link,arp,ip, tcp);
	
	if (fpc != NULL) {
		pcap_close(fpc);
	}

	return 0;
}
