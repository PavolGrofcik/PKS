#include <stdio.h>
#include <stdlib.h>

//Winsock2.h has to be first item included in a row, it defines how to interact with network devices 
#include <WinSock2.h>
#include <pcap.h>

#define LINE_LEN 16 // Jeden riadok 16 B


void print_pckt(pcap_t *f, const u_char *pkt_data, struct pcap_pkthdr *hdr, FILE *r,int *count) {

	//PomocnÈ premennÈ 
	int i, r_value;
	int c, type;
	char buff[15];

	//Prech·dzanie vöetk˝mi packetmi
	while ((r_value = pcap_next_ex(f, &hdr, &pkt_data)) > 0) {

		//loop the packet_data

		printf("Ramec: %d\n", ++(*count));
		printf("Dlzka ramca poskytnuta pcap API: %ld B\n", hdr->caplen);
		
		printf("Dlzka ramca prenasana po mediu: %ld B\n", hdr->len < 60 ? 64 : hdr->len+4);			//Min velkost paketu je 64 B inak sa zaplni bezvyznamnymi datami, aby bola velkost 64 B
		//Ethernet II vs 802.3
		if (pkt_data[12] >= 6) {

			fscanf(r, "%d ", &type);

			while ((c = getc(r)) != '\n') {
				putchar(c);
			}
			putchar('\n');
			rewind(r);
		}
		else
		{
			//naËÌtanie celeho riadku do buff
			fgets(buff, 14, r);
			// naËÌtanie typu 1 - Ethernet, 2 - 802.3
			fscanf(r, "%d ", &type);

			while ((c = getc(r)) != '\n' && c != EOF) {
				putchar(c);
			}
			if (pkt_data[14] == 255) {
				printf("- Raw\n");
			}
			else if (pkt_data[14] == 170)
			{
				printf("- LLC-SNAP\n");
			}
			else
			{
				printf("- LLC\n");
			}
			rewind(r);
		}

		//Zdrojov· Mac
		printf("Zdrojova MAC adresa: ");

		for (i = 6; i < 12; i++) {
			printf("%.2x ", pkt_data[i]);
		}
		putchar('\n');
		//Cielova Mac
		printf("Cielova MAC adresa: ");

		for (i = 0; i < 6; i++) {
			printf("%.2x ", pkt_data[i]);
		}
		putchar('\n');
		
		//V˝pis celÈho packetu

		for (i = 1; i <= hdr->caplen; i++) {

			printf("%.2x ", pkt_data[i - 1]);

			if (i % LINE_LEN == 8) {
				printf("  ");
			}
			else if (i % LINE_LEN == 0) {
				printf("\n");
			}
		}
		printf("\n\n");									//Pre lepöiu priehæadnosù pouûÌvame nov˝ riadok

	}
}


int main(void) {

	pcap_t *f = NULL;
	char errbuff[PCAP_ERRBUF_SIZE];
	int count = 0;										//Ud·va poradovÈ ËÌslo r·mca ,poËet vöetk˝ch r·mcov nach·dzaj˙cich sa v s˙bore
	const u_char *pktdata=NULL;

	struct pcap_pkthdr *header = NULL;
	int r_value;

	FILE *r = NULL;
	

														//errbuff - buffer na opisanie chyby poËas workflow programu
	if ((f = (pcap_open_offline("newsample.pcap", errbuff))) == NULL || 
		(r = fopen("Linkframe.txt", "r")) == NULL){
		printf("Subor sa nepodarilo otvorit\n");
		printf("%s\n", errbuff);									//vypiöe error - errbuff
		return -1;
	}
	else
	{
		print_pckt(f, pktdata, header, r, &count);		//Funkcia zobrazÌ podrobn˝ v˝pis

		pcap_close(f);

		if (fclose(r) == EOF) {
			printf("Subor sa nepodarilo zatvorit\n");
		}
		return 0;
	}

	return 0;
}