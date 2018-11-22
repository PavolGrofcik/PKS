#include <stdio.h>
#include <winsock2.h>
#include <Ws2def.h>
#include <Ws2tcpip.h>
#include <stdbool.h>
#include <stdlib.h>
#include <windows.h>
#include <pthread.h>
#include <time.h>


#pragma comment(lib,"ws2_32.lib")	//Winsock Library



#define TRUE 1
#define IPLEN 16					//DÂûka IP adresy
#define BUFFLEN 10000000			//Max veækosù bufferu
#define LINE_LEN 1024				//Max dÂûka riadku pri naËÌtanÌ
#define FRAGMENT_SIZE 1452			//Veækosù fragmentu
#define ESTABLISHED 2				//Status pre nadviazanie spojenia
#define OFF1		3				//OFFSET 1
#define LOCALHOST "127.0.0.1"		//Localhost

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

int connection;
char buff[BUFFLEN];
char rec[BUFFLEN];


//HlaviËka
typedef struct header {
	unsigned long long header_info;

	char data[32];
	unsigned int crc32;
}Header;

//ätrukt˙ra na prenos s˙boru
typedef struct list{
	char data[FRAGMENT_SIZE];
	int sequence;
	struct list *next;
}List;

typedef struct arr {
	char data[FRAGMENT_SIZE];
	int sequence;
}Arr;

//ätrukt˙ra na keep alive
typedef struct keep{

	char ip[IPLEN];
	int port;
}Keep;

Arr pole[100000];


//Z·sobnÌk
List *first = NULL;
List *last = NULL;
//Funkcia zobrazÌ ˙vodn˝ interface s choices
void user_interface() {

	for (int i = 0; i < 30; i++) {
		putchar('#');
	}
	putchar('\n');
	printf("#\tVitajte v programe   #\n");
	printf("#\tZadajte moznost\t     #\n");
	printf("#\t 1 - client\t\     #\n");
	printf("#\t 2 - server\t     #\n");
	printf("#\t 3 - koniec\t     #\n");

	for (int i = 0; i < 30; i++) {
		putchar('#');
	}
	putchar('\n');
}

//Funkcia sl˙ûi na v˝poËet CRC16 hashu
//https://stackoverflow.com/questions/10564491/function-to-calculate-a-crc16-checksum
unsigned short crc16(const unsigned char* data_p, unsigned char length) {
	unsigned char x;
	unsigned short crc = 0xFFFF;

	while (length--) {
		x = crc >> 8 ^ *data_p++;
		x ^= x >> 4;
		crc = (crc << 8) ^ ((unsigned short)(x << 12)) ^ ((unsigned short)(x << 5)) ^ ((unsigned short)x);
	}
	return crc;
}

//Funkcia sl˙ûi na extrakciu d·t
unsigned long long extract(unsigned long value, int begin, int end)
{
	unsigned short mask = (1 << (end - begin)) - 1;
	return (value >> begin) & mask;
}

//Funkcia inicializuje veækosù init segmentu
char* handshake(int frag_size) {
	char *new = (char*)malloc(sizeof(Header) + ESTABLISHED + 1);

	if (!new) {
		return NULL;
	}
	else {
		return new;
	}
}

List* new_node() {
	List *new = (List*)malloc(sizeof(List));

	if (!new) {
		printf("Nepodarilo sa alokovat pamat\n");
		return NULL;
	}

	new->next = NULL;

	return new;
}

//Funkcia prid· do fronty dan˝ message
void add_front(char *msg, int len, int seq) {
	if (first == NULL) {
		first = new_node();
		last = first;
		strncpy(last->data, msg, len);
		last->sequence = seq;
	}
	else {
		last->next = new_node();
		last = last->next;
		strncpy(last->data, msg, len);
		last->sequence = seq;
	}
}



//Funkcia naËÌta do buffra spr·vu
void load_message(char *message) {

	int counter;
	char buff[LINE_LEN];

	while (TRUE) {

		fgets(buff, LINE_LEN, stdin);
		if (buff[0] == 0 || buff[1] == 0) {
			break;
		}

		counter = 0;
		//PreokopÌrovanie spr·v do datagramu
		for (int i = 0; i < BUFFLEN; i++) {
			if (counter == (strlen(buff)-1)) {
				message[i] = ' ';
				break;
			}

			if (message[i] == '\0') {
				message[i] = buff[counter];
				counter++;
			}
		}
	}
}


//Funkcia zistÌ connection status klienta a servera
int find_conn_status() {
	int status = 0;

	pthread_mutex_lock(&mutex);
	status = connection;
	pthread_mutex_unlock(&mutex);

	return status;
}

//Funkcia na udrûianie spojenia
void* keep_alive(void *arg) {

	int status, s,
		slen;
	char buff[LINE_LEN];

	struct sockaddr_in s_in, s_other;
	Keep *data = (Keep*)arg;
	Header *h = (Header*)malloc(sizeof(Header));

	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s == SOCKET_ERROR) {
		printf("Nepodarilo sa inicializovaù vlakno\n");
		pthread_exit(NULL);
	}

	s_in.sin_family = AF_INET;
	s_in.sin_port = htons(data->port);


	if (inet_pton(AF_INET, data->ip, &s_in.sin_addr) == 0) {
		printf("Neuspesne vytvorenie socketu s danou IP %s pre vlakno\n", data->ip);
		return -3;
	}

	//Zistenie statusu
	status = find_conn_status();
	slen = sizeof(s_other);

	//Posielam keep_alive datagram
	while (TRUE) {
		if (status == 0) {

			h->header_info = 7;
			h->crc32 = crc16((char*)h, strlen((char*)h));

			//Odoöleme Keep_Alive r·mec
			if (sendto(s, (char*)h, sizeof(Header), 0, (struct sockaddr*) &s_in, sizeof(s_in)) == SOCKET_ERROR) {
				printf("Nepodarilo sa odoslat keep alive - ukoncenie spojenia\n");
				pthread_exit(NULL);
			}
			else {

				Sleep(10000);		//UspÌm na 10 sek˙nd
				status = find_conn_status();

				if (status == -1) {
					pthread_exit(NULL);
				}
			}
		}
		else {
			//Inak sa vl·kno uspÌ a bude Ëakaù na sign·l o ukonËenÌ prenosu
			pthread_mutex_lock(&mutex);
			while (connection != 0) {
				pthread_cond_wait(&cond, &mutex);
			}
			pthread_mutex_unlock(&mutex);
			//printf("Vlakno bolo signalizovane\n");

			h->header_info = 7;
			h->crc32 = crc16((char*)h, strlen((char*)h));

			if (sendto(s, (char*)h, sizeof(Header), 0, (struct sockaddr*) &s_in, sizeof(s_in)) == SOCKET_ERROR) {
				printf("Nepodarilo sa odoslat keep alive - ukoncenie spojenia\n");
				pthread_exit(NULL);
			}

			Sleep(10000);

			status = find_conn_status();
			if (status == -1) {
				pthread_exit(NULL);
			}
		}

		status = find_conn_status();

		if (status == -1) {
			printf("Spojenie bolo ukoncene\n");
			break;
		}
	}

	pthread_exit(NULL);
}

//Funkcia inicializuje spr·vu na prijatie
char* message_init() {
	char *new = (char*)malloc(sizeof(char));

	new[0] = '\0';

	return new;
}

//Funkcia defragmentuje dan˙ spr·vu a pripojÌ prijat˙ Ëasù
char* defragment(char *buffer, char* message, int frag_size) {
	int messg_len = strlen(message);

	char *new = (char*)malloc((messg_len + frag_size + 1) * sizeof(char));

	strncpy(new, message, messg_len);

	memcpy(new + messg_len, buffer + sizeof(Header), frag_size);
	new[messg_len + frag_size] = '\0';

	free(message);

	return new;
}

//Funkcia defragmentuje dan˝ fragment s˙boru a pripojÌ prijat˙ Ëasù
char* defragment_file(char *buffer, char *message, int frag_size) {
	int messg_len = strlen(message);

	char *new = (char*)malloc((messg_len + frag_size + 1) * sizeof(char));

	strncpy(new, message, messg_len);
	//printf("Po prekopirovani povodneho %s\n", message);
	memcpy(new + messg_len, buffer + sizeof(Header), frag_size);
	new[messg_len + frag_size] = '\0';
	//printf("Po prekopirovani buffra %s\n", new);
	free(message);

	//printf("New is: %s\n", new);
	return new;
}


//Funkcia pre server a jeho vöetky komponenty
void server() {
	SOCKET s;
	struct sockaddr_in server_in, si_other;

	int recv_len, slen, port,
		status,
		si_other_len,
		attempts = 3,
		mesg_status,
		frag_len,
		crc_check,
		file_size,
		*resend = NULL;

	long frag_num, seek_num;

	char name[256] = "",
		*message = NULL;
	//char buff[BUFFLEN];

	FILE *fw = NULL;

	time_t start, end;

	Header *header = NULL;

	//Vytvorenie socketu
	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s == -1) {
		printf("Nepodarilo sa inicializovat socket\n");
		return -1;
	}

	//⁄vodnÈ menu pre server so zadanÌm portu
	printf("Vitajte v rezime server\n");
	printf("Zadajte port\n");
	scanf("%d", &port);

	if (port < 0 || port < 1023) {
		printf("Zadali ste well know ports. Error\n");
		return -2;
	}

	server_in.sin_family = AF_INET;
	server_in.sin_addr.s_addr = INADDR_ANY;
	server_in.sin_port = htons(port);

	//Nabinodovanie socketu podæa zadanÈho portu
	if (bind(s, (struct sockaddr*) &server_in, sizeof(server_in)) == SOCKET_ERROR) {
		printf("Neuspesna inicializiacia servera\n");
		closesocket(s);
		return -3;
	}
	else {
		printf("Uspesna inicializacia servera\n");
	}

	//Listening rel·cie medzi klientom
	si_other_len = sizeof(si_other);
	message = (char*)malloc(sizeof(char));
	message[0] = '\0';

	//Prebiehanie hlavnej rel·cia medzi serverom a klientom
	while (TRUE) {

		memset(rec, '\0', BUFFLEN);
		//»akanie na spojenie s klientom
		if ((status = recvfrom(s, rec, BUFFLEN, 0, (struct sockaddr*) &si_other, &si_other_len)) == SOCKET_ERROR) {
			printf("Neuspesny receive\n");
			return -4;
		}

		header = (Header*)rec;

		//Zobrazenie adresy odosielateæa
		printf("\n##############################\n");
		printf("Received packet from: %s\n", inet_ntoa(si_other.sin_addr));

		//UrËenie typu spr·vy
		mesg_status = header->header_info & 7;

		//Ak bolo poûiadanie o ukonËenie spojenia
		if (mesg_status == 0) {

			printf("\n#########################\n");
			printf("Message: %s\n", header->data);
			crc_check = crc16((char*)header, strlen((char*)header));

			//Znovuxaslanie ACK datagramu
			Header *ack = (Header*)malloc(sizeof(Header));
			strcpy(ack->data, "Acknowledged");
			ack->header_info = 0;
			ack->crc32 = crc16((char*)ack, strlen((char*)ack));

			if (sendto(s, (char*)ack, sizeof(Header), 0, (struct sockaddr *) &si_other, sizeof(si_other)) == SOCKET_ERROR)
			{
				printf("sendto() failed with error code : %d", WSAGetLastError());
				continue;
			}

			printf("Poziadanie o ukoncenie relacie\n");
			closesocket(s);

			return;
		}
		else if (mesg_status == 1) {

			printf("Sprava: %s\n", header->data);
			frag_len = extract(header->header_info, 3, 15);			//Extrahujmee veækosù fragmentu
			frag_num = extract(header->header_info, 15, 30);		//Extrahujeme poËet fragmentov

			printf("Velkost fragmentu: %d\n", frag_len);
			printf("Pocet fragmentov: %ld\n", frag_num);
			printf("CRC16: %s\n", header->crc32 == crc16((char*)header, strlen((char*)header)) ? "Ok" : "Bad");

			if ((resend = (int*)calloc(frag_len, sizeof(int))) == NULL) {
				printf("Nepodarilo sa alokovat Resend datagramy\n");
			}
			
		}
		else if (mesg_status == 2) {

			printf("Velkost fragmentu: %d\n", frag_len);
			printf("Poradie fragmentu: %d\n", extract(header->header_info, 3, 20));
			printf("CRC16: %s\n", header->crc32 == crc16((char*)header, strlen((char*)header))? "Ok":"Bad");
			message = defragment(rec, message, frag_len);
			
		}
		else if (mesg_status == 3) {
			message = defragment(rec, message, frag_len);
			printf("Velkost fragmentu: %d\n", frag_len);
			printf("Poradie fragmentu %d\n", extract(header->header_info, 3, 20));
			printf("CRC16: %s\n", header->crc32 == crc16((char*)header, strlen((char*)header)) ? "Ok" : "Bad");
			printf("Defragmentovana sprava: %s\n", message);
			

			free(message);
			message = NULL;
			message = message_init();
			free(resend);
			resend = NULL;
			memset(rec, '\0', BUFFLEN);
		}
		//Prijatie s˙boru
		else if (mesg_status == 4) {

			//UloûÌme si veækosù  a poËet fragmentov
			frag_len = extract(header->header_info, 3, 15);
			frag_num = extract(header->header_info, 15, 45);
			strcpy(name, header->data);

			printf("Velkost fragmentu %ld\n", frag_len);
			printf("Pocet fragmentov %ld\n", frag_num);
			printf("Nazov suboru %s\n", name);

			fw = fopen(name, "ab");	//Bolo wb
			
			//first = last = NULL;
			message = message_init();

			//Inicializujeme pole podæa seq number

		}
		else if (mesg_status == 5) {

			/*FILE *fw = NULL;
			//fw = fopen("subor.txt", "w");
			fw = fopen(name, "wb");
			if (fwrite(rec + sizeof(Header), 1, file_size, fw) <= 0) {
				printf("Nepodarilo sa ulozit subor\n");
			}
			else {
				printf("Subor bol uspesne ulozeny\n");
			}

			if (fclose(fw) == EOF) {
				printf("Subor sa nepodarilo zatvorit\n");
			}
			*/

			int counter = 1;
			seek_num = 1;
			
			while (TRUE) {

				header = (Header*)rec;

				int seq = extract(header->header_info, 3, 33);
				int file_status = (header->header_info >> 33) & 3;
				printf("File status %ld\n", file_status);
				printf("Seq is %d\n", seq);
				printf("Counter is %d\n",counter);

				//Znovuvyûiadanie datagramu
				if (counter != seq) {
					seek_num = counter;
					while (TRUE) {
						Header *ack = (Header*)malloc(sizeof(Header));

						strcpy(ack->data, "UnAcknowledged");
						ack->header_info = 4 + (counter << 3);
						ack->crc32 = crc16((char*)ack, strlen((char*)ack));

						//Odoslanie Unacknowledged
						if (sendto(s, (char*)ack, sizeof(Header), 0, (struct sockaddr *) &si_other, sizeof(si_other)) == SOCKET_ERROR)
						{
							printf("sendto() failed with error code : %d", WSAGetLastError());
							continue;
						}

						//»akanie na spr·vny r·mec
						if ((status = recvfrom(s, rec, BUFFLEN, 0, (struct sockaddr*) &si_other, &si_other_len)) == SOCKET_ERROR) {
							printf("Neuspesny receive\n");
							return -4;
						}

						header = (Header*)rec;
						int seq = extract(header->header_info, 3, 33);
						int file_status = (header->header_info >> 33) & 3;


						// Odoslanie ACKnowledged
						if (seq == counter) {
							strcpy(ack->data, "Acknowledged");
							ack->header_info = 5 + (seek_num << 3);
							ack->crc32 = crc16((char*)ack, strlen((char*)ack));

								if (sendto(s, (char*)ack, sizeof(Header), 0, (struct sockaddr *) &si_other, sizeof(si_other)) == SOCKET_ERROR)
								{
									printf("sendto() failed with error code : %d", WSAGetLastError());
									continue;
								}
							break;
						}
					}

				}
				else {
					//Odoöleme ACK
					Header *ack = (Header*)malloc(sizeof(Header));

					strcpy(ack->data, "Acknowledged");
					ack->header_info = 5 + (counter << 3);
					ack->crc32 = crc16((char*)ack, strlen((char*)ack));

					//Odoslanie Unacknowledged
					if (sendto(s, (char*)ack, sizeof(Header), 0, (struct sockaddr *) &si_other, sizeof(si_other)) == SOCKET_ERROR)
					{
						printf("sendto() failed with error code : %d", WSAGetLastError());
						//continue;
					}

					seq = counter;
				}

				if (file_status == 1) {

					//Kontrolovaù 
					pole[seq].sequence = seq;
					strncpy(pole[seq].data, rec + sizeof(Header), frag_len);
					fwrite(rec + sizeof(Header), 1, frag_len, fw);
					//Bolo fwrite(rec + sizeof(Header),1, strlen(rec + sizeof(Header)), fw);
				}
				else {


					pole[seq].sequence = seq;
					strncpy(pole[seq].data, rec + sizeof(Header), frag_len);

					//MusÌme spojiù r·mce podæa poradia ako priöli
					/*for (int i = 1; i <= frag_num; i++) {
						if (pole[i].sequence != i) {
							printf("Packet  %d nedorazil!\n", i);
						}
						message = defragment_file(pole[i].data, message, frag_len);
					}
					*/

					/*if (fwrite(message, 1, strlen(message), fw) <= 0) {
						printf("Nepodarilo sa ulozit subor\n");
					}
					else {
						printf("Subor bol uspesne ulozeny\n");
					}*/

					//Bolo fwrite(rec + sizeof(Header), 1, strlen(rec + sizeof(Header)), fw);
					//long min_frag_len = header->header_info
					fwrite(rec + sizeof(Header), 1, strlen(rec + sizeof(Header)), fw);

					if (fclose(fw) == EOF) {
						printf("Subor sa nepodarilo zatvorit\n");
					}
					else {
						printf("Subor bol uspesne ulozeny\n");
					}

					free(message);
					message = NULL;
					message = message_init();

					break;
				}

				//»akanie na ÔalöÌ r·mec
				if ((status = recvfrom(s, rec, BUFFLEN, 0, (struct sockaddr*) &si_other, &si_other_len)) == SOCKET_ERROR) {
					printf("Neuspesny receive\n");
					return -4;
				}

				counter++;
			}
		}
		//Prijatie chybnej spr·vy
		else if (mesg_status == 6) {

			printf("Velkost fragmentu: %d\n", frag_len);
			printf("Pocet fragmentov: %ld\n", frag_num);
			printf("CRC16: %s\n", header->crc32 == crc16((char*)header, strlen((char*)header)) ? "Ok" : "Bad");


			crc_check = crc16((char*)header, strlen((char*)header));

			if (crc_check != header->crc32) {

				Header *ack = (Header*)malloc(sizeof(Header));
				strcpy(ack->data, "Resend");
				ack->header_info = 6;
				ack->crc32 = crc16((char*)ack, strlen((char*)ack));

				//resend[] = 1;

				if (sendto(s, (char*)ack, sizeof(Header), 0, (struct sockaddr *) &si_other, sizeof(si_other)) == SOCKET_ERROR)
				{
					printf("sendto() failed with error code : %d", WSAGetLastError());
					continue;
				}
			}
			else {
				printf("Dorucena sprava %s\n", rec + sizeof(Header));
			}
		}
		else if (mesg_status == 7) {
			printf("Keep Alive :)\n");
		}
	}

	//Uzavretie socketu po skonËenÌ rel·cie
	closesocket(s);
}


//Funkcia na inicializ·ciu klienta a jeho komponentov
void client(){

	int s, damaged,
		slen,
		attempts = 3,
		port,
		frag_len,
		choice,
		fragment = 0,
		crc_check,
		sequence,
		frag_num,
		file_size,
		error_rate,
		*resend = NULL;;

	pthread_t t;
	Keep *data = NULL;

	struct sockaddr_in client_in, si_other;
	char //buff[BUFFLEN],
		ip[IPLEN],
		path[256],
		*message = NULL,
		*init_msg = NULL,
		*datagram = NULL;

	//Header na odosielanie d·t
	Header *header = NULL;

	//Vytvorenie socketu
	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s == -1) {
		printf("Nepodarilo sa inicializovat socket\n");
		return -1;
	}

	//⁄vodnÈ okno pre klienta
	printf("Vitajte v rezime klienta\n");
	printf("Zadajte port\n");
	scanf("%d", &port);
	printf("Zadajte IP adresu servera\n");
	printf("Pre LocalHost -> 'LH'\n");
	scanf("%s", ip);

	//Nastavenie localhostu
	if (!strcmp(ip, "LH")) {
		strcpy(ip, LOCALHOST);
	}

	//Zadanie veækosti fragmentu
	while (attempts) {
		printf("Zadajte velkost fragmentu\n");
		scanf("%d", &frag_len);

		//Oöetrenie Ëi klient zadal spr·vnu veækost fragmentu
		if (frag_len<= 0 || frag_len > FRAGMENT_SIZE) {
			printf("Nespravna velkost\n");
			printf("Zadajte znovu\n");
			attempts--;

			if (attempts == 0) {
				printf("Nespravne zvolena velkost fragmentu\n");
				printf("Programu bude ukonceny\n");
				return -2;
			}

			continue;
		}
		else {
			break;
		}
	}

	client_in.sin_family = AF_INET;
	client_in.sin_port = htons(port);

	//Nabindovanie socketu podæa zadanej IP
	if (inet_pton(AF_INET, ip, &client_in.sin_addr) == 0) {
		printf("Neuspesne vytvorenie socketu s danou IP %s\n", ip);
		return -3;
	}
	
	//Vytvorenie init segmentu pri nadviazanÌ spojenia
	init_msg = handshake(frag_len);
	slen = sizeof(si_other);

	if (!init_msg) {
		printf("Inicializacia spravy zlyhala\n");
		return -4;
	}

	//Inicializ·cia vl·kna na udrûianie spojenia
	data = (Keep*)malloc(sizeof(Keep));
	strcpy(data->ip, ip);
	data->port = port;

	if (pthread_create(&t, NULL, keep_alive, (void*)data) != 0) {
		printf("Nepodarilo sa inicializovaù keep_alive vlakno\n");
	}

	header = (Header*)init_msg;
	//ZakÛdovanie z·kladn˝ch inform·ciÌ
	//Posun o 4 bity !!!
	header->header_info = frag_len << 4;

	//Naviazanie rel·cie medzi serverom
	while (TRUE) {

		//Pri neËinnosti klienta - Keep Alive
		connection = 0;

		//NaËÌtanie spr·vy
		printf("Zadajte 0 - odhlasenie klienta\n");
		printf("Zadajte 1 - odoslanie spravy\n");
		printf("Zadajte 2 - odoslanie chybneho datagramu\n");
		printf("Zadajte 3 - odoslanie suboru\n");
		scanf("%d", &choice);

		connection = 1;
	
		//Odhlasenie klienta
		if (choice == 0) {
			//Klient sa chce odhl·siù
			connection = -1;

			Header *h = (Header*)malloc(sizeof(Header));

			strcpy(h->data, "End  of Connection");
			h->header_info = 0;
			h->crc32 = crc16((char*)h, strlen((char*)h));

			//Odoslanie ukonËenie spojenia serveru
			if (sendto(s, (char*)h, sizeof(Header), 0, (struct sockaddr*) &client_in, sizeof(client_in)) == SOCKET_ERROR) {
				printf("Nepodarilo sa odoslat ukoncenie spojenia\n");
			}

			free(h);
			h = NULL;

			//Klient musÌ prijaù ACK od serveru u ukonËenÌ spojenia
			memset(buff, '\0', BUFFLEN);
			if (recvfrom(s, buff, BUFFLEN, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
			{
				printf("Server neodpoveda, relacia bude ukoncena\n");
				return -5;
			}

			h = (Header*)buff;
			crc_check = crc16((char*)h, strlen((char*)h));
			//printf("Header ack %d calculated ack %d\n", h->crc32, crc_check);

			if (crc_check != h->crc32) {
				printf("Poskodeny ACK od serveru\n");
			}
			else {
				printf("##############################\n");
				printf("Status servera: %s\n", h->data);
			}

			closesocket(s);
			return;
		}

		//NaËÌtanie a odoslanie spr·vy
		if (choice == 1 || choice == 2) {
			printf("Zadajte spravu\n");

			getc(stdin);

			message = (char*)malloc(BUFFLEN * sizeof(char));
			memset(message, '\0', BUFFLEN);

			gets_s(message, BUFFLEN);
			printf("Sprava je %s\n", message);

			//Alok·cia datagramu na odoslanie a pretypovanie na typ Header
			datagram = (char*)malloc((sizeof(Header) + frag_len + 1) * sizeof(char));
			//memset(datagram, '\0', sizeof(Header) + frag_len + 1);
			header = (Header*)datagram;

			//Odoölem ˙vodn˝ datagram na upovedomenie ûe ide o spr·vu
			//Z·roveÚ veækosù fragmentu
			Header *init = (Header*)malloc(sizeof(Header));
			frag_num = frag_len;

			//UrËÌme poËet fragmentov a zakÛdovanie
			if (strlen(message) % frag_len == 0) {
				frag_num = strlen(message) / frag_len;
			}
			else {
				frag_num = strlen(message) / frag_len;
				frag_num += 1;
			}

			//ZakÛdovanie veækosti fragmentu  a poËet fragmentov
			init->header_info = (frag_len << 3) + (frag_num << 15) + 1;
			strcpy(init->data, "Zaciatok posielania spravy");
			//printf("Init header info %ld\n",init->header_info);

			//printf("Init typ %d cal %d\n", 1, init->header_info & 7);
			//printf("Velkost frag %d cal %d\n", frag_len, extract(init->header_info, 3, 15));
			//printf("Pocet frag %d cal %d\n", frag_num, extract(init->header_info, 15, 30));

			printf("Velkost fragmentu: %d\n", extract(init->header_info, 3, 15));
			printf("Pocet fragmentov: %d\n", extract(init->header_info, 15, 30));
			init->crc32 = crc16((char*)init, strlen((char*)init));

			//Odoslanie init spr·vy
			if (sendto(s, (char*)init, sizeof(Header), 0, (struct sockaddr*)&client_in, sizeof(client_in)) == SOCKET_ERROR) {
				printf("Nepodarilo sa odoslat init spravu serveru\n");
				free(datagram);
				free(message);
				message = datagram = NULL;
				continue;
			}

			//Odoslanie spr·vy
			if (choice == 1) {

				//Odoöleme naraz
				if (strlen(message) + sizeof(Header) <= frag_len) {

					memcpy(datagram + sizeof(Header), message, strlen(message) + 1);
					header->header_info = 3;
					header->header_info += (1 << 3);
					header->crc32 = crc16((char*)header, strlen((char*)header));

					printf("##############################\n");
					printf("Fragment: %d\n", extract(header->header_info, 3, 15));

					if (sendto(s, (char*)datagram, sizeof(Header) + frag_len, 0, (struct sockaddr*)&client_in, sizeof(client_in)) == SOCKET_ERROR) {
						printf("Nepodarilo sa odoslat spravu serveru\n");
					}
				}
				else {
				//MusÌm nastaviù fragment·ciu podæa zvolenej veækosti hlaviËky a n·sledne znovuposlanie r·mcov
				sequence = strlen(message);
				fragment = 1;


				//Rozfragmentovanie a n·slednÈ odosielanie
				while (sequence > 0) {

					//UrËenie stavu odosielania
					if (sequence <= frag_len) {
						header->header_info = 3 + (fragment << 3);		//Posledn˝ fragment
					}
					else {
						header->header_info = 2 + (fragment << 3);		//»asù fragmentu
					}


					memcpy(datagram + sizeof(Header), message + (fragment - 1) * frag_len, frag_len);

					sequence -= frag_len;
					printf("##############################\n");
					printf("Fragment %d\n", fragment);
					printf("Velkost fragmentu: %d\n", frag_len);
					printf("Sprava: %.*s\n", frag_len, datagram + sizeof(Header));
					//ZakÛdovanie header sequence number
					//printf("Header info %d typ %d\n", header->header_info, header->header_info & 7);
					header->crc32 = crc16((char*)datagram, strlen((char*)header));
					fragment++;


					if (sendto(s, datagram, frag_len + sizeof(Header), 0, (struct sockaddr *) &client_in, sizeof(client_in)) == SOCKET_ERROR)
					{
						printf("Nepodarilo sa odoslaù datagram %d\n", fragment);
						break;
					}	

				}
				
				printf("Sprava bola uspesne odoslana\n");
				printf("##############################\n");
				}
			}
			else {
				//Chybov· spr·va!!!
				printf("Zadajte chybovost v %%: ");
				scanf("%d", &error_rate);

				if (error_rate <= 0 || error_rate >100) {
					printf("Nespravna zadana chybovost");
				}
				else {

					//Ak je poËet r·mcov iba 1 - chybovost bude implicitne 100%
					if (strlen(message) + sizeof(Header) <= frag_len) {

						memcpy(datagram + sizeof(Header), message, strlen(message) + 1);
						header->header_info = 6;
						header->header_info += (1 << 3);

						//Explicitne zmenÌm crc
						header->crc32 = crc16((char*)header, strlen((char*)header));
						header->crc32 += 1;

						printf("##############################\n");
						printf("Fragment: %d\n", extract(header->header_info, 3, 15));

						if (sendto(s, (char*)datagram, sizeof(Header) + frag_len, 0, (struct sockaddr*)&client_in, sizeof(client_in)) == SOCKET_ERROR) {
							printf("Nepodarilo sa odoslat spravu serveru\n");
						}

						//PoËkanie na RESEND od serveru
						memset(buff, '\0', BUFFLEN);
						if (recvfrom(s, buff, BUFFLEN, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
						{
							printf("Server neodpoveda, relacia bude ukoncena\n");
							return -5;
						}

						header = (Header*)buff;

						printf("##############################\n");
						printf("Server message %s\n", header->data);
						printf("Sprava je %s\n", message);
						printf("Datagram sprava je %s\n", datagram + sizeof(Header));

						//Znovu odoölem dan˙ spr·vu
						header = (Header*)datagram;
						memcpy(datagram + sizeof(Header), message, strlen(message) + 1);
						header->header_info = 6;
						header->header_info += (1 << 3);

						//Explicitne zmenÌm crc
						header->crc32 = crc16((char*)header, strlen((char*)header));

						printf("##############################\n");
						printf("Fragment: %d\n", extract(header->header_info, 3, 15));

						if (sendto(s, (char*)datagram, sizeof(Header) + frag_len, 0, (struct sockaddr*)&client_in, sizeof(client_in)) == SOCKET_ERROR) {
							printf("Nepodarilo sa odoslat spravu serveru\n");
						}

						printf("Resend bol uspesne odoslany\n");
					}
					else {
						//Nastavenie procesu fragment·cie s pomocn˝m poæom na znovuodoslanie ramcov
						//Inicializovanie random number generator
						srand(time(NULL));

						sequence = strlen(message);
						fragment = 1;

						if ((resend = (int*)calloc(frag_num , sizeof(int))) == NULL) {
							printf("Nepodarilo sa inicializovat pole na resend datagramov\n");
						}


						while (sequence > 0) {

							memcpy(datagram + sizeof(Header), message + (fragment - 1)*frag_len, frag_len);

							sequence -= frag_len;

							printf("##############################\n");
							printf("Fragment %d\n", fragment);
							printf("Velkost fragmentu: %d\n", frag_len);
							printf("Sprava: %.*s\n", frag_len, datagram + sizeof(Header));

							header->header_info = (fragment << 3) + 6;

							//Ak je pravdopodnosù niûöia ako error rate - odoöleme chybn˝ r·mec
							if (rand() % 100 <= error_rate) {
								header->crc32 = crc16((char*)datagram, strlen((char*)header));
								header->crc32 += 1;
							}
							else {
								header->crc32 = crc16((char*)datagram, strlen((char*)header));
							}

							
							fragment++;

							if (sendto(s, datagram, frag_len + sizeof(Header), 0, (struct sockaddr *) &client_in, sizeof(client_in)) == SOCKET_ERROR)
							{
								printf("Nepodarilo sa odoslaù datagram %d\n", fragment);
								break;
							}
						}

						//N·sledne budeme prÌjmaù Resend Ë. datagramov od servera
						//Najprv odoöle poËet vyûiadan˝ch r·mcov

					}
				}
			}

			free(init);
			free(datagram);
			free(message);

			message = datagram = NULL;
			pthread_cond_broadcast(&cond); 
		}

		//Odoslanie s˙boru
		if (choice == 3) {

			FILE *f = NULL;
			char save[256] = "";

			printf("Zadajte subor na odoslanie\n");									//NaËÌtanie s˙boru
			scanf("%s", path);

			printf("Zadajte nazov pre odosielany subor\n");
			scanf("%s", save);
			
			if ((f = fopen(path, "rb")) == NULL) {
				printf("Subor sa nepodarilo otvorit\n");
				pthread_cond_broadcast(&cond);
				continue;
			}

			fseek(f, 0, SEEK_END);													//NaËÌtanie veækosti s˙boru
			file_size = ftell(f);
			fseek(f, 0, SEEK_SET);
			printf("Velkost suboru je %d\n", file_size);


			if ((message = (unsigned char*)calloc((file_size + 10), sizeof(unsigned char))) == NULL) {
				printf("Nepodarilo sa alokovat pamat pre spravu\n");
				fclose(f);

				//pthread_cond_broadcast(&cond);
				continue;
			}

			if ((datagram = (unsigned char*)malloc((sizeof(Header) + 1 + frag_len) * sizeof(unsigned char))) == NULL) {
				printf("Nepodarilo sa alokovaù pamate pre datagram\n");
				fclose(f);
				free(message);
				pthread_cond_broadcast(&cond);
				continue;
			}

			//Odoölem inicializaËn˝ paket na s˙bor
			int fread_status = fread(message, file_size, 1, f);

			if (fread_status < 0) {
				printf("Nie je mozne nacitat subor - fread Error\n");
				free(datagram);
				free(message);
				pthread_cond_broadcast(&cond);
				continue;
			}

			//printf("Nacitana sprava je %s\n", message);

			//ZakÛdovanie a odosielanie s˙boru
			//UrËÌme poËet fragmentov a zakÛdovanie
			/*if (strlen(message) % frag_len == 0) {
				frag_num = strlen(message) / frag_len;
			}
			else {
				frag_num = strlen(message) / frag_len;
				frag_num += 1;
			}*/

			if (file_size % frag_len == 0) {
				frag_num = file_size / frag_len;
			}
			else {
				frag_num = file_size / frag_len;
				frag_num += 1;
			}

			//Fragment·cia s˙boru s odoslanÌm init datagramu
			Header *init = (Header*)malloc(sizeof(Header));

			init->header_info = (frag_num << 15) + (frag_len << 3) + 4;
			strcpy(init->data, save);
			printf("Header info %ld\n", init->header_info);
			init->crc32 = crc16((char*)init, strlen((char*)init));
			printf("Frag length %d calc %ld\n", frag_len, extract(init->header_info, 3, 15));
			printf("Fragments %d calc %ld\n", frag_num, extract(init->header_info, 15, 45));

			if (sendto(s, (char*)init, sizeof(Header), 0, (struct sockaddr*)&client_in, sizeof(client_in)) == SOCKET_ERROR) {
				printf("Nepodarilo sa odoslat init spravu serveru\n");
				free(datagram);
				free(message);
				message = datagram = NULL;
				continue;
			}

			header = (Header*)datagram;

			//sequence = strlen(message);
			sequence = file_size;
			//printf("Strlen mssg %d file_size %d\n", sequence, file_size);
			fragment = 1;
			unsigned long long a = 1,
				b = 2,
				c;

			//printf("Loaded message %s\n", message);

			while (sequence > 0) {

				memset(datagram + sizeof(Header), '\0', frag_len);

				if (sequence <= frag_len) {

					header->header_info = 5 + (b << 33) + (fragment << 3);		//Koniec s˙boru

					//ZakÛdujeme min velkost
				}
				else {
					header->header_info = (a << 33) + (fragment << 3) + 5;		//Nie je koniec - defragmentujeme
				}

				//Fragmentovanie
				memcpy(datagram + sizeof(Header), message + (fragment - 1)*frag_len, min(frag_len, sequence));

				sequence -= frag_len;

				printf("##############################\n");
				//printf("Message to sent %s\n", datagram + sizeof(Header));
				//printf("Header %lld\n", header->header_info);
				//printf("Fragment %d\n", fragment);
				//printf("Velkost fragmentu: %d\n", frag_len);

				//Kontrola
				printf("Messg status %d\n", header->header_info & 7);
				printf("Fragment num %ld\n", extract(header->header_info, 3, 33));
				printf("Send status %ld\n", (header->header_info >> 33) & 3);

				header->crc32 = crc16((char*)datagram, strlen((char*)header));


				if (sendto(s, datagram, frag_len + sizeof(Header), 0, (struct sockaddr *) &client_in, sizeof(client_in)) == SOCKET_ERROR)
				{
					printf("Nepodarilo sa odoslaù datagram %d\n", fragment);
					break;
				}


				if (recvfrom(s, buff, BUFFLEN, 0,(struct sockaddr*) &si_other, &slen) == SOCKET_ERROR) {
					printf("Nedostal ACK od servera");
					return;
				}

				Header *tmp = (Header*)buff;
				c = tmp->header_info >> 3;
				printf("Sprava: %s\n", tmp->data);


				//Status spr·vy 5 je ACK 
				if (!strcmp("Acknowledged", tmp->data)) {
					//Acknowledged
					fragment++;
					continue;
				}
				else {
					printf("Dozadovany ack %ld\n", c);
					while (TRUE) {
						
						if (sendto(s, datagram, frag_len + sizeof(Header), 0, (struct sockaddr *) &client_in, sizeof(client_in)) == SOCKET_ERROR)
						{
							printf("Nepodarilo sa odoslaù datagram %d\n", fragment);
							break;
						}

						if (recvfrom(s, buff, BUFFLEN, 0, (struct sockaddr*) &si_other, &slen) == SOCKET_ERROR) {
							printf("Nedostal ACK od servera");
							return;
						}
						tmp = (Header*)buff;

						c = tmp->header_info >> 3;

						if ((tmp->header_info & 3) == 5) {
							printf("ACK od servera %s\n", tmp->data);
							break;
						}
	
					}
				}

				fragment++;
			}

			printf("Sprava bola uspesne odoslana\n");
			printf("##############################\n");


			fclose(f);
			pthread_cond_broadcast(&cond);
		}
	}

	//Uzavretie socketu po skonËenÌ rel·cie
	closesocket(s);
}

int main(void){
	int choice = 0,
	attempts = 3;

	//Winsock inicializ·cia
	WSADATA datad;

	if (WSAStartup(MAKEWORD(2, 2), &datad) != 0) {
		printf("Winsock inicializacia neuspesna\n");
		return -1;
	}

	//⁄vodnÈ menu
	user_interface();

	//Hlavn˝ flow 
	while (attempts) {

		scanf("%d", &choice);


		if (choice != 1 && choice != 2 && choice != 3) {
			printf("Nespravny zadany argument\n");
			attempts--;

			if (attempts == 0) {
				printf("Program bude ukonceny\n");
				break;
			}
			continue;
		}

		//Spustenie v reûime klienta
		if (choice == 1) {
			client();

		}//Server reûim
		else if (choice == 2) {
			server();
		}
		else if (choice == 3) {
			printf("Program bude ukonceny\n");
			return 0;
		}

		user_interface();

	}
}
