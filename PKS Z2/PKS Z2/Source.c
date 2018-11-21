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
#define IPLEN 16					//D�ka IP adresy
#define BUFFLEN 100000				//Max ve�kos� bufferu
#define LINE_LEN 1024				//Max d�ka riadku pri na��tan�
#define FRAGMENT_SIZE 1500			//Ve�kos� fragmentu
#define ESTABLISHED 2				//Status pre nadviazanie spojenia
#define OFF1		3				//OFFSET 1
#define LOCALHOST "127.0.0.1"		//Localhost

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

int connection;


//Hlavi�ka
typedef struct header {
	unsigned long long header_info;

	char data[32];
	unsigned int crc32;
}Header;


//�trukt�ra na keep alive
typedef struct keep{

	char ip[IPLEN];
	int port;
}Keep;

//Funkcia zobraz� �vodn� interface s choices
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

//Funkcia sl��i na v�po�et CRC16 hashu
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

//Funkcia sl��i na extrakciu d�t
unsigned short extract(unsigned short value, int begin, int end)
{
	unsigned short mask = (1 << (end - begin)) - 1;
	return (value >> begin) & mask;
}

//Funkcia inicializuje ve�kos� init segmentu
char* handshake(int frag_size) {
	char *new = (char*)malloc(sizeof(Header) + ESTABLISHED + 1);

	if (!new) {
		return NULL;
	}
	else {
		return new;
	}
}

//Funkcia na��ta do buffra spr�vu
void load_message(char *message) {

	int counter;
	char buff[LINE_LEN];

	while (TRUE) {

		fgets(buff, LINE_LEN, stdin);
		if (buff[0] == 0 || buff[1] == 0) {
			break;
		}

		counter = 0;
		//Preokop�rovanie spr�v do datagramu
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


//Funkcia zist� connection status klienta a servera
int find_conn_status() {
	int status = 0;

	pthread_mutex_lock(&mutex);
	status = connection;
	pthread_mutex_unlock(&mutex);

	return status;
}

//Funkcia na udr�ianie spojenia
void* keep_alive(void *arg) {

	int status, s,
		slen;
	char buff[LINE_LEN];

	struct sockaddr_in s_in, s_other;
	Keep *data = (Keep*)arg;
	Header *h = (Header*)malloc(sizeof(Header));

	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s == SOCKET_ERROR) {
		printf("Nepodarilo sa inicializova� vlakno\n");
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

			//Odo�leme Keep_Alive r�mec
			if (sendto(s, (char*)h, sizeof(Header), 0, (struct sockaddr*) &s_in, sizeof(s_in)) == SOCKET_ERROR) {
				printf("Nepodarilo sa odoslat keep alive - ukoncenie spojenia\n");
				pthread_exit(NULL);
			}
			else {

				Sleep(5000);		//Usp�m na 10 sek�nd
				status = find_conn_status();

				if (status == -1) {
					pthread_exit(NULL);
				}
			}
		}
		else {
			//Inak sa vl�kno usp� a bude �aka� na sign�l o ukon�en� prenosu
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

			Sleep(5000);

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

//Funkcia inicializuje spr�vu na prijatie
char* message_init() {
	char *new = (char*)malloc(sizeof(char));

	new[0] = "\0";

	return new;
}

//Funkcia defragmentuje dan� spr�vu a pripoj� prijat� �as�
char* defragment(char *buffer, char* message, int frag_size) {
	int messg_len = strlen(message);

	char *new = (char*)malloc((messg_len + frag_size + 1) * sizeof(char));

	strncpy(new, message, messg_len);
	memcpy(new + messg_len, buffer + sizeof(Header), frag_size);
	new[messg_len + frag_size] = '\0';

	free(message);

	return new;
}


//Funkcia pre server a jeho v�etky komponenty
void server() {
	SOCKET s;
	struct sockaddr_in server_in, si_other;

	int recv_len, slen, port,
		status,
		si_other_len,
		attempts = 3,
		mesg_status,
		frag_len,
		crc_check;

	char buff[BUFFLEN],
		*message = NULL;

	time_t start, end;

	Header *header = NULL;

	//Vytvorenie socketu
	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s == -1) {
		printf("Nepodarilo sa inicializovat socket\n");
		return -1;
	}

	//�vodn� menu pre server so zadan�m portu
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

	//Nabinodovanie socketu pod�a zadan�ho portu
	if (bind(s, (struct sockaddr*) &server_in, sizeof(server_in)) == SOCKET_ERROR) {
		printf("Neuspesna inicializiacia servera\n");
		closesocket(s);
		return -3;
	}
	else {
		printf("Uspesna inicializacia servera\n");
	}

	//Listening rel�cie medzi klientom
	si_other_len = sizeof(si_other);
	message = (char*)malloc(sizeof(char));
	message[0] = '\0';

	//Prebiehanie hlavnej rel�cia medzi serverom a klientom
	while (TRUE) {

		memset(buff, '\0', BUFFLEN);
		//�akanie na spojenie s klientom
		if ((status = recvfrom(s, buff, BUFFLEN, 0, (struct sockaddr*) &si_other, &si_other_len)) == SOCKET_ERROR) {
			printf("Neuspesny receive\n");
			return -4;
		}

		//Pretypovanie  na hlavi�ku
		header = (Header*)buff;

		//Zobrazenie adresy odosielate�a
		printf("#########################\n");
		printf("Received packet from %s\n", inet_ntoa(si_other.sin_addr));

		//Ur�enie typu spr�vy
		mesg_status = header->header_info & 7;
		printf("Messg status is %d\n", mesg_status);

		//Ak bolo po�iadanie o ukon�enie spojenia
		if (mesg_status == 0) {

			printf("\n#########################\n");
			printf("Message: %s\n", header->data);
			crc_check = crc16((char*)header, strlen((char*)header));
			printf("Header crc is %d calculated is %d\n", header->crc32, crc_check);

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
			//Prijate spr�vy
			printf("\n#########################\n");
			printf("Message: %s\n", header->data);
			printf("Header info %d\n", header->header_info);
			frag_len = extract(header->header_info, 3, 20);
			printf("Frag len je %d\n", frag_len);
		}
		else if (mesg_status == 2) {

			message = defragment(buff, message, frag_len);
		}
		else if (mesg_status == 3) {
			printf("Message crc %d cal %d\n", header->crc32, crc16((char*)header, strlen((char*)header)));
			message = defragment(buff, message, frag_len);
			printf("Message: %s\n", buff + sizeof(Header));
			printf("Message defragmented is %s\n", message);

			free(message);
			message = NULL;
			message = message_init();
		}
		else if (mesg_status == 7) {
			printf("Keep Alive :)\n");
		}
	}

	//Uzavretie socketu po skon�en� rel�cie
	closesocket(s);
}


//Funkcia na inicializ�ciu klienta a jeho komponentov
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
		frag_num;

	pthread_t t;
	Keep *data = NULL;

	struct sockaddr_in client_in, si_other;
	char buff[BUFFLEN],
		ip[IPLEN],
		*message = NULL,
		*init_msg = NULL,
		*datagram = NULL;

	//Header na odosielanie d�t
	Header *header = NULL;

	//Vytvorenie socketu
	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s == -1) {
		printf("Nepodarilo sa inicializovat socket\n");
		return -1;
	}

	//�vodn� okno pre klienta
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

	//Zadanie ve�kosti fragmentu
	while (attempts) {
		printf("Zadajte velkost fragmentu\n");
		scanf("%d", &frag_len);

		//O�etrenie �i klient zadal spr�vnu ve�kost fragmentu
		if (frag_len<= 0 || frag_len >= FRAGMENT_SIZE) {
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

	//Nabindovanie socketu pod�a zadanej IP
	if (inet_pton(AF_INET, ip, &client_in.sin_addr) == 0) {
		printf("Neuspesne vytvorenie socketu s danou IP %s\n", ip);
		return -3;
	}
	
	//Vytvorenie init segmentu pri nadviazan� spojenia
	init_msg = handshake(frag_len);
	slen = sizeof(si_other);

	if (!init_msg) {
		printf("Inicializacia spravy zlyhala\n");
		return -4;
	}

	//Inicializ�cia vl�kna na udr�ianie spojenia
	data = (Keep*)malloc(sizeof(Keep));
	strcpy(data->ip, ip);
	data->port = port;

	if (pthread_create(&t, NULL, keep_alive, (void*)data) != 0) {
		printf("Nepodarilo sa inicializova� keep_alive vlakno\n");
	}

	header = (Header*)init_msg;
	//Zak�dovanie z�kladn�ch inform�ci�
	//Posun o 4 bity !!!
	header->header_info = frag_len << 4;

	//Naviazanie rel�cie medzi serverom
	while (TRUE) {

		//Pri ne�innosti klienta - Keep Alive
		connection = 0;

		//Na��tanie spr�vy
		printf("Zadajte 0 - odhlasenie klienta\n");
		printf("Zadajte 1 - odoslanie spravy\n");
		printf("Zadajte 2 - odoslanie chybneho datagramu\n");
		printf("Zadajte 3 - odoslanie suboru\n");
		scanf("%d", &choice);

		connection = 1;
	
		//Odhlasenie klienta
		if (choice == 0) {
			//Klient sa chce odhl�si�
			connection = -1;

			Header *h = (Header*)malloc(sizeof(Header));

			strcpy(h->data, "End  of Connection");
			h->header_info = 0;
			h->crc32 = crc16((char*)h, strlen((char*)h));

			//Odoslanie ukon�enie spojenia serveru
			if (sendto(s, (char*)h, sizeof(Header), 0, (struct sockaddr*) &client_in, sizeof(client_in)) == SOCKET_ERROR) {
				printf("Nepodarilo sa odoslat ukoncenie spojenia\n");
			}

			free(h);
			h = NULL;

			//Klient mus� prija� ACK od serveru u ukon�en� spojenia
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

		//Na��tanie a odoslanie spr�vy
		if (choice == 1 || choice == 2) {
			printf("Zadajte spravu\n");

			getc(stdin);

			message = (char*)malloc(BUFFLEN * sizeof(char));
			memset(message, '\0', BUFFLEN);

			//load_message(message);
			gets_s(message, BUFFLEN);
			printf("Sprava je %s\n", message);

			//Alok�cia datagramu na odoslanie a pretypovanie na typ Header
			datagram = (char*)malloc((sizeof(Header) + frag_len + 1) * sizeof(char));
			header = (Header*)datagram;

			//Odo�lem �vodn� datagram na upovedomenie �e ide o spr�vu
			//Z�rove� ve�kos� fragmentu
			Header *init = (Header*)malloc(sizeof(Header));
			frag_num = strlen(message) / frag_len;
			frag_num << 3;

			init->header_info = (frag_len << 3)  + 1;
			strcpy(init->data, "Zaciatok posielania spravy");
			printf("Header info %ld\n", init->header_info);
			printf("Header frag_len %d calc %d\n", frag_len, extract(init->header_info, 3, 20));
			init->crc32 = crc16((char*)init, strlen((char*)init));

			if (sendto(s, (char*)init, sizeof(Header), 0, (struct sockaddr*)&client_in, sizeof(client_in)) == SOCKET_ERROR) {
				printf("Nepodarilo sa odoslat init spravu serveru\n");
				free(datagram);
				free(message);
				message = datagram = NULL;
				continue;
			}

			//Odoslanie spr�vy
			if (choice == 1) {

				//Odo�leme naraz
				if (strlen(message) + sizeof(Header) <= frag_len) {

					memcpy(datagram + sizeof(Header), message, strlen(message)+1);
					header->header_info = 3;
					header->crc32 = crc16((char*)header, strlen((char*)header));
					
					if (sendto(s, (char*)datagram, sizeof(Header) + frag_len , 0, (struct sockaddr*)&client_in, sizeof(client_in)) == SOCKET_ERROR) {
						printf("Nepodarilo sa odoslat spravu serveru\n");
					}
				}
				else {
					//Mus�m nastavi� fragment�ciu pod�a zvolenej ve�kosti hlavi�ky a n�sledne znovuposlanie r�mcov
					sequence = strlen(message);
					fragment = 1;


					//Rozfragmentovanie a n�sledn� odosielanie
					while (sequence) {

						//Ur�enie stavu odosielania
						if (sequence <= frag_len) {
							header->header_info = 3;		//Posledn� fragment
						}
						else {
							header->header_info = 2;
						}

						memcpy(datagram + sizeof(Header), message + (fragment-1) * frag_len, min(frag_len,sequence));
						
						sequence -= frag_len;

						//Zak�dovanie header sequence number
						header->header_info += (fragment << 3);
						header->crc32 = crc16((char*)datagram, strlen((char*)header));
						fragment++;

						if (sendto(s, datagram, frag_len + sizeof(Header), 0, (struct sockaddr *) &client_in, sizeof(client_in)) == SOCKET_ERROR)
						{
							printf("Nepodarilo sa odosla� datagram %d\n", fragment);
							continue;
						}
					}
				}
			}

			free(init);
			free(datagram);
			free(message);

			message = datagram = NULL;
			pthread_cond_broadcast(&cond);
		}

		if (choice == 3) {
			//Simulujem prenos rel�cie
			Sleep(15000);
			pthread_cond_broadcast(&cond);
		}
	}

	//Uzavretie socketu po skon�en� rel�cie
	closesocket(s);
}

int main(void){
	int choice = 0,
	attempts = 3;
	
	printf("Sizeof header is %d\n", sizeof(Header));

	//Winsock inicializ�cia
	WSADATA datad;

	if (WSAStartup(MAKEWORD(2, 2), &datad) != 0) {
		printf("Winsock inicializacia neuspesna\n");
		return -1;
	}

	//�vodn� menu
	user_interface();

	//Hlavn� flow 
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

		//Spustenie v re�ime klienta
		if (choice == 1) {
			client();

		}//Server re�im
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

/*
#define BUFLEN 200000  //Max length of buffer
//#define PORT 8888   //The port on which to listen for incoming data
//#define SERVER "127.0.0.1"  //ip address of udp server

typedef struct Header {
	unsigned crc;
	int info;
	int poradie;
	int velkost;
}Header;


char SERVER[15] = "";
unsigned int PORT = 0;
int velkostF = 0;
int velkostPrijmacieho = 0;

bool prijataVelkost = false;




char *appendMessage(char *buf, char *message, int size) {
	int len = strlen(message);
	char *tmp = (char*)malloc((len + size + 1) * sizeof(char));

	strncpy(tmp, message, len);
	memcpy(tmp + len, buf + sizeof(Header), size);
	tmp[len + size] = '\0';
	free(message);
	return tmp;

}

//https://stackoverflow.com/questions/15169387/definitive-crc-for-c
unsigned crc(unsigned char const *data, int len)
{
	unsigned crc = 0;
	if (data == NULL)
		return 0;
	crc = ~crc & 0xff;
	while (len--) {
		crc ^= *data++;
		for (unsigned k = 0; k < 8; k++)
			crc = crc & 1 ? (crc >> 1) ^ 0xb2 : crc >> 1;
	}
	return crc ^ 0xff;
}

void *server(void *arg)
{
	SOCKET s;
	struct sockaddr_in server, si_other;
	int slen, recv_len;
	char buf[BUFLEN];
	WSADATA wsa;
	char vysledny[99999];
	int vysledna = 0;
	Header *header = NULL;


	slen = sizeof(si_other);

	char *message = (char*)malloc(10);
	message[0] = '\0';

	//Initialise winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	printf("Initialised.\n");

	//Create a socket
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
	}
	printf("Socket created.\n");

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(PORT);

	//Bind
	if (bind(s, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
	{
		printf("Bind failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	puts("Bind done");

	//keep listening for data
	while (1)
	{
		//printf("Waiting for data...\n");
		//fflush(stdout);

		//clear the buffer by filling null, it might have previously received data
		memset(buf, '\0', BUFLEN);

		//try to receive some data, this is a blocking call
		if ((recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == SOCKET_ERROR)
		{
			printf("recvfrom() failed with error code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}

		//print details of the client/peer and the data received

		//printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
		header = (Header*)buf;


		unsigned testcrc;

		testcrc = crc(((const unsigned char*)header) + sizeof(unsigned), header->velkost + sizeof(Header) - sizeof(unsigned));
		if (testcrc != header->crc) {
			//printf("s CRC FAILED %d ... %d... %d... %d - %s %d\n", header->crc, header->info, header->poradie, header->velkost, buf, recv_len);

			Header err;
			err.info = 3;
			err.poradie = 0;
			err.velkost = 0;
			err.crc = crc(((const unsigned char*)&err) + sizeof(unsigned), sizeof(Header) - sizeof(unsigned));


			if (sendto(s, (char*)&err, sizeof(Header), 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
			{
				printf("sendto() failed with error code : %d", WSAGetLastError());
				exit(EXIT_FAILURE);
			}
			continue;
		}
		//printf("s wtf %d ... %d... %d... %d - %c %d\n", header->crc, header->info, header->poradie, header->velkost, buf[sizeof(Header)], recv_len);

		if (header->info == 1 || header->info == 2) {
			message = appendMessage(buf, message, header->velkost);
			//printf("message: %s\n", message);
		}

		if (header->info == 2) { printf("Message full: %s \n", message); message[0] = '\0'; }



		Header conf;
		conf.info = 4;
		if (header->info == 8) {
			conf.info = 9;
			
		}
		conf.poradie = 0;
		conf.velkost = 0;
		conf.crc = crc(((const unsigned char*)&conf) + sizeof(unsigned), sizeof(Header) - sizeof(unsigned));

		//now reply the client with the same data
		if (sendto(s, (char*)&conf, sizeof(Header), 0, (struct sockaddr*) &si_other, slen) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}
		if (header->info == 8) { printf("Spojenie bolo ukoncene\n"); break; }
	}

	closesocket(s);
	WSACleanup();

	return 0;
}

void *klient(void *arg)
{
	Header *header = NULL;
	struct sockaddr_in si_other;
	int s, slen = sizeof(si_other);
	char buf[BUFLEN];
	char message[BUFLEN];
	char *packet;
	char *posielany;
	bool chyba = false;

	WSADATA wsa;

	//Initialise winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	printf("Initialised.\n");

	//create socket
	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
	{
		printf("socket() failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	//setup address structure
	memset((char *)&si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);
	si_other.sin_addr.S_un.S_addr = inet_addr(SERVER);

	//start communication


	//Treba o�etri� pod�a ve�kosti fragmentu 1514 Bytes on Link layer
	//Prerobi�
	printf("Zadaj velkost fragmentu:");
	gets_s(message,1500);
	posielany = (char*)malloc((atoi(message) + sizeof(Header) + 1) * sizeof(char));
	header = (Header*)posielany;
	header->velkost = atoi(message);

	//packet = (char*)malloc((header->velkost + 1) * sizeof(char));


	while (1)
	{
		printf("Enter message : ");

		gets_s(message, BUFLEN);
		//header->velkost = strlen(message);
		header->poradie = 0;

		if ((strcmp(message, "quit") == 0)) {

			Header q;
			q.info = 8;
			q.poradie = 0;
			q.velkost = 0;
			q.crc = crc(((const unsigned char*)&q) + sizeof(unsigned), sizeof(Header) - sizeof(unsigned));
			if (sendto(s, (char*)&q, sizeof(Header), 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
			{
				printf("sendto() failed with error code : %d", WSAGetLastError());
				exit(EXIT_FAILURE);
			}


			break;
		}
		if ((strcmp(message, "chyba") == 0)) {
			chyba = true;
			continue;
		}
		int poslane = 0;
		int dlzka;
		//int crc1 = 0, crc2 = 0;

		dlzka = strlen(message);

		while (dlzka > 0) {


			if (dlzka <= header->velkost) {
				header->info = 2;
			}
			else header->info = 1;

			header->poradie++;


			memcpy(posielany + sizeof(Header), message + ((header->poradie - 1) * header->velkost), min(header->velkost, dlzka + 1));


			dlzka -= header->velkost;
		sem:
			header->crc = crc(((const unsigned char*)posielany) + sizeof(unsigned), header->velkost + sizeof(Header) - sizeof(unsigned));

			if (chyba == true && dlzka <= header->velkost) { header->crc++; chyba = false; }

			//printf("k %d ... %d... %d... %d ... %c\n", header->crc, header->info, header->poradie, header->velkost, posielany[sizeof(Header)]);
			//printf("k %d ... %d... %d... %d - %c %d\n", header->crc, header->info, header->poradie, header->velkost, posielany[sizeof(Header)], header->velkost + sizeof(Header));
			//send the message
			if (sendto(s, posielany, header->velkost + sizeof(Header), 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
			{
				printf("sendto() failed with error code : %d", WSAGetLastError());
				exit(EXIT_FAILURE);
			}
			fd_set fds;
			int n;
			struct timeval tv;

			// Set up the file descriptor set.
			FD_ZERO(&fds);
			FD_SET(s, &fds);

			// Set up the struct timeval for the timeout.
			tv.tv_sec = 5;
			tv.tv_usec = 0;

			// Wait until timeout or data received.
			n = select(s, &fds, NULL, NULL, &tv);
			if (n == 0)
			{
				printf("Timeout..\n");
				goto sem;
			}
			else if (n == -1)
			{
				printf("Error..\n");
				return 0;
			}

			//receive a reply and print it
			//clear the buffer by filling null, it might have previously received data
			memset(buf, '\0', BUFLEN);
			//try to receive some data, this is a blocking call
			if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen) == SOCKET_ERROR)
			{
				printf("recvfrom() failed with error code : %d", WSAGetLastError());
				exit(EXIT_FAILURE);
			}
		tu:
			Header* h = (Header*)buf;
			if (h->info == 3) {
				printf("vyziadany resend! cislo ramca: %d\n", header->poradie);
				goto sem;

			}

			//puts(buf);

		}
	}

	closesocket(s);
	WSACleanup();

	return 0;
}


int main()
{
	
	time_t start, end;
	 long double counter = 100000;

	//printf("Zadaj velkost fragmentu:");
	//scanf("%d", &velkostF);
	//pthread_t klientVlakno, serverVlakno;

	while (1) {
		printf("Pre server zadaj 1\n");
		printf("Pre klient zadaj 2\n");
		char a;
		if ((a = getchar()) == '1') {
			getchar();
			printf("\n");
			printf("Zadaj port:");
			scanf("%d", &PORT);
			getchar();
			server(NULL);

		}
		if (a == '2') {
			getchar();
			printf("\n");
			printf("Zadaj IP adresu prijimatela:");
			scanf("%s", &SERVER);
			printf("Zadaj port:");
			scanf("%d", &PORT);
			getchar();
			klient(NULL);
		}

	}


	 //11 s keep alive
	start = clock();
	while (counter > 0) {

		counter--;
		printf("%Lf\n", counter);
	}
	end = clock();

	printf("Elapsed time %d s\n", (end - start) / 1000);
	
	return 0;
};*/