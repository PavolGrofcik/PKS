/*
*	Pavol GrofËÌk
*	Projekt	2
*/



#define HAVE_STRUCT_TIMESPEC

#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>

#include <pthread.h>
#include <WinSock2.h>

#pragma comment(lib,"ws2_32.lib")
#define PORT 8888



int klient_n = 0,
server_n = 0;

void* read(void *nothing) {
	scanf("%d", &klient_n);
	pthread_exit(NULL);
	return NULL;
}


int main(void) {
	
	int choice;
	WSADATA wsa;

	//Inicializ·cia Winsock-u
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}


	//V˝ber sieùovÈho modulu
	while (1) {

		printf("\n***************************************\n");
		printf("                 Vitajte!                \n");
		printf("      Udp client - moznost  1\n");
		printf("      Udp server - moznost  2\n");
		printf("      Na ukoncenie programu 3\n");
		printf("\n***************************************\n");

		scanf("%d", &choice);

		if (choice < 0 || choice > 3) {
			printf("Nespravny argument\n");
			break;
		}
		else if (choice == 1) {
			//klient
			klient_n = 0;
			int s;
			short port;
			struct sockaddr_in si_other;
			char IP[13];
			char Message[100];
			char Buff[512];


			if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR) {
				printf("Socket failed\n");
				break;
			}
			/*while (1) {
				//NaËÌtanie portu
				printf("Zadajte  port\n");
				scanf("%hi", &port);
				if (port < 1024) {
					printf("Nespravny port\n");
					continue;
				}
				else {
					break;
				}
			}*/

			memset((char *)&si_other, 0, sizeof(si_other));
			si_other.sin_family = AF_INET;
			si_other.sin_port = htons(PORT);
			//printf("Zadajte IP adresu\n");
			//scanf("%s", IP);
			//Inet_Pton(AF_INET, IP, &(si_other.sin_addr.S_un.S_addr));
			si_other.sin_addr.S_un.S_addr = inet_addr("169.254.90.159");
			

			pthread_t klient;
			pthread_create(&klient, NULL, read, NULL);
			//pthread_join(klient, NULL);

			//ZaËiatok komunik·cie
			while (1) {
				fflush(stdout);
				printf("Enter a message\n");
				gets(Message);
				memset(Buff, '\0', 512);
				if (!strcmp(Message, "exit")) {
					//logout 
					break;
				}

				sendto(s, Message, strlen(Message), 0, (struct sockaddr*)&si_other, sizeof(si_other));
				
				recvfrom(s, Buff, 512, 0, (struct sockaddr *)&si_other, sizeof(si_other));
				puts(Buff);
			}
			closesocket(s);
		}
		else if (choice == 2) {
			//Server kod
			server_n = 0;

			SOCKET s;
			struct sockaddr_in server, si_other;
			int slen, recv_len, port;
			char buf[512];

			slen = sizeof(si_other);

			if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
			{
				printf("Could not create socket : %d", WSAGetLastError());
			}
			printf("Socket created.\n");

			while (1) {
				//NaËÌtanie portu
				printf("Zadajte  port\n");
				scanf("%d", &port);
				if (port < 1024) {
					printf("Nespravny port\n");
					continue;
				}
				else {
					break;
				}
			}

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
			pthread_t second;
			pthread_create(&second, NULL, read, NULL);
			while (1)
			{
				printf("Waiting for data...");
				fflush(stdout);
				
				if (klient_n != 0 || server_n != 0) {
					printf("Zmena sietoveho modulu");
					break;
				}

				//clear the buffer by filling null, it might have previously received data
				memset(buf, '\0', 512);

				//try to receive some data, this is a blocking call
				if (klient_n != 0 || server_n != 0 || (recv_len = recvfrom(s, buf, 512, 0, (struct sockaddr *) &si_other, &slen)) == SOCKET_ERROR)
				{
					break;
				}

				//print details of the client/peer and the data received
				printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
				printf("Data: %s\n", buf);

				//now reply the client with the same data
				if (sendto(s, buf, recv_len, 0, (struct sockaddr*) &si_other, slen) == SOCKET_ERROR)
				{
					printf("sendto() failed with error code : %d", WSAGetLastError());
					exit(EXIT_FAILURE);
				}
			}
			pthread_cancel(second);
			closesocket(s);
		}
		else if (choice == 3) {
			printf("Program bude ukonceny\n");
			break;
		}
	
	
	}
	
	WSACleanup();
	return 0;
}