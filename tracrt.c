/* 
 * File:   main.c
 * Author: jose
 *
 * Created on 7 de Julho de 2015, 15:42
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>


typedef unsigned short int u16;

unsigned short in_cksum(unsigned short *ptr, int nbytes);

int trace(unsigned long saddr, unsigned long daddr, int ttl) {
    char consulta[300];
    int loops, continua = 1;
    int escreve = 1;
    
    for (loops = 0; loops < 3; loops++) {


        if (!ttl) {
            system("clear");
            char ip[INET_ADDRSTRLEN]; //para escrever o IP destino na tela
            inet_ntop(AF_INET, &(daddr), ip, INET_ADDRSTRLEN); //atribui o ip destino a variável "ip"

            printf("\nTraceroute para (%s), 30 hops max \n", ip);
            return trace(saddr, daddr, ttl + 1);
        }
        struct timeval inicio, final;
        int tempo_milisegundos;
        char* buffer; //buffer que sera usado na recepcao dos dados
        int addrlen; //tamanho da struct que contem o endereco de destino



        //criacao do socket
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (sockfd < 0) {
            perror("Erro ao criar o socket");
            exit(0);
        }

        int on = 1;

        //definindo que o cabecalho
        //ip sera especificado aqui
        //no codigo
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (const char*) &on, sizeof (on)) == -1) {
            perror("Erro ao definir opcao do socket");
            exit(0);
        }

        //Tamanho total do pacote formado pelo
        //tamanho dos cabecalhos IP + ICMP
        gettimeofday(&inicio, NULL);
        int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr);
        char *packet = (char *) malloc(packet_size);

        if (!packet) {
            perror("Falta de espaco na memoria");
            close(sockfd);
            return (0);
        }

        //cabecalho ip
        struct iphdr *ip = (struct iphdr *) packet;
        //cabecalho icmp
        struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));

        //preenchendo pacote com zero
        memset(packet, 0, packet_size);

        ip->version = 4; //versao
        ip->ihl = 5; //tamanho do cabecalho
        ip->tos = 0; //TypeOfService
        ip->tot_len = htons(packet_size); //tamanho total
        ip->id = rand(); //id, gerado aleatoriamente
        ip->frag_off = 0; //bit de fragmentacao
        ip->ttl = ttl; //ttl
        ip->protocol = IPPROTO_ICMP; //protocolo que sera usado (icmp)
        ip->saddr = saddr; //IP de origem
        ip->daddr = daddr; //IP de destino
        ip->check = in_cksum((u16 *) ip, sizeof (struct iphdr)); //checksum

        icmp->type = ICMP_ECHO; //tipo
        icmp->code = 0; //codigo
        icmp->checksum = in_cksum((unsigned short *) icmp, sizeof (struct icmphdr)); //checksum

        //criando struct com
        //o endereco de destino
        //para envio pelo socket
        struct sockaddr_in servaddr;
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = daddr;

        //tamanho do struct gerado
        addrlen = sizeof (servaddr);

        //envio de dados com os parametros:
        //socket a ser usado
        //pacote
        //tamanho do pacote
        //campo de opcoes
        //endereco de destino
        //tamanho da struct de endereco
        if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1) {
            perror("Falha ao enviar\n");
        }

        //alocando o buffer de recepcao dos dados
        buffer = malloc(sizeof (struct iphdr) + sizeof (struct icmphdr));
        //realizando a recepcao, com parametros semelhantes ao envio

        fd_set socks;
        struct timeval tempo;
        FD_ZERO(&socks);
        FD_SET(sockfd, &socks);
        tempo.tv_sec = 3; //tempo segundos timeout
        tempo.tv_usec = 0;
        struct iphdr* ip_reply;
        ip_reply = (struct iphdr*) buffer;


        if (select(sockfd + 1, &socks, NULL, NULL, &tempo) && recvfrom(sockfd, buffer, sizeof (struct iphdr) + sizeof (struct icmphdr), 0, (struct sockaddr *) &servaddr, &addrlen) != -1) {

            struct iphdr* ip_reply;
            ip_reply = (struct iphdr*) buffer;
            char ipAtingido[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_reply->saddr), ipAtingido, INET_ADDRSTRLEN);
            if (escreve) {


                printf("%d    FROM: %s ", ttl, ipAtingido);


            }
            escreve = 0;
            gettimeofday(&final, NULL);
            tempo_milisegundos = (float) (1000 * (final.tv_sec - inicio.tv_sec) + (final.tv_usec - inicio.tv_usec) / 1000);
            printf(" %dms ", (int) tempo_milisegundos);

            strcpy(consulta, "nslookup  '");
            strcat(consulta, ipAtingido);
            strcat(consulta, "' | grep -v '^[A-Z]' | cut -f2 | cut -d '=' -f2");
            if (ttl > 2 && loops == 0)
                //system(consulta);

            strcpy(consulta, "");
            //system("nslookup  '' | grep -v '^[A-Z]' | cut -f2 | cut -d '=' -f2");
        } else {
            printf("* ");
        }

        if (daddr == ip_reply->saddr || ttl == 30) {
            continua = 0;
        } else {

            free(packet);
            free(buffer);
            close(sockfd);
        }
    }
    printf("\n");
    if(!continua){
    	return (0);
    }else
    return trace(saddr, daddr, ttl + 1);
}

int pingReduzido(unsigned long saddr,unsigned long daddr ){
	int x;
	int atingido = 0;
	int ttl=20;
	printf("\n");
	system("clear");
    char ipDestino[INET_ADDRSTRLEN]; //para escrever o IP destino na tela
    inet_ntop(AF_INET, &(daddr), ipDestino, INET_ADDRSTRLEN); //atribui o ip destino a variável "ip"
	printf("\nDisparando dados para (%s) \n", ipDestino);
	struct timeval inicio, final;
	int tempo_milisegundos;
	int pacotesRecebidos=0 ;
	float mediaPerda=0, rttMedio=0;
	for(x=0;x<4; x++){
		gettimeofday(&inicio, NULL);
		char* buffer;//buffer que sera usado na recepcao dos dados
		int addrlen;//tamanho da struct que contem o endereco de destino

		//criacao do socket
		int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

		if (sockfd < 0)
		{
			perror("Erro ao criar o socket");
			exit(0);
		}

		int on = 1;

		//definindo que o cabecalho
		//ip sera especificado aqui
		//no codigo
		if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1)
		{
			perror("Erro ao definir opcao do socket");
			exit(0);
		}

		//Tamanho total do pacote formado pelo
		//tamanho dos cabecalhos IP + ICMP
		int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr);
		char *packet = (char *) malloc (packet_size);

		if (!packet)
		{
			perror("Falta de espaco na memoria");
			close(sockfd);
			return (0);
		}

		//cabecalho ip
		struct iphdr *ip = (struct iphdr *) packet;
		//cabecalho icmp
		struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));

		//preenchendo pacote com zero
		memset (packet, 0, packet_size);

		ip->version = 4;//versao
		ip->ihl = 5;//tamanho do cabecalho
		ip->tos = 0;//TypeOfService
		ip->tot_len = htons (packet_size);//tamanho total
		ip->id = rand ();//id, gerado aleatoriamente
		ip->frag_off = 0;//bit de fragmentacao
		ip->ttl = ttl;//ttl
		ip->protocol = IPPROTO_ICMP;//protocolo que sera usado (icmp)
		ip->saddr = saddr;//IP de origem
		ip->daddr = daddr;//IP de destino
		ip->check = in_cksum ((u16 *) ip, sizeof (struct iphdr));//checksum

		icmp->type = ICMP_ECHO;//tipo
		icmp->code = 0;//codigo
		icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));//checksum

		//criando struct com
		//o endereco de destino
		//para envio pelo socket
		struct sockaddr_in servaddr;
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = daddr;

		//tamanho do struct gerado
		addrlen = sizeof(servaddr);

		//envio de dados com os parametros:
		//socket a ser usado
		//pacote
		//tamanho do pacote
		//campo de opcoes
		//endereco de destino
		//tamanho da struct de endereco
		if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)
		{
			perror("Falha ao enviar\n");
		}

		//alocando o buffer de recepcao dos dados
		buffer = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
		//realizando a recepcao, com parametros semelhantes ao envio

		fd_set socks;
		struct timeval t;
		FD_ZERO(&socks);
		FD_SET(sockfd, &socks);
		t.tv_sec = 3; //tempo segundos timeout
		t.tv_usec = 0;

		if (select(sockfd+1, &socks, NULL, NULL, &t) &&
				recvfrom(sockfd, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)&servaddr, &addrlen)!=-1)
				{
						
						struct iphdr* ip_reply;
						ip_reply = (struct iphdr*) buffer;

						char ipAt[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &(ip_reply->saddr), ipAt, INET_ADDRSTRLEN);
						printf("Resposta de: %s ",  ipAt);
						pacotesRecebidos++;
						gettimeofday(&final, NULL);
						tempo_milisegundos = (float) (1000 * (final.tv_sec - inicio.tv_sec) + (final.tv_usec - inicio.tv_usec) / 1000);
						printf(" %dms ", (int) tempo_milisegundos);
						rttMedio+=tempo_milisegundos;
				}
		else{
				puts("esgotado tempo limite(timeout)");
				ttl+=20;
			}

		free(packet);
		free(buffer);
		close(sockfd);
		printf("\n");
	}
	mediaPerda = pacotesRecebidos/4;
	printf("\n");
	printf("\n%d pacotes enviados %d pacotes recebidos %2.2f tempo =%3.0f media de rtt: %4.2f TTL: %d\n ", x, pacotesRecebidos, mediaPerda*100, rttMedio, rttMedio/4, ttl);
	return (0);


}

int main(int argc, char **argv) {
    system("clear");
    if (argc != 2) {
        printf("uso: %s <IP destino>\n", argv[0]);
        exit(0);
    }
   pingReduzido(system("ifconfig | grep 'inet end' | awk '{print $3}' | grep -v '127'"), inet_addr(argv[1]));
    //trace(system("ifconfig | grep 'inet end' | awk '{print $3}' | grep -v '127'"), inet_addr(argv[1]), 0);
    printf("\n");
}

/*
        Calculo do checksum
 */
unsigned short in_cksum(unsigned short *ptr, int nbytes) {
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}


