#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
 
typedef unsigned short int u16;

unsigned short in_cksum(unsigned short *ptr, int nbytes);

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		printf("uso: %s <IP origem> <IP destino>\n", argv[0]);
		exit(0);
	}
	 
	unsigned long saddr;//endreco de origem
	unsigned long daddr;//endereco de destino

	char* buffer;//buffer que sera usado na recepcao dos dados
	int addrlen;//tamanho da struct que contem o endereco de destino
	
	saddr = inet_addr(argv[1]);//atribuindo o endereco de origem
	daddr = inet_addr(argv[2]);//atribuindo o endereco de destino

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
	ip->ttl = 1;//ttl
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
	if (recvfrom(sockfd, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)&servaddr, &addrlen) == -1)
	{
		perror("Falha ao receber\n");
	}
	else
	{
		//criando um ponteiro
		//para o cabecalho do 
		//protocolo IP, contido
		//dentro do buffer
		struct iphdr* ip_reply;
		ip_reply = (struct iphdr*) buffer;

		//convertendo o endereco IP
		//para string
		char str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip_reply->saddr), str, INET_ADDRSTRLEN);
		printf("Mensagem recebida de --> %s\n", str);
	}
 
	free(packet);
	free(buffer);
	close(sockfd);
	 
	return (0);
}
 
/*
	Calculo do checksum
*/
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
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
