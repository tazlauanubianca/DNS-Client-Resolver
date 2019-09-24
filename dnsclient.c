#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define BUFLEN 100
#define A 1 /* IPv4 address */
#define NS 2 /* Authoritative name server */
#define CNAME 5 /* Canonical name for an alias */
#define MX 15 /* Mail exchange */
#define SOA 6 /* Start Of a zone of Authority */
#define TXT 16 /* Text strings */
#define PTR 12

typedef struct
{
	unsigned short id;

	unsigned char rd :1;
	unsigned char tc :1;
	unsigned char aa :1;
	unsigned char opcode :4;
	unsigned char qr :1;
	
	unsigned char rcode :4;
	unsigned char z :3;
	unsigned char ra :1;

	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;

} dns_header_t;

typedef struct 
{
	unsigned short qtype;
	unsigned short qclass;

} dns_question_t;

typedef struct 
{
	unsigned char *name;
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
	unsigned char *rdata;

} dns_rr_t;

int usage(char* name)
{
	printf("Usage:\n\t%s <NAME>\n\t%s <TYPE>\n", name, name);
	return 1;
}

void dns_format(char dns_format_name[], char host[]) {
    int index = 0;
	char tmp[BUFLEN], copy[BUFLEN] = {0}, *token;

	strcpy(copy, host);
	token = strtok(copy, ".");

	while(token != NULL) {		
		strcpy(tmp, token);
		dns_format_name[index] = (char)strlen(tmp);
		memcpy(dns_format_name + index + 1, tmp, strlen(tmp));
		
		index += strlen(tmp) + 1;
		token = strtok(NULL, ".");
	}
}

unsigned char* decompress_name(unsigned char* start, unsigned char* buffer, int* count)
{
    unsigned char ok = 0, *decompressed_name = (unsigned char*)malloc(3 * BUFLEN * sizeof(unsigned char));
    unsigned int index = 0, offset;
	int i, j, current_count = 1;
    
	decompressed_name[0]='\0';
	
    while (*start != 0) {
		/* Pointerii la adresa o sa aibe primii doi biti 1,
		 * daca nu sunt ambii 1 atunci este vorba de parte a numelui comprimat 
		 */
		if (*start < 0xC0) { 
			decompressed_name[index] = *start;
			index++;
			start++;

			/* Daca pana acum nu s-a sarit la nicio adresa atunci datele 
			 * sunt in continuarea bufferului */
			if (ok == 0) {
				current_count++;
			}

		} else {
			/* Se calculeaza adresa la care se sarec */
			offset = (*start)*256 + *(start + 1) - 0xC000;
			start = buffer + offset;
			ok = 1;
		}
    }
 
    decompressed_name[index]='\0';
    
	if (ok == 1) {
		current_count++;
    }
 
	/* Se transforma din formatul specific dns-ului in format normal cu . */
    for (i = 0; i < strlen((const char*) decompressed_name); i++) {
        index = decompressed_name[i];
        
		for (j = 0; j < (int)index; j++) {
            decompressed_name[i]=decompressed_name[i+1];
            i++;
        }

        decompressed_name[i]='.';
    }

    decompressed_name[i-1]='\0';
	*count = current_count;

    return decompressed_name;
}


int main(int argc, char **argv)
{
	/* Se verifica daca s-a executat corect programul */
	if (argc < 3) {
		return usage(argv[0]);
	}

	char buffer[BUFLEN], *line, par_type, dns_addresses[BUFLEN][15], dns_name_format[BUFLEN] = {0},
		 parameter[BUFLEN], query[5], answer_received = 0, new_ip_address[BUFLEN], class[5];
	int nb_addresses = 0, index = 0, attempts = 0, stop = 0;
	unsigned char *start;
   	struct sockaddr_in ip_convert;
	unsigned int size;

	struct timeval *timeout = malloc(sizeof(struct timeval));
	timeout->tv_sec = 30;
	timeout->tv_usec = 0;

	dns_header_t header;
	dns_question_t question;
	dns_rr_t answer[BUFLEN];
	
	size_t len = 0;
	ssize_t read;

	FILE *f_message = fopen("message.log", "a+");
	if (f_message == NULL) { 
		perror("Eroare la fisierul de log.");
	}

	FILE *f_dns = fopen("dns.log", "a+");
	if (f_dns == NULL) { 
		perror("Eroare la fisierul de log.");
	}

	strcpy(parameter, argv[1]);
	strcpy(query, argv[2]);

	/* Se stabileste tipul de query */
	if (strcmp(argv[2], "A") == 0) {
		par_type = A;

	} else if (strcmp(argv[2], "MX") == 0){
		par_type = MX;

	} else if (strcmp(argv[2], "NS") == 0){
		par_type = NS;
		
	} else if (strcmp(argv[2], "CNAME") == 0){
		par_type = CNAME;
		
	} else if (strcmp(argv[2], "SOA") == 0){
		par_type = SOA;
		
	} else if (strcmp(argv[2], "TXT") == 0){
		par_type = TXT;
		
	} else if (strcmp(argv[2], "PTR") == 0){
		par_type = PTR;
	
	} else {
		printf("Comanda gresita\n");
	}

	/* Citirea datelor din fisier */
	FILE *f = fopen("dns_servers.conf", "rt");
	if (f == NULL) {
		perror("Eroare la deschiderea fisierului");
	}
	
	while ((read = getline(&line, &len, f)) != -1) {
		if (line[0] != '#' && read > 1) {
			memcpy(dns_addresses[nb_addresses], line, read - 1);
			nb_addresses++;
		}
	}

	if (feof(f)) {
		fclose(f);
	
	} else {
		perror("Eroare la citirea din fisier.");
  	}
	
	printf("\n");

	/* Se realizeaza conexiunea pentru UDP */
	struct sockaddr_in to_station;

	/* Deschidere socket UDP */
	int sockfd_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd_udp == -1) {
		perror("Eroare la deschiderea socket-ului UDP");
	}

	/* Setare struct sockaddr_in pentru a specifica unde trimit datele */
	to_station.sin_family = AF_INET;
	to_station.sin_port = htons(53);
	
	/* Se completeaza header-ul */
	header.id = (unsigned short) htons(getpid());
	header.qr = 0;
	header.opcode = 0;
	header.aa = 0;
	header.tc = 0;
	header.rd = 1;
	header.ra = 0;
	header.z = 0;
	header.rcode = 0;
	header.qdcount = htons(1);
	header.ancount = 0;
	header.arcount = 0;
	header.nscount = 0;

	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, &header, sizeof(dns_header_t));

	/* Se stabileste numele folosit la cautare in functie de tipul cautarii */
	if (par_type != PTR) {
		memset(dns_name_format, 0, sizeof(dns_name_format));
		dns_format(dns_name_format, parameter);

	} else {
		char tmp[BUFLEN], *addr1, *addr2, *addr3, *addr4;
		char *token;

		memcpy(tmp, parameter, strlen(parameter));

		token = strtok(tmp, ".");
		addr1 = token;
		token = strtok(NULL, ".");
		addr2 = token;
		token = strtok(NULL, ".");
		addr3 = token;
		token = strtok(NULL, ".");
		addr4 = token;

		sprintf(new_ip_address, "%s.%s.%s.%s.in-addr.arpa", addr4, addr3, addr2, addr1);
		dns_format(dns_name_format, new_ip_address);
	}

	/* Se copiaza in buffer numele cautat */
	memcpy(buffer + sizeof(dns_header_t), dns_name_format, strlen(dns_name_format) + 1);

	/* Se completeaza intrebarea adresata DNS-ului */
	question.qclass = htons(1);
	question.qtype = htons(par_type);
	
	memcpy(buffer + sizeof(dns_header_t) + 1 + strlen(dns_name_format), &question, sizeof(dns_question_t));
	size = sizeof(dns_header_t) + strlen(dns_name_format) + sizeof(dns_question_t) + 1;	

	for (int i = 0; i < size; i++) {
		fprintf(f_message, "%02x ", (unsigned char) buffer[i]);
	}

	fprintf(f_message, "\n");

	/* Organizarea file-descriptor-ilor */
    fd_set read_fds;
    fd_set tmp_fds;

    FD_ZERO(&read_fds);
    FD_ZERO(&tmp_fds);

    FD_SET(sockfd_udp, &read_fds);
	
	unsigned char *buf = malloc(100000);
	memset(buf, 0, 100000);

	/* Se trimite cererea la cate un server pana primeste raspuns de la unul din ei */
	while (index < nb_addresses && answer_received == 0) {
		to_station.sin_addr.s_addr = inet_addr(dns_addresses[index]);
		fprintf(f_dns, "; %s - %s %s\n\n", dns_addresses[index], parameter, query);

 		while ((attempts < 3) && (answer_received == 0)) {
			tmp_fds = read_fds;

			int send_check = sendto(sockfd_udp, buffer, size, 0, (struct sockaddr *) &to_station, sizeof(struct sockaddr));
			if (send_check == -1) {
				perror("Eroare la trimiterea prin UDP\n");
				attempts++;
				continue;
			}
		
			/* Se verifica daca a fost primit un raspuns pana la timeout */
			if (select(sockfd_udp + 1, &tmp_fds, NULL, NULL, timeout)) {
				memset(buffer, 0, BUFLEN);

				int length = sizeof(to_station);

				if(recvfrom (sockfd_udp,(char*)buf , 65536 , 0 , (struct sockaddr*)&to_station , (socklen_t*)&length ) < 0) {
					perror("Eroare la primirea prin UDP\n");
					attempts++;
    	
				} else {
					answer_received = 1;
				}
    	
			} else {
				attempts++;
			}
		}

		index++;
	}

	memcpy(&header, buf, sizeof(dns_header_t));
	start = buf + size;

	/* Se parseaza raspunsurile pentru fiecare tip de cerere */
	if (ntohs(header.ancount) > 0) {
		fprintf(f_dns, ";; ANSWER SECTION:\n");
	}

	for(int i = 0; i < ntohs(header.ancount); i++) {
        answer[i].name = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
        start = start + stop;

		memcpy(&answer[i].type, start, sizeof(answer[i].type));
		start += sizeof(answer[i].type);

		memcpy(&answer[i].class, start, sizeof(answer[i].class));
		start += sizeof(answer[i].class);

		if(ntohs(answer[i].class) == 1) {
			strcpy(class, "IN");
				
		} else if (ntohs(answer[i].class) == 2) {
			strcpy(class, "CS");
				
		} else if (ntohs(answer[i].class) == 3) {
			strcpy(class, "CH");
				
		} else if (ntohs(answer[i].class) == 4) {
			strcpy(class, "HS");
		}

		/* Se afiseaza numele si clasa */
		printf("%s ", parameter);
		printf("%s ", class);

		fprintf(f_dns, "%s %s ", parameter, class);

		memcpy(&answer[i].ttl, start, sizeof(answer[i].ttl));
		start += sizeof(answer[i].ttl);

		memcpy(&answer[i].rdlength, start, sizeof(answer[i].rdlength));
		start += sizeof(answer[i].rdlength);

		/* Se afiseaza adresa ip pentru tipul A */
        if (par_type == A) { 
            answer[i].rdata = (unsigned char*) malloc(ntohs(answer[i].rdlength));

			memcpy(answer[i].rdata, start, ntohs(answer[i].rdlength));
			answer[i].rdata[ntohs(answer[i].rdlength)] = '\0';
 
            start += ntohs(answer[i].rdlength);
			ip_convert.sin_addr.s_addr = (* (long*) answer[i].rdata);
				
      		printf("A %s\n", inet_ntoa(ip_convert.sin_addr));
			fprintf(f_dns, "A %s\n", inet_ntoa(ip_convert.sin_addr));
        
		/* Se afiseaza valoarea pentru preference si numele pentru MailExchange */
		} else if(par_type == MX) {
			unsigned short int preference;

			memcpy(&preference, start, sizeof(preference));
			printf("MX %d ", ntohs(preference));
			fprintf(f_dns, "MX %d ", ntohs(preference));

			start += sizeof(preference);

			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("%s\n", answer[i].rdata);
            fprintf(f_dns, "%s\n", answer[i].rdata);
            
            start += stop;
        
		/* Se afiseaza PriName AuthoMailbox Serial Refresh Retry Expiration Minimum */
        } else if (par_type == SOA) {
			unsigned char *info = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("SOA %s ", info);
			fprintf(f_dns, "SOA %s ", info);

            start += stop;

			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("%s ", answer[i].rdata);
			fprintf(f_dns, "%s ", answer[i].rdata);

			unsigned int serial, refresh, retry, expire, minimum;

			memcpy(&serial, start, sizeof(serial));
			printf("%d ", ntohs(serial));
			fprintf(f_dns, "%d ", ntohs(serial));

			start += sizeof(serial);
			
			memcpy(&refresh, start, sizeof(serial));
			printf("%d ", ntohs(refresh));
			fprintf(f_dns, "%d ", ntohs(refresh));

			start += sizeof(serial);
			
			memcpy(&retry, start, sizeof(serial));
			printf("%d ", ntohs(retry));
			fprintf(f_dns, "%d ", ntohs(retry));
			
			start += sizeof(serial);
			
			memcpy(&expire, start, sizeof(serial));
			printf("%d ", ntohs(expire));
			fprintf(f_dns, "%d ", ntohs(expire));
			
			start += sizeof(serial);
			
			memcpy(&minimum, start, sizeof(serial));
			printf("%d\n", ntohs(minimum));
			fprintf(f_dns, "%d\n", ntohs(minimum));
			
			start += sizeof(serial);

		/* Se afiseaza NameServer */
		} else if (par_type == NS) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("NS %s\n", answer[i].rdata);
			fprintf(f_dns,"NS %s\n", answer[i].rdata);
            
            start += stop;

		/* Se afiseaza PrimaryName */
		} else if (par_type == CNAME) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("CNAME %s\n", answer[i].rdata);
			fprintf(f_dns, "CNAME %s\n", answer[i].rdata);

            start += stop;

		/* Se afiseaza TXT */
		} else if (par_type == TXT) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("TXT %s\n", answer[i].rdata);
			fprintf(f_dns, "TXT %s\n", answer[i].rdata);

            start += stop;

		/* Se afiseaza adresa */
		} else if (par_type == PTR) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("PTR %s\n", answer[i].rdata);
			fprintf(f_dns, "PTR %s\n", answer[i].rdata);

            start += stop;
		}
    }

	if (ntohs(header.nscount) > 0) {
		fprintf(f_dns, "\n;; AUTHORITY SECTION:\n");
	}

	for(int i=0; i < ntohs(header.nscount); i++) {
		answer[i].name = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
        start = start + stop;

		memcpy(&answer[i].type, start, sizeof(answer[i].type));
		start += sizeof(answer[i].type);

		memcpy(&answer[i].class, start, sizeof(answer[i].class));
		start += sizeof(answer[i].class);

		if(ntohs(answer[i].class) == 1) {
			strcpy(class, "IN");
				
		} else if (ntohs(answer[i].class) == 2) {
			strcpy(class, "CS");
				
		} else if (ntohs(answer[i].class) == 3) {
			strcpy(class, "CH");
				
		} else if (ntohs(answer[i].class) == 4) {
			strcpy(class, "HS");
		}

		printf("%s ", parameter);
		printf("%s ", class);

		fprintf(f_dns, "%s %s ", parameter, class);		

		memcpy(&answer[i].ttl, start, sizeof(answer[i].ttl));
		start += sizeof(answer[i].ttl);

		memcpy(&answer[i].rdlength, start, sizeof(answer[i].rdlength));
		start += sizeof(answer[i].rdlength);

        if (par_type == A) {
            answer[i].rdata = (unsigned char*)malloc(ntohs(answer[i].rdlength));

			memcpy(answer[i].rdata, start, ntohs(answer[i].rdlength));
			answer[i].rdata[ntohs(answer[i].rdlength)] = '\0';
 
            start += ntohs(answer[i].rdlength);

			ip_convert.sin_addr.s_addr = (* (long*) answer[i].rdata);

      		printf("A %s\n", inet_ntoa(ip_convert.sin_addr));
      		fprintf(f_dns, "A %s\n", inet_ntoa(ip_convert.sin_addr));
        
		} else if(par_type == MX) {
			unsigned short int preference;

			memcpy(&preference, start, sizeof(preference));
			printf("MX %d ", ntohs(preference));
			fprintf(f_dns, "MX %d ", ntohs(preference));

			start += sizeof(preference);

			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("%s\n", answer[i].rdata);
			fprintf(f_dns, "%s\n", answer[i].rdata);
            
            start += stop;
        
        } else if (par_type == SOA) {
			unsigned char *info = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("SOA %s ", info);
			fprintf(f_dns, "SOA %s ", info);

            start += stop;

			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("%s ", answer[i].rdata);
			fprintf(f_dns, "%s ", answer[i].rdata);

			unsigned int serial, refresh, retry, expire, minimum;

			memcpy(&serial, start, sizeof(serial));
			printf("%d ", ntohs(serial));
			fprintf(f_dns, "%d ", ntohs(serial));

			start += sizeof(serial);
			
			memcpy(&refresh, start, sizeof(serial));
			printf("%d ", ntohs(refresh));
			fprintf(f_dns, "%d ", ntohs(refresh));

			start += sizeof(serial);
			
			memcpy(&retry, start, sizeof(serial));
			printf("%d ", ntohs(retry));
			fprintf(f_dns, "%d ", ntohs(retry));
			
			start += sizeof(serial);
			
			memcpy(&expire, start, sizeof(serial));
			printf("%d ", ntohs(expire));
			fprintf(f_dns, "%d ", ntohs(expire));
			
			start += sizeof(serial);
			
			memcpy(&minimum, start, sizeof(serial));
			printf("%d\n", ntohs(minimum));
			fprintf(f_dns, "%d\n", ntohs(minimum));
			
			start += sizeof(serial);

		} else if (par_type == NS) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("NS %s\n", answer[i].rdata);
			fprintf(f_dns, "NS %s\n", answer[i].rdata);
            
            start += stop;

		} else if (par_type == CNAME) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("CNAME %s\n", answer[i].rdata);
			fprintf(f_dns, "CNAME %s\n", answer[i].rdata);

            start += stop;

		} else if (par_type == TXT) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("TXT %s\n", answer[i].rdata);
			fprintf(f_dns, "TXT %s\n", answer[i].rdata);

            start += stop;

		} else if (par_type == PTR) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("PTR %s\n", answer[i].rdata);
			fprintf(f_dns, "PTR %s\n", answer[i].rdata);

            start += stop;
		}
    }

	if (ntohs(header.arcount) > 0) {
		fprintf(f_dns, "\n;; ADDITIONAL SECTION:\n");
	}

	for(int i=0; i < ntohs(header.arcount); i++) {
		answer[i].name = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
        start = start + stop;

		memcpy(&answer[i].type, start, sizeof(answer[i].type));
		start += sizeof(answer[i].type);

		memcpy(&answer[i].class, start, sizeof(answer[i].class));
		start += sizeof(answer[i].class);

		if(ntohs(answer[i].class) == 1) {
			strcpy(class, "IN");
				
		} else if (ntohs(answer[i].class) == 2) {
			strcpy(class, "CS");
				
		} else if (ntohs(answer[i].class) == 3) {
			strcpy(class, "CH");
				
		} else if (ntohs(answer[i].class) == 4) {
			strcpy(class, "HS");
		}

		printf("%s ", parameter);
		printf("%s ", class);

		fprintf(f_dns, "%s %s ", parameter, class);		

		memcpy(&answer[i].ttl, start, sizeof(answer[i].ttl));
		start += sizeof(answer[i].ttl);

		memcpy(&answer[i].rdlength, start, sizeof(answer[i].rdlength));
		start += sizeof(answer[i].rdlength);

        if (par_type == A) {
            answer[i].rdata = (unsigned char*)malloc(ntohs(answer[i].rdlength));

			memcpy(answer[i].rdata, start, ntohs(answer[i].rdlength));
			answer[i].rdata[ntohs(answer[i].rdlength)] = '\0';
 
            start += ntohs(answer[i].rdlength);
			ip_convert.sin_addr.s_addr = (* (long*) answer[i].rdata);
				
      		printf("A %s\n", inet_ntoa(ip_convert.sin_addr));
      		fprintf(f_dns, "A %s\n", inet_ntoa(ip_convert.sin_addr));
        
		} else if(par_type == MX) {
			unsigned short int preference;

			memcpy(&preference, start, sizeof(preference));
			printf("MX %d ", ntohs(preference));
			fprintf(f_dns, "MX %d ", ntohs(preference));

			start += sizeof(preference);

			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("%s\n", answer[i].rdata);
			fprintf(f_dns, "%s\n", answer[i].rdata);
            
            start += stop;
        
        } else if (par_type == SOA) {
			unsigned char *info = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("SOA %s ", info);
			fprintf(f_dns, "SOA %s ", info);

            start += stop;

			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("%s ", answer[i].rdata);
			fprintf(f_dns, "%s ", answer[i].rdata);

			unsigned int serial, refresh, retry, expire, minimum;

			memcpy(&serial, start, sizeof(serial));
			printf("%d ", ntohs(serial));
			fprintf(f_dns, "%d ", ntohs(serial));

			start += sizeof(serial);
			
			memcpy(&refresh, start, sizeof(serial));
			printf("%d ", ntohs(refresh));
			fprintf(f_dns, "%d ", ntohs(refresh));

			start += sizeof(serial);
			
			memcpy(&retry, start, sizeof(serial));
			printf("%d ", ntohs(retry));
			fprintf(f_dns, "%d ", ntohs(retry));
			
			start += sizeof(serial);
			
			memcpy(&expire, start, sizeof(serial));
			printf("%d ", ntohs(expire));
			fprintf(f_dns, "%d ", ntohs(expire));
			
			start += sizeof(serial);
			
			memcpy(&minimum, start, sizeof(serial));
			printf("%d\n", ntohs(minimum));
			fprintf(f_dns, "%d\n", ntohs(minimum));
			
			start += sizeof(serial);

		} else if (par_type == NS) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("NS %s\n", answer[i].rdata);
			fprintf(f_dns, "NS %s\n", answer[i].rdata);
            
            start += stop;

		} else if (par_type == CNAME) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("CNAME %s\n", answer[i].rdata);
			fprintf(f_dns, "CNAME %s\n", answer[i].rdata);

            start += stop;

		} else if (par_type == TXT) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop);
			printf("TXT %s\n", answer[i].rdata);
			fprintf(f_dns, "TXT %s\n", answer[i].rdata);

            start += stop;

		} else if (par_type == PTR) {
			answer[i].rdata = decompress_name((unsigned char*)start, (unsigned char*)buf, &stop); 
			printf("PTR %s\n", answer[i].rdata);
			fprintf(f_dns, "PTR %s\n", answer[i].rdata);

            start += stop;
		}
    }

	fprintf(f_dns, "\n\n");

	fclose(f_message);
	fclose(f_dns);

	return 0;
}
