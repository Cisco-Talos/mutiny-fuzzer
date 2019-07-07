#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    const char *IP; 
    unsigned short PORT = 9999;
    char input[100];

    struct sockaddr_in dst_addr;
    if (argc < 2){
        printf("[>_>] USAGE: %s <IPADDR>\n",argv[0]);
        exit(1);
    }

    unsigned int sockfd = socket(AF_INET,SOCK_STREAM,0);
    unsigned int fuzzer_sockfd = socket(AF_INET,SOCK_STREAM,0);

    if (sockfd == -1){
        printf("[;-;] Unable to create socket, aborting!\n");
        exit(1);
    }    

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = ((PORT & 0xff) << 8) + ((PORT & 0xff00) >> 0x8);
        
    if (inet_aton(argv[1],(struct in_addr *)&dst_addr.sin_addr) != 1){
        printf("[;-;] Unable to inet_aton %s, aborting!\n",argv[1]);
        exit(1);
    }
    
    if (connect(sockfd,(struct sockaddr *)&dst_addr,sizeof(dst_addr)) < 0){
        printf("[;-;] Unable to connect to 0x%x:%d, aborting!\n",dst_addr.sin_addr,dst_addr.sin_port);
        exit(1);
    }
    
    int i;
    
    for (int i =0; i < 10; i++){ 
        send(sockfd,"boop",4,0x0);
    }
    int ret = recv(sockfd,input,99,0x0);
    if (ret > 0){
        printf("[^_^] Got %s!\n");
    } else {
        printf("[x_x] Got nothing!");
    }    

}
