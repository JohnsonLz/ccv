#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>


int main() {

	const char * request = "GET /ccv-api/controller/download.php?uri=/Johnson/test/current.tr&range=0-100 HTTP/1.1\r\n\
Accept: application/json\r\nRange:bytes=512-1024\r\nAccept-Language: zh-cn\r\nHost: localhost\r\nConnection: close\r\n\r\n";

	sockaddr_in serverAddr_;
	int sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&serverAddr_, sizeof(serverAddr_));
	serverAddr_.sin_family = AF_INET;
	serverAddr_.sin_port = htons(80);
	if(inet_pton(AF_INET, "localhost", &serverAddr_.sin_addr) <= 0) {
	}
	if(connect(sockfd_, reinterpret_cast<sockaddr*>(&serverAddr_), sizeof(serverAddr_)) < 0) {
	}

	int length = strlen(request);
	char ch;
	send(sockfd_, request, length, 0);
	while(recv(sockfd_, &ch, 1, 0)) {
		printf("%c", ch);
	}
	close(sockfd_);
}
