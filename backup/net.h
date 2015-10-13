/*
 **********************************************************************
 ** md5.c                                                            **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C Version                  **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 2015, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

#ifndef CCV_INS_NET_H_
#define CCV_INS_NET_H_

#include <sys/epoll.h>
#include <stdio.h>
#include "ins/list.h"

namespace ccv {

class info;

class Net {

	protected:
	const int BUFFER_SIZE = 1024;
	char buf[BUFFER_SIZE];
	struct sockaddr_in server_addr;
	int sockfd;

	public:
	Net(){}
	~Net(){}

	void closeSock();

};

class Client:public Net {

	private:
	const int PORT = 6666;
	const char* IPAddr = "127.0.0.1";
	const char* projectPath;
	
	void send_(int fd, const char* arg, ...);
	void recv(int fd);
	
	public:
	Client();
	~Client();

	void connect(const char* project, const char* user, const char* password);
	void upload(const char* fileName);
	void download(const char* fileName);
};

struct missionArg {

	struct epoll_event* ev;
	int epfd;
	const char* sqlProject;
	const char* sqlPassword;
	const char* result;
	Server* sv;
};

struct statue {

	NetStat st;
	FILE* fp;
	const char* buf;
};

enum NetStat {

	Connect = 0,
	Confirm = 1,
	UpLoad = 2,
	DownLoad = 3,
	EXO = 4,
	EXOUP = 5,
	EXOF = 6,
	Success = 7,
	TransFerring = 8,
	TransFerred = 9
};

class Server: public Net {

	private:
	const int PORT = 6666;
	const int LISTEN_QUEUE = 20;
	const int EPOLLSIZE = 256
	const char* mysqlServerHost;
	const char* mysqlUser;
	const char* mysqlPassword;
	const char* mysqlDB;
	const char* repertoryPath;

	ThreadPool tp_;
	ConnectPool cp_;

	void parseDBInI_();
	void clean_();
	char* findInI_(const char* name, List<info>* lt);
	const char* createSQL_(const char* arg, ...);
	static void confirm_(void* arg);
	void addConformMission_(epoll_event* ev, int epfd, const char* ptr);

	public:
	Server();
	~Server();

	void run();

};


}// namespace ccv

#endif

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
