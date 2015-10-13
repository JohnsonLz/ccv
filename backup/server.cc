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

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <mysql.h>
#include <errno.h>
#include <mysql.h>

#include <ins/net.h>
#include <ins/file.h>
#include <ins/logcat.h>
#include <ins/mempool.h>
#include <ins/threadpool.h>
#include <ins/connectpool.h>
#include <ins/transAction.h>
#include <ins/tr.h>
#include <ins/list.h>

namespace ccv {

Server::Server() {

	db.parseDBInI_();
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);
	server_addr.sin_port = htons(PORT);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0) {
		log.w("create socket error");
		throw CreateError;
	}

	if(bind(sockfd, static_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
		log.w("bind error");
		throw Corruption;
	}

	if(listen(sockfd, LISTEN_QUEUE) < 0) {
		log.w("listen error");
		throw Corruption;
	}
}

Server::~Server() {

	clean_();
	cp_.close();
	tp_.Destory();
}

void Server::parseDBInI_() {

	FILE* fp = fopen("./db.ini", "r");
	if(fp == NULL) {
		log.w("can not found db.ini");
		throw NotFound;
	}

	List<info>dbList;
	char ch;
	char buf[bufferSize];
	int count = 0;
	char* tag;
	char* ref;
	while(fread(&ch, 1, 1, fp) != 0) {
		
		if(ch == ':') {
			buf[count] = '\0';
			int length = strlen(buf);
			tag = static_cast<char*>(allocate(length + 1));
			strncpy(tag, buf, length);
			tag[length] = '\0';	
			count = 0;
			continue;
		}

		if(ch == ';') {
			buf[count] = '\0';
			int length = strlen(buf);
			ref = static_cast<char*>(allocate(length + 1));
			strncpy(ref, buf, length);
			ref[length] = '\0';
			count = 0;
			info* inf = static_cast<info*>(allocate(sizeof(info)));
			new(inf) info(tag, ref, false);
			dbList.insert(inf);
			continue;
		}

		buf[count] = ch;
		count++;
	}

	mysqlServerHost = findInI_("ServerHost", &dbList);
	mysqlUser = findInI_("User", &dbList);
	mysqlPassword = findInI_("PassWord", &dbList);
	mydqlDB = findInI_("DB", &dbList);
	repertoryPath = finInI_("Repertory", &dbList);

	cp_.init(mysqlServerHost, mysqlUser, mysqlPassword, mysqlDB);

	List<info>::const_iterator iter;
	iter = dbList.start();
	while(iter != dbList.end) {
		info* tmp = iter->data;
		dellocate(const_cast<char*>(tmp->getTag());
		dellocate(const_cast<char*>(tmp->getRef());
		dellocate(tmp);
		iter = iter->next;
	}

}

char* Server::findInI_(const char* name, List<info>* lt) {

	info tmp(name, NULL, false);
	info* result = lt.search(tmp);
	if(result == NULL) {
		log.w("db.ini parse %s error", name);
		throw IOError;
		return NULL;
	}
	int length = strlen(result->data->getRef());
	char* ref = static_cast<char*>(allocate(length + 1));
	strncpy(ref, result->data->getRef(), length);
	ref[length] = '\0';
	return ref;
}

void Server::clean_() {

	dellocate(const_cast<char*>(mysqlServerHost));
	dellocate(const_cast<char*>(mysqlUser));
	dellocate(const_cast<char*>(mysqlPassword));
	dellocate(const_cast<char*>(mysqlDB));
	dellocate(const_cast<char*>(repertoryPath));
}

const char* Server::createSQL_(const char* arg, ...) {

	va_list argp;
	const char* para;
	int length;
	char buf[BUFFER_SIZE];
	int position = 0;

	va_start(argp, arg);
	while(true) {
		para = va_arg(argp, const char*);
		if(strcmp(para, "\0") == 0)
			break;
		length = strlen(para);
		strncpy(buf+position, para, length);
		position += length;
	}
	va_end(argp);
	buf[position] = '\0';
	char* result = static_cast<char*>(allocate(position+1));
	strncpy(result, bug, position);
	result[position] = '\0';
	return result;

}

void addConfirmMission(epoll_event* ev, int epfd, const char* ptr) {

	int length = decodeFixed32(ptr);
	ptr + =4;
	char* project = static_cast<char*>(allocate(length + 1));
	strncpy(project, ptr, length);
	project[length] = '\0';
	ptr += length;
	length = decodeFixed32(ptr);
	ptr += 4;
	char* user = static_cast<char*>(allocate(length + 1));
	strncpy(user, ptr, length);
	user[length] = '\0';
	ptr += length;
	length = decodeFixed32(ptr);
	ptr += 4;
	char* password = static_cast<char*>(allocate(length + 1));
	strncpy(password, ptr, length);
	password[length] = '\0';

	missionArg* mag = static_cast<missionArg*>(allocate(sizeof(missionArg)));
	mag->ev = ev;
	mag->epfd = epfd;
	mag->sv = this;
	
	const char* sqlProject = createSQL("select projectId from Project where projectName = \'", project, "\';", "\0");
	const char* sqlPassword = createSQL("select password from User where userName = \'", user, "\'", " and userId in (select userId from Contributer where projectId in (select projectId from Project where projectName = \'", project,  "\'));", "\0");
	int repertoryLength = strlen(repertoryPath);
	int userLength = strlen(user);
	int projectLength = strlen(project);
	char* result = static_cast<char*>(allocate(repertoryLength + userLength + projectLength + 4);
	strncpy(result, repertoryPath, repertoryLength);
	repertoryLength;
	result[repertoryLength] = '/';
	repertoryLength ++;
	strncpy(result+repertoryLength, user, userLength);
	result[repertoryLength + userLength] = '/';
	userLength++; 
	strncpy(result+repertoryLength+userLength, project, projectLength);
	result[repertoryLength + userLength + projectLength] = '/';
	projectLength ++;
	result[repertoryLength + userLength + projectLength] = '\0';
	dellocate(const_cast<char*>(project));
	dellocate(const_cast<char*>(user));

	mag->sqlProject = sqlProject;
	mag->sqlPassword = sqlPassword;
	mag->password = password;
	mag->result = result;
	mission* m = static_cast<mission*>(allocate(sizeof(mission)));
	mission->mcb = confirm_;
	mission->arg = static_cast<void*>(mag);
	mission->isFinish = false;
	mission->next = NULL;

	tp_.addMission(m);

}
	

void Server::confirm_(void* arg) {

	missionArg* mag = static_cast<missionArg*>(arg);
	seamphore* sp = mag->sv->cp_.getConnection();
	MYSQL* db = sp->mysql_main;
	MYSQL_RES* res;
	MYSQL_ROW row;
	struct epoll_event event, ev;
	event = mag->ev;
	ev.data.fd = event.data.fd;
	statue* st = static_cast<statue*>(event.data.ptr);
	
	if(mysql_query(db, mag->sqlProject)) {
		log.w("query error");
		st->st = EXO;
	}
	else {
		res = mysql_use_result(db);
		int result == 0;
		while((row = mysql_fetch_row(res)) != NULL) {
			result ++;
		}
		mysql_free_result(res);
		if(result == 0) {
			st->st = EXOF;
		}
		else {
			if(mysql_query(db, mag->sqlPassword)) {
				log.w("query password error");
				st->st = EXO;
			}
			else {
				res = mysql_use_result(db);
				result = 0;
				while((row = mysql_fetch_row(res))!= NULL) {
					result ++;
					if(equal(mag->password, row[0]) {
						st->st = Confirm;
						st->buf = mag->result;
					}
					else {
						st->st = EXOUP;
					}
				}
				mysql_free_result(res);
				if(result == 0) {
					st->st = EXOA;
				}
			}
		}
	}

	returnConnection(sp);			
	ev.data.ptr =static_cast<void*>(st);
	epoll_ctl(mag.epfd, EPOLL_CTL_MOD, event.data.fd, &ev);

}


void Server::run() {

	struct epoll_event ev, events[EPOLLSIZE];
	int epfd = epoll_create(EPOLLSIZE);
	//TODO::unblcok;
	ev.data.fd = sockfd;
	ev.events = EPOLLIN | EPOLLET;
	epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);

	while(true) {

		int nfds = epoll_wait(epfd, events, EPOLLSIZE, 500);
		for(int i=0; i<nfds, i++) {
			if(events[i].data.fd == sockfd) {
				int remoteSock;
				while((remoteSock = accept(sockfd, static_cast<sockaddr*>(&server_addr), sizeof(sockaddr_in)) > 0) {
					ev.data.fd = remoteSock;
					ev.events = EPOLLIN|EPOLLET;
					statue* st = static_cast<statue*>(allocate(sizeof(statue)));
					st->st = Connect;
					st->fp = NULL;
					st->buf = NULL;
					ev.data.ptr = static_cast<void*>(st);
					epoll_ctl(epfd, EPOLL_CTL_ADD, remoteSock, &ev);
				}
				if(remoteSock == -1) {
					if(errno != EAGAIN && errno != ECONNABORTED && errno != EPROTO && errno != EINTR) {
						log.w("accept error");
					}
				}
				continue;
			}
			else if(events[i].events&EPOLLIN) {
				int n, nread;
				int sockfd = events[i].data.fd;
				statue* st = static_cast<statue*>(events[i].data.ptr);
				recv(sockfd, buf, 1, 0);
				n = 1;
				if(buf[0] == 'a' && st.st != TransFerring) {
					st.st = TransFerring;
					n = 0;
				}
				else if(st.st == TransFerring) {
					nread = recv(sockfd, buf+n, BUFFER_SIZE - 10, 0);
					if(nread < 0) {
						if(nread == -1 && errno != EAGAIN) {
							log.w("read error");
							//TODO::
						}
						if(n == 1) {
							int write = fwrite(buf, 1, n, st.fp);
							if(write != n) {
								//TODO:
							}
						}
						ev.data.fd = sockfd;
						ev.events = EPOLLIN | EPOLLET;
						ev.ptr = static_cast<void*>(st);
						epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
						continue;
					}
					int length;
					int position = 0;
					if(st.buf == NULL) { 
						length = 0;
					}
					else {
						legnth = strlen(st.buf);
					}
					if(length < 4) {
						char lengthBuf[4];
						strncpy(lengthBuf, st.buf, length);
						if(length) {
							dellocate(const_cast<char*>(st.buf);
						}
						strncpy(lengthBuf+length, buf, 4-length);
						position = 4-length;
						length = decodeFixed32(lengthBuf);
					}
					else {
						length = decodeFixed32(st.buf);
						dellocate(const_cast<char*>(st.buf));
					}
					nread -= position;
					while(true) {
						if(length > nread) {
							int write = fwrite(buf+position, 1, nread, st.fp);
							if(write != nread) {
								//TODO::
							}
							length -= nread;
							nread = recv(sockfd, buf, BUFFER_SIZE, 0);
							if(nread < 0) {
								if(nread == -1 && errno != EAGAIN) {
									log.w("read error");
									//TODO::
								}
								char* tmp = static_cast<char*>(allocate(5));
								encodeFixed32(tmp, length);
								tmp[4] = '\0';
								st.buf = tmp;
								ev.data.fd = sockfd;
								ev.data.ptr = static_cast<char*>(st);
								ev.events = EPOLLIN | EPOLLET;
								epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
								break;
							}
							continue;
						}
						else {
							if(length == 2 && buf[position] == '*' && buf[position + 1] == '}') {
								fclose(st.fp);
								st.st = TransFerred;
								ev.data.ptr = static_cast<char*>(st);
								ev.events = EPOLLOUT | EPOLLET;
								epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
								break;
							}
							int write = fwrite(buf+position, 1, length, st,fp);
							if(write != length) {
								//TODO::
							}
							position += length;
							nread -= length;
							if(buf[position] != 'a') {
								log.w("parse upload error");
								//TODO::
							}
							position ++;
							nread --;
							if(nread < 4) {
								char lengthBuf[4];
								strncpy(lengthBuf, buf+posotion, nread);
								int tmp = recv(sockfd, buf, BUFFER_SIZE, 0);
								if(tmp < 4-nread) {
									if(tmp == -1 && errno != EAGAIN) {
										log.w("read error");
										//TODO::
									}
									if(tmp > 0) {
										strncpy(lengthBuf+nread, buf, tmp);
									}
									char* stBuf = static_cast<char*>(allocate(nread+tmp +1));
									strncpy(stBuf, lengthBuf, nread+tmp);
									stBuf[nread+tmp] = '\0';
									st.buf = stBuf;
									ev.data.fd = sockfd;
									ev.events = EPOLLIN | EPOLLET;
									ev.data.ptr = static_cast<void*>(st);
									epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
									break;
								}
								strncpy(lengthBuf, buf, 4-nread);
								length = decodeFixed32(lengthBuf);
								position = 4-nread;
								nread = tmp-position;
							}
							else {
								length = decodeFixed32(buf+position);
								position += 4;
								nread -= 4;
							}
						}
					}
					continue;
				}
				else {
					n = 1;
					while((nread = recv(sockfd, buf+n, BUFFER_SIZE, 0)) >0) {
						n+= nread;
					}
					if(nread == -1 && errno != EAGAIN) {
						log.w("read error");
						//TODO::handle
					}
					const char* bufPtr = buf;
				}
				if(bufPtr[0] == 'c') {
					bufPtr++;
					addConfirmMission_(&events[i], bufPtr);
				}
				else if(bufPtr[0] == 'e') {
					ev.data.fd = sockfd;
					if(st->buf != NULL) {
						dellocate(const_cast<char*>(st->buf));
					}
					if(st->fp != NULL) {
						fclose(st->fp);
					}
					dellocate(st);
					epoll_ctl(epfd, EPOLL_CTL_DEL, scokfd, &ev);
				}
				else if(bufPtr[0] == 'u') {
					bufPtr++;
					char bufTmp[BUFFERSIZE];
					char modeBuf[4];
					int length = decodeFixed32(bufPtr);
					bufPtr += 4;
					strncpy(bufTmp, bufPtr, length);
					bufTmp[length] = '\0';
					bufPtr += length;
					length = decodeFixed32(bufPtr);
					bufPtr += 4;
					strncpy(modeBuf, bufPtr, length);
					bufPtr += length;
					int mode = decodeFixed32(modeBuf);
					int fd = open(bufTmp, O_RDWR|O_CREATE, mode);

					ev.data.fd = events[i].data.fd,
					ev.events = EPOLLOUT | EPOLLET;

					if(fd == -1) {
						log.w("open error");
						st->st = EXO;
						ev.data.ptr = static_cast<void*>(st);
						epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
						continue;
					}
					close(fd);

					FILE* fp = fopen(bufTmp, "wb");
					if(fp == NULL) {
						log.w("can not open item: %s", tmp);
						st->st = EXO;
						ev.data.ptr = static_cast<void*>(st);
						epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
					}

					st->st = UpLoad;
					st->fp = fp;
					ev.data.ptr = static_cast<void*>(st);
					epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);

				}
				else if(bufPtr[0] == 'e') {
					ev.data.fd = events[i].data.fd;
					ev.events = EPOLLIN | EPOLLET;
					st->st = Success;
					if(st->fp != NULL) {
						fclose(st->fp);
						st->fp = NULL;
					}
					if(st->buf != NULL) {
						dellocate(const_cast<char*>(st->buf));
						st->buf = NULL;
					}
					ev.data.ptr = static_cast<void*>(st);
					epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);

				}
				else if(bufPtr[0] == 'd') {
					bufPtr++;
					char bufTmp[BUFFERSIZE];
					char modeBuf[4];
					int length = decodeFixed32(bufPtr);
					bufPtr += 4;
					strncpy(bufTmp, bufPtr, length);
					bufTmp[length] = '\0';
					bufPtr += length;
					
					ev.data.fd = events[i].data.fd,
					ev.events = EPOLLOUT | EPOLLET;

					
					struct stat st;
					if(stat(bufTmp, &st) != 0) {
						perror(bufTmp);
						st->st = EXO;
						ev.data.ptr = static_cast<void*>(st);
						epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
						continue;
					}

					FILE* fp = fopen(bufTmp, "rb");
					if(fp == NULL) {
						log.w("can not open item: %s", bufTmp);
						st->st = EXO;
						ev.data.ptr = static_cast<void*>(st);
						epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
						continue;
					}

					char* modeBuf = static_cast<char*>(allocate(9));
					modeBuf[0] = '{';
					modeBuf[1] = '*';
					encodeFixed32(modeBuf+2, st.st_mode);
					modeBuf[6] = '*';
					modeBuf[7] = '}';
					modeBuf[8] = '\0';
					if(st->buf != NULL) {
						dellocate(const_cast<char*>(st->buf));
					}
					st->buf = modeBuf;
					st->st = DownLoad;
					st->fp = fp;
					ev.data.ptr = static_cast<void*>(st);
					epoll_stl(epfd, EPOLL_CTL_MOD, sockfd, &ev);

				}
				else {
					log.w("parse read error");
				}

			}
			else {
				int nwrite, n;
				int sockfd = events[i].data.fd;
				statue* st = static_cast<statue*>(events[i].data.ptr);
				if(st.st == EXO) {
					encodeFixed32(buf, 3);
					strncpy(buf+4, "EXO", 3);
					nwrite = 7;
				}
				else if(st.st == EXOUP) {
					encodeFixed32(buf, 5);
					strncpy(buf+4, "EXOUP", 5);
					nwrite = 9;
				}
				else if(st.st == EXOF) {
					encodeFixed32(buf, 4);
					strncpy(buf+4, "EXOF", 4);
					nwrite = 8;
				}
				else if(st.st == UpLoad) {
					encodeFixed32(buf, 5);
					strncpy(buf+4, "READY", 5);
					nwrite = 9;
				}
				else if(st.st == Confirm) {
					int length = strlen(st.buf);
					encodeFixed32(buf, length);
					strncpy(buf+4, st.buf, length);
					nwrite += length;
				}
				else if(st.st == TransFerred) {
					encodeFixed32(buf, 2);
					strncpy(buf+4, "FN", 2);
					nwrite = 6;
				}
				else if(st.st == DownLoad) {
					int size,nsend;
					if(st.buf != NULL) {
						if(strlen(st.buf) == 8) {
							if(st.buf[0] == '{' && st.buf[1] == '*' && st.buf[6] == '*' && st.buf[7] == '}') {
								encodeFixed32(buf, 4);
								strncpy(buf+4, st.buf, 4);
								nwrite = 8;
							}
						}
						else {
							size = strlen(st.buf);
							strncpy(buf+nwrite, st.buf, size);
							nwrite += size;
						}
						buf[nwrite] = '\0';
						n = nwrite;
						dellocate(const_cast<char*>(st.buf));
						nsend = send(sockfd, buf, n, 0);
						if(nsend < n) {
							if(nsend == -1 && errno != EAGAIN) {
								log.w("write error");
								//TODO:: handle
							}
							n -= nsend;
							char* tmp = static_cast<char*>(allocate(n+1));
							strncpy(tmp, buf+nsend, n);
							tmp[n] = '\0';
							st.buf = tmp;
							ev.data.fd = sockfd;
							ev.events = EPOLLOUT | EPOLLET;
							ev.data.ptr = static_cast<void*>(st);
							epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
							continue;
						}
					}
					else {
						while(true) {
							bool end = false;
							size = fread(buf, 1, BUFFER_SIZE-20, st.fp);
							if(size != (BUFFER_SIZE-20)) {
								fclose(st.fp);
								st.fp = NULL;
								st.st = Success;
								buf[size] = '*';
								buf[size+1] = '}';
								size += 2;
								end = true;
							}
							n = size;
							nsend = send(sockfd, buf, n, 0);
							if(nsend < n) {
								if(nsend == -1 && errno != EAGAIN) {
									log.w("write error");
									//TODO::
								}
								n -= nsend;
								char* tmp = static_cast<char*>(allocate(n+1));
								strncpy(tmp, buf+nsend, n);
								tmp[n] = '\0';
								st.buf = tmp;
								ev.data.fd = sockfd;
								ev.events = EPOLLOUT | EPOLLET;
								ev.data.ptr = static_cast<void*>(st);
								epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
								break;
							}
							if(end) {
								ev.data.fd = sockfd;
								ev.events = EPOLLIN | EPOLLET;
								st.st = Success;
								ev.data.ptr = static_cast<void*>(st);
								epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
								break;
							}
						}
					}
					continue;
				}
				else {
					log.w("parse error");
					continue;
				}
				
				send(sockfd, buf, nwrite, 0);
				ev.data.fd = sockfd;
				ev.data.ptr = static_cast<void*>(st);
				ev.events = EPOLLIN | EPOLLET;
				epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);

			}
		}
		tp_.removeDoneMission();
	}

}


}//namespace ccv
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
