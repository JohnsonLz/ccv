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
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "ins/transfer.h"
#include "ins/logcat.h"
#include "ins/tr.h"
#include "ins/list.h"
#include "ins/mempool.h"
#include "ins/file.h"
#include "ins/md5.h"
#include "ins/transAction.h"
#include "json/json.h"

namespace ccv {

Transfer::Transfer() {

	request_ = "GET %s HTTP/1.1\r\nAccept: application/json\r\nAccept-Language: zh-cn\r\nHost: %s\r\nConnection: close\r\n\r\n";
	downloadUrl_ = "/%s?uri=%s/%s&range=%d-%d";
	downloadAPI_ = "ccv-api/controller/download.php";

}

Transfer::~Transfer() {

}

void Transfer::connect_(const char* host) {

	sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd_ < 0) {
		log.w("create socker faile");
		throw CreateError;
	}
	bzero(&serverAddr_, sizeof(serverAddr_));
	serverAddr_.sin_family = AF_INET;
	serverAddr_.sin_port = htons(80);
	if(inet_pton(AF_INET, host, &serverAddr_.sin_addr) <= 0) {
		log.w("inet_pton failed for %s", host);
		throw CreateError;
	}
	if(connect(sockfd_, reinterpret_cast<sockaddr*>(&serverAddr_), sizeof(serverAddr_)) < 0) {
		log.w("connect failed");
		throw Corruption;
	}

}

void Transfer::close_() {

	close(sockfd_);
}

int Transfer::HexToInt_(const char* str) {

	int res = 0;
	while(*str != '\0') {
		switch(*str) {
			case '0'...'9':
				res = res*16 + *str - '0';
				break;
			case 'a'...'f':
				res = res*16 + *str - 'a' + 10;
				break;
			case 'A'...'F':
				res = res*16 + *str - 'A' + 10;
				break;
			default:
				return -1;
				break;
		}
		str++;
	}
	return res;
}

void Transfer::send_(char* buf) {
	
	int length = strlen(buf);
	int nsend = send(sockfd_, buf, length, 0);
	if(nsend != length) {
		log.w("send error");
		close_();
		throw IOError;
	}
}

void Transfer::recv_(char* buf) {

	int i=0;
	while(recv(sockfd_, &buf[i], 1, 0)) {
		i++;
	}
	buf[i] = '\0';
	close_();
}

void Transfer::parseResponse_(const char* response, char* jsonStr) {

	const char* start = strstr(response, "\r\n\r\n");
	if(start == NULL) {
		log.w("response is invaild");
		throw IOError;
	}
	start += 4;

	int length;
	int position = 0;
	const char* body = start;
	const char* ptmp;
	char tmp[10];
	while(true) {
		ptmp = strchr(body, '\r');
		if(NULL == ptmp) {
			log.w("response body is invaild");
			throw IOError;
		}
		int len = ptmp - body;
		strncpy(tmp, body, len);
		tmp[len] = '\0';
		length = HexToInt_(tmp);
		if(length == 0) {
			//jsonStr[position] = '\0';
			break;
		}
		body = ptmp + 2;

		strncpy(jsonStr+position, body, length);
		position += length;
		body = body+length+2;
	}
}

void Transfer::createPath_(const char* item) {
	
	char buf[bufferSize];
	int position = 0;
	int length = strlen(item);

	while(position < length) {
		if(item[position] == '/') {
			strncpy(buf, item, position);
			buf[position] = '\0';
			DIR* dir = NULL;
			dir = opendir(buf);
			if(dir != NULL) {
				closedir(dir);
				position++;
				continue;
			}
			createDir(buf);
			AddDirTransAction(buf);

		}
		position ++;
	}
}

void Transfer::encodeBase64_(const char* Data, int DataByte, std::string& strEncode) {

    const char EncodeTable[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char Tmp[4]={0};
    int LineLength=0;
    for(int i=0;i<(int)(DataByte / 3);i++)
    {
        Tmp[1] = *Data++;
        Tmp[2] = *Data++;
        Tmp[3] = *Data++;
        strEncode+= EncodeTable[Tmp[1] >> 2];
        strEncode+= EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
        strEncode+= EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
        strEncode+= EncodeTable[Tmp[3] & 0x3F];
        if(LineLength+=4,LineLength==76) {strEncode+="\r\n";LineLength=0;}
    }
    int Mod=DataByte % 3;
    if(Mod==1)
    {
        Tmp[1] = *Data++;
        strEncode+= EncodeTable[(Tmp[1] & 0xFC) >> 2];
        strEncode+= EncodeTable[((Tmp[1] & 0x03) << 4)];
        strEncode+= "==";
    }
    else if(Mod==2)
    {
        Tmp[1] = *Data++;
        Tmp[2] = *Data++;
        strEncode+= EncodeTable[(Tmp[1] & 0xFC) >> 2];
        strEncode+= EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xF0) >> 4)];
        strEncode+= EncodeTable[((Tmp[2] & 0x0F) << 2)];
        strEncode+= "=";
    }

}

void Transfer::decodeBase64_(const char* Data, int DataByte, int& OutByte, std::string& strDecode) {

	const char DecodeTable[] =
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        62, // '+'
        0, 0, 0,
        63, // '/'
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // '0'-'9'
        0, 0, 0, 0, 0, 0, 0,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 'A'-'Z'
        0, 0, 0, 0, 0, 0,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // 'a'-'z'
    };
    int nValue;
    int i= 0;
    while (i < DataByte)
    {
        if (*Data != '\r' && *Data!='\n')
        {
            nValue = DecodeTable[*Data++] << 18;
            nValue += DecodeTable[*Data++] << 12;
            strDecode+=(nValue & 0x00FF0000) >> 16;
            OutByte++;
            if (*Data != '=')
            {
                nValue += DecodeTable[*Data++] << 6;
                strDecode+=(nValue & 0x0000FF00) >> 8;
                OutByte++;
                if (*Data != '=')
                {
                    nValue += DecodeTable[*Data++];
                    strDecode+=nValue & 0x000000FF;
                    OutByte++;
                }
            }
            i += 4;
        }
        else        {
            Data++;
            i++;
        }
     }

}

void Transfer::freeInfo_(void* ptr) {

	info* inf = static_cast<info*>(ptr);
	dellocate(const_cast<char*>(inf->getTag()));
	dellocate(const_cast<char*>(inf->getRef()));
	dellocate(inf);
}


void Transfer::downloadItem_(const char* repertory, const char* item, const char* host, const char* dst) {

	int start = 0;
	int end = 4095;
	char urlBuf[512];
	if(access(dst, F_OK) == 0) {
		return;
	}
	FILE* fp = fopen(dst, "wb");
	if(fp == NULL) {
		log.w("create item: %s failed", item);
		throw IOError;
	}
	AddTransAction(dst);
	char buf[1024*6];
	char jsonBuf[1024*6];

	while(true) {
		sprintf(urlBuf, downloadUrl_, downloadAPI_, repertory, item, start, end);
		sprintf(buf, request_, urlBuf, host);
		connect_("127.0.0.1");
		send_(buf);
		recv_(buf);
		parseResponse_(buf, jsonBuf);

		std::string jsonStr(jsonBuf);
		Json::Reader reader;
		Json::Value value;

		if(reader.parse(jsonStr, value)) {
			std::string success = value["success"].asString();
			if(!equal("true", success.c_str())) {
				log.w("request error");
				fclose(fp);
				std::string errno = value["errno"].asString();
				log.w("%s", errno.c_str());
				throw IOError;
			}
			int len = value["length"].asInt();
			std::string data = value["data"].asString();
			std::string decode;
			int outlen = 0;
			decodeBase64_(data.c_str(), len, outlen, decode);
			int write = fwrite(decode.c_str(), 1, outlen, fp);
			if(write != outlen) {
				fclose(fp);
				log.w("IOError: write error");
				throw IOError;
			}
			if(outlen < 4* 1024) {
				break;
			}
		}
		start = end+1;
		end += 4096;
	}
	fclose(fp);

}

void Transfer::uploadItem_(const char*item, const char* host) {

}


void Transfer::downloadDemo(const char* demoMd5, const char* rep, const char* host) {
	
	const char* demo = packTRFileName(demoPath, demoMd5);
	// rep = /Johnson/test demo+4 = /demo/xx
	downloadItem_(rep, demo+4, host, demo);
	char* md5 = MD5_file(demo, MD5LEN);
	if(!equal(md5, demoMd5)) {
		log.w("Transfer failed %s", demo+4);
		dellocate(md5);
		throw Corruption;
	}
	dellocate(md5);

	List<info> ls;
	parseTRFile(demo, &ls, false);
	List<info>::const_iterator iter;
	iter = ls.start();
	dellocate(const_cast<char*>(demo));
	while(iter != ls.end()) {
		const char* ref = packSourceFileName(refPath, iter->data->getRef());
		downloadItem_(rep, ref+4, host, ref);
		md5 = MD5_file(ref, MD5LEN);
		dellocate(const_cast<char*>(ref));
		if(!equal(md5, iter->data->getRef())) {
			log.w("Transfer failed %s", iter->data->getRef());
			dellocate(md5);
			throw Corruption;
		}
		dellocate(md5);
		iter = iter->next;
	}
	ls.freeValueType(freeInfo_);
	
}

void Transfer::upload(const char* url) {

}

void Transfer::downloadWholeProject(const char* url) {

	DIR* dir;
	struct dirent* file;

	dir = opendir("./");
	while((file = readdir(dir)) != NULL) {
		if(strncmp(file->d_name, ".", 1) == 0)
			continue;
		log.w("Can not clone in a non-empty directory");
		throw Corruption;
	}

	const char* p = strstr(url, "http://");
	if(p == NULL) {
		log.w("url request error");
		throw Corruption;
	}
	p += 7;
	const char* rep = strchr(p, '/');
	int hostLength = rep - p;
	char* host = static_cast<char*>(allocate(hostLength + 1));
	strncpy(host, p, hostLength);
	host[hostLength] = '\0';

	char buf[bufferSize];
	const char* trash = packSourceFileName(trashPath, "branchInfo1");
	moveItem(branchInfoName, trash);
	MoveTransAction(branchInfoName, trash);
	dellocate(const_cast<char*>(trash));
	downloadItem_(rep, branchInfoName+4, host, branchInfoName);

	List<info> ls;
	parseTRFile(branchInfoName, &ls, true);
	List<info>::const_iterator iter;
	iter = ls.start();
	while(iter != ls.end()) {
		
		if(equal("currentBranch", iter->data->getTag())) {
			iter = iter->next;
			continue;
		}
		if(equal("master", iter->data->getTag())) {
			const char* master = unpackSourceFileName(masterName);
			trash = packTRFileName(trashPath, master);
			moveItem(masterName, trash);
			MoveTransAction(masterName, trash);
			dellocate(const_cast<char*>(trash));
			dellocate(const_cast<char*>(master));
		
			int repLength = strlen(rep);
			char* ref = static_cast<char*>(allocate(repLength + 1));
			strncpy(ref, rep, repLength);
			ref[repLength] = '\0';
			dellocate(const_cast<char*>(iter->data->getRef()));
			iter->data->setRef(ref);
		}
		const char* branch = packTRFileName(branchPath, iter->data->getTag());
		downloadItem_(rep, branch+4, host, branch);
		
		Vet<info> vt;
		parseTRFile(branch, &vt, false);
		dellocate(const_cast<char*>(branch));
		Vet<info>::const_iterator viter;
		viter = vt.start();
		while(viter != vt.end()) {
			downloadDemo(viter->data->getRef(), rep, host);
			viter = viter->next;
		}
		vt.freeValueType(freeInfo_);
		iter = iter->next;
	}

	const char* branchInfo = unpackSourceFileName(branchInfoName);
	trash = packSourceFileName(trashPath, branchInfo);
	dellocate(const_cast<char*>(branchInfo));
	moveItem(branchInfoName, trash);
	MoveTransAction(branchInfoName, trash);
	dellocate(const_cast<char*>(trash));
	persistenceTRFile(branchInfoName, &ls, handle_);
	ls.freeValueType(freeInfo_);

	const char* current = unpackSourceFileName(currentName);
	trash = packSourceFileName(trashPath, current);
	moveItem(currentName, trash);
	MoveTransAction(currentName, trash);
	dellocate(const_cast<char*>(current));
	dellocate(const_cast<char*>(trash));	
	downloadItem_(rep, currentName+4, host, currentName);
	const char* log = unpackSourceFileName(logName);
	trash = packSourceFileName(trashPath, log);
	moveItem(logName, trash);
	MoveTransAction(logName, trash);
	dellocate(const_cast<char*>(log));
	dellocate(const_cast<char*>(trash));
	downloadItem_(rep, logName+4, host, logName);
	dellocate(host);

	Vet<info> vt;
	parseTRFile(currentName, &vt, false);
	Vet<info>::const_iterator viter;
	viter = vt.start();
	while(viter != vt.end()) {
		const char* ref = viter->data->getRef();
		const char* tag = viter->data->getTag();

		createPath_(tag);
		const char* refName = packSourceFileName(refPath, ref);
		copyItem(refName, tag);
		AddTransAction(tag);
		viter = viter->next;
		dellocate(const_cast<char*>(refName));
	}
	vt.freeValueType(freeInfo_);

}



	
	


}//namespace ccv

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
