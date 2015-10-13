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

#include <string.h>
#include <stdio.h>
#include <new>

#include "ins/tr.h"
#include "ins/list.h"
#include "ins/md5.h"
#include "ins/vet.h"
#include "ins/file.h"
#include "ins/logcat.h"
#include "ins/mempool.h"
#include "ins/transAction.h"

namespace ccv {
	
void parseTRFile(const char* fileName, List<info>* ls, bool persistence) {

	FILE* fp = fopen(fileName, "rb");
	if(fp == NULL) {
		log.w("open item: %s falied", fileName);
		throw NotFound;
	}

	char buf[bufferSize];
	char size[4];
	int read;
	
	read = fread(size, 4, 1, fp);
	if(read == 0) {
		throw Empty;
	}
	fseek(fp, 0, SEEK_SET);
	while(true) {
		read = fread(size, 4, 1, fp);
		if(read == 0)
			break;
		int length = decodeFixed32(size);
		read = fread(buf, length, 1, fp);
		if(read == 0) {
			log.w("IOError: read error");
			fclose(fp);
			throw IOError;
		}
		char* tag = static_cast<char*>(allocate(length + 1));
		strncpy(tag, buf, length);
		tag[length] ='\0';

		read = fread(buf, MD5LEN, 1, fp);
		if(read == 0) {
			log.w("IOError: read error");
			fclose(fp);
			throw IOError;
		}
		buf[MD5LEN] = '\0';
		length = strlen(buf);
		char* ref = static_cast<char*>(allocate(length + 1));
		strncpy(ref, buf, length);
		ref[length] = '\0';

		info* inf = static_cast<info*>(allocate(sizeof(info)));
		new(inf) info(tag, ref, persistence);
		ls->insert(inf);
	}
	fclose(fp);
}

void parseTRFile(const char* fileName, Vet<info>* vt, bool persistence) {

	FILE* fp = fopen(fileName, "rb");
	if(fp == NULL) {
		log.w("open item: %s falied", fileName);
		throw NotFound;
	}

	char buf[bufferSize];
	char size[4];
	int read;
	
	read = fread(size, 4, 1, fp);
	if(read == 0) {
		throw Empty;
	}
	fseek(fp, 0, SEEK_SET);
	while(true) {
		read = fread(size, 4, 1, fp);
		if(read == 0)
			break;
		int length = decodeFixed32(size);
		read = fread(buf, length, 1, fp);
		if(read == 0) {
			log.w("IOError: read error");
			fclose(fp);
			throw IOError;
		}
		char* tag = static_cast<char*>(allocate(length + 1));
		strncpy(tag, buf, length);
		tag[length] ='\0';

		read = fread(buf, MD5LEN, 1, fp);
		if(read == 0) {
			log.w("IOError: read error");
			fclose(fp);
			throw IOError;
		}
		buf[MD5LEN] = '\0';
		length = strlen(buf);
		char* ref = static_cast<char*>(allocate(length + 1));
		strncpy(ref, buf, length);
		ref[length] = '\0';

		info* inf = static_cast<info*>(allocate(sizeof(info)));
		new(inf) info(tag, ref, persistence);
		vt->append(inf);
	}
	fclose(fp);
}

void persistenceTRFile(const char* fileName, List<info>* ls, Handler hd) {

	FILE* fp = fopen(fileName, "wb+");
	if(fp == NULL) {
		log.w("open item: %s failed", fileName);
		throw NotFound;
	}
	AddTransAction(fileName);

	char size[4];
	List<info>::const_iterator iter;
	iter = ls->start();
	while(iter != ls->end()) {
		info* inf = iter->data;
		if(!inf->Persistence()) {
			(*hd)(fileName);
			iter = iter->next;
			continue;
		}

		int write;
		int length = strlen(inf->getTag());
		encodeFixed32(size, length);
		write = fwrite(size, 4, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		write = fwrite(inf->getTag(), length, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}

		length = strlen(inf->getRef());
		if(length > MD5LEN) {
			log.w("Too long of REF");
			fclose(fp);
			throw Corruption;
		}
		if(length < MD5LEN) {
			char buf[MD5LEN];
			strncpy(buf, inf->getRef(), length);
			buf[length] = '\0';
			length++;
			while(length < MD5LEN) {
				buf[length+1] = '0';
				length++;
			}
			write = fwrite(buf, MD5LEN, 1, fp);
			if(write == 0) {
				log.w("IOError: write error");
				fclose(fp);
				throw IOError;
			}
		}
		else {
			write = fwrite(inf->getRef(), MD5LEN, 1, fp);
			if(write == 0) {
				log.w("IOError: write error");
				fclose(fp);
				throw IOError;
			}
		}
		iter = iter->next;
	}
	fclose(fp);
}

void persistenceTRFile(const char* fileName, Vet<info>* vt, Handler hd) {

	FILE* fp = fopen(fileName, "wb+");
	if(fp == NULL) {
		log.w("open item: %s failed", fileName);
		throw NotFound;
	}
	AddTransAction(fileName);

	char size[4];
	Vet<info>::const_iterator iter;
	iter = vt->start();
	while(iter != vt->end()) {
		info* inf = iter->data;
		if(!inf->Persistence()) {
			(*hd)(fileName);
			continue;
		}

		int write;
		int length = strlen(inf->getTag());
		encodeFixed32(size, length);
		write = fwrite(size, 4, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		write = fwrite(inf->getTag(), length, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}

		length = strlen(inf->getRef());
		if(length > MD5LEN) {
			log.w("Too long of REF");
			fclose(fp);
			throw Corruption;
		}
		if(length < MD5LEN) {
			char buf[MD5LEN];
			strncpy(buf, inf->getRef(), length);
			buf[length] = '\0';
			length++;
			while(length < MD5LEN) {
				buf[length+1] = '0';
				length++;
			}
			write = fwrite(buf, MD5LEN, 1, fp);
			if(write == 0) {
				log.w("IOError: write error");
				fclose(fp);
				throw IOError;
			}
		}
		else {
			write = fwrite(inf->getRef(), MD5LEN, 1, fp);
			if(write == 0) {
				log.w("IOError: write error");
				fclose(fp);
				throw IOError;
			}
		}
		iter = iter->next;
	}
	fclose(fp);
}
	
const char* packTRFileName(const char* path, const char* name) {
	
	int pathLength = strlen(path);
	int nameLength = strlen(name);
	int totalLength = pathLength + nameLength + 4;
	char* trName = static_cast<char*>(allocate(totalLength));
	strncpy(trName, path, pathLength);
	strncpy(trName+pathLength, name, nameLength);
	strncpy(trName+pathLength+nameLength, ".tr", 3);
	trName[totalLength-1] = '\0';
	return trName;
}

const char* unpackTRFileName(const char* TRFileName) {

	int length = strlen(TRFileName);
	if(strncmp(TRFileName+(length-3), ".tr", 3) != 0) {
		log.w("File: %s is not TRFile", TRFileName);
		throw Corruption;
	}

	int i=0;
	int position = -1;
	while(i<length) {
		if(TRFileName[i] == '/')
			position = i;
		i++;
	}
	length -= 3;
	char* name = static_cast<char*>(allocate(length - position));
	strncpy(name, TRFileName + position + 1, length - position -1);
	name[length-position -1] = '\0';
	return name;
}

const char* packSourceFileName(const char* path, const char* name) {

	int pathLength = strlen(path);
	int nameLength = strlen(name);
	int totalLength = pathLength + nameLength + 1;
	char* sourceName = static_cast<char*>(allocate(totalLength));
	strncpy(sourceName, path, pathLength);
	strncpy(sourceName+pathLength, name, nameLength);
	sourceName[totalLength -1] = '\0';
	return sourceName;
}

const char* unpackSourceFileName(const char* fileName) {

	int length = strlen(fileName);
	int i= 0;
	int position = -1;
	while(i < length) {
		if(fileName[i] == '/')
			position = i;
		i++;
	}
	char* name = static_cast<char*>(allocate(length - position));
	strcpy(name, fileName+position+1);
	name[length-position-1] = '\0';
	return name;
}

const char* packBranchInfo(const char* father, const char* stage) {

	int fatherLength = strlen(father);
	int stageLength = strlen(stage);
	int totalLength = fatherLength + stageLength + 2;
	char* branchInfo = static_cast<char*>(allocate(totalLength));
	strncpy(branchInfo, father, fatherLength);
	branchInfo[fatherLength] = '/';
	strncpy(branchInfo+fatherLength+1, stage, stageLength);
	branchInfo[totalLength - 1] ='\0';
	return branchInfo;
}

const char* getFatherBranch(const char* branchName) {

	int length = strlen(branchName); 
	int position = 0;
	while(position < length) {
		if(branchName[position] == '/')
			break;
		position ++;
	}
	char* father = static_cast<char*>(allocate(position + 1));
	strncpy(father, branchName, position);
	father[position] = '\0';
	return father;
}

const char* getStageBranch(const char* branchName) {

	int length = strlen(branchName);
	int position = 0;
	while(position < length) {
		if(branchName[position] == '/')
			break;
		position ++;
	}
	char* stage = static_cast<char*>(allocate(length - position));
	strncpy(stage, branchName+position+1, length-position -1);
	stage[length - position -1] = '\0';
	return stage;
}

const char* handleCorruptionName(const char* name) {

	int length = strlen(name);
	int position1 = 0;
	int position2 = 0;
	int position3 = 0;
	int i = 0;

	while(i < length) {
		if(name[i] == '(') {
			position1 = i;
		}
		if(name[i] == ')') {
			position2 = i;
			break;
		}
		if(name[i] == '.') {
			position3 = i;
			break;
		}
		i++;
	}
	int mark = 0;
	if(position1 && position2) {
		i = position1+1;
		while(i<position2) {
			mark = mark*10 + (name[i] - 16);
		}
		mark++;
		int power = 1;
		while(mark/power) {
			length++;
		}
		char buf[bufferSize];
		strncpy(buf, name, position1+1);
		int lengthtmp = position1+1;
		while(power) {
			int tmp = mark/power;
			buf[lengthtmp] = tmp + 16;
			mark = mark - tmp*power;
			power/= 10;
			lengthtmp++;
		}
		strcpy(buf+lengthtmp, name+position2);
		lengthtmp = strlen(buf);
		char* result = static_cast<char*>(allocate(lengthtmp + 1));
		strncpy(result, buf, lengthtmp);
		result[lengthtmp] = '\0';
		return result;
	}
	else if(position3) {
		char* result = static_cast<char*>(allocate(length + 4));
		strncpy(result, name, position3);
		strcpy(result+position3, "(1)");
		strcpy(result+position3+3, name+position3);
		result[length+3] = '\0';
		return result;
	}
	else {
		char* result = static_cast<char*>(allocate(length + 4));
		strncpy(result, name, length);
		strcpy(result+length, "(1)");
		result[length+3] = '\0';
		return result;
	}
}



bool info::operator > (const info& item) {
		
	if(strcmp(tag_, item.getTag()) > 0)
		return true;
	return false;
}

bool info::operator == (const info& item) {
	
	if(strcmp(tag_, item.getTag()) == 0)
		return true;
	return false;
}
	
}//namesapce ccv

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
