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
#include <cstdio>
#include <string.h>
#include <new>
#include <unistd.h>

#include "ins/file.h"
#include "ins/list.h"
#include "ins/repertory.h"
#include "ins/logcat.h"
#include "ins/mempool.h"
#include "ins/md5.h"
#include "ins/object.h"
#include "ins/transAction.h"

namespace ccv {

void Repertory::init() {
	
	createDir("./.ccv");
	log.v("create .ccv");
	AddDirTransAction(".ccv");

	createDir(".ccv/demo");
	log.v("create .ccv/demo");
	AddDirTransAction(".ccv/demo");

	createDir(".ccv/stage");
	log.v("create ./ccv/stage");
	AddDirTransAction(".ccv/stage");

	createDir(".ccv/ref");
	log.v("create .ccv/ref");
	AddDirTransAction(".ccv/ref");

	createDir(".ccv/trashTmp");
	log.v("create .ccv/trashTmp");
	AddDirTransAction(".ccv/trashTmp");
	
	FILE* fp = fopen(".ccv/current", "wb+");
	if(fp == NULL) {
		throw IOError;
	}
	fclose(fp);
	log.v("create .ccv/current");
	AddTransAction(".ccv/current");

	fp = fopen(".ccv/commit", "wb+");
	if(fp == NULL) {
		throw IOError;
	}
	fclose(fp);
	log.v("create .ccv/commit");
	AddTransAction(".ccv/commit");
}

void Repertory::checkRepertory() {

	try {
		accessDir("./.ccv");
		accessDir(".ccv/demo");
		accessDir(".ccv/stage");
		accessDir(".ccv/ref");
		accessDir(".ccv/trashTmp");

		accessFile(".ccv/current");
		accessFile(".ccv/commit");
	}
	catch(Code c) {
		log.e("Repertory has been destoryed");
		exit(0);
	}
}

void Repertory::persistenceCommit() {

	moveItem(".ccv/commit", ".ccv/trashTmp/commit");
	MoveTransAction(".ccv/commit", ".ccv/trashTmp/commit");

	FILE* fp = fopen(".ccv/commit", "wb+");
	if(fp == NULL) {
		log.w("can not open .ccv/commit");
		throw NotFound;
	}
	AddTransAction(".ccv/commit");

	char size[4];
	List<commitInfo>::const_iterator iter;
	iter = commitList_.start();
	while(iter != commitList_.end()) {
		commitInfo* ci = iter->data;
		int length = strlen(ci->getTag());
		encodeFixed32(size, length);

		int write = fwrite(size, 4, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		write = fwrite(ci->getTag(), length, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		write = fwrite(ci->getRef(), MD5LEN, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		iter = iter->next;
	}
	fclose(fp);
}

void Repertory::parseCommitList() {
	
	FILE* fp = fopen(".ccv/commit", "rb");
	if(fp == NULL) {
		log.w("can not open .ccv/commit");
		throw NotFound;
	}

	char buf[bufferSize];
	char size[4];
	int read;
	int write;

	read = fread(size, 4, 1, fp);
	if(read == 0)
		return ;
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
		char* tag = static_cast<char*>(allocate(length+1));
		strncpy(tag, buf, length);
		tag[length] = '\0';

		read = fread(buf, MD5LEN, 1, fp);
		if(read == 0) {
			log.w("IOError: read error");
			fclose(fp);
			throw IOError;
		}
		char* md5 = static_cast<char*>(allocate(MD5LEN + 1));
		strncpy(md5, buf, MD5LEN);
		md5[MD5LEN] = '\0';

		commitInfo* ci = static_cast<commitInfo*>(allocate(sizeof(commitInfo)));
		new(ci) commitInfo(tag, md5);
		commitList_.insert(ci);		
	}
	fclose(fp);
}

void Repertory::commit(const char* tag) {

	char* md5 = MD5_file(".ccv/current", MD5LEN);
	const char* demoPath = ".ccv/demo/";
	char buf[bufferSize];

	commitInfo* ci = static_cast<commitInfo*>(allocate(sizeof(commitInfo)));
	char* citag = static_cast<char*>(allocate(strlen(tag)+1));
	strcpy(citag, tag);
	
	new(ci) commitInfo(citag, md5);
	commitInfo* tmp = commitList_.search(ci);
	if(tmp != NULL) {
		log.w("Tag: %s has existed", citag);
		dellocate(md5);
		dellocate(citag);
		dellocate(ci);
		throw Corruption;
	}

	strcpy(buf, demoPath);
	strncpy(buf+strlen(demoPath), md5, MD5LEN);
	buf[strlen(demoPath)+MD5LEN] = '\0';
	
	if(access(buf, F_OK) == 0) {
		log.w("Nothing has changed since last commit");
		dellocate(md5);
		dellocate(citag);
		dellocate(ci);
		throw Corruption;
	}

	commitList_.insert(ci);
	Demo demo;
	demo.persistenceRef();

	moveItem(".ccv/current", buf);
	MoveTransAction(".ccv/current", buf);

	FILE* fp = fopen(".ccv/current", "wb+");
	if(fp == NULL) {
		log.w("create item .ccv/current failed");
		throw IOError;
	}
	fclose(fp);
	AddTransAction(".ccv/current");
}

void Repertory::checkoutCommit(const char* tag) {

	commitInfo* tmp = static_cast<commitInfo*>(allocate(sizeof(commitInfo)));
	new(tmp) commitInfo(tag, NULL);
	commitInfo* ci = commitList_.search(tmp);
	if(ci == NULL) {
		log.w("Tag: %s does not existed", tag);
		dellocate(tmp);
		throw NotFound;
	}
	dellocate(tmp);
	const char* ref = ci->getRef();
	Demo demo;
	demo.checkoutDemo(ref);
}


void Repertory::freeMemory_(void* p) {

	commitInfo* ci = static_cast<commitInfo*>(p);
	dellocate(const_cast<char*>(ci->getTag()));
	dellocate(const_cast<char*>(ci->getRef()));
	dellocate(ci);
}

bool Repertory::commitInfo::operator > (const commitInfo& item) {
	
	if(strcmp(tag_, item.getTag()) >0)
		return true;
	return false;
}

bool Repertory::commitInfo::operator == (const commitInfo& item) {

	if(strcmp(tag_, item.getTag()) == 0)
		return true;
	return false;
}

}//namespace ccv

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
