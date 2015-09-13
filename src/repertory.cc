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
#include "ins/tr.h"
#include "ins/object.h"
#include "ins/transAction.h"

namespace ccv {

void Repertory::init() {
	
	createDir("./.ccv");
	log.v("create  .ccv");
	AddDirTransAction(".ccv");

	createDir(demoName);
	log.v("create %s", demoName);
	AddDirTransAction(demoName);

	createDir(stageName);
	log.v("create %s", stageName);
	AddDirTransAction(stageName);

	createDir(refName);
	log.v("create %s", refName);
	AddDirTransAction(refName);

	createDir(trashName);
	log.v("create %s", trashName);
	AddDirTransAction(trashName);
	
	createDir(branchName);
	log.v("create %s", branchName);
	AddDirTransAction(branchName);

	FILE* fp = fopen(currentName, "wb+");
	if(fp == NULL) {
		throw IOError;
	}
	fclose(fp);
	log.v("create %s", currentName);
	AddTransAction(currentName);

	fp = fopen(masterName, "wb+");
	if(fp == NULL) {
		throw IOError;
	}
	fclose(fp);
	log.v("create %s", masterName);
	AddTransAction(masterName);

	fp = fopen(logName, "wb+");
	if(fp == NULL) {
		throw IOError;
	}
	fclose(fp);
	log.v("create %s", logName);
	AddTransAction(logName);

	fp = fopen(branchInfoName, "wb+");
	if(fp == NULL) {
		throw IOError;
	}
	fclose(fp);
	log.v("create %s", branchInfoName);
	AddTransAction(branchInfoName);


}

void Repertory::checkRepertory() {

	try {
		accessDir("./.ccv");
		accessDir(demoName);
		accessDir(stageName);
		accessDir(refName);
		accessDir(trashName);
		accessDir(branchName);

		accessFile(currentName);
		accessFile(masterName);
		accessFile(logName);
		accessFile(branchInfoName);
	}
	catch(Code c) {
		log.e("Repertory has been destoryed");
		exit(0);
	}
}

void Repertory::persistenceBranchInfo() {

	char buf[bufferSize];
	strcpy(buf, trashPath);
	strcpy(buf+strlen(trashPath), "branchInfo.tr");
	moveItem(branchInfoName, buf);
	MoveTransAction(branchInfoName, buf);
	persistenceTRFile(branchInfoName, &branchInfoVet_, persistenceHandler_);
}

void Repertory::parseBranchInfoVet() {

	try {
		parseTRFile(branchInfoName, &branchInfoVet_, true);
	}
	catch(Code c) {
		if(c == Empty) {
			const char* tag = "currentBranch";
			const char* ref = masterName;
			int tagLength = strlen(tag);
			int refLength = strlen(ref);

			char* iftag = static_cast<char*>(allocate(tagLength + 1));
			char* ifref = static_cast<char*>(allocate(refLength + 1));
			info* inf = static_cast<info*>(allocate(sizeof(info)));
			strncpy(iftag, tag, tagLength);
			iftag[tagLength] = '\0';
			strncpy(ifref, ref, refLength);
			ifref[refLength] = '\0';
			new(inf) info(iftag, ifref, true);
			branchInfoVet_.push(inf);

			tag = "master";
			tagLength = strlen(tag);
			iftag = static_cast<char*>(allocate(tagLength + 1));
			inf = static_cast<info*>(allocate(sizeof(info)));
			strncpy(iftag, tag, tagLength);
			iftag[tagLength] = '\0';
			new(inf) info(iftag, ifref, true);
			branchInfoVet_.push(inf);
		}
		else {
			throw c;
		}
	}
}


void Repertory::persistenceCommit() {

	info tmp("currentBranch", NULL, false);
	info* inf = branchInfoVet_.search(&tmp);
	if(inf == NULL) {
		log.w("%s has destoryed", branchInfoName);
		throw IOError;
	}

	const char* currentBranch = unpackTRFileName(inf->getRef());
	const char* oldName = packTRFileName(branchPath, currentBranch);
	const char* newName = packTRFileName(trashPath, currentBranch);
	moveItem(oldName, newName);
	MoveTransAction(oldName, newName);
	dellocate(const_cast<char*>(newName));

	persistenceTRFile(oldName, &commitVet_, persistenceHandler_);
	dellocate(const_cast<char*>(oldName));
	dellocate(const_cast<char*>(currentBranch));
}

void Repertory::parseCommitList() {
	
	parseCommitList_(&commitVet_);
}

void Repertory::parseCommitList_(Vet<info>* vt) {
	
	info tmp("currentBranch", NULL, false);
	info* inf = branchInfoVet_.search(&tmp);
	if(inf == NULL) {
		log.w("%s has been destoryed", branchInfoName);
		throw IOError;
	}

	const char* fileName = inf->getRef();
	try {
		parseTRFile(fileName, vt, true);
	}
	catch(Code c) {
		if(c == Empty) {}
		else {
			throw c;
		}
	}
}

void Repertory::commit(const char* tag) {

	char* md5 = MD5_file(currentName, MD5LEN);
	info* inf = static_cast<info*>(allocate(sizeof(info)));
	char* iftag = static_cast<char*>(allocate(strlen(tag)+1));
	strcpy(iftag, tag);
	
	new(inf) info(iftag, md5, true);
	info* tmp = commitVet_.search(inf);
	if(tmp != NULL) {
		log.w("Tag: %s has existed", iftag);
		dellocate(md5);
		dellocate(iftag);
		dellocate(inf);
		throw Corruption;
	}

	const char* demo = packTRFileName(demoPath, md5);	
	if(access(demo, F_OK) == 0) {
		log.w("Nothing has changed since last commit");
		dellocate(md5);
		dellocate(iftag);
		dellocate(inf);
		dellocate(const_cast<char*>(demo));
		throw Corruption;
	}

	commitVet_.push(inf);
	Demo deo;
	deo.persistenceRef();

	copyItem(currentName, demo);
	AddTransAction(demo);
	dellocate(const_cast<char*>(demo));

}

void Repertory::reverseCommit(const char* tag) {

	info tmp(tag, NULL, false);	
	info* inf = commitVet_.search(&tmp);
	if(inf == NULL) {
		log.w("Tag: %s does not existed", tag);
		throw NotFound;
	}

	const char* ref = inf->getRef();
	Demo demo;
	demo.reverseDemo(ref);
}

void Repertory::newBranch(const char* name) {

	info tmp(name, NULL, false);
	info* inf = branchInfoVet_.search(&tmp);
	if(inf != NULL) {
		log.w("Branch %s has esisted", name);
		throw Corruption;
	}

	Vet<info> commitTmp;
	parseCommitList_(&commitTmp);

	Vet<info>::const_iterator iter;
	iter = commitTmp.start();
	if(iter == NULL) {
		log.w("current branch contain null commit");
		log.w("can not create new branch in current stage");
		commitTmp.freeValueType(freeMemory_);
		throw Corruption;
	}
	const char* ref = iter->data->getRef();
	char* md5 = MD5_file(currentName, MD5LEN);
	if(strcmp(md5, ref) != 0) {
		log.w("create branch must be in the laster commit stage");
		log.w("please reverse to the lastest commit of this branch and then create new branch");
		dellocate(md5);
		commitTmp.freeValueType(freeMemory_);
		throw Corruption;
	}
	dellocate(md5);
	commitTmp.freeValueType(freeMemory_);

	const char* newBranchName = packTRFileName(branchPath, name);
	copyItem(masterName, newBranchName);
	AddTransAction(newBranchName);

	inf = static_cast<info*>(allocate(sizeof(info)));
	int nameLength = strlen(name);
	char* tag = static_cast<char*>(allocate(nameLength + 1));
	strncpy(tag, name, nameLength);
	tag[nameLength] = '\0';
	new(inf) info(tag, newBranchName, true);
	branchInfoVet_.push(inf);
}

void Repertory::switchBranch(const char* name) {

	info tmp(name, NULL, false);
	info* inf = branchInfoVet_.search(&tmp);
	if(inf == NULL) {
		log.w("Branch: %s doesn't exist");
		throw NotFound;
	}

	int length = strlen(inf->getRef());
	char* ref = static_cast<char*>(allocate(length + 1));
	strncpy(ref, inf->getRef(), length);
	ref[length] = '\0';
	tmp.setTag("currentBranch");
	inf = branchInfoVet_.search(&tmp);
	dellocate(const_cast<char*>(inf->getRef()));
	inf->setRef(ref);

	parseCommitList();
	Vet<info>::const_iterator iter;
	iter = commitVet_.start();
	const char* currentCommit = iter->data->getTag();
	reverseCommit(currentCommit);
	log.v("reverse branch: %s lastest commit stage", name);
}

void Repertory::freeMemory_(void* p) {

	info* inf = static_cast<info*>(p);
	dellocate(const_cast<char*>(inf->getTag()));
	dellocate(const_cast<char*>(inf->getRef()));
	dellocate(inf);
}

void Repertory::persistenceHandler_(const char* fileName) {

}


}//namespace ccv

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
