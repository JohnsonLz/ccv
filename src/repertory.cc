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
#include "ins/vet.h"
#include "ins/repertory.h"
#include "ins/logcat.h"
#include "ins/mempool.h"
#include "ins/md5.h"
#include "ins/tr.h"
#include "ins/diff.h"
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

	fp = fopen(emptyName, "wb+");
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

	char buf[bufferSize];
	strcpy(buf, "feature-");
	strcpy(buf+strlen("feature-"), name);
	info tmp(buf, NULL, false);
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

	const char* newBranchName = packTRFileName(branchPath, buf);
	tmp.setTag("currentBranch");
	inf = branchInfoVet_.search(&tmp);
	const char* currentBranchName = unpackTRFileName(inf->getRef());
	copyItem(inf->getRef(), newBranchName);
	AddTransAction(inf->getRef());
	dellocate(const_cast<char*>(newBranchName));

	inf = static_cast<info*>(allocate(sizeof(info)));
	int nameLength = strlen(buf);
	char* tag = static_cast<char*>(allocate(nameLength + 1));
	strncpy(tag, buf, nameLength);
	tag[nameLength] = '\0';
	const char* stage = iter->data->getTag();
	const char* ancestorBranchInfo = packBranchInfo(currentBranchName, stage);
	dellocate(const_cast<char*>(currentBranchName));
	new(inf) info(tag, ancestorBranchInfo, true);
	branchInfoVet_.push(inf);
	commitTmp.freeValueType(freeMemory_);
}

void Repertory::switchBranch(const char* name) {

	char buf[bufferSize];
	if(equal(name, "master")) {
		strcpy(buf, "master");
	}
	else {
		strcpy(buf, "feature-");
		strcpy(buf+strlen("feature-"), name);
	}

	info tmp(buf, NULL, false);
	info* inf = branchInfoVet_.search(&tmp);
	if(inf == NULL) {
		log.w("Branch: %s doesn't exist", name);
		throw NotFound;
	}

	tmp.setTag("currentBranch");
	inf = branchInfoVet_.search(&tmp);
	const char* ref = packTRFileName(branchPath, buf);
	if(equal(ref, inf->getRef())) {
		log.w("Branch %s is currentBranch, don't need switch", name);
		return ;
	}
	dellocate(const_cast<char*>(inf->getRef()));
	inf->setRef(ref);

	parseCommitList();
	Vet<info>::const_iterator iter;
	iter = commitVet_.start();
	const char* currentCommit = iter->data->getTag();
	reverseCommit(currentCommit);
	log.v("reverse branch: %s lastest commit stage", name);
}

void Repertory::merge(const char* branchName) {

	info tmp("currentBranch", NULL, false);
	info* inf = branchInfoVet_.search(&tmp);
	if(inf == NULL) {
		log.w("Branchinfo has been destory");
		throw NotFound;
	}

	const char* tag = unpackTRFileName(inf->getRef());
	tmp.setTag(tag);
	inf = branchInfoVet_.search(&tmp);
//	dellocate(const_cast<char*>(tag));

	const char* fatherBranch = getFatherBranch(inf->getRef());
	if(!equal(branchName, fatherBranch)) {
		log.w("branch: %s is not the father branch of currentBranch", branchName); 
		log.w("only allow to merger to father branch");
		dellocate(const_cast<char*>(fatherBranch));
		throw Corruption;
	}

	List<info>ancestorList;
	List<info>featureList;
	List<info>fatherList;
	Vet<info>commitVet;
	const char* fatherBranchRef = packTRFileName(branchPath, fatherBranch);
	dellocate(const_cast<char*>(fatherBranch));
	parseTRFile(currentName, &featureList, false);
	parseTRFile(fatherBranchRef, &commitVet, false);
	dellocate(const_cast<char*>(fatherBranchRef));

	Vet<info>::const_iterator iter;
	iter = commitVet.start();
	const char* fatherStageRef = packTRFileName(demoPath,iter->data->getRef());
	parseTRFile(fatherStageRef, &fatherList, false);
	const char* ancestor = getStageBranch(inf->getRef());
	tmp.setTag(ancestor);
	inf = commitVet.search(&tmp);
	const char* ancestorStageRef = packTRFileName(demoPath, inf->getRef());
	parseTRFile(ancestorStageRef, &ancestorList, false);
	dellocate(const_cast<char*>(ancestor));
	dellocate(const_cast<char*>(fatherStageRef));
	dellocate(const_cast<char*>(ancestorStageRef));
	commitVet.freeValueType(freeMemory_);

	Vet<info>conflictVet;
	List<info>::const_iterator liter;
	liter = fatherList.start();
	while(liter != fatherList.end()) {
		info* ancestorSearch;
		info* featureSearch;
		info* insertInfo;

		info* currentSearch = liter->data;
		info tmp(currentSearch->getTag(), NULL, false);
		ancestorSearch = ancestorList.search(&tmp);
		featureSearch = featureList.search(&tmp);
		if(ancestorSearch == NULL) {
			if(featureSearch == NULL) {
				const char* dstFile = packSourceFileName(refPath, currentSearch->getRef());
				createPath(currentSearch->getTag());
				copyItem(dstFile, currentSearch->getTag());
				AddTransAction(currentSearch->getTag());
				dellocate(const_cast<char*>(dstFile));
				liter = liter->next;
				continue;
			}
			else {
				if(equal(currentSearch->getRef(), featureSearch->getRef())) {
					featureSearch->setPersistence(true);
					liter = liter->next;
					continue;
				}
				else {
					//TODO::conflict;
					const char* dstFile = packSourceFileName(refPath, currentSearch->getRef());
					insertInfo = static_cast<info*>(allocate(sizeof(info)));
					int tagLength = strlen(currentSearch->getTag());
					char* srcFile = static_cast<char*>(allocate(tagLength+1));
					strncpy(srcFile, currentSearch->getTag(), tagLength);
					srcFile[tagLength] = '\0';
					new(insertInfo) info(srcFile, dstFile, false);
					conflictVet.push(insertInfo);
					featureSearch->setPersistence(true);
					liter = liter->next;
					continue;
				}
			}
		}
		else {
			if(featureSearch == NULL) {
				if(equal(currentSearch->getRef(), ancestorSearch->getRef())) {
					//const char* dstFile = packTRFileName(refPath, currentSearch->getRef());
					//createPath(currentSearch->getTag());
					//copyItem(dstFile, currentSearch->getTag());
					//AddTransAction(currentSearch->getTag());
					//dellocate(const_cast<char*>(dstFile));
					liter = liter->next;
					continue;
				}
				else {
					//TODO::
					const char* dstFile = packSourceFileName(refPath, currentSearch->getRef());
					insertInfo = static_cast<info*>(allocate(sizeof(info)));
					int tagLength = strlen(currentSearch->getTag());
					char* srcFile = static_cast<char*>(allocate(tagLength+1));
					strncpy(srcFile, currentSearch->getTag(), tagLength);
					srcFile[tagLength] = '\0';
					createPath(srcFile);
					copyItem(dstFile, srcFile);
					new(insertInfo) info(srcFile, dstFile, true);
					conflictVet.push(insertInfo);
					liter = liter->next;
					continue;
				}
			}
			else {
				if(equal(currentSearch->getRef(), featureSearch->getRef())) {
					featureSearch->setPersistence(true);
					liter = liter->next;
					continue;
				}
				else {
					if(equal(currentSearch->getRef(), ancestorSearch->getRef())) {
						featureSearch->setPersistence(true);
						liter = liter->next;
						continue;
					}
					if(equal(featureSearch->getRef(), ancestorSearch->getRef())) {
						const char* name = unpackSourceFileName(featureSearch->getRef());
						const char* trashName = packSourceFileName(trashPath, name);
						dellocate(const_cast<char*>(name));
						moveItem(currentSearch->getTag(), trashName);
						MoveTransAction(currentSearch->getTag(), trashName);
						dellocate(const_cast<char*>(name));
						createPath(currentSearch->getTag());
						const char* refName = packSourceFileName(refPath, currentSearch->getRef());
						copyItem(refName, currentSearch->getTag());
						AddTransAction(currentSearch->getTag());
						dellocate(const_cast<char*>(refName));
						featureSearch->setPersistence(true);
						liter = liter->next;
						continue;
					}
					else {
						const char* dstFile = packSourceFileName(refPath, currentSearch->getRef());
						insertInfo = static_cast<info*>(allocate(sizeof(info)));
						int tagLength = strlen(currentSearch->getTag());
						char* srcFile = static_cast<char*>(allocate(tagLength+1));
						strncpy(srcFile, currentSearch->getTag(), tagLength);
						srcFile[tagLength] = '\0';
						new(insertInfo) info(srcFile, dstFile, false);
						conflictVet.push(insertInfo);
						featureSearch->setPersistence(true);
						liter = liter->next;
						continue;

					}
				}
			}
		}
	}

	liter = featureList.start();
	while(liter != featureList.end()) {
		info* currentSearch;
		info* ancestorSearch;
		info* insertInfo;

		currentSearch = liter->data;
		info tmp(currentSearch->getTag(), NULL, false);
		ancestorSearch = ancestorList.search(&tmp);
		if(currentSearch->Persistence()) {
			liter = liter->next;
			continue;
		}
		if(ancestorSearch == NULL) {
			liter = liter->next;
			continue;
		}
		else {
			if(equal(ancestorSearch->getRef(), currentSearch->getRef())) {
				const char* name = unpackSourceFileName(currentSearch->getTag());
				const char* trashName = packSourceFileName(trashPath, name);
				dellocate(const_cast<char*>(name));
				moveItem(currentSearch->getTag(), trashName);
				MoveTransAction(currentSearch->getTag(), trashName);
				dellocate(const_cast<char*>(trashName));
				liter = liter->next;
				continue;
			}
			else {
				const char* dstFile = packSourceFileName(refPath, currentSearch->getRef());
				insertInfo = static_cast<info*>(allocate(sizeof(info)));
				int tagLength = strlen(currentSearch->getTag());
				char* srcFile = static_cast<char*>(allocate(tagLength+1));
				strncpy(srcFile, currentSearch->getTag(), tagLength);
				srcFile[tagLength] = '\0';
				new(insertInfo) info(srcFile, dstFile, true);
				conflictVet.push(insertInfo);
				liter = liter->next;
				continue;
			}
		}
	}

	featureList.freeValueType(freeMemory_);
	fatherList.freeValueType(freeMemory_);
	ancestorList.freeValueType(freeMemory_);

	Vet<info>::const_iterator viter;
	viter = conflictVet.start();
	if(viter == NULL) {
		log.v("merge successfully\n");
		log.v("command ccv-merge commit [commitName] to finish this merge");
		log.v("command ccv-reverse [commitName] to cancel this merge");
		return;
	}
	log.w("Conflict item");
	log.w("        Type        Item\n");
	while(viter != conflictVet.end()) {
		info* tmp = viter->data;
		if(tmp->Persistence()) {
			log.i("         RM       %s", tmp->getTag());	
		}
		else {
			Diff di;
			di.diffItem(tmp->getTag(), tmp->getRef(), tag+8, branchName);
			log.i("         CG       %s", tmp->getTag());
		}
		viter = viter->next;
	}

	dellocate(const_cast<char*>(tag));
	conflictVet.freeValueType(freeMemory_);
	log.w("Type RM : remove conflict, decide remove this item or not");
	log.w("Type CG : change conflict, confliction was marked in the item");
	log.v("Handle the conflict first ");
	log.v("command ccv-merge commit [commitName] to finish this merge");
	log.v("command ccv-reverse [commitName] to cancel this merge");
}

void Repertory::mergeCommit(const char* tag) {

	info tmp("currentBranch", NULL, false);
	info* inf = branchInfoVet_.search(&tmp);
	if(inf == NULL) {
		log.w("Branchinfo has been destory");
		throw NotFound;
	}

	const char* branchName = unpackTRFileName(inf->getRef());
	tmp.setTag(branchName);
	inf = branchInfoVet_.search(&tmp);
	dellocate(const_cast<char*>(branchName));

	const char* fatherName = getFatherBranch(inf->getRef());
	const char* fatherBranchRef = packTRFileName(branchPath, fatherName);
	tmp.setTag(fatherName);
	inf = branchInfoVet_.search(&tmp);
	if(inf == NULL) {
		log.w("Branch: %s doesn't exist", fatherName);
		throw NotFound;
	}

	dellocate(const_cast<char*>(fatherName));
	tmp.setTag("currentBranch");
	inf = branchInfoVet_.search(&tmp);
	dellocate(const_cast<char*>(inf->getRef()));
	inf->setRef(fatherBranchRef);

	parseCommitList();
	Demo demo;
	try {
		demo.parseStructure(currentName);
		demo.travel(".");
		demo.persistenceDemo();
	}
	catch(Code c) {
		log.w("Add failed");
		throw Corruption;
	}

	try {
		commit(tag);
		persistenceCommit();
	}
	catch(Code c) {
		log.w("commit failed");
		throw Corruption;
	}
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
