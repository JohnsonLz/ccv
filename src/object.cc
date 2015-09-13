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

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <new>

#include "ins/object.h"
#include "ins/list.h"
#include "ins/md5.h"
#include "ins/tr.h"
#include "ins/logcat.h"
#include "ins/mempool.h"
#include "ins/file.h"
#include "ins/transAction.h"

namespace ccv {

void Demo::travel(const char* directory) {

	DIR* dir;
	struct dirent* file;
	struct stat st;
	char buf[bufferSize];

	dir = opendir(directory);
	if(dir == NULL) {
		log.w("can not found dir: %s", directory);
		throw NotFound;
	}
	strcpy(buf, directory);
	strcpy(buf+strlen(directory), "/");
	while((file = readdir(dir)) != NULL) {
		if(strncmp(file->d_name, ".", 1) == 0)
			continue;

		strcpy(buf+strlen(directory)+1, file->d_name);
		if(stat(buf, &st) != 0) {
			perror(buf);
			closedir(dir);
			throw IOError;
		}
		if(S_ISDIR(st.st_mode)) {
			try {
				travel(buf);
			}
			catch(Code c) {
				closedir(dir);
				throw c;
			}
		}
		else {
			char* name = static_cast<char*>(allocate(strlen(buf)+1));
			strcpy(name, buf);
			char* md5 = MD5_file(name, MD5LEN);
			info* inf = static_cast<info*>(allocate(sizeof(info)));
			new(inf) info(name, md5, true);

			info* tmp = fileList_.search(inf);
			if(tmp == NULL) {
				inf->setPersistence(true);
				fileList_.insert(inf);
				const char* stage = packSourceFileName(stagePath, md5);
				try {
					copyItem(name, stage);
					AddTransAction(stage);
				}
				catch(Code c) {
					if(c != Corruption) {
						log.w("copy item: %s failed", name);
						dellocate(const_cast<char*>(stage));
						closedir(dir);
						throw c;
					}
				}
				log.i("Add item: %s", name);
				dellocate(const_cast<char*>(stage));
			}
			else {
				if(strncmp(tmp->getRef(), md5, MD5LEN) == 0) {
					tmp->setPersistence(true);
					dellocate(name);
					dellocate(md5);
					dellocate(inf);
					continue;
				}
				else {
					dellocate(const_cast<char*>(tmp->getRef()));
					tmp->setRef(md5);
					tmp->setPersistence(true);
					dellocate(inf);
					log.w("Change item: %s", name);
					const char* stage = packSourceFileName(stagePath, md5);
					try {
						copyItem(name, stage);
						AddTransAction(stage);
					}
					catch(Code c) {
						if(c != Corruption) {
							closedir(dir);
							log.w("copy %s failed", name);
							dellocate(name);
							dellocate(const_cast<char*>(stage));
							throw c;
						}
					}
					dellocate(name);
					dellocate(const_cast<char*>(stage));
				}
			}
		}
	}
	closedir(dir);
}

void Demo::persistenceDemo() {

	char buf[255];
	strcpy(buf, trashPath);
	strcpy(buf+strlen(trashPath), "current.tr"); 
	moveItem(currentName, buf);
	MoveTransAction(currentName, buf);
	
	persistenceTRFile(currentName, &fileList_, persistenceHandler_); 
}

void Demo::parseStructure(const char* fileName) {

	try {
		parseTRFile(fileName, &fileList_, false);
	}
	catch(Code c) {
		if(c == Empty) {}
		else {
			throw c;
		}
	}
}
	
void Demo:: persistenceRef() {

	parseStructure(currentName);
	const char* oldName = NULL;
	const char* newName = NULL;

	List<info>::const_iterator iter;
	iter = fileList_.start();
	while(iter != fileList_.end()) {
		const char* ref = iter->data->getRef();
		if(oldName != NULL)
			dellocate(const_cast<char*>(oldName));
		if(newName != NULL)
			dellocate(const_cast<char*>(newName));
		oldName = packSourceFileName(stagePath, ref);
		newName = packSourceFileName(refPath, ref);
		try {	
			moveItem(oldName, newName);
			MoveTransAction(oldName, newName);
		}
		catch(Code c) {
			if(c == IOError) {
				dellocate(const_cast<char*>(newName));
				dellocate(const_cast<char*>(oldName));
				throw IOError;
			}
		}
		iter = iter->next;
	}
	dellocate(const_cast<char*>(newName));
	dellocate(const_cast<char*>(oldName));

	char buf[bufferSize];
	strcpy(buf, trashPath);
	strcpy(buf+strlen(trashPath), "stage");
	moveItem(stageName, buf, true);
	MoveDirTransAction(stageName, buf);
	createDir(stageName);
	AddDirTransAction(stageName);
}
		
void Demo::reverseDemo(const char* fileName) {

	const char* demo = packTRFileName(demoPath, fileName);
	accessFile(demo);

	char trashbuf[bufferSize];
	strcpy(trashbuf, trashPath);
	strcpy(trashbuf+strlen(trashPath), "current.tr");
	moveItem(currentName, trashbuf);
	MoveTransAction(currentName, trashbuf);
	copyItem(demo, currentName);
	AddTransAction(demo);

	DIR* dir;
	struct dirent* file;
	struct stat st;
	char path[bufferSize];
	
	dir = opendir(".");
	if(dir == NULL) {
		log.w("open dir error");
		throw NotFound;
	}
	strcpy(path, "./");
	while((file = readdir(dir)) != NULL) {
		if(strncmp(file->d_name, ".", 1) == 0)
			continue;
		strcpy(path+2, file->d_name);
		if(stat(path, &st) != 0) {
			perror(path);
			closedir(dir);
			throw IOError;
		}

		char tmp[bufferSize];
		strcpy(tmp, trashPath);
		strcpy(tmp+strlen(trashPath), file->d_name);
		if(S_ISDIR(st.st_mode)) {
			try {
				moveItem(path, tmp, true);
				MoveDirTransAction(path, tmp);
			}
			catch(Code c) {
				closedir(dir);
				log.w("move dir error");
				throw c;
			}
		}
		else {
			try {
				moveItem(path, tmp);
				MoveTransAction(path, tmp);
			}
			catch(Code c) {
				closedir(dir);
				log.w("move dir error");
				throw c;
			}
		}
	}
	closedir(dir);

	AddDemoTransAction(".");
	parseStructure(demo);
	dellocate(const_cast<char*>(demo));
	List<info>::const_iterator iter;
	iter = fileList_.start();
	while(iter != fileList_.end()) {
		const char* name = iter->data->getTag();
		const char* ref = iter->data->getRef();
		
		createPath(name);
		const char* refName = packSourceFileName(refPath, ref);
		copyItem(refName, name);
		
		log.w("reverse item %s", name);
		iter = iter->next;
		dellocate(const_cast<char*>(refName));
	}
}

void Demo:: cleanList_(void* p) {

	info* inf = static_cast<info*>(p);
	dellocate(const_cast<char*>(inf->getTag()));
	dellocate(const_cast<char*>(inf->getRef()));
	dellocate(inf);
}

void Demo:: persistenceHandler_(const char* fileName) {
	
	log.w("remove item: %s", fileName);
}

} //namespace ccv
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
