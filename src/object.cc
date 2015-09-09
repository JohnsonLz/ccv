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
			leaf* lf = static_cast<leaf*>(allocate(sizeof(leaf)));
			new(lf) leaf(md5, name);

			leaf* tmp = fileList_.search(lf);
			if(tmp == NULL) {
				lf->setPersistence();
				fileList_.insert(lf);
				const char* stagePath = ".ccv/stage/";
				char newPath[bufferSize];
				strcpy(newPath, stagePath);
				strncpy(newPath+strlen(stagePath), md5, MD5LEN);
				newPath[strlen(stagePath)+MD5LEN] = '\0';
				try {
					copyItem(name, newPath);
					AddTransAction(newPath);
				}
				catch(Code c) {
					log.w("copy item: %s failed", name);
					closedir(dir);
					throw c;
				}
				log.i("Add item: %s", name);
			}
			else {
				if(strncmp(tmp->getRef(), md5, MD5LEN) == 0) {
					tmp->setPersistence();
					dellocate(name);
					dellocate(md5);
					dellocate(lf);
					continue;
				}
				else {
					dellocate(const_cast<char*>(tmp->getRef()));
					tmp->setRef(md5);
					tmp->setPersistence();
					dellocate(lf);
					log.w("Change item: %s", name);
					const char* stagePath = ".ccv/stage/";
					char newPath[bufferSize];
					strcpy(newPath, stagePath);
					strncpy(newPath+strlen(stagePath), md5, MD5LEN);
					newPath[strlen(stagePath)+MD5LEN] = '\0';
					try {
						copyItem(name, newPath);
						AddTransAction(newPath);
					}
					catch(Code c) {
						closedir(dir);
						log.w("copy %s failed", name);
						dellocate(name);
						throw c;
					}
					dellocate(name);
				}
			}
		}
	}
	closedir(dir);
}

void Demo::persistenceDemo() {

	moveItem(".ccv/current",".ccv/trashTmp/current");
	MoveTransAction(".ccv/current", ".ccv/trashTmp/current");

	FILE* fp = fopen(".ccv/current", "wb+");
	if(fp == NULL) {
		log.w("can not open .ccv/current");
		throw NotFound;
	}
	AddTransAction(".ccv/current");

	char size[4];
	List<leaf>::const_iterator iter;
	iter = fileList_.start();
	while(iter != fileList_.end()) {
		leaf* lf = iter->data;
		if(!lf->persistence()) {
			log.w("remove item %s", lf->getName());
			iter = iter->next;
			continue;
		}
		int length = strlen(lf->getName());
		encodeFixed32(size, length);

		int write = fwrite(size, 4, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		write = fwrite(lf->getName(), length, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		write = fwrite(lf->getRef(), MD5LEN, 1, fp);
		if(write == 0) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		iter = iter->next;
	}
	fclose(fp);
}

void Demo::parseStructure(const char* fileName) {

	FILE* fp = fopen(fileName, "rb");
	if(fp == NULL) {
		log.w("can not open item: %s", fileName);
		throw NotFound;
	}

	char buf[bufferSize];
	char size[4];
	int read;
	int write;

	read = fread(size, 4, 1, fp);
	if(read == 0) 
		return;
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
		char* name = static_cast<char*>(allocate(length+1));
		strncpy(name, buf, length);
		name[length] = '\0';

		read = fread(buf, MD5LEN, 1, fp);
		if(read == 0) {
			dellocate(name);
			log.w("IOError: read error");
			fclose(fp);
			throw IOError;
		}
		char* md5 = static_cast<char*>(allocate(MD5LEN+1));
		strncpy(md5, buf, MD5LEN);
		md5[MD5LEN] = '\0';

		leaf* lf = static_cast<leaf*>(allocate(sizeof(leaf)));
		new(lf) leaf(md5, name);
		fileList_.insert(lf);
	}
}

void Demo:: persistenceRef() {

	parseStructure(".ccv/current");
	const char* refPath = ".ccv/ref/";
	const char* stagePath = ".ccv/stage/";
	char oldName[bufferSize];
	char newName[bufferSize];

	List<leaf>::const_iterator iter;
	iter = fileList_.start();
	while(iter != fileList_.end()) {
		const char* ref = iter->data->getRef();
		strcpy(oldName, stagePath);
		strncpy(oldName+strlen(stagePath), ref, MD5LEN);
		oldName[strlen(stagePath)+MD5LEN] = '\0';
		strcpy(newName, refPath);
		strncpy(newName+strlen(refPath), ref, MD5LEN);
		newName[strlen(refPath)+MD5LEN] = '\0';
		try {	
			moveItem(oldName, newName);
			MoveTransAction(oldName, newName);
		}
		catch(Code c) {
			if(c == IOError)
				throw IOError;
		}
		iter = iter->next;
	}
	moveItem(".ccv/stage", ".ccv/trashTmp/stage", true);
	MoveDirTransAction(".ccv/stage", ".ccv/trashTmp/stage");
	createDir(".ccv/stage");
	AddDirTransAction(".ccv/stage");
}
		
void Demo::checkoutDemo(const char* fileName) {

	const char* demoPath = ".ccv/demo/";
	const char* refPath = ".ccv/ref/";
	const char* trashPath = ".ccv/trashTmp/";
	char buf[bufferSize];

	strcpy(buf, demoPath);
	strncpy(buf+strlen(demoPath), fileName, MD5LEN);
	buf[strlen(demoPath)+MD5LEN] = '\0';
	accessFile(buf);

	moveItem(".ccv/current", ".ccv/trashTmp/current");
	MoveTransAction(".ccv/current", ".ccv/trashTmp/current");
	FILE* fp = fopen(".ccv/current", "wb+");
	if(fp == NULL) {
		log.w("create .ccv/current error");
		throw IOError;
	}
	fclose(fp);
	AddTransAction(".ccv/current");

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
	parseStructure(buf);
	List<leaf>::const_iterator iter;
	iter = fileList_.start();
	while(iter != fileList_.end()) {
		const char* name = iter->data->getName();
		const char* ref = iter->data->getRef();
		
		createPath(name);
		char refName[bufferSize];
		strcpy(refName, refPath);
		strncpy(refName+strlen(refPath), ref, MD5LEN);
		refName[strlen(refPath)+MD5LEN] = '\0';
		copyItem(refName, name);
		
		log.w("checkout item %s", name);
		iter = iter->next;
	}
}

void Demo:: cleanList_(void* p) {

	leaf* lf = static_cast<leaf*>(p);
	dellocate(const_cast<char*>(lf->getName()));
	dellocate(const_cast<char*>(lf->getRef()));
	dellocate(lf);
}

bool leaf::operator>(const leaf& item) {

	if(strcmp(name_, item.getName()) > 0)
		return true;
	return false;
}

bool leaf::operator == (const leaf& item) {

	if(strcmp(name_, item.getName()) == 0)
		return true;
	return false;
}


} //namespace ccv
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
