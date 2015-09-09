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
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include "ins/file.h"
#include "ins/logcat.h"

namespace ccv {

void createDir(const char* dir) {
	
	if(mkdir(dir, 0777) == -1) {
		perror(dir);
		throw CreateError;
	}
}

void createPath(const char* filePath) {

	char buf[bufferSize];
	int position = 0;
	int length = strlen(filePath);

	while(position < length) {
		if(filePath[position] == '/') {
			strncpy(buf, filePath, position);
			buf[position] = '\0';
			DIR* dir = NULL;
			dir = opendir(buf);
			if(dir != NULL) {
				closedir(dir);
				position++;
				continue;
			}
			createDir(buf);
		}
		position ++;
	}
}

void accessDir(const char* directory) {

	DIR* dir = NULL;
	dir = opendir(directory);
	if(dir == NULL)
		throw NotFound;
	closedir(dir);
}

void accessFile(const char* filePath) {

	if(access(filePath, F_OK) != 0)
		throw NotFound;
}

void moveItem(const char* oldName, const char* newName, bool isDir) {
	
	if(isDir) {
		DIR* dir = NULL;
		dir = opendir(newName);
		if(dir != NULL) {
			closedir(dir);
			throw Corruption;
		}
	}
	else {
		if(access(newName, F_OK) == 0)
			throw Corruption;
	}

	if(rename(oldName, newName) != 0) {
		perror(oldName);
		throw IOError;
	}
}

void removeItem(const char* fileName, bool isDir) {

	if(isDir) {
		if(rmdir(fileName) != 0) {
			perror(fileName);
			throw IOError;
		}
	}
	else {
		if(remove(fileName) != 0) {
			perror(fileName);
			throw IOError;
		}
	}
}

void removeAllInDir(const char* directory) {

	DIR* dir;
	struct dirent* file;
	struct stat st;
	char buf[bufferSize];

	dir = opendir(directory);
	if(dir == NULL) {
		log.w("can not open dir: %s", directory); 
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
				removeAllInDir(buf);
				removeItem(buf, true);
			}
			catch(Code c) {
				closedir(dir);
				throw c;
			}

		}
		else {
			try {
				remove(buf);
			}
			catch(Code c) {
				closedir(dir);
				throw c;
			}
		}
	}
	closedir(dir);
}

void copyItem(const char* srcFile, const char* dstFile) {

	if(access(dstFile, F_OK) == 0)
		throw Corruption;
	FILE* src = fopen(srcFile, "rb");
	if(src == NULL) {
		log.w("can not open item: %s", srcFile);
		throw NotFound;
	}

	struct stat st;
	if(stat(srcFile, &st) != 0) {
		perror(srcFile);
		throw IOError;
	}


	int fd = open(dstFile, O_RDWR|O_CREAT, st.st_mode);
	if(fd == -1){
		log.w("open error");
		throw IOError;
	}
	close(fd);

	FILE* dst = fopen(dstFile, "wb+");
	if(dst == NULL) {
		log.w("can not open item: %s", dstFile);
		throw NotFound;
	}

	char buf[bufferSize];
	int write;
	memset(buf, bufferSize, 0);
	int read = fread(buf, 1, bufferSize, src);
	while(read > 0) {
		write = fwrite(buf, read, 1, dst);
		if(write == 0) {
			log.w("copy error");
			fclose(src);
			fclose(dst);
			throw IOError;
		}
		memset(buf, bufferSize, 0);
		read = fread(buf, 1, bufferSize, src);
	}
	fclose(src);
	fclose(dst);
}

void encodeFixed32(char* dst, int value) {

	dst[0] = value & 0xff;
	dst[1] = (value>>8) & 0xff;
	dst[2] = (value>>16) & 0xff;
	dst[3] = (value>>24) & 0xff;
}

int decodeFixed32(const char* ptr) {
	 return((static_cast<uint32_t>(static_cast<unsigned char>(ptr[0])))
        |(static_cast<uint32_t>(static_cast<unsigned char>(ptr[1])) <<8)
        | (static_cast<uint32_t>(static_cast<unsigned char>(ptr[2])) << 16)
        |(static_cast<uint32_t>(static_cast<unsigned char>(ptr[3])) <<24));
}

}// namespace ccv

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
