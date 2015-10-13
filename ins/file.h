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
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
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

#ifndef CCV_INS_FILE_H_
#define CCV_INS_FILE_H_


namespace ccv {

enum Code {
	Success = 0,
	Corruption = 1,
	CreateError = 2,
	NotFound = 3,
	IOError = 4,
	Empty = 5
};

const int bufferSize = 255;
const char currentName[] = ".ccv/current.tr";
const char masterName[] = ".ccv/branch/master.tr";
const char branchInfoName[] = ".ccv/branch/branchInfo.tr";
const char demoPath[] = ".ccv/demo/";
const char demoName[] = ".ccv/demo";
const char refPath[] = ".ccv/ref/";
const char refName[] = ".ccv/ref";
const char trashPath[] = ".ccv/trashTmp/";
const char trashName[] = ".ccv/trashTmp";
const char logName[] = ".ccv/log.tr";
const char stagePath[] = ".ccv/stage/";
const char stageName[] = ".ccv/stage";
const char branchPath[] = ".ccv/branch/";
const char branchName[] = ".ccv/branch";
const char emptyName[] = ".ccv/ref/e4c23762ed2823a27e62a64b95c024e7";



void createDir(const char* dir);
void createPath(const char* filePath);
void accessDir(const char* directory);
void accessFile(const char* filePath);

void moveItem(const char* oldName, const char* newName, bool isDir=false);
void removeItem(const char* fileName, bool isDir = false);
void removeAllInDir(const char* directory);
void copyItem(const char* srcFile, const char* dstFile);

bool equal(const char* src, const char* dst);
void encodeFixed32(char* dst, int value);
int decodeFixed32(const char* ptr);

}// namespace ccv

#endif

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
