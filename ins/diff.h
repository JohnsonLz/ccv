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

#ifndef CCV_INS_DIFF_H_
#define CCV_INS_DIFF_H_

#include <cstdio>
#include "ins/list.h"
#include "ins/vet.h"

namespace ccv {

class lineInfo {

	private:
	int lineNumber_;
	const Vet<char*>* ref_;

	public:
	lineInfo(int number, const Vet<char*>* ref)
		:lineNumber_(number), ref_(ref){}
	~lineInfo(){};

	const Vet<char*>* getRef() const {
		return ref_;
	}
	int getLineNumber() const {
		return lineNumber_;
	}
	void setNumber(int line) {
		lineNumber_ = line;
	}

	bool operator > (const lineInfo& item);
	bool operator == (const lineInfo& item);
};

class Diff {

	private:

	struct commentLine {
		int srcLineNumber;
		int dstLineNumber;
	};

	char** srcMd5Line_;
	char** dstMd5Line_;
	int srcLineCount_;
	int dstLineCount_;
	List<lineInfo> srcLineInfo_;
	List<lineInfo> dstLineInfo_;
	Vet<commentLine> LCS_;

	int countLine_(const char* fileName, List<lineInfo>* lineInfoList, char*** MD5Line);
	void findLCS_();
	void productLCSVet_(int** present, int i, int j);
	static void freeBuf(void* p);
	static void freeLineInfo(void* p);


	public:
	Diff(){}
	~Diff(){
		srcLineInfo_.freeValueType(freeLineInfo);
		dstLineInfo_.freeValueType(freeLineInfo);
		LCS_.freeValueType(freeBuf);
	}
	void diffItem(const char* srcFile, const char* dstFile, const char* currentBranch, const char* fatherBranch);

};

}//manespace ccv

#endif

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
