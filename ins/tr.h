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

#ifndef CCV_INS_TR_H_
#define CCV_INS_TR_H_

#include "ins/list.h"
#include "ins/vet.h"

namespace ccv {

typedef void(*Handler)(const char*);

class info {

	private:
	const char* tag_;
	const char* ref_;
	bool persistence_;

	public:
	info(const char* tag, const char* ref, bool p)
		:tag_(tag), ref_(ref), persistence_(p){}
	~info(){};

	const char* getRef() const {
		return ref_;
	}
	const char* getTag() const {
		return tag_;
	}
	bool Persistence() const {
		return persistence_;
	}
	void setPersistence(bool p) {
		persistence_ = p;
	}
	void setRef(const char* ref) {
		ref_ = ref;
	}
	void setTag(const char* tag) {
		tag_ = tag;
	}

	bool operator > (const info& item);
	bool operator == (const info& item);
};

const char* packTRFileName(const char* path, const char* name);
const char* unpackTRFileName(const char* TRFileName);
const char* packSourceFileName(const char* path, const char* name);
const char* unpackSourceFileName(const char* fileName);
const char* packBranchInfo(const char* father, const char* stage);
const char* getFatherBranch(const char* branchName);
const char* getStageBranch(const char* branchName);
const char* handleCorruptionName(const char* name);

void parseTRFile(const char* flieName, List<info>* ls, bool persistence);
void parseTRFile(const char* fileName, Vet<info>* vt, bool persistence);
void persistenceTRFile(const char* fileName, List<info>* ls, Handler hd);
void persistenceTRFile(const char* fileName, Vet<info>* vt, Handler hd);

}//namesapce ccv

#endif

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
