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

#ifndef CCV_INS_REPERTORY_H_
#define CCV_INS_REPERTORY_H_

#include "ins/vet.h"

namespace ccv {

class info;

class Repertory {

	private:

	static void freeMemory_(void* ptr);
	static void persistenceHandler_(const char* fileName);
	void parseCommitList_(Vet<info>* vt);
	Vet<info> commitVet_;
	Vet<info> branchInfoVet_;

	public:
	Repertory() {}
	~Repertory() {
		branchInfoVet_.freeValueType(freeMemory_);
		commitVet_.freeValueType(freeMemory_);
	}

	void init();
	void checkRepertory();
	void parseBranchInfoVet();
	void parseCommitList();
	void persistenceBranchInfo();
	void persistenceCommit();
	void commit(const char* tag);
	void reverseCommit(const char* tag);
	void newBranch(const char* name);
	void switchBranch(const char* name);
	void merge(const char* branchName);
	void mergeCommit(const char* tag);
};

}// namespace ccv

#endif
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
