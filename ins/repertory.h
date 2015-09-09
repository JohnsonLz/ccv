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

#include "ins/file.h"
#include "ins/list.h"

namespace ccv {

class Repertory {

	private:
	class commitInfo {
		
		private:
		const char* tag_;
		const char* ref_;

		public:
		commitInfo(const char* tag, const char* ref):tag_(tag), ref_(ref){}
		~commitInfo(){}

		const char* getTag() const {
			return tag_;
		}
		const char* getRef() const {
			return ref_;
		}

		bool operator > (const commitInfo& item);
		bool operator == (const commitInfo& item);

	};

	static void freeMemory_(void* ptr);
	List<commitInfo> commitList_;

	public:
	Repertory() {}
	~Repertory() {
		commitList_.freeValueType(freeMemory_);
	}

	void init();
	void checkRepertory();
	void parseCommitList();
	void persistenceCommit();
	void commit(const char* tag);
	void checkoutCommit(const char* tag);
};

}// namespace ccv

#endif
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
