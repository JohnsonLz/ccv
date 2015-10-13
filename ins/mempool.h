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

#ifndef CCV_INS_MEMPOOL_H_
#define CCV_INS_MEMPOOL_H_

#include <sys/types.h>

namespace ccv {

class MemPool {

	private:

	enum {align = 8};
	enum {MaxBytes = 128};
	enum {MemListSize = MaxBytes/align};

	union obj {
		union obj* free_list_link;
		char clientData[1];
	};

	struct node {
		struct node* next ;
		char* address;
	};

	node*  mallocList_;
	obj* freeList_[MemListSize] ;
	char* poolStart_;
	char* poolEnd_;
	size_t poolSize_;
	
	size_t round_up(size_t bytes);
	size_t freeListIndex(size_t bytes);
	void* injectPool(size_t bytes);
	char* chunkAlloc(size_t size, int& nobjs);
	void clean();

	public:
	MemPool():poolStart_(0),poolEnd_(0),poolSize_(0) {
		mallocList_ = 0;
		for(int i=0;i<MemListSize; i++)
			freeList_[i] = 0;
	}
	~MemPool(){
		clean();
	}
	void* allocate(size_t n);
	void dellocate(void* p);

	static MemPool& sharedMemPool() {
		static MemPool mp;
		return mp;
	}
};

void* allocate(size_t n); 
void dellocate(void* p);


}// namespace ccv

#endif
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
