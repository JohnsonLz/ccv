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

#ifndef CCV_INS_VET_H_
#define CCV_INS_VET_H_

#include <cstdlib>
#include "mempool.h"

namespace ccv {

typedef void(*freeMem)(void*);

template<typename ValueType>
class Vet {

	private:

	struct innerNode_ {
		struct innerNode_* next;
		ValueType* data;
	};

	struct innerNode_* head_;

	void clean_() {

		innerNode_* curson;
		curson = head_;
		while(curson != NULL) {
			innerNode_* tmp = curson;
			curson = curson->next;
			dellocate(tmp);
		}
	}

	public:
	Vet():head_(NULL) {}
	~Vet() {
		clean_();
	}

	void push(ValueType* item) {

		innerNode_* tmp = static_cast<innerNode_*>(allocate(sizeof(innerNode_)));
		tmp->next = head_;
		tmp->data = item;
		head_ = tmp;
	}

	void append(ValueType* item) {

		innerNode_* tmp = static_cast<innerNode_*>(allocate(sizeof(innerNode_)));
		tmp->data = item;
		tmp->next = NULL;
		if(head_ == NULL) {
			head_ = tmp;
		}
		else {
			innerNode_* curson = head_;
			while(curson->next != NULL)
				curson = head_->next;
			curson->next = tmp;
		}
	}
	
	typedef const innerNode_* const_iterator;
	const_iterator start()const {
		return head_;
	}
	const_iterator end()const {
		return NULL;
	}

	ValueType* search(ValueType* item) {

		innerNode_* curson = head_;
		while(curson != NULL) {
			if(*(curson->data) == *item)
				return curson->data;
			curson = curson->next;
		}
		return NULL;
	}
	
	void freeValueType(freeMem fm) {

		innerNode_* curson = head_;
		while(curson != NULL) {
			(*fm)(static_cast<void*>(curson->data));
			curson = curson->next;
		}
	}
};



}// namesapce ccv

#endif

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
