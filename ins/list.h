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

#ifndef CCV_INS_LIST_H_
#define CCV_INS_LIST_H_

#include <cstdlib>
#include "mempool.h"

namespace ccv {

typedef void(*freeMem)(void*);

template<typename ValueType>
class List {

	private:

	struct innerNode_ {
		struct innerNode_* next;
		struct innerNode_* down;
		ValueType* data;
	};

	class Compare {

		public:

		bool greater(ValueType* left, ValueType* right) {
			return *left > *right;
		}
		bool equal(ValueType* left, ValueType* right) {
			return *left == *right;
		}
	};


	struct innerNode_* head_[5];
	Compare comp_;

	int randomLevel_() {
		int level = 1;
		while((rand() % 2))
			level++;

		return level < 5? level:5;
	}

	void clean_() {

		innerNode_* curson;
		for(int i=4; i>=0; i--) {
			curson = head_[i];
			while(curson != NULL) {
				innerNode_* tmp = curson;
				curson = curson->next;
				dellocate(tmp);
			}
		}
	}


	public:
	List() {
		for(int i=0; i<5; i++) {
			head_[i] = static_cast<innerNode_*>(allocate(sizeof(innerNode_)));
			head_[i]->data = NULL;
			head_[i]->down = NULL;
			head_[i]->next = NULL;
		}
	}
	~List() {
		clean_();
	}

	typedef const innerNode_* const_iterator;
	const_iterator start() const {
		return head_[0]->next;
	}
	const_iterator end() const {
		return NULL;
	}

	void insert(ValueType* item) {
		
		int level = randomLevel_();
		innerNode_* tmp = NULL;
		for(int i=0; i<level; i++) {
			innerNode_* nodeToInsert = static_cast<innerNode_*>(allocate(sizeof(innerNode_)));
			nodeToInsert->data = item;
			nodeToInsert->down = tmp;
			tmp = nodeToInsert;
			innerNode_* cursonHead = head_[i];
			innerNode_* cursonTail = head_[i]->next;
			
			int hasInsert = 0;
			while(cursonTail != NULL) {
				if(comp_.greater(cursonTail->data, item)) {
					nodeToInsert->next = cursonTail;
					cursonHead->next = nodeToInsert;
					hasInsert = 1;
					break;
				}
				cursonHead = cursonTail;
				cursonTail = cursonTail->next;
			}
			if(!hasInsert) {
				nodeToInsert->next = NULL;
				cursonHead->next = nodeToInsert;
			}
		}
	}

	ValueType* search(ValueType* item) {

		int level = 4;
		innerNode_* curson = head_[level];
		while(curson->next == NULL) {
			if(level == 0)
				return NULL;
			curson = head_[--level];
		}
		while(comp_.greater(curson->next->data,item)) {
			curson = head_[--level];
			if(level == 0)
				return NULL;
		}

		curson = curson->next;
		while(true) {
			if(comp_.equal(curson->data, item))
				return curson->data;
			if(curson->next == NULL) {
				curson = curson->down;
				if(curson == NULL)
					return NULL;
			} 
			else if(comp_.greater(curson->next->data, item)) {
				curson = curson->down;
				if(curson == NULL)
					return NULL;
			}
			else
				curson = curson->next;
		}
	}

	void freeValueType(freeMem fm) {

		innerNode_* curson = head_[0]->next;
		while(curson != NULL) {
			(*fm)(static_cast<void*>(curson->data));
			curson = curson->next;
		}
	}



};

} // namespace ccv

#endif
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
