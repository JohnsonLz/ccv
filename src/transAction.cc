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
#include <string.h>

#include "ins/transAction.h"
#include "ins/mempool.h"
#include "ins/file.h"

namespace ccv {

void TransAction::addTransAction(const char* fileName, TAMode m) {

	int length = strlen(fileName);
	char* buf = static_cast<char*>(allocate(length+1));
	strncpy(buf, fileName, length);
	buf[length] = '\0';

	node_* tmp = static_cast<node_*>(allocate(sizeof(node_)));
	tmp->next = head_;
	tmp->data = buf;
	tmp->m = m;
	head_ = tmp;
}


void TransAction::beginTransAction() {
	head_ = NULL;
}

void TransAction::endTransAction() {

	node_* tmp = head_;
	while(tmp != NULL) {
		head_ = head_->next;
		dellocate(const_cast<char*>(tmp->data));
		dellocate(tmp);
		tmp = head_;
	}
	cleanTrash_();
}

void TransAction::rollback() {

	node_* tmp = head_;
	while(tmp != NULL) {
		node_* next;
		switch(tmp->m) {
			case ADD:
				removeItem(tmp->data);
				break;
			case REMOVE:
				break;
			case MOVE:
				next = tmp->next;
				moveItem(tmp->data, next->data);
				dellocate(const_cast<char*>(tmp->data));
				dellocate(tmp);
				tmp = next;
				break;
			case MVDIR:
				next = tmp->next;
				moveItem(tmp->data, next->data, true);
				dellocate(const_cast<char*>(tmp->data));
				dellocate(tmp);
				tmp = next;
				break;
			case ADIR:
				removeItem(tmp->data, true);
				break;
			case ADEMO:
				removeAllInDir(tmp->data);
				break;
		}
		next = tmp->next;
		dellocate(const_cast<char*>(tmp->data));
		dellocate(tmp);
		tmp = next;
	}
	try {
		accessDir(".ccv");
	}
	catch(Code c) {
		return;
	}
	cleanTrash_();
}

void TransAction::cleanTrash_() {

	removeAllInDir(trashName);
}

void AddTransAction(const char* fileName) {
	TransAction::sharedTransAction().addTransAction(fileName, ADD);
}

void AddDirTransAction(const char* dirName) {
	TransAction::sharedTransAction().addTransAction(dirName, ADIR);
}

void AddDemoTransAction(const char* path) {
	TransAction::sharedTransAction().addTransAction(path, ADEMO);
}

void RemoveTransAction(const char* fileName) {
	TransAction::sharedTransAction().addTransAction(fileName, REMOVE);
}

void MoveTransAction(const char* oldName, const char* newName) {

	TransAction::sharedTransAction().addTransAction(oldName, MOVE);
	TransAction::sharedTransAction().addTransAction(newName, MOVE);
}

void MoveDirTransAction(const char* oldName, const char* newName) {

	TransAction::sharedTransAction().addTransAction(oldName, MVDIR);
	TransAction::sharedTransAction().addTransAction(newName, MVDIR);
}

void BeginTransAction() {
	TransAction::sharedTransAction().beginTransAction();
}

void EndTransAction() {
	TransAction::sharedTransAction().endTransAction();
}

void Rollback() {
	TransAction::sharedTransAction().rollback();
}

}// namesapce ccv
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
