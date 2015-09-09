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

#ifndef CCV_INS_TRANSACTION_H_
#define CCV_INS_TRANSACTION_H_

namespace ccv {

enum TAMode {
	ADD = 0,
	REMOVE = 1,
	MOVE = 2,
	ADIR = 3,
	ADEMO = 4,
	MVDIR = 5
};

class TransAction {
	
	private:

		struct node_ {
			node_* next;
			const char* data;
			TAMode m; 
		};

		node_* head_;
		void cleanTrash_();

	public:
		TransAction(){}
		~TransAction(){}

		void addTransAction(const char* fileName, TAMode m);
		void rollback();
		void beginTransAction();
		void endTransAction();

		static TransAction& sharedTransAction() {
			static TransAction ts;
			return ts;
		}
};

void AddTransAction(const char* fileName);
void AddDirTransAction(const char* dirName);
void AddDemoTransAction(const char* path);
void RemoveTransAction(const char* fileName);
void MoveTransAction(const char* oldName, const char* newName);
void MoveDirTransAction(const char* oldName, const char* newName);
void BeginTransAction();
void EndTransAction();
void Rollback();




}//namespace ccv

#endif
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
