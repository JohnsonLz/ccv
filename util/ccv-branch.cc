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
#include "ins/repertory.h"
#include "ins/object.h"
#include "ins/logcat.h"
#include "ins/file.h"
#include "ins/transAction.h"

using namespace ccv;

int main(int argc, char* argv[]) {

	if(argc < 3) {
		log.w("Too few arguments in command ccv-branch");
		log.e("ccv-branch failed");
		return 0;
	}
	if(argc > 4) {
		log.w("Too more arguments in command ccv-branch");
		log.e("ccv-branch failed");
		return 0;
	}

	Repertory db;
	db.checkRepertory();
	if(equal("new", argv[1])) {
		BeginTransAction();
		try {
			db.parseBranchInfoVet();	
			db.newBranch(argv[2]);
			if(argc == 4) {
				if(equal("-s", argv[3])) {
					db.switchBranch(argv[2]);
				}
				else {
					log.w("wrong argument in command ccv-branch");
					log.e("ccv-branch failed");
					return 0;
				}
			}
			db.persistenceBranchInfo();
		}
		catch(Code c) {
			log.e("Create new Branch failed");
			Rollback();
			return 0;
		}
		EndTransAction();
		log.v("New branch \"%s\" establish successfully", argv[2]);
		return 0;
	}
	if(equal("switch", argv[1])) {
		if(argc != 3) {
			log.w("wrong argument in command ccv-branch");
			log.e("ccv-branch failed");
			return 0;
		}
		BeginTransAction();
		try{
			db.parseBranchInfoVet();
			db.switchBranch(argv[2]);
			db.persistenceBranchInfo();
		}
		catch(Code c) {
			log.e("Switch branch failed");
			Rollback();
			return 0;
		}
		EndTransAction();
		log.v("Switch to Branch %s successfully", argv[2]);
		return 0;
	}

	else {
		log.w("wrong argument in command ccv-branch");
		log.e("ccv-branch failed");
		return 0;
	}
}
		
		
		
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
