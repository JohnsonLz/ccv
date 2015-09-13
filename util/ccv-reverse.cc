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

#include "ins/repertory.h"
#include "ins/logcat.h"
#include "ins/transAction.h"
#include "ins/file.h"

using namespace ccv; 

int main(int argc, char* argv[]) {

	if(argc != 2) {
		log.w("Wrong arguments in command ccv-reverse");
		log.e("reverse failed");
		return 0;
	}
	Repertory db;
	db.checkRepertory();

	BeginTransAction();
	try {
		db.parseBranchInfoVet();
		db.parseCommitList();
		db.reverseCommit(argv[1]);
	}
	catch(Code c) {
		log.e("reverse failed");
		Rollback();
		return 0;
	}
	EndTransAction();
	log.v("reverse %s successfully", argv[1]);
}

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
