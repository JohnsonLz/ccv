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
#include "ins/object.h"
#include "ins/repertory.h"
#include "ins/transAction.h"
#include "ins/logcat.h"
#include "ins/file.h"

using namespace ccv;

int main(int argc, char* argv[]) {

	if(argc < 2) {
		log.w("Too few arguments in command ccv-add");
		log.e("Add failed");
	}
	
	Repertory db;
	db.checkRepertory();
	if(strncmp(argv[1], "-a", 2) == 0) {
		Demo demo;
		try {
			demo.parseStructure(currentName); 
		}
		catch(Code c) {
			log.w("parse structure failed");
			log.e("Add failed");
			return 0;
		}
		BeginTransAction();
		try {
			demo.travel(".");
			demo.persistenceDemo();
		}
		catch(Code c) {
			log.w("travel error");
			log.e("Add failed");
			Rollback();
			return 0;
		}
		EndTransAction();
		log.v("Add successfully");
	}
}

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
