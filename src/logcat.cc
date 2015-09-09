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

#include <cstdio>
#include <string.h>

#include <ins/logcat.h>

namespace ccv {

void logcat::v(const char* verbose) {

	printf("\033[34m info: %s\n\033[0m", verbose);
}

void logcat::v(const char* verbose, const char* add) {

	printf("\033[34m info: \033[0m");
	int position = 0;
	while(verbose[position] != '%') {
		printf("\033[34m%c\033[0m", verbose[position]);
		position++;
	}
	position+=2;
	printf("\033[34m %s\033[0m", add);
	printf("\033[34m %s\n\033[0m", verbose+position);
}

void logcat::i(const char* verbose) {

	printf("\033[32m info: %s\n\033[0m", verbose);
}

void logcat::i(const char* verbose, const char* add) {

	printf("\033[32m info: \033[0m");
	int position = 0;
	while(verbose[position] != '%') {
		printf("\033[32m%c\033[0m", verbose[position]);
		position++;
	}
	position+=2;
	printf("\033[32m %s\033[0m", add);
	printf("\033[32m %s\n\033[0m", verbose+position);
}

void logcat::w(const char* verbose) {

	printf("\033[33m warn: %s\n\033[0m", verbose);
}

void logcat::w(const char* verbose, const char* add) {

	printf("\033[33m warn: \033[0m");
	int position = 0;
	while(verbose[position] != '%') {
		printf("\033[33m%c\033[0m", verbose[position]);
		position++;
	}
	position+=2;
	printf("\033[33m %s\033[0m", add);
	printf("\033[33m %s\n\033[0m", verbose+position);
}

void logcat::e(const char* verbose) {

	printf("\033[31m error: %s\n\033[0m", verbose);
}


}//namespace ccv
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
