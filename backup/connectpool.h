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

#ifndef CCV_INS_CONNECTPOOL_H_
#define CCV_INS_CONNECTPOOL_H_

#include <mysql.h>
#include <pthread.h>

namespace ccv {

struct semaphore {
	MYSQL* mysql_main;
	semaphore* next;
};

class ConnectPool {

	private:
	const char* host_;
	const char* user_;
	const char* password_;
	const char* db_;
	const int num_;
	bool isDestoryed;
	struct semaphore* head_;

	pthread_mutex_t mutex_;
	pthread_cond_t cond_;

	public:
	ConnectPool(){}
	~ConnectPool(){}
	
	void init(const char* host, const char* user, const char* password,
		const char* db);

	semaphre* getConnection();
	void returnConnection(semaphre* sp);
	void close();


};

}// namespace ccv

#endif

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
