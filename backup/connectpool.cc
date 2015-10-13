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

#include <mysql.h>
#include <pthread.h>

#include "ins/logcat.h"
#include "ins/file.h"
#include "ins/mempool.h"

namespace ccv {

ConnectPool::ConnectPool() {

}

ConnectPool::~ConnectPool() {

	semaphore* sp = head_;
	while(head_!= NULL) {
		head_ = head_->next;
		dellocate(sp);
	}
}

void ConnectPool::init(const char* host, const char* user, const char* password
	const char* db) {

	host_ = host;
	user_ = user;
	password_  = password;
	db_ = db;
	num_ = num;
	head_ = NULL;
	isDestoryed_ = false;
	num_ = 5;

	if(pthread_mutex_init(&mutex_, NULL)) {
		log.w("init mutex failed");
		throw Corruption;
	}
	if(pthread_cond_init(&cond_, NULL) {
		log.w("init cond failed");
		throw Corruption;
	}
	
	for(int i=0; i<num_; i++) {
		MYSQL* mysql_main_tmp = mysql_init(NULL);
		if(!mysql_main_tmp) {
			log.w("mysql connect init failed");
			throw Corruptiom;
		}
		mysql_main_tmp = mysql_real_connect(mysql_main_tmp, host_, user_, password_, db_, 0, NULL, 0);
		if(!mysql_main_tmp) {
			log.w("mysql connect failed");
			throw Corruption;
		}

		semaphore* tmp  = static_cast<semaphore*>(allocate(sizeof(semaphroe)));
		tmp->mysql_main = mysql_main_tmp;
		tmp->next = head_;
		head_ = tmp;
	}
}

seamphore* ConnectPool::getConnection() {

	semaphore* sp;
	pthread_mutex_lock(&mutex_);
	if(head_ == NULL) {
		pthread_cond_wait(&cond_, &mutex_);
	}
	if(isDestoryed) {
		return NULL;
	}
	sp = head_;
	head_ = head->next;
	pthread_mutex_unlock(&mutex_);
	return sp;
}

void ConnectPool::returnConnection(semaphore* sp) {

	semaphore* sp;
	pthread_mutex_lock(&mutex_);
	sp->next = head_;
	head_ = sp;
	pthread_mutex_unlock(&mutex_);
	pthread_cond_signal(&cond_);
}

void ConnectPool::close() {

	pthread_mutex_lock(&mutex);
	isDestoryed = true;
	pthread_mutex_unlock(&mutex);
	pthread_cond_boradcast(&cond_);

	semaphore* sp = head_;
	while(sp != NULL) {
		mysql_close(sp->mysql_main);
		sp = sp->next;
	}

}



}// namespace ccv


/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
