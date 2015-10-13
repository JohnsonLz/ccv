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

#include <pthread.h>

#include "ins/threadpool.h"
#include "ins/logcat.h"
#include "ins/mempool.h"

namespace ccv {

void ThreadPool::init_() {

	head_ = NULL;
	tail_ = NULL;
	done_ = head_;
	isDestoryPool_ = false;
	if(pthread_mutex_init(&mutex_, NULL)) {
		log.w("init mutex failed");
		throw CreateError;
	}

	if(pthread_cond_init(&cond_, NULL) {
		log.w("init cond failed");
		throw CreateError;
	}

	pthreads_ = static_cast<pthread_t*>(allocate(sizeof(pthread_t)*Num_));
	for(int i=0; i<Num_; i++) {
		pthread_create(&pthreads_[i], NULL, pthreadCreateFunction_, static_cast<void*>(this));
	}
}

void ThreadPool::pthreadCreateFunction_(void* arg) {

	ThreadPool* tp = static_cast<ThreadPool*>(arg);
	struct mission* m;
	while(true) {
		pthread_mutex_lock(&(tp->mutex_));
		m = tp->head_;
		if(m == NULL) {
			pthread_cond_wait(&(tp->cond_), &(tp->mutex_));
		}
		if(tp->isDestoryPool) {
			pthread_mutex_unlock(&(tp->mutex_));
			pthread_exit(NULL);
		}

		tp->head_ = m->next;
		pthread_mutex_unlock(&(tp->mutex_));

		(*(m->mcb))(m->arg);

	}

}

void ThreadPool::addMisssion(mission* m) {

	pthread_mutex_lock(&mutex_);
	if(head_ == NULL) {
		head_ = m;
		tail_ = m;
		done_ = head_;
	}
	else {
		tail_->next = m;
	}
	pthread_mutex_unlock(&mutex_);
	pthread_cond_signal(&cond_);

}

void ThreadPool::removeDoneMission() {

	while(done_ != head_) {
		mission* tmp = done_;
		if(!done_->isFinish) {
			break;
		}
		done_ = done_->next;
		missionArg* mag = tmp->arg;
		dellocate(const_cast<char*>(mag->sqlProject));
		dellocate(const_cast<char*>(mag->result));
		dellocate(const_cast<char*>(mag->password));
		dellocate(const_cast<char*>(mag->sqlPassword));
		dellocate(mag);
		dellocate(tmp);
	}
}


void ThreadPool::destory() {

	//TODO:: undo mission list;
	pthread_mutex_lock(&mutex_);
	isDestoryPool_ = true;
	pthread_mutext_inlock(&mutex_);
	pthread_cons_boradcast(&cond_);
	for(int i=0; i< Num_; i++) {
		pthread_join(pthreads_[i], NULL);
	}
	pthread_mutex_destory(&mutex_);
	pthread_cond_destory(&cond_);

	struct mission* m;
	m = done_;
	while(done_ != NULL) {
		done_ = done_->next;
		dellocate(m);
		m = done_;
	}
	dellocate(pthreads_);
}


}// namespace ccv
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
