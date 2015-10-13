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

#ifndef CCV_INS_THREADPOOL_H_
#define CCV_INS_THREADPOOL_H_

#include <pthread.h>

namespace ccv {

typedef void (*missionCallback)(void* arg);

struct mission {
	missionCallback mcb;
	void* arg;
	bool isFinish;
	struct mission* next;
};
	
class ThreadPool {

	private:
	int Num_;
	struct mission* done_;
	struct mission* head_;
	struct mission* tail_;
	pthread_t* pthreads_;
	pthread_mutex_t mutex_;
	pthread_cond_t cond_;
	bool isDestoryPool_;

	void init_();
	static void pthreadCreateFunction_(void* arg);

	public:
	ThreadPool():Num_(4){
		init_();
	}
	~ThreadPool(){}

	void addMission(mission* m);
	void removeDoneMission();
	void Destory();
	
};

} // namespace ccv

#endif
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
