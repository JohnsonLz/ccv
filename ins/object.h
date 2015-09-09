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

#ifndef CCV_INS_OBJECT_H_
#define CCV_INS_OBJECT_H_

#include "list.h"
#include "file.h"


namespace ccv {

class leaf {

	private:
		const char* ref_;
		const char* name_;
		bool persistence_;
	
	public:
		leaf(char* ref, char* name):ref_(ref), name_(name), persistence_(false) {}
		~leaf(){}

		const char* getRef() const {
			return ref_;
		}
		const char* getName() const {
			return name_;
		}
		bool persistence() {
			return persistence_;
		}
		void setRef(const char* ref) {
			ref_ = ref;
		}
		void setName(const char* name) {
			name_ = name;
		}
		void setPersistence() {
			persistence_ = true;
		}
		bool operator >(const leaf& item);
		bool operator == (const leaf& item);

};
		

class Demo {

	private:
		List<leaf> fileList_;
		
		static void cleanList_(void* p);
		
	public:
		Demo() {}
		~Demo(){
			fileList_.freeValueType(cleanList_);
		}

		void travel(const char* directory);	
		void persistenceRef();	
		void persistenceDemo();
		void parseStructure(const char* fileName);
		void checkoutDemo(const char* fileName);

};


}// namespace ccv

#endif
/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
