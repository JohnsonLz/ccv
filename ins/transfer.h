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

#ifndef CCV_INS_TRANSFER_
#define CCV_INS_TRANSFER_

#include <sys/socket.h>
#include <netinet/in.h>
#include <string>

namespace ccv {

class Transfer {

	private:
	const char* request_;
	const char* downloadAPI_;
	const char* downloadUrl_;
	struct sockaddr_in serverAddr_;
	int sockfd_;

	void connect_(const char* host);
	void close_();
	int HexToInt_(const char* str);
	void receiveAndParseResponse_(std::string& jsonStr);
	void createPath_(const char* item);
	void uploadItem_(const char* item, const char* host);
	void downloadItem_(const char* repertory, const char* item, const char* host, const char* dst);

	void send_(char* buf);
	// unsafe long link recv_
	bool recv_(char* buf, int len);

	void encodeBase64_(const char* data, int len, std::string& encodeStr);
	void decodeBase64_(const char* data, int len, int& outlen, std::string& decodeStr);
	
	static void freeInfo_(void* ptr);
	static void handle_(const char* fileName) {}

	public:
	Transfer();
	~Transfer();

	void upload(const char* url);
	void downloadWholeProject(const char* url);
	void downloadDemo(const char* demoMd5, const char* rep, const char* host);

	void test();
};

}//namespace ccv

#endif

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
