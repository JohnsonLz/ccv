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

#include <stdio.h>
#include <new>
#include <string.h>

#include "ins/file.h"
#include "ins/logcat.h"
#include "ins/mempool.h"
#include "ins/vet.h"
#include "ins/list.h"
#include "ins/diff.h"
#include "ins/md5.h"
#include "ins/tr.h"
#include "ins/transAction.h"

namespace ccv {

int Diff::countLine_(const char* fileName, List<lineInfo>* linesInfoList, char*** Md5Lines) {

	FILE* fp = fopen(fileName, "rb");
	if(fp == NULL) {
		log.w("can not open file: %s", fileName);
		throw NotFound;
	}

	int lineLength = 125;
	char* buf = static_cast<char*>(allocate(lineLength));
	bool fileEmpty = true;
	bool mid = true;
	char current;
	Vet<char*>* lines = static_cast<Vet<char*>*>(allocate(sizeof(Vet<char*>)));
	new(lines) Vet<char*>();
	Vet<char*> md5LinesVet;
	int lineCount = 0;
	int lineSize = 0;

	while(fread(&current, 1, 1, fp) != 0) {
		fileEmpty = false;
		buf[lineSize] = current;
		lineSize ++;
		mid = true;
		if(lineSize == lineLength -1) {
			buf[lineSize] = '\0';
			lineSize = 0;
			lines->append(buf);
			buf = static_cast<char*>(allocate(lineLength));
		}
		if(current == '\n') {
			buf[lineSize] = '\0';
			if(lineSize != 0) {
				lineSize = 0;
				lines->append(buf);
				buf = static_cast<char*>(allocate(lineLength));
			}
			lineCount ++;
			char* lineMd5 = MD5_lines(lines, MD5LEN);
			md5LinesVet.append(lineMd5);

			lineInfo* insertTmp = static_cast<lineInfo*>(allocate(sizeof(lineInfo)));
			new(insertTmp) lineInfo(lineCount, lines);
			linesInfoList->insert(insertTmp);
			lines = static_cast<Vet<char*>*>(allocate(sizeof(Vet<char*>)));
			new(lines) Vet<char*>();
			mid = false;
		}
	}

	if(fileEmpty) {
		return 0;
	}

	if(lineSize != 0 || mid) {
		buf[lineSize] = '\0';
		lineCount ++;
		lines->append(buf);
		char* lineMd5 = MD5_lines(lines, MD5LEN);
		md5LinesVet.append(lineMd5);
		lineInfo* insertTmp = static_cast<lineInfo*>(allocate(sizeof(lineInfo)));
		new(insertTmp) lineInfo(lineCount, lines);
		linesInfoList->insert(insertTmp);
	}
	else {
		dellocate(buf);
		lines->freeValueType(freeBuf);
		dellocate(lines);
	}

	(*Md5Lines) = static_cast<char**>(allocate(sizeof(char*)*lineCount));
	int i = 0;
	Vet<char*>::const_iterator iter;
	iter = md5LinesVet.start();
	while(iter != md5LinesVet.end()) {
		Md5Lines[0][i] = iter->data;
		iter = iter->next;
		i++;
	}
	return lineCount;

}

void Diff::findLCS_() {

	int** matrix = static_cast<int**>(allocate(sizeof(int*)*(srcLineCount_+1)));
	int** present = static_cast<int**>(allocate(sizeof(int*)*(srcLineCount_+1)));
	for(int i=0; i<= srcLineCount_ ; i++) {
		matrix[i] = static_cast<int*>(allocate(sizeof(int)*(dstLineCount_+1)));
		present[i] = static_cast<int*>(allocate(sizeof(int)*(dstLineCount_+1)));
		matrix[i][0] = 0;
		present[i][0] = 0;
	}
	for(int i=0; i<= dstLineCount_; i++) {
		matrix[0][i] = 0;
		present[0][i] =0;
	}

	for(int i = 1; i<= srcLineCount_; i++)
    {
        for(int j = 1; j <= dstLineCount_; j++)
        {
            if(equal(srcMd5Line_[i-1], dstMd5Line_[j-1]))
            {
                matrix[i][j] = matrix[i-1][j-1] + 1;
				present[i][j] = 0;
            }
            else if(matrix[i-1][j] >= matrix[i][j-1])
            {
                matrix[i][j] = matrix[i-1][j];
				present[i][j] = 1;
            }
            else
            {
                matrix[i][j] = matrix[i][j-1];
				present[i][j] = -1;
            }
        }
    }

	if(srcLineCount_ != 0) {	
		for(int i=0; i<srcLineCount_; i++)
			dellocate(srcMd5Line_[i]);
		dellocate(srcMd5Line_);
	}
	if(dstLineCount_ != 0) {
		for(int i=0; i<dstLineCount_; i++)
			dellocate(dstMd5Line_[i]);		
		dellocate(dstMd5Line_);
	}

	productLCSVet_(present, srcLineCount_, dstLineCount_);
	for(int i=0; i<srcLineCount_; i++) {
		dellocate(present[i]);
	}
	dellocate(present);

}

void Diff::productLCSVet_(int** present, int i, int j) {

	if(i==0 || j==0)
		return;
	if(present[i][j] == 0) {
		productLCSVet_(present, i-1, j-1);
		commentLine* tmp = static_cast<commentLine*>(allocate(sizeof(commentLine)));
		tmp->srcLineNumber = i;
		tmp->dstLineNumber = j;
		LCS_.append(tmp);
	}
	else if(present[i][j] == 1) {
		productLCSVet_(present, i-1, j);
	}
	else {
		productLCSVet_(present, i, j-1);
	}

}

void Diff::diffItem(const char* srcFile, const char* dstFile, const char* currentBranch, const char* fatherBranch) {

	srcLineCount_ = countLine_(srcFile, &srcLineInfo_, &srcMd5Line_);
	dstLineCount_ = countLine_(dstFile, &dstLineInfo_, &dstMd5Line_);
	findLCS_();

	const char* srcName = unpackSourceFileName(srcFile);
	const char* trashSrcName = packSourceFileName(trashPath, srcName);
	try {
		moveItem(srcFile, trashSrcName);
	}
	catch(Code c) {
		if(c == Corruption) {
			const char* tmp = trashSrcName;
			trashSrcName = handleCorruptionName(trashSrcName);
			moveItem(srcFile, trashSrcName);
			dellocate(const_cast<char*>(tmp));
		}
	}
	MoveTransAction(srcName, trashSrcName);
	dellocate(const_cast<char*>(srcName));
	dellocate(const_cast<char*>(trashSrcName));
	
	FILE* fp = fopen(srcFile, "wb+");
	if(fp == NULL) {
		log.w("can not open file: %s", srcFile);
		throw NotFound;
	}
	AddTransAction(srcFile);

	int srcCount = 0;
	int dstCount = 0;
	int lengthStart;
	int lengthEnd;
	int write;
	const char* lineStart = "\n\n\n<<<<<<<< ";
	const char* lineMid = "\n========\n\n";
	const char* lineEnd = "\n>>>>>>>> ";
	char bufStart[bufferSize];
	char bufEnd[bufferSize];
	
	lengthStart = strlen(lineStart);
	write = strlen(currentBranch);
	strncpy(bufStart, lineStart, lengthStart);
	strncpy(bufStart+lengthStart, currentBranch, write);
	bufStart[lengthStart + write] = '\0';
	lengthStart = lengthStart + write;
	lengthEnd = strlen(lineEnd);
	write = strlen(fatherBranch);
	strncpy(bufEnd, lineEnd, lengthEnd);
	strncpy(bufEnd + lengthEnd, fatherBranch, write);
	bufEnd[lengthEnd+write] = '\0';
	lengthEnd = lengthEnd + write;

	Vet<commentLine>::const_iterator iter;
	iter = LCS_.start();

	if(iter == LCS_.end()) {
		int length;
		write = fwrite(bufStart, 1, lengthStart, fp);
		if(write != lengthStart) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		fwrite("\n\n", 1, 2, fp);
		List<lineInfo>::const_iterator liter;
		liter = srcLineInfo_.start();
		while(liter != srcLineInfo_.end()) {
			const Vet<char*>* line = liter->data->getRef();
			Vet<char*>::const_iterator citer;
			citer = line->start();
			while(citer != line->end()) {
				length = strlen(citer->data);
				write = fwrite(citer->data, 1, length, fp);
				if(write !=  length) {
					log.w("IOError: write error");
					fclose(fp);
					throw IOError;
				}
				citer = citer->next;
			}
			liter = liter->next;
		}

		length = strlen(lineMid);
		write = fwrite(lineMid, 1, length, fp);
		if(write != length) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		liter = dstLineInfo_.start();
		while(liter != dstLineInfo_.end()) {
			const Vet<char*>* line =  liter->data->getRef();
			Vet<char*>::const_iterator citer;
			citer = line->start();
			while(citer != line->end()) {
				length = strlen(citer->data);
				write = fwrite(citer->data, 1, length, fp);
				if(write !=  length) {
					log.w("IOError: write error");
					fclose(fp);
					throw IOError;
				}
				citer = citer->next;
			}
			liter = liter->next;
		}	

		write = fwrite(bufEnd, 1, lengthEnd, fp);
		if(write != lengthEnd) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		fwrite("\n\n", 1, 2, fp);

		fclose(fp);
		return;
	}

	while(iter != LCS_.end()) {
		srcCount ++;
		dstCount ++;
		lineInfo tmp(0, NULL);
		lineInfo* result;
		const Vet<char*>* line;
		Vet<char*>::const_iterator citer;
		int length;

		if((iter->data->srcLineNumber != srcCount) || (iter->data->dstLineNumber != dstCount)) {
			write = fwrite(bufStart, 1, lengthStart, fp);
			if(write !=  lengthStart) {
				log.w("IOError: write error");
				fclose(fp);
				throw IOError;
			}
			fwrite("\n\n", 1, 2, fp);

			while(srcCount < iter->data->srcLineNumber) {
				tmp.setNumber(srcCount);
				result = srcLineInfo_.search(&tmp);
				if(result == NULL) {
					log.w("LineInfo has been destory");
					throw IOError;
				}
				line = result->getRef();
				citer = line->start();
				while(citer != line->end()) {
					length = strlen(citer->data);
					write = fwrite(citer->data, 1, length, fp);
					if(write !=  length) {
						log.w("IOError: write error");
						fclose(fp);
						throw IOError;
					}
					citer = citer->next;
				}
				srcCount ++;
			}
			length = strlen(lineMid);
			write = fwrite(lineMid, 1, length, fp);
			if(write != length) {
				log.w("IOError: write error");
				fclose(fp);
				throw IOError;
			}
			while(dstCount < iter->data->dstLineNumber) {
				tmp.setNumber(dstCount);
				result = dstLineInfo_.search(&tmp);
				if(result == NULL) {
					log.w("LineInfo has been destory");
					throw IOError;
				}
				line = result->getRef();
				citer = line->start();
				while(citer != line->end()) {
					length = strlen(citer->data);
					write = fwrite(citer->data, 1, length, fp);
					if(write !=  length) {
						log.w("IOError: write error");
						fclose(fp);
						throw IOError;
					}
					citer = citer->next;
				}
				dstCount ++;
			}	
			write = fwrite(bufEnd, 1, lengthEnd, fp);
			if(write != lengthEnd) {
				log.w("IOError: write error");
				fclose(fp);
				throw IOError;
			}
			fwrite("\n\n\n", 1, 3, fp);

		}
		
		// same
		tmp.setNumber(srcCount);
		result = srcLineInfo_.search(&tmp);
		if(result == NULL) {
			log.w("LineInfo has been destory");
			throw IOError;
		}
		line = result->getRef();
		citer = line->start();
		while(citer != line->end()) {
			length = strlen(citer->data);
			write = fwrite(citer->data, 1, length, fp);
			if(write != length) {
				log.w("IOError: write error");
				fclose(fp);
				throw IOError;
			}
			citer = citer->next;
		}
		srcCount = iter->data->srcLineNumber;
		dstCount = iter->data->dstLineNumber;
		iter = iter->next;
	}

	// the last
	lineInfo tmp(0, NULL);
	lineInfo* result;
	const Vet<char*>* line;
	Vet<char*>::const_iterator citer;
	int length;

	if(srcCount != srcLineCount_ || dstCount != dstLineCount_) {
		write = fwrite(bufStart, 1, lengthStart, fp);
		if(write != lengthStart) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		fwrite("\n\n", 1, 2, fp);

		while(++srcCount <= srcLineCount_) {
			tmp.setNumber(srcCount);
			result = srcLineInfo_.search(&tmp);
			if(result == NULL) {
				log.w("LineInfo has been destory");
				throw IOError;
			}
			line = result->getRef();
			citer = line->start();
			while(citer != line->end()) {
				length = strlen(citer->data);
				write = fwrite(citer->data, 1, length, fp);
				if(write !=  length) {
					log.w("IOError: write error");
					fclose(fp);
					throw IOError;
				}
				citer = citer->next;
			}
			srcCount ++;
		}
		length = strlen(lineMid);
		write = fwrite(lineMid, 1, length, fp);
		if(write != length) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		while(++dstCount < dstLineCount_) {
			tmp.setNumber(dstCount);
			result = dstLineInfo_.search(&tmp);
			if(result == NULL) {
				log.w("LineInfo has been destory");
				throw IOError;
			}
			line = result->getRef();
			citer = line->start();
			while(citer != line->end()) {
				length = strlen(citer->data);
				write = fwrite(citer->data, 1, length, fp);
				if(write !=  length) {
					log.w("IOError: write error");
					fclose(fp);
					throw IOError;
				}
				citer = citer->next;
			}
			dstCount ++;
		}	
		write = fwrite(bufEnd, 1, lengthEnd, fp);
		if(write != lengthEnd) {
			log.w("IOError: write error");
			fclose(fp);
			throw IOError;
		}
		fwrite("\n\n\n", 1, 3, fp);

	}



	fclose(fp);
}

void Diff::freeBuf(void* p) {

	dellocate(p);
}

void Diff::freeLineInfo(void* p) {

	lineInfo* tmp = static_cast<lineInfo*>(p);
	Vet<char*>* ref = const_cast<Vet<char*>*>(tmp->getRef());
	ref->freeValueType(freeBuf);
	dellocate(ref);
	dellocate(tmp);
}

bool lineInfo::operator > (const lineInfo& item) {

	if(lineNumber_ > item.getLineNumber())
		return true;
	return false;
}

bool lineInfo::operator == (const lineInfo& item) {

	if(lineNumber_ == item.getLineNumber())
		return true;
	return false;
}

}//namesapce ccv

/*
 **********************************************************************
 ** End                                                              **
 ******************************* (cut) ********************************
 */
