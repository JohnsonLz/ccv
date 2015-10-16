#include <string>
#include <stdio.h>


void encodeBase64_(const char* Data, int DataByte, std::string& strEncode) {

    const char EncodeTable[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char Tmp[4]={0};
    int LineLength=0;
    for(int i=0;i<(int)(DataByte / 3);i++)
    {
        Tmp[1] = *Data++;
        Tmp[2] = *Data++;
        Tmp[3] = *Data++;
        strEncode+= EncodeTable[Tmp[1] >> 2];
        strEncode+= EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
        strEncode+= EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
        strEncode+= EncodeTable[Tmp[3] & 0x3F];
        if(LineLength+=4,LineLength==76) {strEncode+="\r\n";LineLength=0;}
    }
    int Mod=DataByte % 3;
    if(Mod==1)
    {
        Tmp[1] = *Data++;
        strEncode+= EncodeTable[(Tmp[1] & 0xFC) >> 2];
        strEncode+= EncodeTable[((Tmp[1] & 0x03) << 4)];
        strEncode+= "==";
    }
    else if(Mod==2)
    {
        Tmp[1] = *Data++;
        Tmp[2] = *Data++;
        strEncode+= EncodeTable[(Tmp[1] & 0xFC) >> 2];
        strEncode+= EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xF0) >> 4)];
        strEncode+= EncodeTable[((Tmp[2] & 0x0F) << 2)];
        strEncode+= "=";
    }

}

int createBase64File(const char* file, const char* dst) {

	char buf[1024];
	FILE* fp = fopen(file, "rb");

	int read;
	std::string str;
	int len = 0;
	while(true) {
		read = fread(buf, 1, 1023, fp);
		len+= read;
		if(read < 1023) {
			buf[read] = '\0';
			str.append(buf);
			break;
		}
		buf[read] = '\0';
		str.append(buf);
	}
	fclose(fp);

	std::string out;
	encodeBase64_(str.c_str(), len, out);

	fp = fopen(dst, "wb+");
	fwrite(out.c_str(), 1, out.size(), fp);
	fclose(fp);
}

int cutFile(const char* file, const char* dst) {

	FILE* fp = fopen(file, "rb");
	FILE* res = fopen(dst, "wb+");
	
	char buf[76];
	while(true) {

		int len = fread(buf, 1, 76, fp);
		fwrite(buf, 1, len, res);
		if(len == 76) {
			fwrite("\r\n", 1, 2, res);
		}
		else {
			break;
		}
	}
	fclose(fp);
	fclose(res);
}

void cut(const char* file) {

	FILE* fp = fopen(file, "rb");
	int i=0;
	char buf[255];

	std::string tmp;
	char ch;
	while(fread(&ch, 1, 1, fp)) {

		if(ch == '\n') {
			sprintf(buf, "./mark%d.txt", i);
			i++;
			FILE* mark = fopen(buf, "wb+");
			int len = tmp.size();
			const char* ptmp = tmp.c_str();
			int j;
			for(j =0; j < len/76; j++) {
				fwrite(ptmp, 1, 76, mark);
				fwrite("\r\n", 1, 2, mark);
				ptmp += 76;
			}
			int les = len - j*76;
			fwrite(ptmp, 1, les, mark);
			fclose(mark);
			tmp.erase();
		}
		else
			tmp += ch;
	}
}

int main(int argc, char* argv[]) {

	if(argc == 2) {
		cut(argv[1]);
		return 0;
	}
	if(argv[1][0] == 'c') {
		cutFile(argv[2], argv[3]);
	}
	else  {
		createBase64File(argv[2], argv[3]);
	}
}

