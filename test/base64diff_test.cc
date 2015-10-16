#include <string>
#include <stdio.h>


void encodeBase64_(const char* Data, int DataByte, std::string& strEncode) {

    const char EncodeTable[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char Tmp[4]={0};
    //int LineLength=0;
    for(int i=0;i<(int)(DataByte / 3);i++)
    {
        Tmp[1] = *Data++;
        Tmp[2] = *Data++;
        Tmp[3] = *Data++;
        strEncode+= EncodeTable[Tmp[1] >> 2];
        strEncode+= EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
        strEncode+= EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
        strEncode+= EncodeTable[Tmp[3] & 0x3F];
       // if(LineLength+=4,LineLength==76) {strEncode+="\r\n";LineLength=0;}
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

int main(int argc, char* argv[]) {

	FILE* fp = fopen(argv[1], "rb");
	FILE* data = fopen(argv[2], "rb");

	char buf[1024];
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

	int i;
	char c;
	const char* pout = out.c_str();
	for(int i=0; i<len; i++) {
		fread(&c, 1, 1, data);
		if(c != *(pout+i)) {
			printf("%d:%c, %c", i, c, *(pout+i));

		}

	}
	fclose(data);
}
		
