#include <cstdio>
#include <stdint.h>

int decodeFixed32(const char* ptr) {
	 return((static_cast<uint32_t>(static_cast<unsigned char>(ptr[0])))
        |(static_cast<uint32_t>(static_cast<unsigned char>(ptr[1])) <<8)
        | (static_cast<uint32_t>(static_cast<unsigned char>(ptr[2])) << 16)
        |(static_cast<uint32_t>(static_cast<unsigned char>(ptr[3])) <<24));
}


int parseFile(const char* fileName) {

	char buf[255];
	FILE* fp = fopen(fileName, "rb");
	if(fp == NULL) {
		printf("can not open %s", fileName);
		return 0;
	}

	char size[4];
	int read;
	int write;

	read = fread(size, 4, 1, fp);
	if(read == 0)
		return 0;
	fseek(fp, 0, SEEK_SET);
	while(true) {
		read = fread(size, 4, 1, fp);
		if(read == 0)
			break;
		int length = decodeFixed32(size);
		printf("%d ", length);
		read = fread(buf, length, 1, fp);
		if(read == 0) {
			printf("IOError: read error");
			fclose(fp);
			return 0;
		}
		buf[length] = '\0';
		printf("%s\n", buf);
		read = fread(buf, 32, 1, fp);
		if(read == 0) {
			printf("IOError: read error");
			fclose(fp);
			return 0;
		}
		buf[32] = '\0';
		printf("%s\n", buf);
	}
	fclose(fp);
}

int main(int argc, char* argv[]) {

	parseFile(argv[1]);
}

