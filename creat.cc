#include <stdio.h>

int main(int argc, char* argv[]) {

	FILE* fp = fopen("./header.txt","r");
	
	if(fp == NULL) {

		printf("header.txt doesn't exist\n");
		return 0;

	}

	while(--argc) {
		
		rewind(fp);
		FILE* fw = fopen(*(++argv),"w");
		char ch;
		ch = fgetc(fp);
		
		while(ch !=EOF) {
			fputc(ch, fw);
			ch = fgetc(fp);
		}
		
		fclose(fw);
	
	}

	fclose(fp);

}
