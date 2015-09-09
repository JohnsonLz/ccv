#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <iostream>

class A {

	private:

	public:
	A() {
		i = 10;
		printf("create A\n");
	}
	~A() {
		printf("delete A\n");
	}

	int i;
	void say() {
		printf("%d\n", i);
	}
};

int test() {

	A* a = static_cast<A*>(malloc(sizeof(A)));
	printf("malloc\n");
	new(a) A();
	a->say();
	delete a;
	printf("end\n");
}

int test1() {

	FILE* fp = fopen("./util/test5.cc","wb+");
	if(fp == NULL) {
		printf("error");
		return 0;
	}
	fclose(fp);
}

int test2() {

	char src[10];
	char dst[10];
	const char* tmp = "hello";
	strcpy(src, tmp);
	printf("%s\n", src);
	strncpy(dst, src, 5);
	printf("%s\n", dst);
}

int test3() {

	FILE* fp = fopen("1.txt", "r");
	char buf[255];
	int count = fread(buf, 10, 1, fp);
	printf("%d\n", count);
	count = fread(buf, 10, 2, fp);
	printf("%d\n", count);
}

void test4() {

	int a = 34;
	char b = (static_cast<unsigned int>(a)) & 0xff;
	printf("%c\n", b);

	int c = static_cast<int>(b);
	printf("%d\n", c);
}

void test5() {

	A a;
	printf("before");
	throw 1;
	printf("behind");
	a.say();
}

void test6() {

	test5();
	int a= 1;
	printf("%d\n",a);
}

void test7() {

	FILE* fp = fopen("./1.txt","r");
	char buf[100];
	int s = fread(buf, 1, 100, fp);

	for(int i=0;i<s;i++)
	printf("%c", buf[i]);

	FILE* tmp = fopen("./2.txt","w+");
	fwrite(buf, s, 1, tmp);
	fclose(tmp);
	fclose(fp);
}

enum Code {
	IOError =1,
	Corruption =2
};

void test8() {

	try {
		int a =1;
		throw IOError;
	}
	catch (Code c) {
		if(c == IOError)
			printf("Corruption\n");
		printf("IOError\n");
	}
	catch(Code IOError) {
		printf("Corruption\n");
	}
	catch(...) {
		printf("throw\n");
	}
	printf("2\n");
}

int main() {
	
	try {
		test8();
	}
	catch(Code c) {
		printf("1");
	}
}
