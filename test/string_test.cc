#include <string>
#include <string.h>
#include <stdio.h>

using namespace std;

void test1() {

	char buf[10];
	buf[0] = 'a';
	buf[1] = 'b';
	buf[2] = '\0';

	string a(buf);
	buf[0] = 'c';
	a.append(buf);
	string b;
	b.append(buf);

	printf("%s", b.c_str());
}

void test2() {

	char buf[10] = "abcde";
	strncpy(buf, buf+2, 3);
	printf("%s", buf);
}

int main() {

	test2();
}
