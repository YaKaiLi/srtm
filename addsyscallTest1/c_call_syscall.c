// #include <syscall.h>
#include <stdio.h>
int main(void)
{
	printf("%d\n", syscall(334));
	return 0;
}