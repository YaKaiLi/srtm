#include <syscall.h>
#include <stdio.h>
int main(void)
{
	printf("%d\n", syscall(335, 10));
	return 0;
}