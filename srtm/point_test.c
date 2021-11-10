#include <stdio.h>
#include <sys/syscall.h>


void getLenConfigJSON(int ***uintptrConfigJSONlen){


    printf("uintptrConfigJSONlen data: %d\n",***uintptrConfigJSONlen);

    return ;
}

void lenConfigJSON(){
    int lenConfigJSON = 10;
    int *lenConfigJSONPoint = &lenConfigJSON;
    int **unsafePointerConfigJSONlen = &lenConfigJSONPoint;
    int ***uintptrConfigJSONlen = &unsafePointerConfigJSONlen;
	printf("lenConfigJSON: %d\n",lenConfigJSON);
	printf("lenConfigJSONPoint ptr: %p\n",lenConfigJSONPoint);
	printf("unsafePointerConfigJSONlen ptr: %p\n",unsafePointerConfigJSONlen);
	printf("uintptrConfigJSONlen ptr: %p\n",uintptrConfigJSONlen);
	printf("uintptrConfigJSONlen data: %d\n",***uintptrConfigJSONlen);
	printf("sizeof int***: %d\n",sizeof(int ***));
    // getLenConfigJSON(uintptrConfigJSONlen);
    return ;
}

void configJSON(){
    char configJSON[10] = {'c','o','d','e','\0'};
    char *unsafePointerConfigJSON = configJSON;
	char **uintptrConfigJSON = &unsafePointerConfigJSON;
    printf("configJSON: %s\n", configJSON);
	printf("ConfigJSON ptr: %p\n",configJSON);
	printf("unsafePointerConfigJSON ptr: %p\n",unsafePointerConfigJSON);
	printf("unsafePointerConfigJSON data: %c\n",*unsafePointerConfigJSON);
	printf("uintptrConfigJSON ptr: %p\n",uintptrConfigJSON);
	printf("uintptrConfigJSON data: %c\n", **uintptrConfigJSON);
    return ;
}

void syscallIntPoint(){
    int lenConfigJSON = 10;
    int *lenConfigJSONPoint = &lenConfigJSON;
    printf("lenConfigJSONPoint x %lx\n",lenConfigJSONPoint);
    printf("lenConfigJSONPoint p %p\n",lenConfigJSONPoint);
    printf("lenConfigJSONPoint u %lu\n",lenConfigJSONPoint);
    printf("%d\n",syscall(335,2,3,4,5));
}

int main(void)
{
    // lenConfigJSON();
    printf("=====================\n");
    syscallIntPoint();
    // configJSON();
	return 0;
}