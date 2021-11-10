#include <stdio.h>

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

int main(void)
{
    lenConfigJSON();
    printf("=====================\n");
    configJSON();
	return 0;
}