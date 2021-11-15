#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <string.h>

void getConfigJSON(char **uintptrConfigJSON, int lenConfigJSON)
{
    printf("[getConfigJSON]=====================\n");
    char **UintptrConfigJSONKernel = NULL;
    char *ConfigJSONKernel = NULL;

    UintptrConfigJSONKernel = malloc(sizeof(char *));
    ConfigJSONKernel = malloc(sizeof(char));
    memcpy(UintptrConfigJSONKernel, uintptrConfigJSON, sizeof(char *));
    printf("UintptrConfigJSONKernel data: %x\n", UintptrConfigJSONKernel);
    printf("UintptrConfigJSONKernel *s: %s\n", *UintptrConfigJSONKernel);
    printf("UintptrConfigJSONKernel *c: %c\n", *UintptrConfigJSONKernel);
    printf("UintptrConfigJSONKernel **c: %c\n", **UintptrConfigJSONKernel);
    memcpy(ConfigJSONKernel, *UintptrConfigJSONKernel, sizeof(char) * lenConfigJSON);
    printf("ConfigJSONKernel data: %c\n", *(ConfigJSONKernel + 1));

    return;
}

void configJSONAndLen()
{
    char configJSON[10] = {'c', 'o', 'd', 'e', '\0'};
    char *unsafePointerConfigJSON = configJSON;
    char **uintptrConfigJSON = &unsafePointerConfigJSON;
    int lenConfigJSON = strlen(unsafePointerConfigJSON);
    int *lenConfigJSONPoint = &lenConfigJSON;
    printf("configJSON: data %s\n", configJSON);
    printf("configJSON: addr %p\n", &configJSON);
    printf("ConfigJSON: ptr: %p\n", configJSON);
    printf("unsafePointerConfigJSON ptr: %p\n", unsafePointerConfigJSON);
    printf("unsafePointerConfigJSON addr: %p\n", &unsafePointerConfigJSON);
    printf("unsafePointerConfigJSON *data: %c\n", *unsafePointerConfigJSON);
    printf("uintptrConfigJSON ptr: %p\n", uintptrConfigJSON);
    printf("uintptrConfigJSON addr: %p\n", &uintptrConfigJSON);
    printf("uintptrConfigJSON **data: %c\n", **uintptrConfigJSON);
    printf("%d\n", syscall(335, uintptrConfigJSON, lenConfigJSONPoint));
    // getConfigJSON(uintptrConfigJSON, lenConfigJSON);
    return;
}

void configJSONCharAndLen()
{
    char *unsafePointerConfigJSON = {"code"};
    char **uintptrConfigJSON = &unsafePointerConfigJSON;
    int lenConfigJSON = strlen(unsafePointerConfigJSON);
    int *lenConfigJSONPoint = &lenConfigJSON;
    printf("unsafePointerConfigJSON ptr: %p\n", unsafePointerConfigJSON);
    printf("unsafePointerConfigJSON addr: %p\n", &unsafePointerConfigJSON);
    printf("unsafePointerConfigJSON data: %c\n", *unsafePointerConfigJSON);
    printf("uintptrConfigJSON ptr: %p\n", uintptrConfigJSON);
    printf("uintptrConfigJSON addr: %p\n", &uintptrConfigJSON);
    printf("uintptrConfigJSON data: %d\n", uintptrConfigJSON);
    printf("uintptrConfigJSON **data: %c\n", **uintptrConfigJSON);
    printf("=====================\n");
    printf("%d\n", syscall(335, uintptrConfigJSON, lenConfigJSONPoint));
    // getConfigJSON(uintptrConfigJSON, lenConfigJSON);
    return;
}

int main(void)
{
    configJSONAndLen();
    printf("=====================\n");
    return 0;
}