#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include "jsmn/jsmn.h"

//gcc point_test.c cJSON/cJSON.c -lm -o point_test

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
    // printf("%d\n", syscall(335, uintptrConfigJSON, lenConfigJSONPoint));
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
    // printf("%d\n", syscall(335, uintptrConfigJSON, lenConfigJSONPoint));
    // getConfigJSON(uintptrConfigJSON, lenConfigJSON);
    return;
}

// void cJson()
// {
//     char *unsafePointerConfigJSON = "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"80/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"NGINX_VERSION=1.21.3\",\"NJS_VERSION=0.6.2\",\"PKG_RELEASE=1~buster\"],\"Cmd\":[\"nginx\",\"-g\",\"daemon off;\"],\"Image\":\"sha256:e30f1b92b2c67fbe72fb24af7353a945f6df4f48d9064d47bf0f51674311251e\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":[\"/docker-entrypoint.sh\"],\"OnBuild\":null,\"Labels\":{\"maintainer\":\"NGINX Docker Maintainers \\u003cdocker-maint@nginx.com\\u003e\"},\"StopSignal\":\"SIGQUIT\"},\"container\":\"21fd1c6cb532225ca7e04c77f6592e220574b919aec07021663576ef438e0fee\",\"container_config\":{\"Hostname\":\"21fd1c6cb532\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"80/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"NGINX_VERSION=1.21.3\",\"NJS_VERSION=0.6.2\",\"PKG_RELEASE=1~buster\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"nginx\\\" \\\"-g\\\" \\\"daemon off;\\\"]\"],\"Image\":\"sha256:e30f1b92b2c67fbe72fb24af7353a945f6df4f48d9064d47bf0f51674311251e\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":[\"/docker-entrypoint.sh\"],\"OnBuild\":null,\"Labels\":{\"maintainer\":\"NGINX Docker Maintainers \\u003cdocker-maint@nginx.com\\u003e\"},\"StopSignal\":\"SIGQUIT\"},\"created\":\"2021-10-12T02:03:40.360294686Z\",\"docker_version\":\"20.10.7\",\"history\":[{\"created\":\"2021-10-12T01:21:05.468695913Z\",\"created_by\":\"/bin/sh -c #(nop) ADD file:910392427fdf089bc26b64d6dc450ff3d020c7c1a474d85b2f9298134d0007bd in / \"},{\"created\":\"2021-10-12T01:21:05.839089155Z\",\"created_by\":\"/bin/sh -c #(nop)  CMD [\\\"bash\\\"]\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:10.048137094Z\",\"created_by\":\"/bin/sh -c #(nop)  LABEL maintainer=NGINX Docker Maintainers \\u003cdocker-maint@nginx.com\\u003e\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:10.25626375Z\",\"created_by\":\"/bin/sh -c #(nop)  ENV NGINX_VERSION=1.21.3\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:10.444687439Z\",\"created_by\":\"/bin/sh -c #(nop)  ENV NJS_VERSION=0.6.2\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:10.627714216Z\",\"created_by\":\"/bin/sh -c #(nop)  ENV PKG_RELEASE=1~buster\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:38.726257148Z\",\"created_by\":\"/bin/sh -c set -x     \\u0026\\u0026 addgroup --system --gid 101 nginx     \\u0026\\u0026 adduser --system --disabled-login --ingroup nginx --no-create-home --home /nonexistent --gecos \\\"nginx user\\\" --shell /bin/false --uid 101 nginx     \\u0026\\u0026 apt-get update     \\u0026\\u0026 apt-get install --no-install-recommends --no-install-suggests -y gnupg1 ca-certificates     \\u0026\\u0026     NGINX_GPGKEY=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62;     found='';     for server in         ha.pool.sks-keyservers.net         hkp://keyserver.ubuntu.com:80         hkp://p80.pool.sks-keyservers.net:80         pgp.mit.edu     ; do         echo \\\"Fetching GPG key $NGINX_GPGKEY from $server\\\";         apt-key adv --keyserver \\\"$server\\\" --keyserver-options timeout=10 --recv-keys \\\"$NGINX_GPGKEY\\\" \\u0026\\u0026 found=yes \\u0026\\u0026 break;     done;     test -z \\\"$found\\\" \\u0026\\u0026 echo \\u003e\\u00262 \\\"error: failed to fetch GPG key $NGINX_GPGKEY\\\" \\u0026\\u0026 exit 1;     apt-get remove --purge --auto-remove -y gnupg1 \\u0026\\u0026 rm -rf /var/lib/apt/lists/*     \\u0026\\u0026 dpkgArch=\\\"$(dpkg --print-architecture)\\\"     \\u0026\\u0026 nginxPackages=\\\"         nginx=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-xslt=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-geoip=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-image-filter=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-njs=${NGINX_VERSION}+${NJS_VERSION}-${PKG_RELEASE}     \\\"     \\u0026\\u0026 case \\\"$dpkgArch\\\" in         amd64|i386|arm64)             echo \\\"deb https://nginx.org/packages/mainline/debian/ buster nginx\\\" \\u003e\\u003e /etc/apt/sources.list.d/nginx.list             \\u0026\\u0026 apt-get update             ;;         *)             echo \\\"deb-src https://nginx.org/packages/mainline/debian/ buster nginx\\\" \\u003e\\u003e /etc/apt/sources.list.d/nginx.list                         \\u0026\\u0026 tempDir=\\\"$(mktemp -d)\\\"             \\u0026\\u0026 chmod 777 \\\"$tempDir\\\"                         \\u0026\\u0026 savedAptMark=\\\"$(apt-mark showmanual)\\\"                         \\u0026\\u0026 apt-get update             \\u0026\\u0026 apt-get build-dep -y $nginxPackages             \\u0026\\u0026 (                 cd \\\"$tempDir\\\"                 \\u0026\\u0026 DEB_BUILD_OPTIONS=\\\"nocheck parallel=$(nproc)\\\"                     apt-get source --compile $nginxPackages             )                         \\u0026\\u0026 apt-mark showmanual | xargs apt-mark auto \\u003e /dev/null             \\u0026\\u0026 { [ -z \\\"$savedAptMark\\\" ] || apt-mark manual $savedAptMark; }                         \\u0026\\u0026 ls -lAFh \\\"$tempDir\\\"             \\u0026\\u0026 ( cd \\\"$tempDir\\\" \\u0026\\u0026 dpkg-scanpackages . \\u003e Packages )             \\u0026\\u0026 grep '^Package: ' \\\"$tempDir/Packages\\\"             \\u0026\\u0026 echo \\\"deb [ trusted=yes ] file://$tempDir ./\\\" \\u003e /etc/apt/sources.list.d/temp.list             \\u0026\\u0026 apt-get -o Acquire::GzipIndexes=false update             ;;     esac         \\u0026\\u0026 apt-get install --no-install-recommends --no-install-suggests -y                         $nginxPackages                         gettext-base                         curl     \\u0026\\u0026 apt-get remove --purge --auto-remove -y \\u0026\\u0026 rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list         \\u0026\\u0026 if [ -n \\\"$tempDir\\\" ]; then         apt-get purge -y --auto-remove         \\u0026\\u0026 rm -rf \\\"$tempDir\\\" /etc/apt/sources.list.d/temp.list;     fi     \\u0026\\u0026 ln -sf /dev/stdout /var/log/nginx/access.log     \\u0026\\u0026 ln -sf /dev/stderr /var/log/nginx/error.log     \\u0026\\u0026 mkdir /docker-entrypoint.d\"},{\"created\":\"2021-10-12T02:03:39.053118949Z\",\"created_by\":\"/bin/sh -c #(nop) COPY file:65504f71f5855ca017fb64d502ce873a31b2e0decd75297a8fb0a287f97acf92 in / \"},{\"created\":\"2021-10-12T02:03:39.259073164Z\",\"created_by\":\"/bin/sh -c #(nop) COPY file:0b866ff3fc1ef5b03c4e6c8c513ae014f691fb05d530257dfffd07035c1b75da in /docker-entrypoint.d \"},{\"created\":\"2021-10-12T02:03:39.456167355Z\",\"created_by\":\"/bin/sh -c #(nop) COPY file:0fd5fca330dcd6a7de297435e32af634f29f7132ed0550d342cad9fd20158258 in /docker-entrypoint.d \"},{\"created\":\"2021-10-12T02:03:39.659084098Z\",\"created_by\":\"/bin/sh -c #(nop) COPY file:09a214a3e07c919af2fb2d7c749ccbc446b8c10eb217366e5a65640ee9edcc25 in /docker-entrypoint.d \"},{\"created\":\"2021-10-12T02:03:39.846854805Z\",\"created_by\":\"/bin/sh -c #(nop)  ENTRYPOINT [\\\"/docker-entrypoint.sh\\\"]\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:40.019565522Z\",\"created_by\":\"/bin/sh -c #(nop)  EXPOSE 80\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:40.186760128Z\",\"created_by\":\"/bin/sh -c #(nop)  STOPSIGNAL SIGQUIT\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:40.360294686Z\",\"created_by\":\"/bin/sh -c #(nop)  CMD [\\\"nginx\\\" \\\"-g\\\" \\\"daemon off;\\\"]\",\"empty_layer\":true}],\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"sha256:e81bff2725dbc0bf2003db10272fef362e882eb96353055778a66cda430cf81b\",\"sha256:43f4e41372e42dd32309f6a7bdce03cf2d65b3ca34b1036be946d53c35b503ab\",\"sha256:788e89a4d186f3614bfa74254524bc2e2c6de103698aeb1cb044f8e8339a90bd\",\"sha256:f8e880dfc4ef19e78853c3f132166a4760a220c5ad15b9ee03b22da9c490ae3b\",\"sha256:f7e00b807643e512b85ef8c9f5244667c337c314fa29572206c1b0f3ae7bf122\",\"sha256:9959a332cf6e41253a9cd0c715fa74b01db1621b4d16f98f4155a2ed5365da4a\"]}} ";
//     char **uintptrConfigJSON = &unsafePointerConfigJSON;
//     int lenConfigJSON = strlen(unsafePointerConfigJSON);
//     int *lenConfigJSONPoint = &lenConfigJSON;
//     // printf("syscall %d\n", syscall(335, uintptrConfigJSON, lenConfigJSONPoint));

//     printf("[c]-----------------[c]");

//     cJSON *root = cJSON_Parse(unsafePointerConfigJSON);
//     cJSON *rootfs = cJSON_GetObjectItem(root, "rootfs");
//     cJSON *rootfs_diff_ids = cJSON_GetObjectItem(rootfs, "diff_ids");
//     printf("rootfs_diff_ids array size: %d\n", cJSON_GetArraySize(rootfs_diff_ids));
//     printf("rootfs_diff_ids array 0: %s\n", cJSON_GetArrayItem(rootfs_diff_ids, 0)->valuestring);
//     printf("rootfs_diff_ids array 0: %s\n", cJSON_GetArrayItem(rootfs_diff_ids, 5)->valuestring);
// }

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0)
    {
        return 0;
    }
    return -1;
}

int jsmna()
{
    char *unsafePointerConfigJSON = "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"80/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"NGINX_VERSION=1.21.3\",\"NJS_VERSION=0.6.2\",\"PKG_RELEASE=1~buster\"],\"Cmd\":[\"nginx\",\"-g\",\"daemon off;\"],\"Image\":\"sha256:e30f1b92b2c67fbe72fb24af7353a945f6df4f48d9064d47bf0f51674311251e\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":[\"/docker-entrypoint.sh\"],\"OnBuild\":null,\"Labels\":{\"maintainer\":\"NGINX Docker Maintainers \\u003cdocker-maint@nginx.com\\u003e\"},\"StopSignal\":\"SIGQUIT\"},\"container\":\"21fd1c6cb532225ca7e04c77f6592e220574b919aec07021663576ef438e0fee\",\"container_config\":{\"Hostname\":\"21fd1c6cb532\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"80/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"NGINX_VERSION=1.21.3\",\"NJS_VERSION=0.6.2\",\"PKG_RELEASE=1~buster\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"nginx\\\" \\\"-g\\\" \\\"daemon off;\\\"]\"],\"Image\":\"sha256:e30f1b92b2c67fbe72fb24af7353a945f6df4f48d9064d47bf0f51674311251e\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":[\"/docker-entrypoint.sh\"],\"OnBuild\":null,\"Labels\":{\"maintainer\":\"NGINX Docker Maintainers \\u003cdocker-maint@nginx.com\\u003e\"},\"StopSignal\":\"SIGQUIT\"},\"created\":\"2021-10-12T02:03:40.360294686Z\",\"docker_version\":\"20.10.7\",\"history\":[{\"created\":\"2021-10-12T01:21:05.468695913Z\",\"created_by\":\"/bin/sh -c #(nop) ADD file:910392427fdf089bc26b64d6dc450ff3d020c7c1a474d85b2f9298134d0007bd in / \"},{\"created\":\"2021-10-12T01:21:05.839089155Z\",\"created_by\":\"/bin/sh -c #(nop)  CMD [\\\"bash\\\"]\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:10.048137094Z\",\"created_by\":\"/bin/sh -c #(nop)  LABEL maintainer=NGINX Docker Maintainers \\u003cdocker-maint@nginx.com\\u003e\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:10.25626375Z\",\"created_by\":\"/bin/sh -c #(nop)  ENV NGINX_VERSION=1.21.3\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:10.444687439Z\",\"created_by\":\"/bin/sh -c #(nop)  ENV NJS_VERSION=0.6.2\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:10.627714216Z\",\"created_by\":\"/bin/sh -c #(nop)  ENV PKG_RELEASE=1~buster\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:38.726257148Z\",\"created_by\":\"/bin/sh -c set -x     \\u0026\\u0026 addgroup --system --gid 101 nginx     \\u0026\\u0026 adduser --system --disabled-login --ingroup nginx --no-create-home --home /nonexistent --gecos \\\"nginx user\\\" --shell /bin/false --uid 101 nginx     \\u0026\\u0026 apt-get update     \\u0026\\u0026 apt-get install --no-install-recommends --no-install-suggests -y gnupg1 ca-certificates     \\u0026\\u0026     NGINX_GPGKEY=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62;     found='';     for server in         ha.pool.sks-keyservers.net         hkp://keyserver.ubuntu.com:80         hkp://p80.pool.sks-keyservers.net:80         pgp.mit.edu     ; do         echo \\\"Fetching GPG key $NGINX_GPGKEY from $server\\\";         apt-key adv --keyserver \\\"$server\\\" --keyserver-options timeout=10 --recv-keys \\\"$NGINX_GPGKEY\\\" \\u0026\\u0026 found=yes \\u0026\\u0026 break;     done;     test -z \\\"$found\\\" \\u0026\\u0026 echo \\u003e\\u00262 \\\"error: failed to fetch GPG key $NGINX_GPGKEY\\\" \\u0026\\u0026 exit 1;     apt-get remove --purge --auto-remove -y gnupg1 \\u0026\\u0026 rm -rf /var/lib/apt/lists/*     \\u0026\\u0026 dpkgArch=\\\"$(dpkg --print-architecture)\\\"     \\u0026\\u0026 nginxPackages=\\\"         nginx=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-xslt=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-geoip=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-image-filter=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-njs=${NGINX_VERSION}+${NJS_VERSION}-${PKG_RELEASE}     \\\"     \\u0026\\u0026 case \\\"$dpkgArch\\\" in         amd64|i386|arm64)             echo \\\"deb https://nginx.org/packages/mainline/debian/ buster nginx\\\" \\u003e\\u003e /etc/apt/sources.list.d/nginx.list             \\u0026\\u0026 apt-get update             ;;         *)             echo \\\"deb-src https://nginx.org/packages/mainline/debian/ buster nginx\\\" \\u003e\\u003e /etc/apt/sources.list.d/nginx.list                         \\u0026\\u0026 tempDir=\\\"$(mktemp -d)\\\"             \\u0026\\u0026 chmod 777 \\\"$tempDir\\\"                         \\u0026\\u0026 savedAptMark=\\\"$(apt-mark showmanual)\\\"                         \\u0026\\u0026 apt-get update             \\u0026\\u0026 apt-get build-dep -y $nginxPackages             \\u0026\\u0026 (                 cd \\\"$tempDir\\\"                 \\u0026\\u0026 DEB_BUILD_OPTIONS=\\\"nocheck parallel=$(nproc)\\\"                     apt-get source --compile $nginxPackages             )                         \\u0026\\u0026 apt-mark showmanual | xargs apt-mark auto \\u003e /dev/null             \\u0026\\u0026 { [ -z \\\"$savedAptMark\\\" ] || apt-mark manual $savedAptMark; }                         \\u0026\\u0026 ls -lAFh \\\"$tempDir\\\"             \\u0026\\u0026 ( cd \\\"$tempDir\\\" \\u0026\\u0026 dpkg-scanpackages . \\u003e Packages )             \\u0026\\u0026 grep '^Package: ' \\\"$tempDir/Packages\\\"             \\u0026\\u0026 echo \\\"deb [ trusted=yes ] file://$tempDir ./\\\" \\u003e /etc/apt/sources.list.d/temp.list             \\u0026\\u0026 apt-get -o Acquire::GzipIndexes=false update             ;;     esac         \\u0026\\u0026 apt-get install --no-install-recommends --no-install-suggests -y                         $nginxPackages                         gettext-base                         curl     \\u0026\\u0026 apt-get remove --purge --auto-remove -y \\u0026\\u0026 rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list         \\u0026\\u0026 if [ -n \\\"$tempDir\\\" ]; then         apt-get purge -y --auto-remove         \\u0026\\u0026 rm -rf \\\"$tempDir\\\" /etc/apt/sources.list.d/temp.list;     fi     \\u0026\\u0026 ln -sf /dev/stdout /var/log/nginx/access.log     \\u0026\\u0026 ln -sf /dev/stderr /var/log/nginx/error.log     \\u0026\\u0026 mkdir /docker-entrypoint.d\"},{\"created\":\"2021-10-12T02:03:39.053118949Z\",\"created_by\":\"/bin/sh -c #(nop) COPY file:65504f71f5855ca017fb64d502ce873a31b2e0decd75297a8fb0a287f97acf92 in / \"},{\"created\":\"2021-10-12T02:03:39.259073164Z\",\"created_by\":\"/bin/sh -c #(nop) COPY file:0b866ff3fc1ef5b03c4e6c8c513ae014f691fb05d530257dfffd07035c1b75da in /docker-entrypoint.d \"},{\"created\":\"2021-10-12T02:03:39.456167355Z\",\"created_by\":\"/bin/sh -c #(nop) COPY file:0fd5fca330dcd6a7de297435e32af634f29f7132ed0550d342cad9fd20158258 in /docker-entrypoint.d \"},{\"created\":\"2021-10-12T02:03:39.659084098Z\",\"created_by\":\"/bin/sh -c #(nop) COPY file:09a214a3e07c919af2fb2d7c749ccbc446b8c10eb217366e5a65640ee9edcc25 in /docker-entrypoint.d \"},{\"created\":\"2021-10-12T02:03:39.846854805Z\",\"created_by\":\"/bin/sh -c #(nop)  ENTRYPOINT [\\\"/docker-entrypoint.sh\\\"]\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:40.019565522Z\",\"created_by\":\"/bin/sh -c #(nop)  EXPOSE 80\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:40.186760128Z\",\"created_by\":\"/bin/sh -c #(nop)  STOPSIGNAL SIGQUIT\",\"empty_layer\":true},{\"created\":\"2021-10-12T02:03:40.360294686Z\",\"created_by\":\"/bin/sh -c #(nop)  CMD [\\\"nginx\\\" \\\"-g\\\" \\\"daemon off;\\\"]\",\"empty_layer\":true}],\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"sha256:e81bff2725dbc0bf2003db10272fef362e882eb96353055778a66cda430cf81b\",\"sha256:43f4e41372e42dd32309f6a7bdce03cf2d65b3ca34b1036be946d53c35b503ab\",\"sha256:788e89a4d186f3614bfa74254524bc2e2c6de103698aeb1cb044f8e8339a90bd\",\"sha256:f8e880dfc4ef19e78853c3f132166a4760a220c5ad15b9ee03b22da9c490ae3b\",\"sha256:f7e00b807643e512b85ef8c9f5244667c337c314fa29572206c1b0f3ae7bf122\",\"sha256:9959a332cf6e41253a9cd0c715fa74b01db1621b4d16f98f4155a2ed5365da4a\"]}} ";
    char *littleJson = "{\"user\": \"johndoe\", \"admin\": false, \"uid\": 1000,\n  "
                       "\"groups\": [\"users\", \"wheel\", \"audio\", \"video\"]}";
    char **uintptrConfigJSON = &unsafePointerConfigJSON;
    int lenConfigJSON = strlen(unsafePointerConfigJSON);
    int *lenConfigJSONPoint = &lenConfigJSON;
    printf("%s\n", unsafePointerConfigJSON);
    // printf("syscall %d\n", syscall(335, uintptrConfigJSON, lenConfigJSONPoint));

    printf("[c]-----------------[c]\n");

    int i;
    int r;
    jsmn_parser p;
    jsmntok_t tokens[1280]; /* We expect no more than 128 tokens */
    jsmn_init(&p);

    // r = jsmn_parse(&p, littleJson, strlen(littleJson), tokens, 128);
    // if (r < 0)
    // {
    //     printf("Failed to parse JSON: %d\n", r);
    //     return 1;
    // }
    // else
    // {
    //     printf("可以的啊大兄弟\n");
    //     return 0;
    // }
    r = jsmn_parse(&p, unsafePointerConfigJSON, lenConfigJSON, tokens, 128);
    if (r < 0)
    {
        printf("Failed to parse JSON: %d\n", r);
        return 1;
    }
    /* Assume the top-level element is an object */
    if (r < 1 || tokens[0].type != JSMN_OBJECT)
    {
        printf("Object expected\n");
        return 1;
    }

    /* Loop over all keys of the root object */
    for (i = 1; i < r; i++)
    {
        if (jsoneq(unsafePointerConfigJSON, &tokens[i], "architecture") == 0)
        {
            /* We may use strndup() to fetch string value */
            printf("- architecture: %.*s\n", tokens[i + 1].end - tokens[i + 1].start,
                   unsafePointerConfigJSON + tokens[i + 1].start);
            i++;
        }
        else if (jsoneq(unsafePointerConfigJSON, &tokens[i], "container") == 0)
        {
            /* We may additionally check if the value is either "true" or "false" */
            printf("- container: %.*s\n", tokens[i + 1].end - tokens[i + 1].start,
                   unsafePointerConfigJSON + tokens[i + 1].start);
            i++;
        }
        else
        {
            printf("Unexpected key: %.*s\n", tokens[i].end - tokens[i].start,
                   unsafePointerConfigJSON + tokens[i].start);
        }
    }

    // cJSON *root = cJSON_Parse(unsafePointerConfigJSON);
    // cJSON *rootfs = cJSON_GetObjectItem(root, "rootfs");
    // cJSON *rootfs_diff_ids = cJSON_GetObjectItem(rootfs, "diff_ids");
    // printf("rootfs_diff_ids array size: %d\n", cJSON_GetArraySize(rootfs_diff_ids));
    // printf("rootfs_diff_ids array 0: %s\n", cJSON_GetArrayItem(rootfs_diff_ids, 0)->valuestring);
    // printf("rootfs_diff_ids array 0: %s\n", cJSON_GetArrayItem(rootfs_diff_ids, 5)->valuestring);
    return 1;
}

int main(void)
{
    jsmna();
    printf("=====================\n");
    return 0;
}