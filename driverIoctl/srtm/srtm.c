#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>    // for vfs_*
#include <crypto/hash.h> // for crypto_hash_*

/*
./arch/x86/include/asm/uaccess.h:32:9: error: dereferencing pointer to incomplete type struct task_struct
  current->thread.addr_limit = fs;
报错修改：
/lib/modules/4.18.0-305.12.1.el8_4.x86_64/build/arch/x86/include/asm/uaccess.h文件中添加

#include <linux/sched.h>
*/

/*
修改
Since version 4.14 of Linux kernel, vfs_read function is no longer exported for use in modules. Use kernel_read instead. It has the the same signature:
4.14之后vfs_read不再导出，应使用kernel_read
*/

//引入发送驱动接口
extern void *__symbol_get(const char *symbol);
extern void __symbol_put(const char *symbol);

typedef int (*fp_container_or_image_create)(const char *vsoc_id, const char *con_img_id, unsigned char mark);
typedef int (*fp_send_confile_to_soc)(const char *vsoc_id, const char *con_img_id, unsigned char mark,
                                      const char *file_name, int flag, const char *data, int data_len);
typedef int (*fp_send_log_to_soc)(const char *vsoc_id, const char *con_img_id, unsigned char mark,
                                  const char *file_name, int flag, const char *data, int data_len);
typedef int (*fp_get_soc_confile_len)(const char *vsoc_id, const char *con_img_id, unsigned char mark, const char *file_name);
typedef int (*fp_get_soc_confile)(const char *vsoc_id, const char *con_img_id, unsigned char mark, const char *file_name, char *buf, int buf_len);
typedef int (*fp_container_or_image_delete)(const char *vsoc_id, const char *con_img_id, unsigned char mark);

fp_container_or_image_create _container_or_image_create = NULL;
fp_send_confile_to_soc _send_confile_to_soc = NULL;
fp_send_log_to_soc _send_log_to_soc = NULL;
fp_get_soc_confile _get_soc_confile = NULL;
fp_get_soc_confile_len _get_soc_confile_len = NULL;
fp_container_or_image_delete _container_or_image_delete = NULL;

#define N_RDONLY 0
#define N_WRONLY 1
#define N_RDWR 2
#define N_CREAT 00000100
#define N_EXCL 00000200   /* not fcntl */
#define N_NOCTTY 00000400 /* not fcntl */
#define N_TRUNC 00001000  /* not fcntl */
#define N_APPEND 00002000
#define N_NONBLOCK 00004000
#define N_DSYNC 00010000  /* used to be O_SYNC, see below */
#define N_FASYNC 00020000 /* fcntl, for BSD compatibility */
#define N_DIRECT 00040000 /* direct disk access hint */
#define N_LARGEFILE 00100000
#define N_DIRECTORY 00200000 /* must be a directory */
#define N_NOFOLLOW 00400000  /* don't follow links */
#define N_NOATIME 01000000
#define N_CLOEXEC 02000000 /* set close_on_exec */

struct _srtm_data
{
    struct cdev cdev;
    uint8_t data;
};
typedef struct _srtm_data cd_data; //设备使用的结构体

static cd_data srtm_data;
static struct class *cl;
static dev_t dev;

typedef struct
{
    char *configJsonAndImageID;
    int lenConfigJsonAndImageID;
} diffIDListAndImageIDStruct;
// diffIDListAndImageIDStruct diffIDListAndImageID; // docker传递数据使用的结构体

struct sdesc
{
    struct shash_desc shash;
    char ctx[];
}; // hash使用的结构体

//执行hash
static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
                     const unsigned char *data, unsigned int datalen,
                     unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc))
    {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    if (sdesc != NULL)
    {
        kfree(sdesc);
        sdesc = NULL;
    }
    return ret;
}

static int do_sha256(const unsigned char *data, unsigned char *out_digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    // unsigned int datalen = sizeof(data) - 1; // remove the null byte
    unsigned int datalen = strlen(data);

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg))
    {
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    calc_hash(alg, data, datalen, out_digest);

    // Very dirty print of 8 first bytes for comparaison with sha256sum
    printk(KERN_INFO "HASH(%s, %i): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           data, datalen, out_digest[0], out_digest[1], out_digest[2], out_digest[3], out_digest[4],
           out_digest[5], out_digest[6], out_digest[7]);

    crypto_free_shash(alg);
    return 0;
}

//打开文件
struct file *file_open(const char *path, int mode, int flags)
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, mode, flags);
    set_fs(oldfs);
    if (IS_ERR(filp) || filp == NULL)
    {
        err = PTR_ERR(filp);
        printk(KERN_ALERT "ERROR: filp_open\n");
        return NULL;
    }

    return filp;
}
//关闭文件
void file_close(struct file *file)
{
    filp_close(file, NULL);
}

// 16进制数组转为字符
unsigned char *hex2char(unsigned char *hex, int len)
{
    int i;
    unsigned char *str = kmalloc(len * 2 + 1, GFP_KERNEL);
    if (str == NULL)
    {
        printk(KERN_ALERT "[hex2char] ERROR: kmalloc\n");
        return NULL;
    }
    printk(KERN_INFO "hex array len: %d\n", len);
    for (i = 0; i < len; i++)
    {
        sprintf(str + i * 2, "%02x", hex[i]);
    }
    str[len * 2] = '\0';
    return str;
}

//文件读取
ssize_t file_read(char *filePath, void *data, size_t size, loff_t offset)
{
    // int file_read(char *filePath, unsigned char *data, unsigned int size, unsigned long long offset)
    //  char *filename, void *buffer, size_t size, loff_t offset
    struct file *foRes;
    ssize_t ret;

    foRes = file_open(filePath, O_RDONLY, 0);
    if (foRes == NULL)
    {
        printk(KERN_INFO "file_open failed\n");
        return -1;
    }

    ret = kernel_read(foRes, data, size, &offset);

    file_close(foRes);
    return ret;
}

//写入到文件
int write_to_log(char *layerid, size_t size, loff_t *offset)
{
    // TODO：调用send_log_to_soc将字符串传输到SOC

    // offset 0 就可以
    unsigned char *logStringPrefix = " layerid: ";
    unsigned char *logString = NULL;
    unsigned char *tarCommandSuffix = " is modify!";

    // struct file *destFile;
    // char *filePath = "/srtm/srtm.log";

    logString = kmalloc(288, GFP_KERNEL);
    if (logString == NULL)
    {
        printk(KERN_ALERT "[write_to_log] ERROR: kmalloc\n");
        return -1;
    }
    memset(logString, 0, 288);
    strcat(logString, logStringPrefix);
    strcat(logString, layerid);
    strcat(logString, tarCommandSuffix);

    printk("write: %s", logString);
    return 0;

    // destFile = file_open(filePath, O_CREAT | O_WRONLY | O_APPEND, 0666);
    // if (IS_ERR(destFile))
    // {
    //     printk("Error in opening: <%ld>", (long)destFile);
    //     return NULL;
    // }
    // if (destFile == NULL)
    // {
    //     printk("Error in opening: null");
    //     return NULL;
    // }
    // // size_t res = kernel_write(destFile, logString, size, offset);
    // size_t res = kernel_write(destFile, logString, strlen(logString), 0);
    // printk("%ld", res);
    // file_close(destFile);
}

//执行压缩文件夹命令
int execTarCmd(char *readLayerDirPathBuffer, char *singleDiffIDWithSHA, const char *firstOrSecond)
{
    // /bin/bash -c "tar -czvf /tmp/c73aea831b3d279f1d68267f5d6a6828f1d0f71b81a73c9cd5a31c493314ec8a.tar.gz /var/lib/docker/overlay2/c73aea831b3d279f1d68267f5d6a6828f1d0f71b81a73c9cd5a31c493314ec8a/diff"
    unsigned char *tarCommandPrefix = "tar -cf /srtm/tar/";
    unsigned char *tarCommandMiddle = ".tar --absolute-names /var/lib/docker/overlay2/";
    unsigned char *tarCommandSuffix = "/diff";
    int tarResult = 0;

    unsigned char *tarCommand = NULL;

    tarCommand = kmalloc(288, GFP_KERNEL);
    if (tarCommand == NULL)
    {
        printk(KERN_ALERT "[execTarCmd] ERROR: kmalloc\n");
        return -1;
    }
    memset(tarCommand, 0, 288);

    //拼接打包命令
    strcat(tarCommand, tarCommandPrefix);
    strcat(tarCommand, singleDiffIDWithSHA + 7);
    strcat(tarCommand, firstOrSecond);
    strcat(tarCommand, tarCommandMiddle);
    strcat(tarCommand, readLayerDirPathBuffer);
    strcat(tarCommand, tarCommandSuffix);
    printk("tarCommand: %s\n", tarCommand);
    char tar_cmd_path[] = "/bin/bash";
    char *tar_cmd_argv[] = {tar_cmd_path, "-c", tarCommand, NULL};
    char *tar_cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/user/bin", NULL};
    tarResult = call_usermodehelper(tar_cmd_path, tar_cmd_argv, tar_cmd_envp, UMH_WAIT_PROC);
    if (tarCommand != NULL)
    {
        kfree(tarCommand);
        tarCommand = NULL;
    }

    return tarResult;
}

//执行哈希计算命令，并将结果写入文件
int execSha256Cmd(char *singleDiffIDWithSHA, const char *firstOrSecond)
{
    // /bin/bash -c "tar -czvf /tmp/c73aea831b3d279f1d68267f5d6a6828f1d0f71b81a73c9cd5a31c493314ec8a.tar.gz /var/lib/docker/overlay2/c73aea831b3d279f1d68267f5d6a6828f1d0f71b81a73c9cd5a31c493314ec8a/diff"
    unsigned char *sha256CommandPrefix = "sha256sum /srtm/tar/";
    unsigned char *sha256CommandMiddle = ".tar > /srtm/sha256/";
    unsigned char *sha256CommandSuffix = ".sha256";
    int sha256Result = 0;

    unsigned char *sha256Command = NULL;

    sha256Command = kmalloc(288, GFP_KERNEL);
    if (sha256Command == NULL)
    {
        printk(KERN_ALERT "[execSha256Cmd] ERROR: kmalloc\n");
        return -1;
    }
    memset(sha256Command, 0, 288);

    //拼接打包命令
    strcat(sha256Command, sha256CommandPrefix);
    strcat(sha256Command, singleDiffIDWithSHA + 7);
    strcat(sha256Command, firstOrSecond);
    strcat(sha256Command, sha256CommandMiddle);
    strcat(sha256Command, singleDiffIDWithSHA + 7);
    strcat(sha256Command, sha256CommandSuffix);
    strcat(sha256Command, firstOrSecond);
    printk("sha256Command: %s\n", sha256Command);
    char sha256_cmd_path[] = "/bin/bash";
    char *sha256_cmd_argv[] = {sha256_cmd_path, "-c", sha256Command, NULL};
    char *sha256_cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/user/bin", NULL};
    sha256Result = call_usermodehelper(sha256_cmd_path, sha256_cmd_argv, sha256_cmd_envp, UMH_WAIT_PROC);
    if (sha256Command != NULL)
    {
        kfree(sha256Command);
        sha256Command = NULL;
    }

    return sha256Result;
}

//通过diffID获取chainID
unsigned char *getChainIDFromDiffID(char *singleDiffIDWithSHA, char *lastChainID)
{
    unsigned char *diffIDWithLastChainID = NULL;
    unsigned char *chainIDHex = NULL;
    unsigned char *chainIDString = NULL;
    unsigned char *diffIDWithLastChainIDPrefix = "sha256:";
    unsigned char *diffIDWithLastChainIDMiddle = " sha256:";
    unsigned char *singleDiffIDWithSHACopy = NULL;

    if (singleDiffIDWithSHA == NULL)
    {
        printk(KERN_ALERT "[getChainIDFromDiff ID] ERROR: singleDiffIDWithSHA is NULL\n");
        return NULL;
    }

    singleDiffIDWithSHACopy = kmalloc(strlen(singleDiffIDWithSHA + 7) + 1, GFP_KERNEL);
    if (singleDiffIDWithSHACopy == NULL)
    {
        printk(KERN_ALERT "[getChainIDFromDiff ID] ERROR: singleDiffIDWithSHACopy kmalloc\n");
        return NULL;
    }
    memset(singleDiffIDWithSHACopy, 0, strlen(singleDiffIDWithSHA + 7) + 1);
    memmove(singleDiffIDWithSHACopy, singleDiffIDWithSHA + 7, strlen(singleDiffIDWithSHA + 7));
    // char *diffIDWithLastChainIDSuffix = "/diff";
    if (lastChainID == NULL)
    {
        return singleDiffIDWithSHACopy;
    }
    else
    {
        //申请空间
        diffIDWithLastChainID = kmalloc(188, GFP_KERNEL);
        if (diffIDWithLastChainID == NULL)
        {
            if (singleDiffIDWithSHACopy != NULL)
            {
                kfree(singleDiffIDWithSHACopy);
                singleDiffIDWithSHACopy = NULL;
            }
            printk(KERN_ALERT "[getChainIDFromDiff ID] ERROR: kmalloc\n");
            return NULL;
        }
        memset(diffIDWithLastChainID, 0, 188);
        chainIDHex = kmalloc(64, GFP_KERNEL);
        if (chainIDHex == NULL)
        {
            if (diffIDWithLastChainID != NULL)
            {
                kfree(diffIDWithLastChainID);
                diffIDWithLastChainID = NULL;
            }
            if (singleDiffIDWithSHACopy != NULL)
            {
                kfree(singleDiffIDWithSHACopy);
                singleDiffIDWithSHACopy = NULL;
            }
            printk(KERN_ALERT "[getChainIDFromDiff ID] ERROR: kmalloc\n");
            return NULL;
        }
        memset(chainIDHex, 0, 64);
        // chainIDString = kmalloc(1024, GFP_KERNEL);
        // memset(chainIDString, 0, 1024);
        //开始拼接
        strcat(diffIDWithLastChainID, diffIDWithLastChainIDPrefix);
        strcat(diffIDWithLastChainID, lastChainID);
        strcat(diffIDWithLastChainID, diffIDWithLastChainIDMiddle);
        strcat(diffIDWithLastChainID, singleDiffIDWithSHACopy);
        printk(KERN_INFO "diffIDWithLastChainID: %s\n", diffIDWithLastChainID);
        do_sha256(diffIDWithLastChainID, chainIDHex);
        // printk(KERN_INFO "first 16 byte chainIDHex: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        // 	   chainIDHex[0], chainIDHex[1], chainIDHex[2], chainIDHex[3], chainIDHex[4],
        // 	   chainIDHex[5], chainIDHex[6], chainIDHex[7]);

        // chainIDString = hex2char(chainIDHex, strlen(chainIDHex));
        chainIDString = hex2char(chainIDHex, 32);
        // printk(KERN_INFO "chainIDString: %s\n", chainIDString);

        if (diffIDWithLastChainID != NULL)
        {
            kfree(diffIDWithLastChainID);
            diffIDWithLastChainID = NULL;
        }
        if (chainIDHex != NULL)
        {
            kfree(chainIDHex);
            chainIDHex = NULL;
        }
        if (singleDiffIDWithSHACopy != NULL)
        {
            kfree(singleDiffIDWithSHACopy);
            singleDiffIDWithSHACopy = NULL;
        }
        return chainIDString;
    }
}

//通过chainID获取LayerKey
unsigned char *getLayerKeyFromchainID(char *chainID)
{
    //从chainID中获取lay目录字段
    unsigned char *layerdbDirPrefix = "/var/lib/docker/image/overlay2/layerdb/sha256/";
    unsigned char *layerdbDirSuffix = "/cache-id";
    unsigned char *readLayerDirPathBuffer = NULL;
    unsigned char *layerdbDir = NULL;
    // char *singleDiffID = NULL;
    const size_t readLayerDirPathSize = 128;
    ssize_t readLayerDirPathBytes;
    // int addZeroLen = 0;

    if (chainID == NULL)
    {
        printk(KERN_ALERT "[getLayerKeyFromchain ID] ERROR: chainID is NULL\n");
        return NULL;
    }

    layerdbDir = kmalloc(188, GFP_KERNEL);
    if (layerdbDir == NULL)
    {
        printk(KERN_ALERT "[getLayerKeyFromchain ID] ERROR: kmalloc\n");
        return NULL;
    }
    memset(layerdbDir, 0, 188);

    // printk("%s\n", singleDiffIDWithSHA);
    printk("chainID: %s\n", chainID);

    //拼接diffID路径
    strcat(layerdbDir, layerdbDirPrefix);
    strcat(layerdbDir, chainID);
    strcat(layerdbDir, layerdbDirSuffix);
    printk("diffID Path: %s\n", layerdbDir);
    printk("diffID Path length: %ld\n", strlen(layerdbDir));
    // strcpy(layerdbDir, "cc ");
    // layerdbDir[0] = '\0';

    //读取layerid目录路径
    readLayerDirPathBuffer = kmalloc(readLayerDirPathSize, GFP_KERNEL);
    if (readLayerDirPathBuffer == NULL)
    {
        if (layerdbDir != NULL)
        {
            kfree(layerdbDir);
            layerdbDir = NULL;
        }
        printk(KERN_ALERT "[getLayerKeyFromchain ID] ERROR: kmalloc\n");
        return NULL;
    }
    readLayerDirPathBytes = file_read(layerdbDir, readLayerDirPathBuffer, readLayerDirPathSize, 0);
    if (readLayerDirPathBytes < 0)
    {
        printk(KERN_INFO "readLayerDirPathBytes length < 0\n");
        if (readLayerDirPathBuffer != NULL)
        {
            kfree(readLayerDirPathBuffer);
            readLayerDirPathBuffer = NULL;
        }
        if (layerdbDir != NULL)
        {
            kfree(layerdbDir);
            layerdbDir = NULL;
        }
        return NULL;
    }
    else
    {
        //可以正常读了
        // add a zero terminator
        // addZeroLen = readLayerDirPathBytes % (readLayerDirPathSize - 1);
        readLayerDirPathBuffer[readLayerDirPathBytes % (readLayerDirPathSize - 1)] = '\0';
        // printk(KERN_INFO "[in func]addZeroLen %ld\n", readLayerDirPathBytes % (readLayerDirPathSize - 1));
        // printk(KERN_INFO "[in func]bytes read %d\n", (unsigned int)readLayerDirPathBytes);
        printk(KERN_INFO "[in func]read string: %s\n", readLayerDirPathBuffer);
    }
    //读layerid目录路径完了

    //结束 释放变量
    if (layerdbDir != NULL)
    {
        kfree(layerdbDir);
        layerdbDir = NULL;
    }
    return readLayerDirPathBuffer;
}

unsigned char *readFirstSha256sum(char *singleDiffIDWithSHA)
{
    //定义读第一次sha256使用的变量
    unsigned char *firstSha256FilePathPrefix = "/srtm/sha256/";
    unsigned char *firstSha256FilePathSuffix = ".sha256.first";
    unsigned char *readFirstSha256FileBuffer = NULL;
    unsigned char *firstSha256FilePath = NULL;
    const size_t readfirstSha256FileSize = 256;
    ssize_t readfirstSha256FileBytes;

    //申请空间
    firstSha256FilePath = kmalloc(128, GFP_KERNEL);
    if (firstSha256FilePath == NULL)
    {
        printk(KERN_ALERT "[verify Sha256sum] ERROR: firstSha256FilePath kmalloc\n");
        return NULL;
    }
    memset(firstSha256FilePath, 0, 128);

    //拼接第一次sha256路径路径
    strcat(firstSha256FilePath, firstSha256FilePathPrefix);
    strcat(firstSha256FilePath, singleDiffIDWithSHA + 7);
    strcat(firstSha256FilePath, firstSha256FilePathSuffix);
    printk("firstSha256FilePath Path: %s\n", firstSha256FilePath);
    printk("firstSha256FilePath Path length: %ld\n", strlen(firstSha256FilePath));
    //读取第一次sha256文件
    readFirstSha256FileBuffer = kmalloc(readfirstSha256FileSize, GFP_KERNEL);
    if (readFirstSha256FileBuffer == NULL)
    {
        if (firstSha256FilePath != NULL)
        {
            kfree(firstSha256FilePath);
            firstSha256FilePath = NULL;
        }
        printk(KERN_ALERT "[verify Sha256sum] ERROR: readFirstSha256FileBuffer kmalloc\n");
        return NULL;
    }
    readfirstSha256FileBytes = file_read(firstSha256FilePath, readFirstSha256FileBuffer, readfirstSha256FileSize, 0);
    if (readfirstSha256FileBytes < 0)
    {
        printk(KERN_INFO "readfirstSha256FileBytes length < 0\n");
        if (firstSha256FilePath != NULL)
        {
            kfree(firstSha256FilePath);
            firstSha256FilePath = NULL;
        }
        if (readFirstSha256FileBuffer != NULL)
        {
            kfree(readFirstSha256FileBuffer);
            readFirstSha256FileBuffer = NULL;
        }
        return NULL;
    }
    else
    {
        //可以正常读了
        // add a zero terminator
        // printk(KERN_INFO "addZeroLen %ld\n", readfirstSha256FileBytes % (readfirstSha256FileSize - 1));
        // printk(KERN_INFO "bytes read %d\n", (unsigned int)readfirstSha256FileBytes);
        readFirstSha256FileBuffer[readfirstSha256FileBytes % (readfirstSha256FileSize - 1)] = '\0';
        printk(KERN_INFO "[verify Sha256sum]read string: %s\n", readFirstSha256FileBuffer);
    }
    //读文件完了

    return readFirstSha256FileBuffer;
}

unsigned char *readSecondSha256sum(char *singleDiffIDWithSHA)
{
    //定义读第二次sha256使用的变量
    unsigned char *secondSha256FilePathPrefix = "/srtm/sha256/";
    unsigned char *secondSha256FilePathSuffix = ".sha256.second";
    unsigned char *readSecondSha256FileBuffer = NULL;
    unsigned char *secondSha256FilePath = NULL;
    const size_t readsecondSha256FileSize = 256;
    ssize_t readsecondSha256FileBytes;

    //申请空间
    secondSha256FilePath = kmalloc(128, GFP_KERNEL);
    if (secondSha256FilePath == NULL)
    {
        printk(KERN_ALERT "[verify Sha256sum] ERROR: secondSha256FilePath kmalloc\n");
        return NULL;
    }
    memset(secondSha256FilePath, 0, 128);

    //拼接第二次sha256路径路径
    strcat(secondSha256FilePath, secondSha256FilePathPrefix);
    strcat(secondSha256FilePath, singleDiffIDWithSHA + 7);
    strcat(secondSha256FilePath, secondSha256FilePathSuffix);
    printk("secondSha256FilePath Path: %s\n", secondSha256FilePath);
    printk("secondSha256FilePath Path length: %ld\n", strlen(secondSha256FilePath));
    //读取第二次sha256文件
    readSecondSha256FileBuffer = kmalloc(readsecondSha256FileSize, GFP_KERNEL);
    if (readSecondSha256FileBuffer == NULL)
    {
        printk(KERN_ALERT "[verify Sha256sum] ERROR: readSecondSha256FileBuffer kmalloc\n");

        if (secondSha256FilePath != NULL)
        {
            kfree(secondSha256FilePath);
            secondSha256FilePath = NULL;
        }
        return NULL;
    }
    readsecondSha256FileBytes = file_read(secondSha256FilePath, readSecondSha256FileBuffer, readsecondSha256FileSize, 0);
    if (readsecondSha256FileBytes < 0)
    {
        printk(KERN_INFO "readsecondSha256FileBytes length < 0\n");

        if (secondSha256FilePath != NULL)
        {
            kfree(secondSha256FilePath);
            secondSha256FilePath = NULL;
        }
        if (readSecondSha256FileBuffer != NULL)
        {
            kfree(readSecondSha256FileBuffer);
            readSecondSha256FileBuffer = NULL;
        }
        return NULL;
    }
    else
    {
        //可以正常读了
        // add a zero terminator
        // printk(KERN_INFO "addZeroLen %ld\n", readfirstSha256FileBytes % (readfirstSha256FileSize - 1));
        // printk(KERN_INFO "bytes read %d\n", (unsigned int)readfirstSha256FileBytes);
        readSecondSha256FileBuffer[readsecondSha256FileBytes % (readsecondSha256FileSize - 1)] = '\0';
        printk(KERN_INFO "[readSecondSha256sum] readSecondSha256sum: %s\n", readSecondSha256FileBuffer);
    }
    //读文件完了

    return readSecondSha256FileBuffer;
}

//验证两次sha256结果是否一致
int verifySha256sum(char *singleDiffIDWithSHA, char *allSha256String)
{
    // DONE：传入两个参数：1、singleDiffIDWithSHA 2、整个度量字符串
    // DONE：逻辑改为字符串匹配
    //定义读第二次sha256使用的变量
    unsigned char *readSecondSha256FileBuffer = NULL;
    unsigned char *readSecondSha256FileJustSha256 = NULL;
    //定义比较使用的变量
    char *compareResult = NULL;
    int retResult = -1;

    //读取第二次sha256文件
    readSecondSha256FileBuffer = readSecondSha256sum(singleDiffIDWithSHA);

    readSecondSha256FileJustSha256 = kmalloc(128, GFP_KERNEL);
    if (readSecondSha256FileJustSha256 == NULL)
    {
        printk(KERN_ALERT "[verify Sha256sum] ERROR: readSecondSha256FileJustSha256 kmalloc\n");
        return retResult;
    }
    memset(readSecondSha256FileJustSha256, 0, 128);

    if (readSecondSha256FileBuffer == NULL)
    {
        printk(KERN_ALERT "[verify Sha256sum] ERROR: readSecondSha256FileBuffer is NULL\n");
        retResult = -2;
    }
    else
    {
        strncpy(readSecondSha256FileJustSha256, readSecondSha256FileBuffer, 64);

        printk(KERN_INFO "[verify Sha256sum] allSha256String: %s\n", allSha256String);
        printk(KERN_INFO "[verify Sha256sum] readSecondSha256FileBuffer: %s\n", readSecondSha256FileBuffer);
        printk(KERN_INFO "[verify Sha256sum] readSecondSha256FileJustSha256: %s\n", readSecondSha256FileJustSha256);
        compareResult = strstr(allSha256String, readSecondSha256FileJustSha256);
        printk(KERN_INFO "[verify Sha256sum] compareResult: %s\n", compareResult);
        if (compareResult != NULL)
        {
            retResult = 1;
        }
        else
        {
            retResult = -3;
        }
    }

    //结束 释放变量
    if (readSecondSha256FileBuffer != NULL)
    {
        kfree(readSecondSha256FileBuffer);
        readSecondSha256FileBuffer = NULL;
    }
    if (readSecondSha256FileJustSha256 != NULL)
    {
        kfree(readSecondSha256FileJustSha256);
        readSecondSha256FileJustSha256 = NULL;
    }
    return retResult;
}

int srtm_pull_image(char *configJsonAndImageIDKernel, int lenConfigJsonAndImageID)
{
    // char **uintptrConfigJSON, int *uintptrConfigJSONLen
    // di、si、dx、r10、r8、r9
    int retTmp = 789;
    //字符串分割
    // char *strsepResult = NULL;
    unsigned char *singleDiffIDWithSHA = NULL;
    unsigned char *imageIDWithSHA = NULL;
    char *const delimComma = ",";
    char *const imaegIDDelimComma = ";";
    // char *const delimColons = ":";
    //从diffID中获取chainID
    unsigned char *lastChainID = NULL;
    unsigned char *chainID = NULL;
    //从chainID中获取lay目录字段
    unsigned char *LayerKey = NULL;
    //压缩文件夹相关字段
    int tarResult = 0;
    // sha256相关字段
    int sha256Result = 0;
    //定义读第一次sha256使用的变量
    unsigned char *readFirstSha256FileBuffer = NULL;
    unsigned char *allFirstSha256String = NULL;
    //存储全部sha256字符串
    unsigned char *allSha256String = NULL;

    //申请空间
    allFirstSha256String = kmalloc(128, GFP_KERNEL);
    if (allFirstSha256String == NULL)
    {
        printk(KERN_ALERT "[verify Sha256sum] ERROR: allFirstSha256String kmalloc\n");
        return -1;
    }
    memset(allFirstSha256String, 0, 128);

    allSha256String = kmalloc(lenConfigJsonAndImageID, GFP_KERNEL);
    if (allSha256String == NULL)
    {
        printk(KERN_ALERT "[verify Sha256sum] ERROR: allSha256String kmalloc\n");
        return -1;
    }
    memset(allSha256String, 0, lenConfigJsonAndImageID);

    // int i = 0;
    printk("srtm_pull_ image is running!\n");

    if (configJsonAndImageIDKernel == NULL)
    {
        printk("configJsonAndImageIDKernel is NULL\n");
        retTmp = -1;
        return retTmp;
    }
    printk("configJsonAndImageIDKernel *s: %s", configJsonAndImageIDKernel);

    //获取imageID
    imageIDWithSHA = strsep(&configJsonAndImageIDKernel, imaegIDDelimComma);
    printk("imageIDWithSHA *s: %s", imageIDWithSHA);

    // DONE：调用container_or_image_create创建镜像目录
    _container_or_image_create(NULL, imageIDWithSHA + 7, 0);

    // attaction:strsep函数会修改configJsonAndImageIDKernel字符串数据
    singleDiffIDWithSHA = strsep(&configJsonAndImageIDKernel, delimComma);
    while (singleDiffIDWithSHA != NULL)
    {
        // printk("长度:%ld\n", strlen(singleDiffIDWithSHA)); //预计为71
        if (strlen(singleDiffIDWithSHA) != 71)
        {
            printk(KERN_INFO "singleDiffIDWithSHA != 71");
            printk(KERN_INFO "singleDiffIDWithSHA: %s\n", singleDiffIDWithSHA);
            printk(KERN_INFO "singleDiffIDWithSHA length: %ld\n", strlen(singleDiffIDWithSHA));
            break;
        }
        printk(KERN_INFO "singleDiffIDWithSHA: %s\n", singleDiffIDWithSHA);
        printk(KERN_INFO "singleDiffIDWithSHA length: %ld\n", strlen(singleDiffIDWithSHA));

        chainID = getChainIDFromDiffID(singleDiffIDWithSHA, lastChainID);
        if (chainID == NULL)
        {
            printk(KERN_INFO "getChainIDFromDiff ID failed\n");
            break;
        }

        if (lastChainID != NULL)
        {
            printk(KERN_INFO "lastChainID: %s\n", lastChainID);
            kfree(lastChainID);
            lastChainID = NULL;
        }
        lastChainID = kmalloc(88, GFP_KERNEL);
        if (lastChainID == NULL)
        {
            if (chainID != NULL)
            {
                kfree(chainID);
                chainID = NULL;
            }
            printk("lastChainID kmalloc filed");
            break;
        }
        memset(lastChainID, 0, 88);
        memmove(lastChainID, chainID, strlen(chainID));
        printk(KERN_INFO "chainIDString: %s\n", chainID);

        LayerKey = getLayerKeyFromchainID(chainID);
        if (LayerKey == NULL)
        {
            if (chainID != NULL)
            {
                kfree(chainID);
                chainID = NULL;
            }
            printk(KERN_INFO "LayerKey is NULL");
            break;
        }
        printk(KERN_INFO "[LayerKey]%s\n", LayerKey);

        //执行打包文件夹命令
        tarResult = execTarCmd(LayerKey, singleDiffIDWithSHA, ".first");
        printk(KERN_DEBUG "THe result of execTarCmd call_usermodehelper is %d\n", tarResult);

        //执行计算sha256命令
        sha256Result = execSha256Cmd(singleDiffIDWithSHA, ".first");
        printk(KERN_DEBUG "THe result of execSha256Cmd call_usermodehelper is %d\n", sha256Result);

        //读出sha256文件
        readFirstSha256FileBuffer = readFirstSha256sum(singleDiffIDWithSHA);
        printk(KERN_DEBUG "THe result of readFirstSha256FileBuffer %s\n", readFirstSha256FileBuffer);
        strncat(allSha256String, readFirstSha256FileBuffer, 64);
        printk(KERN_DEBUG "THe result of allSha256String %s\n", allSha256String);

        // DONE:读取sha256并拼接成字符串

        // LayerKey 置空
        if (LayerKey != NULL)
        {
            kfree(LayerKey);
            LayerKey = NULL;
        }
        if (chainID != NULL)
        {
            kfree(chainID);
            chainID = NULL;
        }
        if (readFirstSha256FileBuffer != NULL)
        {
            kfree(readFirstSha256FileBuffer);
            readFirstSha256FileBuffer = NULL;
        }
        printk("[one layer over]==========================================[one layer over]\n");

        //拷贝下一个diffIDWithSHA字符串
        singleDiffIDWithSHA = strsep(&configJsonAndImageIDKernel, delimComma);
    }

    // TODO：拼接字符串调用send_confile_to_soc传到物理安全卡
    _send_confile_to_soc(NULL, imageIDWithSHA + 7, 0, "test", N_APPEND, allSha256String, strlen(allSha256String));
    //_send_confile_to_soc(phs_vsoc_id, con_img_id, container_mark, filename, N_APPEND, data, sizeof(data));

    if (lastChainID != NULL)
    {
        kfree(lastChainID);
        lastChainID = NULL;
    }
    if (allSha256String != NULL)
    {
        kfree(allSha256String);
        allSha256String = NULL;
    }

    printk("[kernel function over]==========================================[kernel function over]\n");

    return retTmp;
}

int srtm_run_container(char *configJsonAndImageIDKernel, int lenConfigJsonAndImageID)
{
    // char **uintptrConfigJSON, int *uintptrConfigJSONLen
    // di、si、dx、r10、r8、r9
    // int retTmp = 456;
    //字符串分割
    // char *strsepResult = NULL;
    unsigned char *singleDiffIDWithSHA = NULL;
    unsigned char *imageIDWithSHA = NULL;
    char *const imaegIDDelimComma = ";";
    char *const delimComma = ",";
    // char *const delimColons = ":";
    //安全卡读取度量值
    int allSha256StringLen = 0;
    unsigned char *allSha256String = NULL;
    //从diffID中获取chainID
    unsigned char *lastChainID = NULL;
    unsigned char *chainID = NULL;
    //从chainID中获取lay目录字段
    unsigned char *LayerKey = NULL;
    //压缩文件夹相关字段
    int tarResult = 0;
    // sha256相关字段
    int sha256Result = 0;
    //验证两次哈希 相关字段
    int verifySha256sumResult = 0;
    //返回结果
    int retRes = 666;

    // int i = 0;
    printk("srtm_run_ container is runing!\n");

    if (configJsonAndImageIDKernel == NULL)
    {
        printk("configJsonAndImageIDKernel is NULL\n");
        return 1;
    }
    printk("configJsonAndImageIDKernel *s: %s", configJsonAndImageIDKernel);

    //申请空间
    allSha256String = kmalloc(lenConfigJsonAndImageID, GFP_KERNEL);
    if (allSha256String == NULL)
    {
        printk(KERN_ALERT "[verify Sha256sum] ERROR: allSha256String kmalloc\n");
        return -1;
    }
    memset(allSha256String, 0, lenConfigJsonAndImageID);

    // get imageIDWithSHA
    imageIDWithSHA = strsep(&configJsonAndImageIDKernel, imaegIDDelimComma);
    printk("imageIDWithSHA *s: %s", imageIDWithSHA);

    // TODO：根据image ID获取度量值长度 get_soc_confile_len
    // TODO：获取度量值存到字符串 get_soc_confile
    //临时
    // strcpy(allSha256String, "ef4b654a8e7358f234731f1402e4b19ba0b618b6273cb28a13624a038ebe6a693dba8612509206ed541a9123fde79a9f8a69231cbab1b6ee9a0bf3b7b4d6ff4a66cf60026f94f3a9bfa76cadace815b64ea0a0bcc5466320284d1adbf59063920a651d80dc5d8c1352c81a1cd2fd576d5bdfc7c917c0f26d0f9bb5638c8fbac46f161e62a26c51273294650a146324d58d3948109a4dec2626784b3f33f9b8a1673d606998e157996afff3066b3cb7ced9c57bd52e02b1ec071b313c506c319a");
    allSha256StringLen = _get_soc_confile_len(NULL, imageIDWithSHA + 7, 0, "test");
    _get_soc_confile(NULL, imageIDWithSHA + 7, 0, "test", allSha256String, allSha256StringLen);

    // attaction:strsep函数会修改configJsonAndImageIDKernel字符串数据
    singleDiffIDWithSHA = strsep(&configJsonAndImageIDKernel, delimComma);
    while (singleDiffIDWithSHA != NULL)
    {
        // printk("长度:%ld\n", strlen(singleDiffIDWithSHA)); //预计为71
        if (strlen(singleDiffIDWithSHA) != 71)
        {
            printk(KERN_INFO "singleDiffIDWithSHA != 71");
            printk(KERN_INFO "singleDiffIDWithSHA: %s\n", singleDiffIDWithSHA);
            printk(KERN_INFO "singleDiffIDWithSHA length: %ld\n", strlen(singleDiffIDWithSHA));
            retRes = 403;
            break;
        }
        printk(KERN_INFO "singleDiffIDWithSHA: %s\n", singleDiffIDWithSHA);
        printk(KERN_INFO "singleDiffIDWithSHA length: %ld\n", strlen(singleDiffIDWithSHA));

        chainID = getChainIDFromDiffID(singleDiffIDWithSHA, lastChainID);
        if (chainID == NULL)
        {
            printk(KERN_INFO "getChainIDFromDiff ID failed\n");
            retRes = 403;
            break;
        }

        if (lastChainID != NULL)
        {
            printk(KERN_INFO "lastChainID: %s\n", lastChainID);
            kfree(lastChainID);
            lastChainID = NULL;
        }
        lastChainID = kmalloc(88, GFP_KERNEL);
        if (lastChainID == NULL)
        {
            printk("lastChainID kmalloc filed");
            if (chainID != NULL)
            {
                kfree(chainID);
                chainID = NULL;
            }
            retRes = 403;
            break;
        }
        memset(lastChainID, 0, 88);
        memmove(lastChainID, chainID, strlen(chainID));
        printk(KERN_INFO "chainIDString: %s\n", chainID);

        LayerKey = getLayerKeyFromchainID(chainID);
        if (LayerKey == NULL)
        {
            printk(KERN_INFO "LayerKey is NULL");
            retRes = 403;
            if (chainID != NULL)
            {
                kfree(chainID);
                chainID = NULL;
            }
            break;
        }
        printk(KERN_INFO "[LayerKey]%s\n", LayerKey);

        //执行打包文件夹命令
        tarResult = execTarCmd(LayerKey, singleDiffIDWithSHA, ".second");
        printk(KERN_DEBUG "THe result of execTarCmd call_usermodehelper is %d\n", tarResult);

        //执行计算sha256命令
        sha256Result = execSha256Cmd(singleDiffIDWithSHA, ".second");
        printk(KERN_DEBUG "THe result of execSha256Cmd call_usermodehelper is %d\n", sha256Result);

        //比较两次sha256值是否相同
        verifySha256sumResult = verifySha256sum(singleDiffIDWithSHA, allSha256String);
        printk(KERN_DEBUG "THe result of verifySha256sumResult is %d\n", sha256Result);
        if (verifySha256sumResult < 0)
        {
            // TODO：二次校验失败进行后续处理--写入日志
            //  write_to_log(singleDiffIDWithSHA);
            if (LayerKey != NULL)
            {
                kfree(LayerKey);
                LayerKey = NULL;
            }
            if (chainID != NULL)
            {
                kfree(chainID);
                chainID = NULL;
            }
            if (allSha256String != NULL)
            {
                kfree(allSha256String);
                allSha256String = NULL;
            }
            retRes = 404;
            break;
        }

        if (LayerKey != NULL)
        {
            kfree(LayerKey);
            LayerKey = NULL;
        }
        if (chainID != NULL)
        {
            kfree(chainID);
            chainID = NULL;
        }
        printk("[one layer over]==========================================[one layer over]\n");

        //拷贝下一个diffIDWithSHA字符串
        singleDiffIDWithSHA = strsep(&configJsonAndImageIDKernel, delimComma);
    }
    if (lastChainID != NULL)
    {
        kfree(lastChainID);
        lastChainID = NULL;
    }
    if (allSha256String != NULL)
    {
        kfree(allSha256String);
        allSha256String = NULL;
    }

    printk("[kernel function over]==========================================[kernel function over]\n");

    return retRes;
}

static int get_symbol(void)
{
    _container_or_image_create = (fp_container_or_image_create)__symbol_get("container_or_image_create");
    _send_confile_to_soc = (fp_send_confile_to_soc)__symbol_get("send_confile_to_soc");
    _get_soc_confile = (fp_get_soc_confile)__symbol_get("get_soc_confile");
    _send_log_to_soc = (fp_send_log_to_soc)__symbol_get("send_log_to_soc");
    _get_soc_confile_len = (fp_get_soc_confile_len)__symbol_get("get_soc_confile_len");
    _container_or_image_delete = (fp_container_or_image_delete)__symbol_get("container_or_image_delete");

    if (_container_or_image_create == NULL || _send_confile_to_soc == NULL || _get_soc_confile == NULL ||
        _send_log_to_soc == NULL || _get_soc_confile_len == NULL || _container_or_image_delete == NULL)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

static void put_symbol(void)
{
    if (_container_or_image_create != NULL)
        __symbol_put("container_or_image_create");

    if (_send_confile_to_soc != NULL)
        __symbol_put("send_confile_to_soc");

    if (_get_soc_confile != NULL)
        __symbol_put("get_soc_confile");

    if (_send_log_to_soc != NULL)
        __symbol_put("send_log_to_soc");

    if (_get_soc_confile_len != NULL)
        __symbol_put("get_soc_confile_len");

    if (_container_or_image_delete != NULL)
        __symbol_put("container_or_image_delete");
}

static int srtm_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "srtm_open()\n");
    // cd_data *customdevice_data = container_of(inode->i_cdev, cd_data, cdev);
    return 0;
}

static int srtm_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "srtm_release()\n");
    // cd_data *customdevice_data = container_of(inode->i_cdev, cd_data, cdev);
    return 0;
}

static long srtm_ioctl(struct file *file,
                       unsigned int cmd,
                       unsigned long arg)
{
    //将diffIDListAndImageID拷贝到内核空间
    diffIDListAndImageIDStruct *DiffIdPtrAndImageID = NULL;
    int copy_from_user_ret = 0;
    char *configJsonAndImageID = NULL;
    char *configJsonAndImageIDForFree = NULL;
    int lenConfigJsonAndImageID = 0;
    int srtm_pull_image_ret = 0;
    int srtm_run_container_ret = 0;
    int ret = 0;

    switch (cmd)
    {
    case 0xFFFA:
        //拉取镜像
        //从用户态复制结构体数据
        DiffIdPtrAndImageID = kmalloc(sizeof(diffIDListAndImageIDStruct), GFP_KERNEL);
        if (DiffIdPtrAndImageID == NULL)
        {
            printk("DiffIdPtrAndImageID kmalloc filed");
            return -ENOMEM;
        }
        copy_from_user_ret = copy_from_user(DiffIdPtrAndImageID, (void *)arg, sizeof(diffIDListAndImageIDStruct));
        //返回0代表成功
        //从用户态复制结构体数据完成
        lenConfigJsonAndImageID = DiffIdPtrAndImageID->lenConfigJsonAndImageID;

        printk(KERN_INFO "lenConfigJsonAndImageID :%d", lenConfigJsonAndImageID);

        //从用户态获取config json字符串
        configJsonAndImageID = kmalloc(sizeof(char) * (lenConfigJsonAndImageID + 1), GFP_KERNEL);
        copy_from_user_ret = copy_from_user(configJsonAndImageID, DiffIdPtrAndImageID->configJsonAndImageID, sizeof(char) * lenConfigJsonAndImageID);
        configJsonAndImageID[lenConfigJsonAndImageID] = '\0';
        configJsonAndImageIDForFree = configJsonAndImageID;
        printk(KERN_INFO "configJsonAndImageID :%s", configJsonAndImageID);

        //执行初次度量
        srtm_pull_image_ret = srtm_pull_image(configJsonAndImageID, lenConfigJsonAndImageID);

        printk(KERN_INFO "0xFFFA copy_from_user_ret: %d, lenConfigJsonAndImageID: %d, srtm_pull_ image_ret:%d\n",
               copy_from_user_ret,
               lenConfigJsonAndImageID, srtm_pull_image_ret);
        if (configJsonAndImageIDForFree != NULL)
        {
            kfree(configJsonAndImageIDForFree);
            configJsonAndImageIDForFree = NULL;
        }
        if (DiffIdPtrAndImageID != NULL)
        {
            kfree(DiffIdPtrAndImageID);
            DiffIdPtrAndImageID = NULL;
        }
        ret = srtm_pull_image_ret;
        break;
    case 0xFFFB:
        //运行容器
        DiffIdPtrAndImageID = kmalloc(sizeof(diffIDListAndImageIDStruct), GFP_KERNEL);
        if (NULL == DiffIdPtrAndImageID)
        {
            printk("DiffIdPtrAndImageID kmalloc filed");
            return -ENOMEM;
        }
        copy_from_user_ret = copy_from_user(DiffIdPtrAndImageID, (void *)arg, sizeof(diffIDListAndImageIDStruct));
        //返回0代表成功
        //从用户态复制结构体数据完成
        lenConfigJsonAndImageID = DiffIdPtrAndImageID->lenConfigJsonAndImageID;

        configJsonAndImageID = kmalloc(sizeof(char) * (lenConfigJsonAndImageID + 1), GFP_KERNEL);
        copy_from_user_ret = copy_from_user(configJsonAndImageID, DiffIdPtrAndImageID->configJsonAndImageID, sizeof(char) * lenConfigJsonAndImageID);
        configJsonAndImageID[lenConfigJsonAndImageID] = '\0';
        configJsonAndImageIDForFree = configJsonAndImageID;
        srtm_run_container_ret = srtm_run_container(configJsonAndImageID, lenConfigJsonAndImageID);

        printk(KERN_INFO "0xFFFB copy_from_user_ret: %d, DiffIDListLength: %d, srtm_run_container_ret:%d\n",
               copy_from_user_ret,
               lenConfigJsonAndImageID, srtm_run_container_ret);
        if (configJsonAndImageIDForFree != NULL)
        {
            kfree(configJsonAndImageIDForFree);
            configJsonAndImageIDForFree = NULL;
        }
        if (DiffIdPtrAndImageID != NULL)
        {
            kfree(DiffIdPtrAndImageID);
            DiffIdPtrAndImageID = NULL;
        }
        ret = srtm_run_container_ret;

        break;
    default:
        printk(KERN_INFO "cmd not current\n");
        break;
    }
    return ret;
}

const struct file_operations srtm_fops = {
    .owner = THIS_MODULE,
    .open = srtm_open,           //打开设备时调用
    .release = srtm_release,     //关闭设备时调用
    .unlocked_ioctl = srtm_ioctl //执行ioctl时调用
};

static int __init srtm_init(void)
{
    int ret;
    struct device *dev_ret;

    // Create character device region
    ret = alloc_chrdev_region(&dev, 0, 1, "srtm");
    if (ret < 0)
    {
        return ret;
    }

    // Create class for sysfs
    cl = class_create(THIS_MODULE, "chardrv");
    if (IS_ERR(cl))
    {
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(cl);
    }

    // Create device for sysfs
    dev_ret = device_create(cl, NULL, dev, NULL, "srtm");
    if (IS_ERR(dev_ret))
    {
        class_destroy(cl);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(dev_ret);
    }

    // Create character device
    cdev_init(&srtm_data.cdev, &srtm_fops);
    ret = cdev_add(&srtm_data.cdev, dev, 1);
    if (ret < 0)
    {
        device_destroy(cl, dev);
        class_destroy(cl);
        unregister_chrdev_region(dev, 1);
        return ret;
    }

    if (get_symbol() == -1)
    {
        printk("[TEST_DEMO]get_symbol() failed.\n");
        put_symbol();
        ret = -1;
        return ret;
    }
    printk(KERN_INFO "srtm device initialized \n");
    return 0;
}

static void __exit srtm_exit(void)
{
    printk(KERN_INFO "srtm device unreigstered \n");
    put_symbol();
    device_destroy(cl, dev);
    class_destroy(cl);
    cdev_del(&srtm_data.cdev);
    unregister_chrdev_region(dev, 1);
}

module_init(srtm_init);
module_exit(srtm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yakai li <liyakai@iie.ac.cn>");
MODULE_DESCRIPTION("srtm driver char device");
