#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>	 // for vfs_*
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

/*
问题思考：
1、kallsyms_lookup_name获取到的系统调用表位置不正确，但为什么能正确运行？
2、直接读取用户空间地址崩溃的根本原因是什么？
3、为什么写到同一地址的函数能够分别执行呢：335 336 地址都为0x00000000a2f75fc4
4、对指针的%d代表什么？
*/

#define __NR_pull_images 335   /* 系统调用号335 */
#define __NR_run_container 336 /* 系统调用号336 */
unsigned long *sys_call_table;

unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);

int orig_cr0; /* 用来存储cr0寄存器原来的值 */
unsigned long *sys_call_table = 0;
static int (*pull_images_saved)(void);	 /*定义一个函数指针，用来保存一个系统调用*/
static int (*run_container_saved)(void); /*定义一个函数指针，用来保存一个系统调用*/

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
	kfree(sdesc);
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

/*
 * 设置cr0寄存器的第17位为0
 */
unsigned int clear_and_return_cr0(void)
{
	unsigned int cr0 = 0;
	unsigned int ret;
	/* 前者用在32位系统。后者用在64位系统，本系统64位 */
	// asm volatile ("movl %%cr0, %%eax" : "=a"(cr0));
	asm volatile("movq %%cr0, %%rax"
				 : "=a"(cr0)); /* 将cr0寄存器的值移动到rax寄存器中，同时输出到cr0变量中 */
	ret = cr0;
	cr0 &= 0xfffeffff; /* 将cr0变量值中的第17位清0，将修改后的值写入cr0寄存器 */
	// asm volatile ("movl %%eax, %%cr0" :: "a"(cr0));
	asm volatile("movq %%rax, %%cr0" ::"a"(cr0)); /* 读取cr0的值到rax寄存器，再将rax寄存器的值放入cr0中 */
	return ret;
}

/* 读取val的值到rax寄存器，再将rax寄存器的值放入cr0中 */
void setback_cr0(unsigned int val)
{

	// asm volatile ("movl %%eax, %%cr0" :: "a"(val));
	asm volatile("movq %%rax, %%cr0" ::"a"(val));
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

//执行压缩文件夹命令
int execTarCmd(char *readLayerDirPathBuffer, char *singleDiffIDWithSHA, const char *firstOrSecond)
{
	// /bin/bash -c "tar -czvf /tmp/c73aea831b3d279f1d68267f5d6a6828f1d0f71b81a73c9cd5a31c493314ec8a.tar.gz /var/lib/docker/overlay2/c73aea831b3d279f1d68267f5d6a6828f1d0f71b81a73c9cd5a31c493314ec8a/diff"
	unsigned char *tarCommandPrefix = "tar -cf /srtm/tar/";
	unsigned char *tarCommandMiddle = ".tar --absolute-names /var/lib/docker/overlay2/";
	unsigned char *tarCommandSuffix = "/diff";
	int tarResult = 0;

	unsigned char *tarCommand = NULL;

	tarCommand = kmalloc(1024, GFP_KERNEL);
	if (tarCommand == NULL)
	{
		printk(KERN_ALERT "[execTarCmd] ERROR: kmalloc\n");
		return -1;
	}
	memset(tarCommand, 0, 1024);

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

	sha256Command = kmalloc(1024, GFP_KERNEL);
	if (sha256Command == NULL)
	{
		printk(KERN_ALERT "[execSha256Cmd] ERROR: kmalloc\n");
		return -1;
	}
	memset(sha256Command, 0, 1024);

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
	unsigned char *diffIDWithLastChainIDMiddle = " ";
	unsigned char *singleDiffIDWithSHACopy = NULL;
	singleDiffIDWithSHACopy = kmalloc(strlen(singleDiffIDWithSHA) + 1, GFP_KERNEL);
	if (singleDiffIDWithSHACopy == NULL)
	{
		printk(KERN_ALERT "[getChainIDFromDiffID] ERROR: singleDiffIDWithSHACopy kmalloc\n");
		return NULL;
	}
	memset(singleDiffIDWithSHACopy, 0, strlen(singleDiffIDWithSHA) + 1);
	memmove(singleDiffIDWithSHACopy, singleDiffIDWithSHA, strlen(singleDiffIDWithSHA));
	// char *diffIDWithLastChainIDSuffix = "/diff";
	if (lastChainID == NULL)
	{
		return singleDiffIDWithSHACopy + 7;
	}
	else
	{
		//申请空间
		diffIDWithLastChainID = kmalloc(1024, GFP_KERNEL);
		if (diffIDWithLastChainID == NULL)
		{
			printk(KERN_ALERT "[getChainIDFromDiffID] ERROR: kmalloc\n");
			return NULL;
		}
		memset(diffIDWithLastChainID, 0, 1024);
		chainIDHex = kmalloc(1024, GFP_KERNEL);
		if (chainIDHex == NULL)
		{
			printk(KERN_ALERT "[getChainIDFromDiffID] ERROR: kmalloc\n");
			return NULL;
		}
		memset(chainIDHex, 0, 1024);
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

		chainIDString = hex2char(chainIDHex, strlen(chainIDHex));
		// printk(KERN_INFO "chainIDString: %s\n", chainIDString);

		if (diffIDWithLastChainID)
		{
			kfree(diffIDWithLastChainID);
			diffIDWithLastChainID = NULL;
		}
		if (chainIDHex)
		{
			kfree(chainIDHex);
			chainIDHex = NULL;
		}
		return chainIDString;
	}
}

//通过chainID获取LayerKey
char *getLayerKeyFromchainID(char *chainID)
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
	layerdbDir = kmalloc(1024, GFP_KERNEL);
	if (layerdbDir == NULL)
	{
		printk(KERN_ALERT "[getLayerKeyFromchainID] ERROR: kmalloc\n");
		return NULL;
	}
	memset(layerdbDir, 0, 1024);

	// printk(KERN_INFO "layerDeep: %d\n", layerDeep);

	// printk("%s\n", singleDiffIDWithSHA);
	// singleDiffID = chainID + 7;
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
		printk(KERN_ALERT "[getLayerKeyFromchainID] ERROR: kmalloc\n");
		return NULL;
	}
	readLayerDirPathBytes = file_read(layerdbDir, readLayerDirPathBuffer, readLayerDirPathSize, 0);
	if (readLayerDirPathBytes < 0)
	{
		printk(KERN_INFO "readLayerDirPathBytes length < 0\n");
		if (readLayerDirPathBuffer)
		{
			kfree(readLayerDirPathBuffer);
			readLayerDirPathBuffer = NULL;
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
	if (layerdbDir)
	{
		kfree(layerdbDir);
		layerdbDir = NULL;
	}
	return readLayerDirPathBuffer;
}

//验证两次sha256结果是否一致
int verifySha256sum(char *singleDiffIDWithSHA)
{
	//定义读第一次sha256使用的变量
	unsigned char *firstSha256FilePathPrefix = "/srtm/sha256/";
	unsigned char *firstSha256FilePathSuffix = ".sha256.first";
	unsigned char *readFirstSha256FileBuffer = NULL;
	unsigned char *firstSha256FilePath = NULL;
	const size_t readfirstSha256FileSize = 256;
	ssize_t readfirstSha256FileBytes;
	//定义读第二次sha256使用的变量
	unsigned char *secondSha256FilePathPrefix = "/srtm/sha256/";
	unsigned char *secondSha256FilePathSuffix = ".sha256.first";
	unsigned char *readSecondSha256FileBuffer = NULL;
	unsigned char *secondSha256FilePath = NULL;
	const size_t readsecondSha256FileSize = 256;
	ssize_t readsecondSha256FileBytes;
	//定义比较使用的变量
	int compareResult = 0;
	int retResult = -1;

	//申请空间
	firstSha256FilePath = kmalloc(1024, GFP_KERNEL);
	if (firstSha256FilePath == NULL)
	{
		printk(KERN_ALERT "[verifySha256sum] ERROR: firstSha256FilePath kmalloc\n");
		return -1;
	}
	memset(firstSha256FilePath, 0, 1024);
	secondSha256FilePath = kmalloc(1024, GFP_KERNEL);
	if (secondSha256FilePath == NULL)
	{
		printk(KERN_ALERT "[verifySha256sum] ERROR: secondSha256FilePath kmalloc\n");
		return -1;
	}
	memset(secondSha256FilePath, 0, 1024);
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
		printk(KERN_ALERT "[verifySha256sum] ERROR: readFirstSha256FileBuffer kmalloc\n");
		return -1;
	}
	readfirstSha256FileBytes = file_read(firstSha256FilePath, readFirstSha256FileBuffer, readfirstSha256FileSize, 0);
	if (readfirstSha256FileBytes < 0)
	{
		printk(KERN_INFO "readfirstSha256FileBytes length < 0\n");
		if (readFirstSha256FileBuffer)
		{
			kfree(readFirstSha256FileBuffer);
			readFirstSha256FileBuffer = NULL;
		}
		return -1;
	}
	else
	{
		//可以正常读了
		// add a zero terminator
		// printk(KERN_INFO "addZeroLen %ld\n", readfirstSha256FileBytes % (readfirstSha256FileSize - 1));
		// printk(KERN_INFO "bytes read %d\n", (unsigned int)readfirstSha256FileBytes);
		readFirstSha256FileBuffer[readfirstSha256FileBytes % (readfirstSha256FileSize - 1)] = '\0';
		printk(KERN_INFO "[verifySha256sum]read string: %s\n", readFirstSha256FileBuffer);
	}
	//读文件完了

	//拼接第二次sha256路径路径
	strcat(secondSha256FilePath, secondSha256FilePathPrefix);
	strcat(secondSha256FilePath, singleDiffIDWithSHA + 7);
	strcat(secondSha256FilePath, secondSha256FilePathSuffix);
	printk("secondSha256FilePath Path: %s\n", secondSha256FilePath);
	printk("secondSha256FilePath Path length: %ld\n", strlen(secondSha256FilePath));
	//读取第一次sha256文件
	readSecondSha256FileBuffer = kmalloc(readsecondSha256FileSize, GFP_KERNEL);
	if (readSecondSha256FileBuffer == NULL)
	{
		printk(KERN_ALERT "[verifySha256sum] ERROR: readSecondSha256FileBuffer kmalloc\n");
		return -1;
	}
	readsecondSha256FileBytes = file_read(secondSha256FilePath, readSecondSha256FileBuffer, readsecondSha256FileSize, 0);
	if (readsecondSha256FileBytes < 0)
	{
		printk(KERN_INFO "readsecondSha256FileBytes length < 0\n");
		if (readSecondSha256FileBuffer)
		{
			kfree(readSecondSha256FileBuffer);
			readSecondSha256FileBuffer = NULL;
		}
		return -1;
	}
	else
	{
		//可以正常读了
		// add a zero terminator
		// printk(KERN_INFO "addZeroLen %ld\n", readfirstSha256FileBytes % (readfirstSha256FileSize - 1));
		// printk(KERN_INFO "bytes read %d\n", (unsigned int)readfirstSha256FileBytes);
		readSecondSha256FileBuffer[readsecondSha256FileBytes % (readsecondSha256FileSize - 1)] = '\0';
		printk(KERN_INFO "[verifySha256sum] second read string: %s\n", readSecondSha256FileBuffer);
	}
	//读文件完了

	compareResult = strncmp(readFirstSha256FileBuffer, readSecondSha256FileBuffer, 64);
	printk(KERN_INFO "[verifySha256sum] compareResult: %d\n", compareResult);
	if (compareResult == 0)
	{
		retResult = 1;
	}
	else
	{
		retResult = -2;
	}

	//结束 释放变量
	if (firstSha256FilePath)
	{
		kfree(firstSha256FilePath);
		firstSha256FilePath = NULL;
	}
	if (readFirstSha256FileBuffer)
	{
		kfree(readFirstSha256FileBuffer);
		readFirstSha256FileBuffer = NULL;
	}
	if (secondSha256FilePath)
	{
		kfree(secondSha256FilePath);
		secondSha256FilePath = NULL;
	}
	if (readSecondSha256FileBuffer)
	{
		kfree(readSecondSha256FileBuffer);
		readSecondSha256FileBuffer = NULL;
	}
	return retResult;
}

/* 添加自己的系统调用函数 */
asmlinkage int srtm_pull_image(const struct pt_regs *regs)
{
	// char **uintptrConfigJSON, int *uintptrConfigJSONLen
	// di、si、dx、r10、r8、r9
	int retTmp = 789;
	//字符串长度相关字段
	int *uintPtrConfigJSONLenPointKernel = NULL;
	int __user *uintPtrConfigJSONLenUser = NULL;
	int copy_from_user_ret = 0;
	//字符串相关字段
	char __user **UintptrConfigJSONUser = NULL;
	char **UintptrConfigJSONKernel = NULL;
	char *ConfigJSONKernel = NULL;
	//字符串分割
	// char *strsepResult = NULL;
	unsigned char *singleDiffIDWithSHA = NULL;
	char *const delimComma = ",";
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

	// int i = 0;
	printk("srtm_pull_image syscall is successful!\n");

	//拷贝configJSON长度
	uintPtrConfigJSONLenPointKernel = kmalloc(sizeof(int), GFP_KERNEL);
	if (NULL == uintPtrConfigJSONLenPointKernel)
	{
		printk("uintPtrConfigJSONLenPointKernel kmalloc filed");
		return -ENOMEM;
	}
	uintPtrConfigJSONLenUser = (int *)regs->si;
	copy_from_user_ret = copy_from_user(uintPtrConfigJSONLenPointKernel, uintPtrConfigJSONLenUser, sizeof(int));
	printk("uintPtrConfigJSONLenPointKernel *data: %d", *uintPtrConfigJSONLenPointKernel);

	printk("[configJSONLen over]------------------------------------[configJSONLen over]\n");

	//拷贝configJSON字符串
	//第一阶段
	UintptrConfigJSONKernel = kmalloc(sizeof(char *), GFP_KERNEL);
	if (NULL == UintptrConfigJSONKernel)
	{
		printk("UintptrConfigJSONKernel kmalloc filed");
		return -ENOMEM;
	}
	UintptrConfigJSONUser = (char **)regs->di;
	// printk("UintptrConfigJSONUser access %ld: ", access_ok(UintptrConfigJSONUser, sizeof(char **)));
	copy_from_user_ret = copy_from_user(UintptrConfigJSONKernel, UintptrConfigJSONUser, sizeof(char *));

	// //第二阶段
	ConfigJSONKernel = kmalloc(sizeof(char) * (*uintPtrConfigJSONLenPointKernel + 1), GFP_KERNEL);
	if (NULL == ConfigJSONKernel)
	{
		printk("ConfigJSONKernel kmalloc filed");
		return -ENOMEM;
	}
	// ConfigJSONUser = *UintptrConfigJSONKernel;
	// printk("ConfigJSONUser access %ld: ", access_ok(*UintptrConfigJSONKernel, sizeof(char) * (*uintPtrConfigJSONLenPointKernel)));
	copy_from_user_ret = copy_from_user(ConfigJSONKernel, *UintptrConfigJSONKernel, sizeof(char) * (*uintPtrConfigJSONLenPointKernel));
	ConfigJSONKernel[*uintPtrConfigJSONLenPointKernel] = '\0';
	printk("ConfigJSONKernel *s: %s", ConfigJSONKernel);

	// attaction:strsep函数会修改ConfigJSONKernel字符串数据
	singleDiffIDWithSHA = strsep(&ConfigJSONKernel, delimComma);
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

		if (lastChainID)
		{
			printk(KERN_INFO "lastChainID: %s\n", lastChainID);
			kfree(lastChainID);
			lastChainID = NULL;
		}
		lastChainID = kmalloc(1024, GFP_KERNEL);
		if (NULL == lastChainID)
		{
			printk("lastChainID kmalloc filed");
			break;
		}
		memset(lastChainID, 0, 1024);
		memmove(lastChainID, chainID, strlen(chainID));
		printk(KERN_INFO "chainIDString: %s\n", chainID);

		LayerKey = getLayerKeyFromchainID(chainID);
		if (LayerKey == NULL)
		{
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

		// LayerKey 置空
		if (LayerKey)
		{
			kfree(LayerKey);
			LayerKey = NULL;
		}
		if (chainID)
		{
			kfree(chainID);
			chainID = NULL;
		}
		printk("[one layer over]==========================================[one layer over]\n");

		//拷贝下一个diffIDWithSHA字符串
		singleDiffIDWithSHA = strsep(&ConfigJSONKernel, delimComma);
	}
	if (lastChainID)
	{
		kfree(lastChainID);
		lastChainID = NULL;
	}

	printk("copy_from_user_ret= %d\n", copy_from_user_ret);
	printk("[kernel function over]==========================================[kernel function over]\n");

	if (uintPtrConfigJSONLenPointKernel)
	{
		kfree(uintPtrConfigJSONLenPointKernel);
		uintPtrConfigJSONLenPointKernel = NULL;
	}
	if (UintptrConfigJSONKernel)
	{
		kfree(UintptrConfigJSONKernel);
		UintptrConfigJSONKernel = NULL;
	}
	if (ConfigJSONKernel)
	{
		kfree(ConfigJSONKernel);
		ConfigJSONKernel = NULL;
	}
	return retTmp;
}

asmlinkage static int srtm_run_container(const struct pt_regs *regs)
{
	// char **uintptrConfigJSON, int *uintptrConfigJSONLen
	// di、si、dx、r10、r8、r9
	// int retTmp = 456;
	//字符串长度相关字段
	int *uintPtrConfigJSONLenPointKernel = NULL;
	int __user *uintPtrConfigJSONLenUser = NULL;
	int copy_from_user_ret = 0;
	//字符串相关字段
	char __user **UintptrConfigJSONUser = NULL;
	char **UintptrConfigJSONKernel = NULL;
	char *ConfigJSONKernel = NULL;
	//字符串分割
	// char *strsepResult = NULL;
	unsigned char *singleDiffIDWithSHA = NULL;
	char *const delimComma = ",";
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
	//验证两次哈希 相关字段
	int verifySha256sumResult = 0;
	//返回结果
	int retRes = 666;

	// int i = 0;
	printk("srtm_run_container is successful!\n");

	//拷贝configJSON长度
	uintPtrConfigJSONLenPointKernel = kmalloc(sizeof(int), GFP_KERNEL);
	if (NULL == uintPtrConfigJSONLenPointKernel)
	{
		printk("uintPtrConfigJSONLenPointKernel kmalloc filed");
		return -ENOMEM;
	}
	uintPtrConfigJSONLenUser = (int *)regs->si;
	copy_from_user_ret = copy_from_user(uintPtrConfigJSONLenPointKernel, uintPtrConfigJSONLenUser, sizeof(int));
	printk("uintPtrConfigJSONLenPointKernel *data: %d", *uintPtrConfigJSONLenPointKernel);

	printk("[configJSONLen over]------------------------------------[configJSONLen over]\n");

	//拷贝configJSON字符串
	//第一阶段
	UintptrConfigJSONKernel = kmalloc(sizeof(char *), GFP_KERNEL);
	if (NULL == UintptrConfigJSONKernel)
	{
		printk("UintptrConfigJSONKernel kmalloc filed");
		return -ENOMEM;
	}
	UintptrConfigJSONUser = (char **)regs->di;
	// printk("UintptrConfigJSONUser access %ld: ", access_ok(UintptrConfigJSONUser, sizeof(char **)));
	copy_from_user_ret = copy_from_user(UintptrConfigJSONKernel, UintptrConfigJSONUser, sizeof(char *));

	// //第二阶段
	ConfigJSONKernel = kmalloc(sizeof(char) * (*uintPtrConfigJSONLenPointKernel + 1), GFP_KERNEL);
	if (NULL == ConfigJSONKernel)
	{
		printk("ConfigJSONKernel kmalloc filed");
		return -ENOMEM;
	}
	// ConfigJSONUser = *UintptrConfigJSONKernel;
	// printk("ConfigJSONUser access %ld: ", access_ok(*UintptrConfigJSONKernel, sizeof(char) * (*uintPtrConfigJSONLenPointKernel)));
	copy_from_user_ret = copy_from_user(ConfigJSONKernel, *UintptrConfigJSONKernel, sizeof(char) * (*uintPtrConfigJSONLenPointKernel));
	ConfigJSONKernel[*uintPtrConfigJSONLenPointKernel] = '\0';
	printk("ConfigJSONKernel *s: %s", ConfigJSONKernel);

	// attaction:strsep函数会修改ConfigJSONKernel字符串数据
	singleDiffIDWithSHA = strsep(&ConfigJSONKernel, delimComma);
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

		if (lastChainID)
		{
			printk(KERN_INFO "lastChainID: %s\n", lastChainID);
			kfree(lastChainID);
			lastChainID = NULL;
		}
		lastChainID = kmalloc(1024, GFP_KERNEL);
		if (NULL == lastChainID)
		{
			printk("lastChainID kmalloc filed");
			retRes = 403;
			break;
		}
		memset(lastChainID, 0, 1024);
		memmove(lastChainID, chainID, strlen(chainID));
		printk(KERN_INFO "chainIDString: %s\n", chainID);

		LayerKey = getLayerKeyFromchainID(chainID);
		if (LayerKey == NULL)
		{
			printk(KERN_INFO "LayerKey is NULL");
			retRes = 403;
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
		verifySha256sumResult = verifySha256sum(singleDiffIDWithSHA);
		printk(KERN_DEBUG "THe result of verifySha256sumResult is %d\n", sha256Result);
		if (verifySha256sumResult < 0)
		{
			if (LayerKey)
			{
				kfree(LayerKey);
				LayerKey = NULL;
			}
			if (chainID)
			{
				kfree(chainID);
				chainID = NULL;
			}
			retRes = 404;
			break;
		}

		if (LayerKey)
		{
			kfree(LayerKey);
			LayerKey = NULL;
		}
		if (chainID)
		{
			kfree(chainID);
			chainID = NULL;
		}
		printk("[one layer over]==========================================[one layer over]\n");

		//拷贝下一个diffIDWithSHA字符串
		singleDiffIDWithSHA = strsep(&ConfigJSONKernel, delimComma);
	}
	if (lastChainID)
	{
		kfree(lastChainID);
		lastChainID = NULL;
	}

	printk("copy_from_user_ret= %d\n", copy_from_user_ret);
	printk("[kernel function over]==========================================[kernel function over]\n");

	if (uintPtrConfigJSONLenPointKernel)
	{
		kfree(uintPtrConfigJSONLenPointKernel);
		uintPtrConfigJSONLenPointKernel = NULL;
	}
	if (UintptrConfigJSONKernel)
	{
		kfree(UintptrConfigJSONKernel);
		UintptrConfigJSONKernel = NULL;
	}
	if (ConfigJSONKernel)
	{
		kfree(ConfigJSONKernel);
		ConfigJSONKernel = NULL;
	}
	return retRes;
}

/*模块的初始化函数，模块的入口函数，加载模块*/
static int __init init_addsyscall(void)
{
	printk("SRTM syscall is starting...\n");
	sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table"); /* 获取系统调用服务首地址 */

	printk("sys_call_table: 0x%p\n", sys_call_table);
	printk("__NR_pull_images sys_call_table: 0x%p\n", (int (*)(void))(sys_call_table[__NR_pull_images]));
	printk("__NR_run_container sys_call_table: 0x%p\n", (int (*)(void))(sys_call_table[__NR_run_container]));

	pull_images_saved = (int (*)(void))(sys_call_table[__NR_pull_images]);	   /* 保存原始系统调用 */
	run_container_saved = (int (*)(void))(sys_call_table[__NR_run_container]); /* 保存原始系统调用 */

	orig_cr0 = clear_and_return_cr0(); /* 设置cr0可更改 */

	sys_call_table[__NR_pull_images] = (unsigned long)&srtm_pull_image;		 /* 更改原始的系统调用服务地址 */
	sys_call_table[__NR_run_container] = (unsigned long)&srtm_run_container; /* 更改原始的系统调用服务地址 */

	setback_cr0(orig_cr0); /* 设置为原始的只读cr0 */
	return 0;
}

/*出口函数，卸载模块*/
static void __exit exit_addsyscall(void)
{
	orig_cr0 = clear_and_return_cr0(); /* 设置cr0中对sys_call_table的更改权限 */ /* 设置cr0可更改 */
	sys_call_table[__NR_pull_images] = (unsigned long)pull_images_saved;		 /* 恢复原有的中断向量表中的函数指针的值 */
	sys_call_table[__NR_run_container] = (unsigned long)run_container_saved;	 /* 恢复原有的中断向量表中的函数指针的值 */
	setback_cr0(orig_cr0);														 /* 恢复原有的cr0的值 */
	printk("SRTM syscall exit....\n");
}

module_init(init_addsyscall);
module_exit(exit_addsyscall);
MODULE_LICENSE("GPL");