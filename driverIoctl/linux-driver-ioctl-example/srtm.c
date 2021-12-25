#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

struct _srtm_data
{
	struct cdev cdev;
	uint8_t data;
};
typedef struct _srtm_data cd_data;

typedef struct
{
	char *ConfigJSON;
	int lenConfigJSON;
} diffIDListAndLengthStruct;

diffIDListAndLengthStruct diffIDListAndLength;

static cd_data srtm_data;
static struct class *cl;
static dev_t dev;

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
	//将diffIDListAndLength拷贝到内核空间
	diffIDListAndLengthStruct *DiffIdPtrAndLength = NULL;
	int copy_from_user_ret = 0;
	char *configJSON = NULL;
	int lenConfigJSON = 0;

	switch (cmd)
	{
	case 0xFFFA:

		DiffIdPtrAndLength = kmalloc(sizeof(diffIDListAndLengthStruct), GFP_KERNEL);
		if (NULL == DiffIdPtrAndLength)
		{
			printk("DiffIdPtrAndLength kmalloc filed");
			return -ENOMEM;
		}
		copy_from_user_ret = copy_from_user(DiffIdPtrAndLength, (void *)arg, sizeof(diffIDListAndLengthStruct));
		//返回0代表成功
		//从用户态复制结构体数据完成
		lenConfigJSON = DiffIdPtrAndLength->lenConfigJSON;

		configJSON = kmalloc(sizeof(char) * (lenConfigJSON + 1), GFP_KERNEL);
		copy_from_user_ret = copy_from_user(configJSON, DiffIdPtrAndLength->ConfigJSON, sizeof(char) * lenConfigJSON);
		configJSON[lenConfigJSON] = '\0';

		printk(KERN_INFO "0xFFFA copy_from_user_ret: %d, DiffIDListLength: %d, configJSONPoint:%s\n",
			   copy_from_user_ret,
			   lenConfigJSON, configJSON);
		break;
	case 0xFFFB:
		printk(KERN_INFO "0xFFFB device: %d, %s\n",
			   task_pid_nr(current),
			   current->comm);
		break;
	default:
		printk(KERN_INFO "cmd not current\n");
		break;
	}
	return 0;
}

const struct file_operations srtm_fops = {
	.owner = THIS_MODULE,
	.open = srtm_open,			 //打开设备时调用
	.release = srtm_release,	 //关闭设备时调用
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
	printk(KERN_INFO "srtm device initialized \n");
	return 0;
}

static void __exit srtm_exit(void)
{
	printk(KERN_INFO "srtm device unreigstered \n");
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
