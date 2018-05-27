#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define ARP_NAME "arp"
#define ARP_SNAME "arp"

#define ARP_MAX_MINORS 1
#define ARP_PAGE_SIZE 4096
#define ARP_CAPACITY 1

#define ARP_IOCTL_MAGIC 'c'
#define ARP_IOCTL_SET_CHANNEL _IOW(ARP_IOCTL_MAGIC, 0, int)
#define ARP_IOCTL_SET_PAGE_SIZE _IOW(ARP_IOCTL_MAGIC, 1, int)
#define ARP_IOCTL_SET_CAPACITY _IOW(ARP_IOCTL_MAGIC, 2, int)
#define ARP_IOCTL_SET_TIMEOUT _IOW(ARP_IOCTL_MAGIC, 3, int)
#define ARP_IOCTL_SET_USERDATA _IOR(ARP_IOCTL_MAGIC, 4, int)
#define ARP_IOCTL_GET_USERDATA _IOR(ARP_IOCTL_MAGIC, 5, int)
#define ARP_IOCTL_NR_MAX 5

#ifndef MIN
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#endif
#ifndef MAX
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#endif

#define IS_OWNER(f) (f->f_mode & FMODE_WRITE)

static int arp_open(struct inode *inode, struct file *filp);
static int arp_release(struct inode *inode, struct file *filp);
static ssize_t arp_read(struct file *filp, char *buf, size_t count, loff_t *f_pos);
static ssize_t arp_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos);
static unsigned int arp_poll(struct file *filp, struct poll_table_struct *wait);
static long arp_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static char *arp_devnode(struct device *dev, umode_t *mode);

typedef struct arp_buffer
{
  int channel;
  int page_size;
  int capacity;
  int userdata;

  atomic_t count; /* Ref count */

  uint8_t *data;
  int pos;
  atomic_t seq;

  spinlock_t lock;

  wait_queue_head_t wait;

  struct arp_buffer *prev;
  struct arp_buffer *next;
} arp_buffer;

typedef struct
{
  int seq;

  int channel;
  long timeout;
  arp_buffer *buffer;
} arp_file;

static int arp_set_channel(arp_file *arpf, int channel);
static int arp_set_page_size(arp_file *arpf, int page_size);
static int arp_set_capacity(arp_file *arpf, int capacity);
static int arp_set_timeout(arp_file *arpf, int timeout);
static int arp_set_userdata(arp_file *arpf, int userdata);
static int arp_get_userdata(arp_file *arpf, int *userdata);
static int arp_prepare(arp_file *arpf, int mode);

static arp_buffer *arp_buffer_open(int channel);
static int arp_buffer_alloc_data(arp_buffer *buf);
static int arp_buffer_free(arp_buffer *buf);
static int arp_buffer_count(void);

static dev_t arp_dev;
static struct cdev arp_cdev;
static struct class arp_class = {
    .owner = THIS_MODULE,
    .name = ARP_NAME,
    .devnode = arp_devnode};
static struct file_operations arp_fops = {
    .open = arp_open,
    .release = arp_release,
    .read = arp_read,
    .write = arp_write,
    .poll = arp_poll,
    .unlocked_ioctl = arp_unlocked_ioctl};

static arp_buffer *arp_head = NULL, *arp_tail = NULL;
static spinlock_t arp_lock;

int arp_open(struct inode *inode, struct file *filp)
{
  arp_file *arpf = filp->private_data = kzalloc(sizeof(arp_file), GFP_KERNEL);
  if (arpf == NULL)
  {
    return -ENOMEM;
  }

  arpf->timeout = MAX_SCHEDULE_TIMEOUT;

  return 0;
}

int arp_release(struct inode *inode, struct file *filp)
{
  arp_file *arpf = (arp_file *)filp->private_data;
  if (arpf != NULL)
  {
    arp_buffer *buf = arpf->buffer;
    if (buf != NULL)
    {
      arp_buffer_free(buf);
    }

    kfree(arpf);
    filp->private_data = NULL;
  }

  return 0;
}

ssize_t arp_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
  ssize_t ret = -EAGAIN;

  arp_file *arpf = (arp_file *)filp->private_data;
  arp_buffer *arpb = NULL;

  if (!access_ok(VERIFY_WRITE, buf, count))
    return -EFAULT;

  ret = arp_prepare(arpf, FMODE_READ);
  if (ret < 0)
    return ret;

  arpb = arpf->buffer;

  /* Reads data newly arrived only, returns `EAGAIN` otherwise. */
  if (atomic_read(&arpb->seq) <= arpf->seq)
  {
    ret = wait_event_interruptible_timeout(arpb->wait,
                                           atomic_read(&arpb->seq) > arpf->seq,
                                           arpf->timeout);
    if (ret == 0)
    {
      return -EAGAIN;
    }
    else if (ret < 0)
    {
      return ret;
    }
  }

  if (count < arpb->page_size)
    return -EINVAL;

  spin_lock(&arpb->lock);
  {
    int seq = atomic_read(&arpb->seq);
    int fseq = MAX(seq - arpb->capacity, 0);
    int off = 0, index = 0;

    /* Reads newest data for the first time, then reads sequence */
    if (arpf->seq == 0)
    {
      arpf->seq = seq - 1;
    }
    /* Skips droped data */
    if (arpf->seq < fseq)
    {
      arpf->seq = fseq;
    }
    /* Calculates data index and copy to user */
    off = seq - arpf->seq;
    index = (arpb->pos + arpb->capacity - off) % arpb->capacity;
    ret = copy_to_user(buf, arpb->data + index * arpb->page_size, count);

    if (ret == 0)
    {
      arpf->seq++;

      ret = arpb->page_size;
    }
    else
    {
      ret = -EFAULT;
    }
  }
  spin_unlock(&arpb->lock);

  return ret;
}

ssize_t arp_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
  arp_file *arpf = (arp_file *)filp->private_data;
  arp_buffer *arpb = NULL;
  int ret = -1;

  if (!access_ok(VERIFY_READ, buf, count))
    return -EFAULT;

  ret = arp_prepare(arpf, FMODE_WRITE);
  if (ret < 0)
    return ret;

  arpb = arpf->buffer;
  if (count != arpb->page_size)
    return -EINVAL;

  spin_lock(&arpb->lock);

  ret = copy_from_user(arpb->data + arpb->pos * arpb->page_size, buf, count);
  if (ret == 0)
  {
    arpb->pos = (arpb->pos + 1) % arpb->capacity;
    atomic_inc(&arpb->seq);
  }

  spin_unlock(&arpb->lock);

  if (ret == 0)
    wake_up_interruptible_all(&arpb->wait);

  return ret == 0 ? count : -EFAULT;
}

unsigned int arp_poll(struct file *filp, struct poll_table_struct *wait)
{
  unsigned int mask = 0;

  arp_file *arpf = filp->private_data;
  arp_buffer *arpb = NULL;
  int ret = -1;

  ret = arp_prepare(arpf, filp->f_mode & (FMODE_WRITE | FMODE_READ));
  if (ret < 0)
    return POLLERR;

  arpb = arpf->buffer;
  poll_wait(filp, &arpb->wait, wait);
  mask |= POLLOUT | POLLWRNORM;
  if (arpf->seq < atomic_read(&arpb->seq))
    mask |= POLLIN | POLLRDNORM;

  return mask;
}

long arp_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  int ret = 0;

  int val = 0;
  arp_file *arpf = (arp_file *)filp->private_data;

  /* Tests command */
  if (_IOC_TYPE(cmd) != ARP_IOCTL_MAGIC || _IOC_NR(cmd) > ARP_IOCTL_NR_MAX)
    return -EINVAL;

  /* Checks command access permission */
  if (_IOC_DIR(cmd) & _IOC_READ)
    ret = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
  else if (_IOC_DIR(cmd) & _IOC_WRITE)
    ret = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
  if (ret)
    return -EFAULT;

  switch (cmd)
  {
  case ARP_IOCTL_SET_CHANNEL:
    if (get_user(val, (int __user *)arg))
    {
      ret = -EFAULT;
      break;
    }
    ret = arp_set_channel(arpf, val);
    break;

  case ARP_IOCTL_SET_PAGE_SIZE:
    if (!IS_OWNER(filp))
    {
      ret = -EINVAL;
      break;
    }
    if (get_user(val, (int __user *)arg))
    {
      ret = -EFAULT;
      break;
    }
    ret = arp_set_page_size(arpf, val);
    break;

  case ARP_IOCTL_SET_CAPACITY:
    if (!IS_OWNER(filp))
    {
      ret = -EINVAL;
      break;
    }
    if (get_user(val, (int __user *)arg))
    {
      ret = -EFAULT;
      break;
    }
    ret = arp_set_capacity(arpf, val);
    break;

  case ARP_IOCTL_SET_TIMEOUT:
    if (IS_OWNER(filp))
    {
      ret = -EINVAL;
      break;
    }
    if (get_user(val, (int __user *)arg))
    {
      ret = -EFAULT;
      break;
    }
    ret = arp_set_timeout(arpf, val);
    break;

  case ARP_IOCTL_SET_USERDATA:
    if (!IS_OWNER(filp))
    {
      ret = -EINVAL;
      break;
    }
    if (get_user(val, (int __user *)arg))
    {
      ret = -EFAULT;
      break;
    }
    ret = arp_set_userdata(arpf, val);
    break;

  case ARP_IOCTL_GET_USERDATA:
    if (IS_OWNER(filp))
    {
      ret = -EINVAL;
      break;
    }
    if (arp_get_userdata(arpf, &val))
    {
      ret = -ENOENT;
      break;
    }
    if (put_user(val, (int __user *)arg))
    {
      ret = -EFAULT;
      break;
    }
    break;

  default:
    printk(KERN_WARNING "%s: Unknown ioctl command (%d)\n", ARP_SNAME, cmd);
    ret = -EINVAL;
    break;
  }

  return ret;
}

char *arp_devnode(struct device *dev, umode_t *mode)
{
  if (mode != NULL)
  {
    *mode = 0666;
  }

  return kasprintf(GFP_KERNEL, "%s", dev_name(dev));
}

int arp_set_channel(arp_file *arpf, int channel)
{
  if (arpf->buffer != NULL)
    return -EINVAL;

  arpf->channel = channel;

  return 0;
}

int arp_set_page_size(arp_file *arpf, int page_size)
{
  if (page_size < 1)
    return -EINVAL;

  if (arpf->buffer == NULL)
  {
    arpf->buffer = arp_buffer_open(arpf->channel);
    if (arpf->buffer == NULL)
      return -ENOMEM;
  }

  if (arpf->buffer->data != NULL && page_size != arpf->buffer->page_size)
    return -EINVAL;

  arpf->buffer->page_size = page_size;

  return 0;
}

int arp_set_capacity(arp_file *arpf, int capacity)
{
  if (capacity < 1)
    return -EINVAL;

  if (arpf->buffer == NULL)
  {
    arpf->buffer = arp_buffer_open(arpf->channel);
    if (arpf->buffer == NULL)
      return -ENOMEM;
  }

  if (arpf->buffer->data != NULL && capacity != arpf->buffer->capacity)
    return -EINVAL;

  arpf->buffer->capacity = capacity;

  return 0;
}

int arp_set_timeout(arp_file *arpf, int timeout)
{
  arpf->timeout = timeout * HZ / 1000;

  return 0;
}

int arp_set_userdata(arp_file *arpf, int userdata)
{
  if (arpf->buffer == NULL)
  {
    arpf->buffer = arp_buffer_open(arpf->channel);
    if (arpf->buffer == NULL)
      return -ENOMEM;
  }

  arpf->buffer->userdata = userdata;

  return 0;
}

int arp_get_userdata(arp_file *arpf, int *userdata)
{
  if (arpf->buffer == NULL)
  {
    arpf->buffer = arp_buffer_open(arpf->channel);
    if (arpf->buffer == NULL)
      return -ENOMEM;
  }

  *userdata = arpf->buffer->userdata;

  return 0;
}

int arp_prepare(arp_file *arpf, int mode)
{
  if (arpf->buffer == NULL)
    arpf->buffer = arp_buffer_open(arpf->channel);
  if (arpf->buffer == NULL)
    return -ENOMEM;

  return mode & FMODE_WRITE ? arp_buffer_alloc_data(arpf->buffer) : 0;
}

arp_buffer *arp_buffer_open(int channel)
{
  arp_buffer *buf = NULL;

  spin_lock(&arp_lock);

  for (buf = arp_head; buf != NULL; buf = buf->next)
  {
    if (buf->channel == channel)
    {
      break;
    }
  }

  if (buf == NULL)
  {
    buf = kzalloc(sizeof(arp_buffer), GFP_KERNEL);
    if (buf != NULL)
    {
      buf->channel = channel;
      buf->page_size = ARP_PAGE_SIZE;
      buf->capacity = ARP_CAPACITY;
      buf->prev = arp_tail;
      if (arp_tail != NULL)
      {
        arp_tail->next = buf;
        arp_tail = arp_tail->next;
      }
      else
      {
        arp_head = arp_tail = buf;
      }

      spin_lock_init(&buf->lock);
      init_waitqueue_head(&buf->wait);

      printk(KERN_INFO "%s: open buffer. count=%d\n", ARP_SNAME, arp_buffer_count());
    }
  }

  spin_unlock(&arp_lock);

  if (buf != NULL)
  {
    atomic_inc(&buf->count);
  }

  return buf;
}

int arp_buffer_alloc_data(arp_buffer *buf)
{
  spin_lock(&buf->lock);

  if (buf->data == NULL)
    buf->data = kmalloc(buf->page_size * buf->capacity, GFP_KERNEL);

  spin_unlock(&buf->lock);

  return buf->data != NULL ? 0 : -ENOMEM;
}

int arp_buffer_free(arp_buffer *buf)
{
  if (atomic_dec_and_test(&buf->count))
  {
    spin_lock(&arp_lock);

    if (buf == arp_head)
    {
      arp_head = buf->next;
    }
    if (buf == arp_tail)
    {
      arp_tail = buf->prev;
    }
    if (buf->prev != NULL)
    {
      buf->prev->next = buf->next;
    }
    if (buf->next != NULL)
    {
      buf->next->prev = buf->prev;
    }

    kfree(buf->data);
    kfree(buf);

    printk(KERN_INFO "%s: free buffer. count=%d\n", ARP_SNAME, arp_buffer_count());

    spin_unlock(&arp_lock);
  }

  return 0;
}

int arp_buffer_count(void)
{
  int count = 0;
  arp_buffer *buf = arp_head;
  for (; buf != NULL; buf = buf->next, count++)
    ;

  return count;
}

static int __init arp_init(void)
{
  int rc = -1;

  rc = alloc_chrdev_region(&arp_dev, 0, ARP_MAX_MINORS, ARP_NAME);
  if (rc < 0)
  {
    printk(KERN_ERR "%s: can't obtain major number.\n", ARP_SNAME);

    return rc;
  }

  cdev_init(&arp_cdev, &arp_fops);
  rc = cdev_add(&arp_cdev, arp_dev, ARP_MAX_MINORS);
  if (rc < 0)
  {
    printk(KERN_ERR "%s: can't add cdev.\n", ARP_SNAME);
    goto error_region;
  }

  rc = class_register(&arp_class);
  if (rc < 0)
  {
    printk(KERN_ERR "%s: can't register class '%s'.\n", ARP_SNAME, ARP_NAME);
    cdev_del(&arp_cdev);
    goto error_region;
  }
  device_create(&arp_class, NULL, arp_dev, NULL, ARP_SNAME);

  spin_lock_init(&arp_lock);

  printk(KERN_INFO "%s: inited.\n", ARP_SNAME);

  return 0;

error_region:
  unregister_chrdev_region(arp_dev, ARP_MAX_MINORS);

  return rc;
}

static void __exit arp_exit(void)
{
  device_destroy(&arp_class, arp_dev);
  class_unregister(&arp_class);
  cdev_del(&arp_cdev);
  unregister_chrdev_region(arp_dev, ARP_MAX_MINORS);

  printk(KERN_INFO "%s: exited.\n", ARP_SNAME);
}

module_init(arp_init);
module_exit(arp_exit);
MODULE_LICENSE("Dual BSD/GPL");
