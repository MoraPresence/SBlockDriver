#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/random.h>

//-----------------------------------------for-driver-------------------------------------------

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MORA & OGREBATEL");
MODULE_DESCRIPTION("DEV EXAMPLE");
MODULE_VERSION("1.0");

#define DEVICE_NAME "DZ_four"
#define EXAMPLE_MSG "~~(0)~~\n"
#define MSG_BUFFER_LEN 1024
#define bool int
#define ENCRYPT 1
#define DECRYPT 0
#define FALSE 0
#define TRUE 1

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
static int file_read(struct file *, unsigned long long, unsigned char *, unsigned int);
static int major_num;
static int device_open_count = 0;
static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;

static struct file_operations file_ops = {
        .read = device_read,
        .write = device_write,
        .open = device_open,
        .release = device_release
};

//------------------------------functions---------------------------------------------------

static int scan_block(unsigned char* block, unsigned block_size, struct file* file);
static void print_block(unsigned char* block, unsigned block_size, struct file* o_file);
static void s_reconstruct(unsigned char* block, unsigned block_size, char ** s_table);
static void work_with(unsigned char* block, unsigned block_size, struct file* file, struct file* o_file, char ** s_table);
static int fileWrite(struct file* file, unsigned long long offset, unsigned char*
data, unsigned int size);
int fileRead(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size);
static char *shuffleSymbols(void);
static void randomTable(char**, unsigned);
static void uploadReconstructorToDisk(char**, size_t, struct file*);
struct file *kernel_fopen(const char *path, int flags, int rights);
//-----------------------------------crypto-------------------------------------------------

#define BYTES_IN_CHAR 8

static char symbols[16] = {
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};

static unsigned long long input_offset = 0;
static unsigned long long output_offset = 0;

static int scan_block(unsigned char* block, unsigned block_size, struct file* file){
    int ret = 0;
    memset(block, ' ', block_size/8);
    ret = fileRead(file, input_offset, block, block_size/8);
    input_offset = input_offset + block_size/8;
    return ret;
}
static void print_block(unsigned char* block, unsigned block_size, struct file* o_file){
    fileWrite(o_file, output_offset, block, block_size/8);
    output_offset = output_offset + block_size/8;
}

bool table_is_right (char** s_table, unsigned block_size){
    unsigned current_table, current_element;
    bool *check_array;

    check_array = kmalloc(16 * sizeof(bool), 0);

    for (current_table = 0; current_table < block_size/4; ++current_table) {
        memset(check_array, false, 16 * sizeof(bool));
            for (current_element = 0; current_element < 16; ++current_element){
                if (s_table[current_table][current_element] < 16) {
                    if (check_array[s_table[current_table][current_element]] == false) {
                        check_array[s_table[current_table][current_element]] = true;
                    } else {
                        kfree(check_array);
                        return false;
                    }
                } else {
                    kfree(check_array);
                    return false;
                }
        }
    }
    kfree(check_array);
    return true;
}

void fill_s_reconstructor(char ** s_table, int block_size)
{
    randomTable(s_table, block_size);
}

static void s_reconstruct(unsigned char* block, unsigned block_size, char ** s_table)
{
    int s_number = 0; //номер s-блока
    char tmp = 0;
    char rez = 0;
    int char_number;
    for (char_number = 0; char_number < block_size / BYTES_IN_CHAR; ++char_number){

        tmp = block[char_number]  & 0xF; //vhodnaya tetrada
        rez = s_table[s_number][tmp];
        s_number = (s_number + 1);

        tmp = (block[char_number] >> 4) & 0xF;

        rez = rez | (s_table[s_number][tmp] << 4);
        s_number = (s_number + 1);

        block[char_number] = rez;
    }
}

static char ** create_s_reconstructor (int block_size){
    int i;
    int j;
    //--
    char ** s_reconstructor_;
    s_reconstructor_ = kmalloc((block_size/4) * sizeof(char*), 0);
    for (i = 0; i < block_size/4; ++i) {
        s_reconstructor_[i] = kmalloc(16, 0);
        memset(s_reconstructor_[i], 0, 16);
    }
    printk(KERN_INFO "create s reconstructor \n");
    //--

    //--------zapolnenie-s_tablitci---------------------
    fill_s_reconstructor(s_reconstructor_, block_size);
    //--------------------------------------------------
	
    printk(KERN_INFO "end creation \n");

    return s_reconstructor_;
}

static char ** create_s_deconstructor (char ** s_table, int block_size){
    int i;
    int j;
    char current_element;
    //--
    printk(KERN_INFO "create s deconstructor \n");
    char ** s_deconstructor = NULL;
    s_deconstructor = kmalloc((block_size/4)* sizeof(char*), 0);
    for (i = 0; i < block_size/4; ++i) {
        s_deconstructor[i] = kmalloc(16, 0);
        memset(s_deconstructor[i], 0, 16);
    }

    //--
    for (i = 0; i < block_size/4; ++i) {
        current_element = 0;
        while (current_element < 16){
            for (j = 0; j < 16; ++j) {
                if (s_table[i][j] == current_element) {
                    s_deconstructor[i][current_element] = j;
                    ++current_element;
                    break;
                }
            }
        }
    }
    printk(KERN_INFO "end creation \n");

    return s_deconstructor;
}

static void uploadReconstructorToDisk(char **s_reconstructor, size_t block_size, struct file *o_file){
	int i;
	unsigned o_offset = 0;
    for(i = 0; i < block_size/4; ++i){
	  fileWrite(o_file, o_offset, s_reconstructor[i], 16);
	  o_offset = o_offset + 16;
	 }
}

static char ** uploadReconstructorFromDisk(size_t block_size, struct file *file){
    int i;
    char ** s_reconstructor = NULL;

    s_reconstructor = kmalloc((block_size/4)* sizeof(char*), 0);
    for (i = 0; i < block_size/4; ++i) {
        s_reconstructor[i] = kmalloc(16, 0);
        memset(s_reconstructor[i], 0, 16);
    }

    unsigned offset = 0;
    for(i = 0; i < block_size/4; ++i){
        fileRead(file, offset, s_reconstructor[i], 16); // dodelat proverky (ret)
        offset = offset + 16;
    }
    return s_reconstructor;
}
//
//static int scan_block(unsigned char* block, unsigned block_size, struct file* file){
//    int ret = 0;
//    memset(block, ' ', block_size/8);
//    ret = fileRead(file, input_offset, block, MSG_BUFFER_LEN);
//    input_offset = input_offset + block_size/8;
//    return ret;
//}
//
static void work_with(unsigned char* block, unsigned block_size,
        struct file* file, struct file* o_file, char ** s_table){
    while(scan_block(block, block_size, file)){
        s_reconstruct(block, block_size, s_table);
        print_block(block, block_size, o_file);
    }
}


//-------------------------------------crypto-end---------------------------------------------

//-------------------------------------work-with-files--------------------------------------

//функция для открsxытия файла
//path - путь
//flags - флаги (не используется, можно передать 0)
//mode - режим
struct file *kernel_fopen(const char *path, int flags, int rights){
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

//функция для записи данных в файл
//file - файловая переменная
//offset - смещение относительно 0
//data - массив байтов, которые надо записать в файл
//size - размер массива байтов
int fileWrite(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size){
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}
int fileRead(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size){
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

//функция для закрытия файла
//flip - sфайловая переменная
void kernel_fclose(struct file* flip) {
    filp_close(flip, NULL);
}

//-------------------------------------work-with-files-end----------------------------------

//-------------------------------------work-with-input--------------------------------------

int kernel_atoi(char* str){
    int res = 0;
    int i = 0;
    for(; str[i] != '\0'; ++i)
        res = res * 10 + str[i] - '0';
    return res;
}

static char *shuffleSymbols() {
    char *array = kmalloc(sizeof(char) * 16, 0);
    size_t i = 0;
    unsigned randNumb  = 0;
    for (; i < 16; ++i) {
        array[i] = symbols[i];
    }
    size_t n = 16;
    if (n > 1) {
        for (i = 0; i < n - 1; i++) {
            randNumb = 0;
            get_random_bytes(&randNumb, sizeof(randNumb));
            size_t j =  randNumb%16;
            char t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
    return array;
}

static void randomTable(char** Ss_reconstructor, unsigned size) {
    unsigned columnSize = size / 4;
    if (columnSize == 0 || (size % 4) != 0) return NULL;
    unsigned i = 0;
    for (; i < columnSize; ++i) {
        Ss_reconstructor[i] = shuffleSymbols();
    }
}

bool work_with_args(bool* type_work, char* input_path[], char* output_path[], char* key_path[], unsigned* block_size){
    bool ret = 0;
    int iter = 0;
    int j = 0;
    int space = 0;
    char* first_param;
    for (; (iter < MSG_BUFFER_LEN) && (msg_buffer[iter] != ' ') && (msg_buffer[iter] != '\0'); ++iter);

    first_param = kmalloc(iter, 0);
    for(; j < iter; ++j) first_param[j] = msg_buffer[j];


    if (!strcmp(first_param, "encrypt"))
        *type_work = ENCRYPT;
    else if (!strcmp(first_param, "decrypt"))
        *type_work = DECRYPT;
    else {
        printk(KERN_INFO "unknown first parameter \n");
        return FALSE;
    }

    printk(KERN_INFO "first parameter %s\n", first_param);

    space = iter;
    ++iter;
    for (; (iter < MSG_BUFFER_LEN) && (msg_buffer[iter] != ' ') && (msg_buffer[iter] != '\0'); ++iter);
    *input_path = kmalloc((iter - (space + 1)), 0);
    printk(KERN_INFO "second parameter size %d\n", iter - (space + 1));
    for(j = 0; j < (iter - (space + 1)); ++j)
        (*input_path)[j] = msg_buffer[j + space + 1];
    //encrypt [7]/tmp/output.txt [23]/tmp/input.txt 64
    printk(KERN_INFO "second parameter %s\n", *input_path);


    space = iter;
    ++iter;
    for (; (iter < MSG_BUFFER_LEN) && (msg_buffer[iter] != ' ') && (msg_buffer[iter] != '\0'); ++iter);
    *output_path = kmalloc((iter - (space + 1)), 0);
    printk(KERN_INFO "third parameter size %d\n", iter - (space + 1));
    for(j = 0; j < (iter - (space + 1)); ++j)
        (*output_path)[j] = msg_buffer[j + space + 1];
    //encrypt [7]/tmp/output.txt [23]/tmp/input.txt 64
    printk(KERN_INFO "third parameter %s\n", *output_path);


    space = iter;
    ++iter;
    for (; (iter < MSG_BUFFER_LEN) && (msg_buffer[iter] != ' ') && (msg_buffer[iter] != '\0'); ++iter);
    *key_path = kmalloc((iter - (space + 1)), 0);
    printk(KERN_INFO "fourth parameter size %d\n", iter - (space + 1));
    for(j = 0; j < (iter - (space + 1)); ++j)
        (*key_path)[j] = msg_buffer[j + space + 1];
    //encrypt [7]/tmp/output.txt [23]/tmp/input.txt 64
    printk(KERN_INFO "fourth parameter %s\n", *key_path);

    char * char_block_size;

    space = iter;
    ++iter;
    for (; (iter < MSG_BUFFER_LEN) && (msg_buffer[iter] != ' ') && (msg_buffer[iter] != '\0'); ++iter); // \n
    char_block_size = kmalloc((iter - (space + 2)), 0);
    printk(KERN_INFO "fifth parameter size %d\n", iter - (space + 2));
    for(j = 0; j < (iter - (space + 2)); ++j)
        char_block_size[j] = msg_buffer[j + space + 1];
    //encrypt [7]/tmp/output.txt [23]/tmp/input.txt 64

    *block_size = kernel_atoi(char_block_size);
    printk(KERN_INFO "fifth parameter %d\n", *block_size);

    if (!((*block_size == 8) || (*block_size == 16) || (*block_size == 32) || (*block_size == 64)
          || (*block_size == 128) || (*block_size == 256)))
    {
        kfree(first_param);
        kfree(char_block_size);
        printk(KERN_INFO "bad fifth parameter\n");
        return FALSE;
    }

    kfree(first_param);
    kfree(char_block_size);
    return TRUE;



}
//-------------------------------------work-with-input-end----------------------------------

//-----------------------------------driver-code----------------------------------------------

static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {
    int bytes_read = 0;

    if (*msg_ptr == 0) {
        return 0;
    }

    while (len && *msg_ptr) {
        put_user(*(msg_ptr++), buffer++);
        len--;
        bytes_read++;
    }
    return bytes_read;
}
static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset) {
    memset(msg_buffer, 0, sizeof(msg_buffer));
    int i = 0;
    for (i = 0; i < len && i < MSG_BUFFER_LEN; i++)
        get_user(msg_buffer[i], buffer + i);
    msg_ptr = msg_buffer;

    char ** s_table = NULL;
    char ** s_reconstructor = NULL;
    unsigned block_size;// = 64;
    bool type_work;// = ENCRYPT;
    char *input_path = NULL;// = "/tmp/input.txt";
    char *output_path = NULL;// = "/tmp/output.txt";
    char *key_path = NULL;

    if (!work_with_args(&type_work, &input_path, &output_path, &key_path, &block_size)) {
        if(!input_path)
            kfree(input_path);
        if(!output_path)
            kfree(output_path);
        if(!key_path)
            kfree(key_path);
        return i;
    }


    unsigned char* block = kmalloc(block_size/8, 0); //64/8

    struct file *file;
    if (!(file = kernel_fopen(input_path, O_RDONLY, 0))){
        printk(KERN_INFO "err file\n");
        return i;
    }

    struct file *o_file;
    if (!(o_file = kernel_fopen(output_path, O_WRONLY, 0))){
        printk(KERN_INFO "err o_file\n");
        kernel_fclose(file);
        return i;
    }

    struct file *key_file;
    if (type_work == ENCRYPT) {
        if (!(key_file = kernel_fopen(key_path, O_WRONLY, 0))){
            printk(KERN_INFO "err key file\n");
            kernel_fclose(o_file);
            kernel_fclose(file);
            return i;
        }
        s_table = create_s_reconstructor(block_size);
        work_with(block, block_size, file, o_file, s_table);
        uploadReconstructorToDisk(s_table, block_size, key_file);
        kfree(s_table);
    }
    else {
        if (!(key_file = kernel_fopen(key_path, O_RDONLY, 0))){
            printk(KERN_INFO "err key file\n");
            kernel_fclose(o_file);
            kernel_fclose(file);
            return i;
        }
        s_reconstructor = uploadReconstructorFromDisk(block_size, key_file);
        if(table_is_right(s_reconstructor, block_size)) {
            s_table = create_s_deconstructor(s_reconstructor, block_size);
            work_with(block, block_size, file, o_file, s_table);
            kfree(s_table);
            kfree(s_reconstructor);
        }
        else kfree(s_reconstructor);
    }
    kfree(input_path);
    kfree(output_path);
    kfree(block);

    kernel_fclose(file);
    kernel_fclose(o_file);
    kernel_fclose(key_file);

    return i;
}

static int device_open(struct inode *inode, struct file *file) {
    if (device_open_count) {
        return -EBUSY;
    }
    device_open_count++;
    try_module_get(THIS_MODULE);
    return 0;
}
static int device_release(struct inode *inode, struct file *file) {
    device_open_count--;
    module_put(THIS_MODULE);
    return 0;
}

static int __init kernel_driver_init(void) {
    strncpy(msg_buffer, EXAMPLE_MSG, MSG_BUFFER_LEN);
    msg_ptr = msg_buffer;
    major_num = register_chrdev(0, DEVICE_NAME, &file_ops);
    if (major_num < 0) {
        printk(KERN_ALERT "Could not register device: %d\n", major_num);
        return major_num;
    } else {
        printk(KERN_INFO "driver module loaded with device major number %d\n", major_num);
        return 0;
    }
}
static void __exit kernel_driver_exit(void) {
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(kernel_driver_init);
module_exit(kernel_driver_exit);

//-----------------------------------driver-code-end---------------------------------------
