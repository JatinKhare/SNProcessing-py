# Lab1 | 461S


In order to run all the 75 testcases, one needs to mplement the following features:

1. [Modify the threads/threads.c + threads/threads.h](thread.h)
2. [Modify userprog/process.c + userprog/process.h (the process_execute(), start_process(), load(), setup_stack(), process_wait(), and process_exit() functions)](process.c)
3. [Modify the userprog/syscall.c + userprog/syscall.h](syscall.c)

### Steps

## 1. thread.h

### Modifying the thread structure

Added the following parameters to the thread struct:

``` c 
    struct thread *parent_thread;
    struct file *fd[25];
    int fd_index;
    struct list children_list;
    struct list_elem child_s_elem;
    int child_tid;
    int child_status_exit;
    struct semaphore process_semaphore; 
```

### thread.c

(a) **init_thread()**

Initialized the new variables in the structure inside the initi_thread()

``` c
    list_init(&t->children_list);
    sema_init(&t->process_semaphore, 0);
    t->fd[0] = 0;
    t->fd[1] = 1;
    t->fd[2] = 2;
    t->fd_index = 3;
```
(b) **thread_create()**
This is called by the process_execute() and will put the child in the parents' list

```c
    //Remember the child thread is not yet up and running and is just being set up now, 
    //hence this is still the parent thread running.
    t->parent_thread = thread_current();
    list_push_back(&thread_current()->children_list, &t->child_s_elem);
    thread_current()->child_status_exit = tid;
```

### process.c

(a) **process_execute()**

This will call the thread_create and return the child pid
(tokenizing the string before passing it to the thread_create()
``` c
    //*****[Project 2 addition]                         //tokenizing the string
    char *token0, *save_ptr;
    token0 = strtok_r(fn_copy, " ", &save_ptr);
    //*****

    tid = thread_create(token0, PRI_DEFAULT, start_process, save_ptr);

    //*****[Project 2 addition]
    struct thread *curr_thread = thread_current();
    sema_down(&thread_current()->process_semaphore);    //parent's semaphore down, codeword: loading_the_process
    //*****
    .
    .
    .
    //*****[Project 2 addition]
    return curr_thread->child_status_exit;
```

(b) **load()**

This is called by the start_process() to setup to load the executable and setup the stack

```
    //*****[Project 2 addition]
    const char *f_name = thread_name();
    char *file_name_temp;
    file_name_temp = palloc_get_page(0);
    if (file_name_temp == NULL) {
        return TID_ERROR;
    }    
    strlcpy(file_name_temp, f_name, PGSIZE);
    char *save_ptr;
    int index = 0;
    f_name = strtok_r(file_name_temp, " \t", &save_ptr);
    //*****
    
    /* Open executable file. */
    file = filesys_open(f_name);
    
```
(c) **setup_stack**

_string parsing_

The following code was written in order to split the input string into two strings. 

``` bash
$ echo hello world  --->  'echo' and 'hello world'

```

``` c
    char *file_name_temp;
    file_name_temp = palloc_get_page(0);
    if (file_name_temp == NULL) {
        return TID_ERROR;
    }
    strlcpy(file_name_temp, file_name, PGSIZE);
    char* token0, *save_ptr;
    int index = 0;
    token0 = strtok_r(file_name_temp, " \t", &save_ptr);
```

_setup_stack()_

The input string is tokenized and used to populate the stack in the following way, where we modified the setup_stack parameters to:
```c
    //*****[Project 2 addition] the argument passing
    if (!setup_stack(esp, file_name)) {
        goto done;
    }
``` 
``` c
            *esp = PHYS_BASE;
            char **tokens[100];
            char **esp_values[100];
            char* token, *save_ptr;
            int argc = 1;
            tokens[0] = f_name;
            //tokenize the given string
            while((token = strtok_r(file_name, " \t", &save_ptr))){
                tokens[argc] = token;
                argc++;
                file_name = NULL;
            }   
            //put it in the stack, while saving each argument's pointer
            for(int i = 0;i<argc; i++){
                int len = strlen(tokens[i])+1;
                *esp -= len;
                strlcpy(*esp, tokens[i], len);
                esp_values[i] = *esp;
            }

            char* esp_char_prt;
            uint32_t padding_esp = (int*)*esp;
            int padding = (padding_esp) % 4;

            int additional_padding = (padding_esp - padding) & 0xF;
            padding = padding + additional_padding;         //add this many zeros

            esp_char_prt = (char *)*esp;
            while(padding){
                esp_char_prt--;
                *esp_char_prt = 0;
                padding--;
            }

            //start putting the saved pointers to the arguments
            *esp = esp_char_prt;
            uint32_t *esp_int = (uint32_t*)*esp;
            for(int i=0 ; i<argc; i++){
                esp_int--;
                *esp_int = esp_values[argc-1-i];
            }

            //save the argv, argc, and return value = 0, and point the esp to it
            uint32_t *argv = esp_int;
            esp_int--;
            *esp_int = argv;
            esp_int--;
            *esp_int = argc;
            esp_int--;
            *esp_int = 0;
            *esp = esp_int;
            
``` 
the stack is populated in the following manner-

For example. the input is **args-multiple some arguments for you!**, the stack should be populated as-

| Address  | 67 | 45 | 23 | 01 |
|---|---|---|---|---|
| 0xbfff_ffb4  | 00 | 00 | 00 | 00 |
| 0xbfff_ffb8  | 05 | 00 | 00 | 00 |
| 0xbfff_ffbc  | c0 | ff | ff | bf |
| 0xbfff_ffc0  | da | ff | ff | bf |
| 0xbfff_ffc4  | e8 | ff | ff | bf |
| 0xbfff_ffc8  | ed | ff | ff | bf |
| 0xbfff_ffcc  | fb | ff | ff | bf |
| 0xbfff_ffd0  | bf | ff | ff | bf |
| 0xbfff_ffd4  | 00 | 00 | 00 | 00 |
| 0xbfff_ffd8  | 0 | 00 | **a** | r |
| 0xbfff_ffdc  | g | s | - | m |
| 0xbfff_ffe0  | u | l | t | i |
| 0xbfff_ffe4  | p | l | e | 00 |
| 0xbfff_ffe8  | **s** | o | m | e |
| 0xbfff_ffec  | 00 | **a** | r | g |
| 0xbfff_fff0  | u | m | e | n |
| 0xbfff_fff4  | t | s | 0 | **f** |
| 0xbfff_fff8  | o | r | 0 | **y**|
| 0xbfff_fffc  | o | u | ! | \0 |

and the hexdump() gives us the following stack-

```bash
bfffffb0              00 00 00 00-05 00 00 00 c0 ff ff bf |    ............|
bfffffc0  da ff ff bf e8 ff ff bf-ed ff ff bf f7 ff ff bf |................|
bfffffd0  fb ff ff bf 00 00 00 00-00 00 61 72 67 73 2d 6d |..........args-m|
bfffffe0  75 6c 74 69 70 6c 65 00-73 6f 6d 65 00 61 72 67 |ultiple.some.arg|
bffffff0  75 6d 65 6e 74 73 00 66-6f 72 00 79 6f 75 21 00 |uments.for.you!.|
```
(d) **start_process**

This is called by thread_create() to load the executable and setup the stack. It calls the load() which in turn calls the setup_stack()

If the load is succesful:

``` c
    //*****[Project 2 addition]
    sema_up(&thread_current()->parent_thread->process_semaphore);       //parent's semaphore up, codeword: loading_the_process
    file_deny_write(filesys_open(thread_name()));
    //*****

```
(e) **process_wait()**

Given the child ID, traverse through the list and check if the parent has a child with the same ID

``` c
    //*****[Project 2 addition] 
    struct list_elem *le;
    struct thread *curr_thread = thread_current();
    struct thread *child = NULL;
    //Traversing through the list to find the child with the given IDs
    for (le = list_begin (&curr_thread->children_list); le != list_end(&curr_thread->children_list); le = list_next(le)){
        struct thread *tmp = list_entry (le, struct thread, child_s_elem);

        if (tmp->tid == child_tid){
            child = tmp;
            break;
        }
    }
    //If found, wait for it to be completed and signal you that its done.
    if(child!=NULL){
        sema_down(&curr_thread->process_semaphore);             //parent's semaphore up, codeword: wait_for_child_to_exit
        return curr_thread->child_status_exit;
    }
    //else return -1
    else
        return -1;
    //*****
```

(f) **process_exit()**

Remove yourself from the list and signal to the parent.

``` c
    //*****[Project 2 addition]
    if(cur->parent_thread != NULL){
        list_remove(&cur->child_s_elem);    
        sema_up(&cur->parent_thread->process_semaphore);        //parent's semaphore down, codeword: wait_for_child_to_exit
    }
    //*****
```

## 3. syscall.c

(a) **syscall_handler()**

``` c
    void *usp = f->esp;
    memory_check((uint32_t*)usp);
    int call_number = *(int *)usp;

    /*SYS_HALT,    Halt the operating system. 
    SYS_EXIT,      Terminate this process. 
    SYS_EXEC,      Start another process. 
    SYS_WAIT,      Wait for a child process to die. 
    SYS_CREATE,    Create a file. 
    SYS_REMOVE,    Delete a file. 
    SYS_OPEN,      Open a file. 
    SYS_FILESIZE,  Obtain a file's size. 
    SYS_READ,      Read from a file. 
    SYS_WRITE,     Write to a file. 
    SYS_SEEK,      Change position in a file. 
    SYS_TELL,      Report current position in a file.
    SYS_CLOSE,     Close a file. */

    switch(call_number){

        case 0: {         //SYS_HALT  void halt(void)
            sys_halt();
            break;
        }
        case 1: {         //SYS_EXIT  void exit(int status)
            memory_check((uint32_t*)usp + 1);
            sys_exit((*((int *)usp + 1)));
            break;
        }
        case 2: {         //SYS_EXEC  tid_t exec(const char* cmd_line)
            int return_val;
            return_val = sys_exec((char *)(*((int *)usp + 1)));
            f->eax = return_val;
            break;
        }
        case 3: {         //SYS_WAIT  int wait(tid_t pid)
            int return_val;
            return_val = sys_wait((*((int *)usp + 1)));
            f->eax = return_val;
            break;
        }
        case 4: {         //SYS_CREATE  bool create(const char* file, unsigned initial_size)
            bool return_val;
            return_val = sys_create((char *)(*((int *)usp + 1)), (*((unsigned *)usp + 2)));
            f->eax = return_val;
            break;
        }
        case 5: {         //SYS_REMOVE  bool remove(const char* file)
            bool return_val;
            return_val = sys_remove((char *)(*((int *)usp + 1)));
            f->eax = return_val;
            break;
        }
        case 6: {         //SYS_OPEN  int open(const char* file)
            int return_val;
            return_val = sys_open((char *)(*((int *)usp + 1)));
            f->eax = return_val;
            break;
        }
        case 7: {         //SYS_FILESIZE  int filesize(int fd)
            int return_val;
            return_val = sys_filesize((*((int *)usp + 1)));
            f->eax = return_val;
            break;
        }
        case 8: {         //SYS_READ  int read(int fd, void* buffer, unsigned size)
            int return_val;
            return_val = sys_read((*((int *)usp + 1)), (void *)(*((int *)usp + 2)), (*((unsigned *)usp + 3)));
            f->eax = return_val;
            break;
        }
        case 9: {         //SYS_WRITE  int write(int fd, const void* buffer, unsigned size)
            int return_val;
            return_val = return_val = sys_write((*((int *)usp + 1)), (void *)(*((int *)usp + 2)), (*((unsigned *)usp + 3)));
            f->eax = return_val;
            break;  
        }
        case 10: {        //SYS_SEEK  void seek(int fd, unsigned position)
            sys_seek((*((int *)usp + 1)), (*((unsigned *)usp + 2)));
            break;
        }
        case 11: {        //SYS_TELL  unsigned tell(int fd)
            unsigned return_val;
            return_val = sys_tell((*((int *)usp + 1)));
            f->eax = return_val;
            break;
        }
        case 12: {         //SYS_CLOSE void close(int fd)
            sys_close((*((int *)usp + 1)));
            break;
        }
        default: 
            printf("Call number %d not implemented yet..\n", call_number);
            thread_exit();
    }
}

```
(b) The syscall implemented are as follows:

I. **sys_halt()**
``` c
void sys_halt(){
    shutdown_power_off();
}
```
II. **sys_exit()**
```c
void sys_exit(int status){
    struct thread *curr_thread = thread_current();
    
    //check if the parent exists at all or not
    if(curr_thread->parent_thread!=NULL){
        curr_thread->parent_thread->child_status_exit = status;
    }
    else
        ;//what to do here?
    
    //remove spaces from the string
    char *file_name_temp;
    file_name_temp = palloc_get_page(0);
    if (file_name_temp == NULL) {
        return TID_ERROR;
    }    
    strlcpy(file_name_temp, curr_thread->name, 16);
    char* token0, *save_ptr;
    int index = 0;
    token0 = strtok_r(file_name_temp, " \t", &save_ptr);
    printf("%s: exit(%d)\n", token0, status);
    //[TODO: close all the files opened by this thread and then exit]
    thread_exit();
}
```
III. **sys_exec()**
```c
tid_t sys_exec(char *cmd_line){    
    memory_check((uint32_t *) cmd_line);
    lock_acquire(&filesys_lock);
    tid_t pid = process_execute(cmd_line);
    lock_release(&filesys_lock);

    return pid;
}
```

IV. **sys_wait()**
```c
int sys_wait(tid_t pid){
    tid_t wpid = process_wait(pid);
    return wpid;
}
```
V. **sys_create()**
```c
bool sys_create(char* file, unsigned initial_size){
    memory_check((uint32_t *) file);
    bool val;
    val = filesys_create(file, initial_size);
    return val;
}
```

VI. **sys_remove()**
```c
bool sys_remove(char* file){
    memory_check((uint32_t *) file);
    bool val;
    val = filesys_remove(file);
    return val;
}
```
VII. **sys_open()**
```c
int sys_open(char* file){
    memory_check((uint32_t *) file);
    int file_o;
    if(file == NULL)
        sys_exit(-1);

    file_o = filesys_open(file);
    struct thread *curr_thread = thread_current();
    
    if(file_o!=NULL){
    curr_thread->fd[curr_thread->fd_index] = file_o;
    curr_thread->fd_index++;
    
    return curr_thread->fd_index-1;

}
    return -1;
}
```
VIII. **sys_filesize()**
```c
int sys_filesize(int fd){

    struct thread *curr_thread = thread_current();

    if(fd > curr_thread->fd_index)
        return -1;

    else{
        return file_length(curr_thread->fd[fd]);
    }
}
```
IX. **sys_read()**
```c
int sys_read(int fd, void* buffer, unsigned size){
    memory_check((uint32_t *)buffer);
    int len = size;
    struct thread *curr_thread = thread_current();
    int *ch, return_val;
    if(fd == 0){
        while(len--){

            *ch = input_getc();
            ch++;
        }
         *ch = 0;
    return_val = size - len;
    }
    else if(fd == 1)
        return_val = -1;
    else{
        if(fd > curr_thread->fd_index){
            return_val = -1;   
        }    
        else{
            return_val = file_read(curr_thread->fd[fd], buffer, size);
        }
    }
    return return_val;
}
```
X. **sys_write()**
```c
int sys_write(int fd, void* buffer, unsigned size){
    memory_check((uint32_t *)buffer);
    struct thread *curr_thread = thread_current();
    int return_val;

    lock_acquire(&filesys_lock);
    if(fd > curr_thread->fd_index){
        return_val = -1;   
    }
    else if(fd==1){
        putbuf(buffer, size);
        return_val = size;
    }
    else if(fd == 0)
        return_val = -1;
    else
        return_val = file_write(curr_thread->fd[fd], buffer, size);
    lock_release(&filesys_lock);

    return return_val;
}
```
XI. **sys_seek()**
```c
void sys_seek(int fd, unsigned position){
    struct thread *curr_thread = thread_current();
    if(fd > curr_thread->fd_index)
        return -1;
    else{
        file_seek(curr_thread->fd[fd], position);
    }
    return;
}
```
XII. **sys_tell()**
```c
unsigned sys_tell(int fd){
    struct thread *curr_thread = thread_current();
    if(fd > curr_thread->fd_index)
        return -1;
    else{
        return file_tell(curr_thread->fd[fd]);
    }
}
```
XIII. **sys_close()**
```c
void sys_close(int fd){
    struct thread *curr_thread = thread_current();

    if(fd > curr_thread->fd_index)
        return -1;
    //else if(curr_thread->fd[fd]>=PHYS_BASE)
    //    return -1;
    else{
        if(curr_thread->fd[fd] == -1)
            return;
        else{
            file_close(curr_thread->fd[fd]);
            curr_thread->fd[fd] = -1;
    }
    return;
}
}
```

The validity of the pointer is checked by:

```c
static void memory_check (uint32_t *address){
    #ifdef PINTOS_P2
    printf("** Inside function memory_check() in syscall.c **\n");
    #endif
    if(address!=NULL){
       int invalid = ((void *)address >= PHYS_BASE);
        if(invalid){
        //exit gracefully. 
        //[TODO:] free the memory and locks
        sys_exit(-1);
    }
}   
    else{

        //exit gracefully. 
        //[TODO:] free the memory and locks
        sys_exit(-1);
    }
}
```

