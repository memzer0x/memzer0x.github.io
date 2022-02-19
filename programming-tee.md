# Exercise 4.1
This is one of the first exercises in this book, it's a pretty simple and cool challenge, we are asked to reproduce the `tee` linux binary, using our knowledge from the chapter.

Since `tee` is a simple program, rewriting the program should take us only a few minutes. The `tee` command reads its standard input until end-of-file, writing a copy of the input to standard output and to the file named in it's command line argument.

The `read` system call reads input until end-of-file, when read encounter an end-of-file it will return 0, we can just do a while loop and check if the return value of read was equal to `0` if it was not, the program will write to standard output.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int main(int argc, char **argv){
    char buf[1024];
    ssize_t ret;
    int fd;
    if(argc == 2){
        fd = open(argv[1], O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
        if(fd == -1){
            if(errno == EACCES) perror("open");
            exit(EXIT_FAILURE);
        }
    } else {
        fd = 1;
    }
    while((ret = read(0, buf, 1024-1)) != 0 && write(fd, buf, ret)){
        if(ret == -1){
            if(errno == EINTR){
                continue;
            }
            perror("read");
            break;
        }
    }

    return 0;
}
```

Note that i haven't implemented `getopt` to the program i was too lazy for it... deal with it.

Also if you want to have a better error coverage in your program then you should instead go for this version.
```cpp
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int main(int argc, char **argv){
    char buf[1024];
    ssize_t ret;
    int fd;
    if(argc == 2){
        fd = open(argv[1], O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
        if(fd == -1){
            if(errno == EACCES) perror("open");
            exit(EXIT_FAILURE);
        }
    } else {
        fd = 1;
    }
    while((ret = read(0, buf, 1024-1)) != 0){
        if(ret == -1){
            if(errno == EINTR){
                continue;
            }
            perror("read");
            break;
        }
        ret = write(fd, buf, ret);
        if(ret == -1){
            perror("write");
            break;
        }
    }

    return 0;
}
```
