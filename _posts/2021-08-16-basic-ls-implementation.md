---
layout: post
title: "Basic ls implementation and understanding how it works"
description: "Uderstand how OS kernel interact with file system and how you can use it. We are making basic ls command implementation for learning purpose."
---
**TL;DR** Here is the source code of implementation ([LINK]()), but I encourage you to read the whole article :)

## Introduction
Writing your own implementation of the classic `ls` is a great way to learn how Linux works in practice, or rather its interface to communicate with the filesystem through system calls. The Linux kernel, like the kernel of any serious operating system, provides certain functions (system calls) that are used to operate on files. This is a convenient abstraction for real file systems such such as _FAT32_, _ext3_, _ext4_, _NTFS_. Note that although Linux uses _ext4_ by default, it understands all of the above. When you plug in another drive, such as a flash drive with Microsoft's file system _NTFS_, the `ls` or `cat` command executed on files and directories in that file system will still work completely correctly. File systems were created to provide an abstraction for raw bytes on a storage medium such as an HDD, from then a few bytes became a file. Operating systems were created, among other things, to understand these file systems, to support them, and to provide for the programmer convenient tools to operate on them, without the need to know their implementation. Convenient, ah this humanity :')

## How to read a directory?
Now let's look at how Linux allows the programmer to use his ability to operate on the filesystem. This happens, like all interaction with the kernel, through system calls. These that we will be interested in are `open`, `getdents64` and `fstat`. We can check them with the `man` command to see what each of them does.

The first thing we need to do is get the absolute path to the directory that we want to list. The classic `ls` uses the current directory by default, which is `.` (period), but you can also provide a relative path. The `realpath` function (`stdlib.h`) will replace the relative path with an absolute path. The maximum length path length (`PATH_MAX`) can be found in `linux/limits.h`.

Opening a directory as a file and getting a file descriptor for it is quite unusual, so we will have to use the low level `open` system call. This is the most basic, low-level 'open' call for anything by the operating system, so it has many more options than the standard high-level `fopen`. The standard `glibc` library provides a convenient wrapper for this system call (`fcntl.h`). The attribute to get the file descriptor for the directory is `O_DIRECTORY`, and the permissions are defined by `O_RDONLY`.

{% highlight c %}

const size_t READ_BUF_SIZE = 4096;

int main(int argc, char *argv[]) {
    char pathbuf[PATH_MAX];

    // If not specified, get current directory
    char *path = realpath(argc == 2 ? argv[1] : ".", pathbuf);

    // Get file descriptor of directory
    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        puts("Error: failed to open the file.");
        exit(1);
    }
}
{% endhighlight %}

## Getting directory's content information
To understand the rest of the code we need to explain what the `getdents64` system call does. So let's execute `man 2 getdents64`. The number `2` means that this is the page that describes `getdents64` as a system call. The full list of different pages can be found here: [link](https://www.kernel.org/doc/man-pages/). From the manual we learn that `getdents64` returns a list of `linux_dirent64` structures read from the specified directory. `dirent` stands for `directory entry`, which means anything that can contain a directory, files, other directories, symbolic links, etc. Unfortunately `glibc` for some reason does not have a ready made implementation of the `linux_dirent` structure, so we will create it ourselves by simply copying it from the manual to a new `utils.h` file.


{% highlight c %}
// d_type definitions
#define D_SYMBOLIC   1 
#define D_DIR        4
#define D_FILE       8

struct linux_dirent64 {
  ino64_t        d_ino;    /* 64-bit inode number */
  off64_t        d_off;    /* 64-bit offset to next structure */
  unsigned short d_reclen; /* Size of this dirent */
  unsigned char  d_type;   /* File type */
  char           d_name[]; /* Filename (null-terminated) */
};
{% endhighlight %}

By the way, we defined constants for the `d_type` field. There are actually more types, but for our purposes these three will suffice because they are the most common. Now we need to allocate some space in `main()`  for the read structures from the directory.

{% highlight c %}
#define DIRENTS_BUF_SIZE 4096 // Max 
// ...
char *direntsbuf = malloc(DIRENTS_BUF_SIZE);
struct linux_dirent64 *dirent;
struct stat *inode_stat = malloc(sizeof(struct stat));
{% endhighlight %}

The `direntsbuf` buffer will contain whatever `getdents64` returns, which is a list of `linux_dirent64` structures, one for each element in the directory. What if there are more elements than space size in the `direntsbuf`? Let's look at the definition of the `getdents64` function from the manual:

{% highlight c %}
int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
{% endhighlight %}

Arguments:
* _fd_ - file description of the directory we have already obtained
* _dirp_ - this is our buffer, into which function will put entries
* _count_ - size of the buffer in bytes

The last argument makes the function safe and don't let the function returns more entries than there is space in the buffer. To get all entries from the directory we'll execute `getdents64` in a loop. The function returns the number of bytes loaded, so if that number is zero, we can exit the loop because everything has been loaded. There is one more problem. In the manual we have: `Glibc does not provide a wrapper for these system calls`, which means there is no convenient wrapper in C for this system call. Fortunately, `glibc` provides a general purpose wrapper for all system calls (in `unistd.h`).

{% highlight c %}
long syscall(long number, ...);
{% endhighlight %}

If we need a complete list of system call numbers, it can be found here: https://filippo.io/linux-syscall-table/. However, in this case we are also helped by `glibc`, which provides ready-made constants in the `sys/syscall.h` file. The one we are looking for is `SYS_getdents64`. We know the parameters from the manual. 

{% highlight c %}
// ...

while (true)
{
    int n_read = syscall(SYS_getdents64, fd, direntsbuf, READ_BUF_SIZE);

    if (n_read == -1)
    {
        puts("Error: failed to read data.");
        exit(1);
    }

    // EOF - no more entries to read
    if (n_read == 0) break;

    // ...
}
{% endhighlight %}

Once we have the list of `linux_dirent64` structures obtained, we can start reading subsequent elements.

{% highlight c %}
// ...

while (true)
{
    // ...

    // Read all dirent structs
    for (int bytes_offset = 0; bytes_offset < n_read;)
    {
        // Get dirent struct
        dirent = (struct linux_dirent64 *)(direntsbuf + bytes_offset);

        // Get file_path (2 extra bytes for slash and null-terminator)
        char *file_path = malloc(strlen(path) + strlen(dirent->d_name) + 2);
        get_file_path(file_path, path, dirent->d_name);

        // Get i-node info (stat struct) of file
        stat(file_path, inode_stat);

        // Format and print data
        print_data(dirent, inode_stat);

        bytes_offset += dirent->d_reclen;
        free(file_path);
    }
}
{% endhighlight %}

## Retrieving detailed information about a file (i-node)
In the above code, we retrieve the following `linux_dirent64` structures, get the file name from them, and construct the full path to the file for the `stat()` function. Each element in a filesystem on Linux has something called a `i-node`, which is a structure assigned to it with various filesystem-specific metadata. This includes file access rights, owner, group, size, creation and modification datetimes, and more. Each file has a unique `i-node` within a given file system. While we can read the basic file name from `linux_dirent64`, we can only get the permissions of a file by reading its `i-node`. We need the permissions because we want to mark executable and non-executable files with a different color. To read the `i-node` of a file we use the `stat()` system call, which has a wrapper in `glibc` in the form of a function of the same name. The `stat()` function takes a path to a file and a pointer to a buffer, to which it returns a `stat` structure. Both the `stat` structure and the `stat()` function are in the `sys/stat.h` header file. Why do we need to use the path rather than `d_ino` value from `linux_dirent64` to read the `i-node`? Probably because the `i-node` number is unique only within a given filesystem, we can have many different partitions mounted in OS and only the absolute path to the file uniquely identifies it.

Once we have retrieved the `linux_dirent64` structure and the `stat` structure for a given file, we have pretty much all the data that exists on the filesystem about that specific file. That allows us to print the filename to the screen in the appropriate color, just as we do in the terminal using `ls`. Our function for printing data to the screen is `print_dirent`. Below is a very basic implementation, but it uses data from both retrieved structures. I won't go into aesthetic details, because that's not the purpose of this article.

{% highlight c %}
void print_dirent(struct linux_dirent64 *dirent, struct stat *file_stat) {
	char *name = malloc(strlen(dirent->d_name) + 1);
	strcat(name, dirent->d_name);

	switch (dirent->d_type) {
		case D_SYMBOLIC:
			add_color(name, BOLD_CYAN);
			break;
		case D_DIR:
			add_color(name, BOLD_BLUE);
			break;
		case D_FILE:
			if (file_stat->st_mode & S_IXUSR) {
				// If file is executable
				add_color(name, BOLD_GREEN);
			}
			break;
	}

	printf("%s\n", name);
}
{% endhighlight %}

## Summary
This is what my very basic implementation of the `ls` command looks like. Researching it was a great lesson for me. Of course, the goal was not to create a functional tool. The goal was to learn and get to know how exactly the kernel interacts with the filesystem. I hope it was fun :)

