#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include "mytar.h"

#define NAME_OFFSET 0
#define MODE_OFFSET 100
#define UID_OFFSET 108
#define GID_OFFSET 116
#define SIZE_OFFSET 124
#define MTIME_OFFSET 136
#define CHKSUM_OFFSET 148
#define TYPEFLAG_OFFSET 156
#define LINKNAME_OFFSET 157
#define MAGIC_OFFSET 257
#define VERSION_OFFSET 263
#define UNAME_OFFSET 265
#define GNAME_OFFSET 297
#define DEVMAJOR_OFFSET 329
#define DEVMINOR_OFFSET 337
#define PREFIX_OFFSET 345

#define NAME_SIZE 100
#define MODE_SIZE 8
#define UID_SIZE 8
#define GID_SIZE 8
#define SIZE_SIZE 12
#define MTIME_SIZE 12
#define CHKSUM_SIZE 8
#define TYPEFLAG_SIZE 1
#define LINKNAME_SIZE 100
#define MAGIC_SIZE 6
#define VERSION_SIZE 2
#define UNAME_SIZE 32
#define GNAME_SIZE 32
#define DEVMAJOR_SIZE 8
#define DEVMINOR_SIZE 8
#define PREFIX_SIZE 155

#define MALLOC_SIZE 500
#define BLOCK_SIZE 512
#define PERMS_SIZE 10
#define TIME_SIZE 16

typedef struct __attribute__ ((packed))
{
        char name[NAME_SIZE];
        char mode[MODE_SIZE];
        char uid[UID_SIZE];
        char gid[GID_SIZE];
        char size[SIZE_SIZE];
        char mtime[MTIME_SIZE];
        char chksum[CHKSUM_SIZE];
        char typeflag[TYPEFLAG_SIZE];
        char linkname[LINKNAME_SIZE];
        char magic[MAGIC_SIZE];
        char version[VERSION_SIZE];
        char uname[UNAME_SIZE];
        char gname[GNAME_SIZE];
        char devmajor[DEVMAJOR_SIZE];
        char devminor[DEVMINOR_SIZE];
        char prefix[PREFIX_SIZE];

        char padding[12];
} header;

int f_flag, c_flag, t_flag, x_flag, v_flag, S_flag;

uint32_t extract_special_int(const char *where, int len) {
    /* For interoperability with GNU tar. GNU seems to
    * set the high–order bit of the first byte, then
    * treat the rest of the field as a binary integer
    * in network byte order.
    * I don’t know for sure if it’s a 32 or 64–bit int, but for
    * this version, we’ll only support 32. (well, 31)
    * returns the integer on success, –1 on failure.
    * In spite of the name of htonl(), it converts int32 t
    */
    int32_t val = -1;
    if ((len >= sizeof(val)) && (where[0] & 0x80)) {
        /* the top bit is set, and we have space
        * extract the last four bytes */
        val = *(int32_t *) (where + len - sizeof(val));
        val = ntohl(val); /* convert to host byte order */
    }
    return val;
}

int insert_special_int(char *where, size_t size, int32_t val) {
    /* For interoperability with GNU tar. GNU seems to
    * set the high–order bit of the first byte, then
    * treat the rest of the field as a binary integer
    * in network byte order.
    * Insert the given integer into the given field
    * using this technique. Returns 0 on success, nonzero
    * otherwise
    */
    int err = 0;
    if (val < 0 || (size < sizeof(val))) {
        /* if it’s negative, bit 31 is set and we can’t use the flag
        * if len is too small, we can’t write it. Either way, we’re
        * done.
        */
        err++;
    } else {
        /* game on....*/
        memset(where, 0, size); /* Clear out the buffer */
        *(int32_t *) (where + size - sizeof(val)) = htonl(val); /* place the int */
        *where |= 0x80; /* set that high–order bit */
    }
    return err;
}

/* extract files from the archive */
int extract_archive(char *tar_file, char **paths,
                    int supplied_path, int path_count) {
    int fd;
    int new_fd;
    char *name;
    char *mode;
    char *uid;
    char *gid;
    char *size;
    char *mtime;
    char *chksum;
    char *typeflag;
    char *linkname;
    char *magic;
    char *version;
    char *uname;
    char *gname;
    char *devmajor;
    char *devminor;
    char *prefix;
    char *contents;
    int size_read;
    int file_chunk_size;
    int converted_mode;
    int i;
    int j;
    int match;
    int our_sum;

    /* open the tar file for reading */
    if ((fd = open(tar_file, O_RDONLY)) == -1) {
        perror(tar_file);
        exit(25);
    }

    /* save the file chunk size */
    file_chunk_size = 0;
    while ((size_read = read(fd, NULL, 512)) != 0) {
        /*  reset fd back to beginning of block */
        lseek(fd, -(size_read + 1), SEEK_CUR);

        if (!(name = (char *) malloc(NAME_SIZE))) {
            perror("malloc:");
            exit(9);
        }

        if (!(mode = malloc(MODE_SIZE))) {
            perror("malloc:");
            exit(10);
        }

        if (!(uid = malloc(UID_SIZE))) {
            perror("malloc:");
            exit(11);
        }

        if (!(gid = malloc(GID_SIZE))) {
            perror("malloc:");
            exit(12);
        }

        if (!(size = malloc(SIZE_SIZE))) {
            perror("malloc:");
            exit(13);
        }

        if (!(mtime = malloc(MTIME_SIZE))) {
            perror("malloc:");
            exit(14);
        }

        if (!(chksum = malloc(CHKSUM_SIZE))) {
            perror("malloc:");
            exit(15);
        }

        if (!(typeflag = malloc(TYPEFLAG_SIZE))) {
            perror("malloc:");
            exit(16);
        }

        if (!(linkname = malloc(LINKNAME_SIZE))) {
            perror("malloc:");
            exit(17);
        }

        if (!(magic = malloc(MAGIC_SIZE))) {
            perror("malloc:");
            exit(18);
        }

        if (!(version = malloc(VERSION_SIZE))) {
            perror("malloc:");
            exit(19);
        }

        if (!(uname = malloc(UNAME_SIZE))) {
            perror("malloc:");
            exit(20);
        }

        if (!(gname = malloc(GNAME_SIZE))) {
            perror("malloc:");
            exit(21);
        }

        if (!(devmajor = malloc(DEVMAJOR_SIZE))) {
            perror("malloc:");
            exit(22);
        }

        if (!(devminor = malloc(DEVMINOR_SIZE))) {
            perror("malloc:");
            exit(23);
        }

        if (!(prefix = malloc(PREFIX_SIZE))) {
            perror("malloc:");
            exit(24);
        }

        if (read(fd, name, NAME_SIZE) == -1) {
            perror(name);
            exit(26);
        }

        our_sum = 0;

        /* split the block into appropriate fields with
         * increment our_sum to verify with chksum */
        for (i = 0; i < NAME_SIZE; i++) {
            our_sum += (unsigned char) name[i];
        }

        if (read(fd, mode, MODE_SIZE) == -1) {
            perror(mode);
            exit(130);
        }
        for (i = 0; i < MODE_SIZE; i++) {
            our_sum += (unsigned char) mode[i];
        }

        if (read(fd, uid, UID_SIZE) == -1) {
            perror(uid);
            exit(131);
        }
        for (i = 0; i < UID_SIZE; i++) {
            our_sum += (unsigned char) uid[i];
        }

        if (read(fd, gid, GID_SIZE) == -1) {
            perror(gid);
            exit(132);
        }
        for (i = 0; i < GID_SIZE; i++) {
            our_sum += (unsigned char) gid[i];
        }

        if (read(fd, size, SIZE_SIZE) == -1) {
            perror(size);
            exit(133);
        }
        for (i = 0; i < SIZE_SIZE; i++) {
            our_sum += (unsigned char) size[i];
        }

        if (read(fd, mtime, MTIME_SIZE) == -1) {
            perror(mtime);
            exit(134);
        }
        for (i = 0; i < MTIME_SIZE; i++) {
            our_sum += (unsigned char) mtime[i];
        }

        if (read(fd, chksum, CHKSUM_SIZE) == -1) {
            perror(mtime);
            exit(135);
        }
        for (i = 0; i < CHKSUM_SIZE; i++) {
            our_sum += 32;
        }

        if (read(fd, typeflag, TYPEFLAG_SIZE) == -1) {
            perror(typeflag);
            exit(136);
        }
        for (i = 0; i < TYPEFLAG_SIZE; i++) {
            our_sum += (unsigned char) typeflag[i];
        }

        if (read(fd, linkname, LINKNAME_SIZE) == -1) {
            perror(linkname);
            exit(137);
        }
        for (i = 0; i < LINKNAME_SIZE; i++) {
            our_sum += (unsigned char) linkname[i];
        }

        if (read(fd, magic, MAGIC_SIZE) == -1) {
            perror(magic);
            exit(138);
        }
        for (i = 0; i < MAGIC_SIZE; i++) {
            our_sum += (unsigned char) magic[i];
        }

        if (read(fd, version, VERSION_SIZE) == -1) {
            perror(version);
            exit(139);
        }
        for (i = 0; i < VERSION_SIZE; i++) {
            our_sum += (unsigned char) version[i];
        }

        if (read(fd, uname, UNAME_SIZE) == -1) {
            perror(uname);
            exit(140);
        }
        for (i = 0; i < UNAME_SIZE; i++) {
            our_sum += (unsigned char) uname[i];
        }

        if (read(fd, gname, GNAME_SIZE) == -1) {
            perror(gname);
            exit(141);
        }
        for (i = 0; i < GNAME_SIZE; i++) {
            our_sum += (unsigned char) gname[i];
        }

        if (read(fd, devmajor, DEVMAJOR_SIZE) == -1) {
            perror(devmajor);
            exit(142);
        }
        for (i = 0; i < DEVMAJOR_SIZE; i++) {
            our_sum += (unsigned char) devmajor[i];
        }

        if (read(fd, devminor, DEVMINOR_SIZE) == -1) {
            perror(devminor);
            exit(143);
        }
        for (i = 0; i < DEVMINOR_SIZE; i++) {
            our_sum += (unsigned char) devminor[i];
        }

        if (read(fd, prefix, PREFIX_SIZE) == -1) {
            perror(prefix);
            exit(144);
        }
        for (i = 0; i < PREFIX_SIZE; i++) {
            our_sum += (unsigned char) prefix[i];
        }

        /* chksun failed: abort */
        if ((our_sum) != strtol(chksum, NULL, 8)) {
            free(name);
            free(mode);
            free(uid);
            free(gid);
            free(size);
            free(mtime);
            free(chksum);
            free(typeflag);
            free(linkname);
            free(magic);
            free(version);
            free(uname);
            free(gname);
            free(devmajor);
            free(devminor);
            exit(150);
        }

        /* go to the next block */
        lseek(fd, 12, SEEK_CUR);

        if (!(contents = malloc((strtol(size, NULL, 8)) + 1))) {
            perror("malloc:");
            exit(25);
        }

        /* read the contents of the file */
        if (read(fd, contents, (strtol(size, NULL, 8) + 1)) == -1) {
            perror(contents);
            exit(145);
        }


        /* concat prefix and name */
        if(strlen(prefix) != 0) {
            prefix[strlen(prefix)] = '/';
        }
        strcat(prefix, name);

        if (S_flag) {
            /* if strict mode, ensure magic null terminated
             * and version is 00
             */
            if (memcmp(magic, "ustar\0", MAGIC_SIZE) != 0) {
                fprintf(stderr, "incorrect magic\n");
                exit(100);
            }
            if (memcmp(version, "00", VERSION_SIZE) != 0) {
                fprintf(stderr, "incorrect version\n");
                exit(101);
            }
        } else {
            /* if non-strict, check for ustar */
            if (memcmp(magic, "ustar", MAGIC_SIZE - 1) != 0) {
                fprintf(stderr, "incorrect magic\n");
                exit(102);
            }
        }

        /* check if a specific path was supplied on the command line */
        if(supplied_path) {
            match = 0;
            for(j = 0; j < path_count; j++) {
                /* check to see if the
                 * header file name is a prefix of our target */
                if(strncmp(prefix, paths[j], strlen(paths[j])) == 0
                && (prefix[strlen(paths[j])] == '\0'
                || prefix[strlen(paths[j])] == '/')) {
                    match = 1;
                    if (memcmp(typeflag, "0", 1) == 0
                        || memcmp(typeflag, "\0", 1) == 0) {
                        /* we have a regular file */
                        converted_mode = (int) strtol(mode, NULL, 8);
                        if(((S_IXUSR | S_IXGRP | S_IXOTH)
                            & converted_mode) != 0) {
                            /* offer execute perms to everybody */
                            new_fd = open(name, O_WRONLY | O_CREAT
                                    , S_IRWXU, S_IRWXG, S_IRWXO);
                        } else {
                            new_fd = open(name, O_WRONLY | O_CREAT,
                                          S_IRUSR | S_IWUSR
                                          | S_IRGRP | S_IWGRP
                                          | S_IROTH | S_IWOTH);
                        }
                        /* write the contents of the file
                         * to the newly created file */
                        write(new_fd, contents, (strtol(size, NULL, 8)));
                        free(contents);
                        close(new_fd);

                        /* calculate how far back to lseek */
                        file_chunk_size = (int)
                                (strtol(size, NULL, 8) / 512) + 1;
                        lseek(fd, -(strtol(size, NULL, 8) + 1), SEEK_CUR);

                        /* lseek to next header */
                        lseek(fd, (512 * file_chunk_size), SEEK_CUR);
                    } else if (memcmp(typeflag, "5", 1) == 0) {
                        /* we've found a directory */
                        mkdir(prefix,
                              S_IRUSR | S_IWUSR | S_IXUSR
                              | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                        lseek(fd, -1, SEEK_CUR);
                    } else if (memcmp(typeflag, "2", 1) == 0) {
                        /* symbolic link */
                        if(symlink(linkname, prefix) == -1) {
                            perror("symlink");
                            exit(40);
                        }
                        lseek(fd, -1, SEEK_CUR);
                    } else {
                        fprintf(stderr, "Unsupported file type supplied\n");
                    }
                    /* verbose */
                    if(v_flag) {
                        printf("%s\n", prefix);
                    }
                }
            }
            /* this chunk of the tape was not
             * targeted by the command line input
             */
            if(!match) {
                /* skip past this */
                if (memcmp(typeflag, "0", 1) == 0
                    || memcmp(typeflag, "\0", 1) == 0) {
                    /* we have a regular file */
                    file_chunk_size = (int) (strtol(size, NULL, 8) / 512) + 1;
                    lseek(fd, -(strtol(size, NULL, 8) + 1), SEEK_CUR);
                    lseek(fd, (512 * file_chunk_size), SEEK_CUR);
                } else if (memcmp(typeflag, "5", 1) == 0) {
                    lseek(fd, -1, SEEK_CUR);
                } else if (memcmp(typeflag, "2", 1) == 0) {
                    /* symbolic link */
                    lseek(fd, -1, SEEK_CUR);
                }
                free(contents);
            }
        } else {
            /* no targets were supplied on the command line
             * extract all files
             */
            if (memcmp(typeflag, "0", TYPEFLAG_SIZE) == 0
                || memcmp(typeflag, "\0", TYPEFLAG_SIZE) == 0) {
                /* we have a regular file */
                converted_mode = (int) strtol(mode, NULL, 8);
                if (((S_IXUSR | S_IXGRP | S_IXOTH) & converted_mode) != 0) {
                    /* offer execute permissions to everybody */
                    new_fd = open(prefix, O_WRONLY | O_CREAT,
                                  S_IRWXU, S_IRWXG, S_IRWXO);
                } else {
                    /* nobody had execute permissions */
                    new_fd = open(prefix,
                                  O_WRONLY | O_CREAT,
                                  S_IRUSR | S_IWUSR | S_IRGRP
                                  | S_IWGRP | S_IROTH | S_IWOTH);
                }
                write(new_fd, contents, (strtol(size, NULL, 8)));
                free(contents);
                close(new_fd);
                /* calculate how many 512 block chunks this file occupied */
                file_chunk_size = (int) (strtol(size, NULL, 8) / 512) + 1;

                /* find the next file header */
                lseek(fd, -(strtol(size, NULL, 8) + 1), SEEK_CUR);
                lseek(fd, (512 * file_chunk_size), SEEK_CUR);
            } else if (memcmp(typeflag, "5", TYPEFLAG_SIZE) == 0) {
                mkdir(prefix, S_IRUSR | S_IWUSR
                              | S_IXUSR |
                              S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                lseek(fd, -1, SEEK_CUR);
            } else if (memcmp(typeflag, "2", TYPEFLAG_SIZE) == 0) {
                /* symbolic link */
                if (symlink(linkname, prefix) == -1) {
                    perror("symlink");
                    exit(40);
                }
                lseek(fd, -1, SEEK_CUR);
            } else {
                fprintf(stderr, "Unsupported file type supplied\n");
            }
            /* verbose list files as extracted */
            if (v_flag) {
                printf("%s\n", prefix);
            }
        }
        free(name);
        free(mode);
        free(uid);
        free(gid);
        free(size);
        free(mtime);
        free(chksum);
        free(typeflag);
        free(linkname);
        free(magic);
        free(version);
        free(uname);
        free(gname);
        free(devmajor);
        free(devminor);
    }
    return 1;
}

int print_archive(char *tarfile, char **files, int numFiles) {
    int fd;
    /*keep track of the current block we are on*/
    int blckIndex = 0;
    char perms[PERMS_SIZE+1] = "-rwxrwxrwx";
    char rbuff[BLOCK_SIZE];
    char *endptr;
    /*put octal strings from strtol into octalstr*/
    long octalstr = 0;
    int i =0, j=0;
    uint32_t chksum = 0;
    struct tm *time;
    /*put mtime formatted as a string into this var*/
    char pbuff[TIME_SIZE+1];
    char *fname;


    if((fd = open(tarfile, O_RDONLY)) == -1){
        perror("open: tarfile");
        exit(EXIT_FAILURE);
    }

    for(;;){
        if(read(fd, rbuff, BLOCK_SIZE) == -1){
            perror("read");
            exit(EXIT_FAILURE);
        }

        /*check the magic is "ustar"*/
        if(strncmp(rbuff+MAGIC_OFFSET, "ustar", 5)){
                fprintf(stderr, "Magic no. wasn't 'ustar'\n");
                exit(EXIT_FAILURE);
            }
        /*if in strict mode, check magic is null terminated, that the
 * version is 00, and that all ocatal strings are properly formatted*/
        if(S_flag){
            if(rbuff[TYPEFLAG_OFFSET-1] != '\0'){
                fprintf(stderr,
"Magic # is not null terminated.\n");
                exit(EXIT_FAILURE);
            }
            if(strncmp(rbuff+VERSION_OFFSET, "00", 2)){
                fprintf(stderr, "Invalid Version #\n");
                exit(EXIT_FAILURE);
            }

            if((extract_special_int(rbuff+MODE_OFFSET, 8) != -1) ||
(extract_special_int(rbuff+CHKSUM_OFFSET, 8) != -1) ||
(extract_special_int(rbuff+UID_OFFSET, 8) != -1) ||
(extract_special_int(rbuff+GID_OFFSET, 8) != -1) ||
(extract_special_int(rbuff+DEVMAJOR_OFFSET, 8) != -1) ||
(extract_special_int(rbuff+DEVMINOR_OFFSET, 8) != -1) ||
(extract_special_int(rbuff+SIZE_OFFSET, 12) != -1) ||
(extract_special_int(rbuff+MTIME_OFFSET, 12) != -1)){
                fprintf(stderr,"Bad octal strings in header\n");
                exit(EXIT_FAILURE);
            }
        }

        /*get the filename from the
 * header's prefix and name fields*/
        fname = calloc(PREFIX_SIZE+NAME_SIZE+2, sizeof(char));
        if(fname == NULL){
            perror("calloc");
            exit(EXIT_FAILURE);
        }
        /*get prefix if there is one*/
        if(rbuff[PREFIX_OFFSET] != '\0'){
            j = snprintf(fname,PREFIX_SIZE+1,
"%s",rbuff+PREFIX_OFFSET);
            /*get name field if there
 * is one and put it after prefix*/
            if(rbuff[NAME_OFFSET] != '\0'){
               snprintf(fname+j,NAME_SIZE+2,
"/%s",rbuff+NAME_OFFSET);
            }
        } else{
            snprintf(fname, NAME_SIZE+1, "%s", rbuff+NAME_OFFSET);
        }


        /*calculate chksum*/
        i=0;
        while(i<BLOCK_SIZE){
            /*treat the chksum area as 8 spaces*/
            if(i == CHKSUM_OFFSET){
                chksum += 32*8;
                i = TYPEFLAG_OFFSET;
            }
            chksum += (uint8_t)rbuff[i++];

        }
        octalstr = strtol(rbuff+CHKSUM_OFFSET, &endptr, 8);

        /*if my chksum is 256 but the one in file
 * is 0, we might be at the end or its corrupt*/
        if(chksum == 256 && octalstr == 0){
            /*check if end*/
            if(read(fd, rbuff, BLOCK_SIZE) == -1){
                perror("read");
                exit(EXIT_FAILURE);
            }
            i = 0;
            /*if the next block is all 0s
 * stop, otherwise header is corrupt*/
            while(i<BLOCK_SIZE){
                if(rbuff[i++] != '\0'){
                    fprintf(stderr, "invalid chksum");
                    exit(EXIT_FAILURE);
                }
            }
            close(fd);
            return 1;
        /*if chksums differ then corrupt header*/
        } else if(chksum != octalstr){
            fprintf(stderr, "invalid chksum");
            exit(EXIT_FAILURE);
        }
        chksum = 0;




/*check filenames if they are given*/
        if(numFiles !=0){
            j = 0;
            i = 0;
            while(j<numFiles){
                i=0;
                /*keep going until all
 * chars in given filename are read*/
                while(files[j][i] != '\0'){
                    /*if strings don't
 * match, check next given file name*/
                    if(fname[i] != files[j][i]){
                        break;
                    }
                    i++;
                }

                /*check if read the whole filename*/
                /*if i did read the whole filename,
 * is the header name the same*/
                if( (files[j][i] != '\0') &&
 (fname[i] != '\0' || fname[i] != '/')){
                    if(++j == numFiles){
                        i = -1;
                    }
                    continue;
                } else{
                    break;
                }
            }

            /*if we header name wasn't any requested
 * file name or member of a requested directory
 * go to next header by changing the block index*/
            if(i==-1){
                blckIndex += 1;
                octalstr =strtol(rbuff+SIZE_OFFSET, &endptr, 8);
                blckIndex += octalstr/BLOCK_SIZE;
                if( (octalstr%BLOCK_SIZE) != 0){
                    blckIndex += 1;
                }
                if(lseek(fd, blckIndex*BLOCK_SIZE,SEEK_SET)
 == -1){
                    perror("lseek");
                    exit(EXIT_FAILURE);
                }

                free(fname);
                /*like a break statement but forces another
 * iteration of a loop instead of forcing termination*/
                continue;
            }
        }


        /*do this stuff if we are in verbose mode*/
        if(v_flag){
            /*check file type*/
            if(rbuff[TYPEFLAG_OFFSET] == '5'){
                perms[0] = 'd';
            } else if(rbuff[TYPEFLAG_OFFSET] == '2'){
                perms[0] = 'l';
            }

            /*check mode bits*/
            /*probably should have been a switch statement but I
 *          forgot about those and this works*/
            octalstr = strtol(rbuff+MODE_OFFSET, &endptr, 8);
            if(  !(octalstr & S_IRUSR)){
                perms[1] = '-';
            }
            if(  !(octalstr & S_IWUSR)){
                perms[2] = '-';
            }
            if(  !(octalstr & S_IXUSR)){
                perms[3] = '-';
            }
            if(  !(octalstr & S_IRGRP)){
                perms[4] = '-';
            }
            if(  !(octalstr & S_IWGRP)){
                perms[5] = '-';
            }
            if(  !(octalstr & S_IXGRP)){
                perms[6] = '-';
            }
            if(  !(octalstr & S_IROTH)){
                perms[7] = '-';
            }
            if(  !(octalstr & S_IWOTH)){
                perms[8] = '-';
            }
            if(  !(octalstr & S_IXOTH)){
                perms[9] = '-';
            }

            printf("%s ", perms);
            strcpy(perms, "-rwxrwxrwx");

            /*uname/gname*/
            /*if uname or gname not there, use uid & gid*/
            if( rbuff[UNAME_OFFSET] == '\0'){
                if(rbuff[UID_OFFSET] == 0x80){
                    octalstr =
extract_special_int(rbuff+UID_OFFSET, 8);
                }else{
                    octalstr =
strtol(rbuff+UID_OFFSET, &endptr, 8);
                }
                printf("%ld/", octalstr);
            }else{
                printf("%s/", rbuff+UNAME_OFFSET);
            }
            if( rbuff[GNAME_OFFSET] == '\0'){
                if(rbuff[GID_OFFSET] == 0x80){
                    octalstr =
extract_special_int(rbuff+GID_OFFSET, 8);
                }else{
                    octalstr =
strtol(rbuff+GID_OFFSET, &endptr, 8);
                }
                printf("%ld/", octalstr);
            }else{
                printf("%s ", rbuff+GNAME_OFFSET);
            }

            /*printf the size*/
            octalstr = strtol(rbuff+SIZE_OFFSET, &endptr, 8);
            printf("%8ld ", octalstr);

            /*print the mtime in the format specified*/
            octalstr = strtol(rbuff+MTIME_OFFSET, &endptr, 8);
            if((time = localtime(&octalstr)) == NULL){
                perror("localtime");
                exit(EXIT_FAILURE);
            }
            strftime(pbuff, TIME_SIZE+1, "%Y-%m-%d %H:%M", time);
            printf("%s ", pbuff);
        }

        /*print the file name*/
        printf("%s\n", fname);
        free(fname);

        /*change the block index to go
 * to the block with the next header*/
        blckIndex += 1;
        octalstr = strtol(rbuff+SIZE_OFFSET, &endptr, 8);
        blckIndex += octalstr/BLOCK_SIZE;
        if( (octalstr%BLOCK_SIZE) != 0){
            blckIndex += 1;
        }
        if(lseek(fd, blckIndex*BLOCK_SIZE,SEEK_SET) == -1){
            perror("lseek");
            exit(EXIT_FAILURE);
        }
    }


    return 1;
}



void tapeFile(int tarFd, char *file){
    struct stat *lbuff = malloc(sizeof(struct stat));
    struct group *grp;
    struct passwd *pass;
    char *fileDir;
    DIR *dir;
    struct dirent *df;
    char *fileContents;
    int i = 0, fnameLength = 0, fd, fd2;
    uint32_t chksum = 0, mode = 0;
    header *head = calloc(1, sizeof(header));
    /*used to add up all the bytes in the header*/
    uint8_t *altHead = (uint8_t *)head;


    if(lstat(file, lbuff) == -1){
        perror("lstat");
        return;
    }

    if(lbuff == NULL){
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    if(head == NULL){
        perror("calloc");
        exit(EXIT_FAILURE);
    }


    fd = open(file, O_RDONLY);

    /*cant open?, skip and go to next file*/
    if(fd ==-1){
        perror("open failed... skipping");
        return;
    }

    /*add a '/' to the end of a directory name*/
    fnameLength = strlen(file);
    if(S_ISDIR(lbuff->st_mode)){
        strncat(file, "/", 2);
        fnameLength++;
    }


    /*if the filename is bigger
 * than 256 then we can't do anything*/
    if(fnameLength > PREFIX_SIZE+NAME_SIZE+1){
        fprintf(stderr, "path name is too long");
        return;
    /*cut up a name into prefix and name fields*/
    } else if(fnameLength > 100){
        /*look for a '/' to break up the file name*/
        i = fnameLength - NAME_SIZE-1;
        while(i<fnameLength){
            /*if I can't break up the file
 * name then we can't do anything*/
            if( (i > PREFIX_SIZE) || (i==fnameLength)){
            fprintf(stderr, "prefix: can't be broken on a '/'");
                return;
            }
            /*break up the prefix and name if we found a '/'*/
            if(file[i] == '/'){
                strncpy(head->prefix, file, i);
                strncpy(head->name, file+i+1, NAME_SIZE);
                break;
            }
            i++;
        }
    /*only put in the name if it is 100 or less than characters*/
    } else{
        strncpy(head->name, file, NAME_SIZE);
    }

    /*get the permissions, S_ISUID, S_ISGID, and sticky bit*/
    mode = (((uint32_t)lbuff->st_mode) & (S_ISUID | S_ISGID
 | S_ISVTX | S_IRUSR | S_IWUSR |
 S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP
| S_IROTH | S_IWOTH | S_IXOTH));
    snprintf(head->mode, MODE_SIZE, "%07o", mode);
 
    /*use the insert function if the
 * uid is too big for a 7 digit octal*/
    if(lbuff->st_uid > 07777777){
        /*we can't do anything if the octal is
 * too big and we are in strict*/
        if(S_flag){
            fprintf(stderr, "uid is too big for an octal string\n");
            free(head);
            /*if dir, then put in all the files*/
            if( S_ISDIR(lbuff->st_mode)){
                dir = opendir(file);
                if(dir == NULL){
                    perror("opendir");
                    return;
                }
                /*no point in adding '.' and '..'
 * directories to the tar file*/
                readdir(dir);
                readdir(dir);
                /*call the tapefile function for
 * every file in the directory*/
                while( (df = readdir(dir))){
                    fileDir =
                    malloc((fnameLength+2+
strlen(df->d_name))*sizeof(char));
                    if(fileDir == NULL){
                        perror("malloc");
                        exit(EXIT_FAILURE);
                    }
                    sprintf(fileDir, "%s%s",
 file, df->d_name);
                    tapeFile(tarFd, fileDir);
                    free(fileDir);
                }
                free(dir);
            }
            free(lbuff);
            close(fd);
            return;
        }
        /*put in the special int if not in strict*/
        if(S_flag != 1){
            insert_special_int(head->uid, 8,(int32_t)lbuff->st_uid);
        }
    /*put in uid if it is not too big*/
    } else {
        snprintf(head->uid, UID_SIZE, "%07o", lbuff->st_uid);
    }

    /*put in the gid*/
    snprintf(head->gid, GID_SIZE, "%07o", lbuff->st_gid);


    /*put in file size*/
    if(S_ISREG(lbuff->st_mode)){
        sprintf(head->size, "%011o", (unsigned int)(lbuff->st_size));
    } else{
        /*size is 0 if not a regular file*/
        sprintf(head->size, "00000000000");
    }
    /*set the mtime*/
    sprintf(head->mtime, "%011o", (unsigned int)(lbuff->st_mtime));

    /*put in the magic and version field*/
    strncpy(head->magic, "ustar", MAGIC_SIZE);
    strncpy(head->version, "00", VERSION_SIZE);

    /*set typeflag*/
    if( S_ISREG(lbuff->st_mode)){
        strncpy(head->typeflag, "0", TYPEFLAG_SIZE);
    }else if( S_ISLNK(lbuff->st_mode)){
        strncpy(head->typeflag, "2", 1);
        readlink(file, head->linkname, LINKNAME_SIZE);
    }else if(S_ISDIR(lbuff->st_mode)){
        strncpy(head->typeflag, "5", 1);
    }

    /*get the uname*/
    pass = getpwuid(lbuff->st_uid);
    strncpy(head->uname, pass->pw_name, UNAME_SIZE);

    /*get gname*/
    grp = getgrgid(lbuff->st_gid);
    strncpy(head->gname, grp->gr_name, GNAME_SIZE);

/*our assignment doesnt really interact
 * with special files so I commented this out*/

/*
    sprintf(head->devmajor, "%07o", major(lbuff->st_rdev));
    sprintf(head->devminor, "%07o", minor(lbuff->st_rdev));
*/

    /*index through bytes and set chksum, and set it*/
    i=0;
    while(i < BLOCK_SIZE){
        /*treat the chksum part as all spaces*/
        if(i == CHKSUM_OFFSET){
            chksum += 32*8;
            i = TYPEFLAG_OFFSET;
        }
        chksum += (uint8_t)altHead[i++];

    }
    sprintf(head->chksum, "%07o", chksum);

    /*print the file name if verbose*/
    if(v_flag == 1){
        printf("%s\n", file);
    }

    /*write the header*/
    if(write(tarFd, head, BLOCK_SIZE) == -1){
        perror("write");
        exit(EXIT_FAILURE);
    }

    /*write the file contents*/
    if( S_ISREG(lbuff->st_mode)){
        fileContents = malloc(lbuff->st_size);
        if(fileContents==NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        if(fileContents == NULL){
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        if((fd2 = open(file, O_RDONLY)) == -1 ){
            fprintf(stderr, "Can't open file... skipping\n");
            return;
        }
        if(read(fd2, fileContents, lbuff->st_size) == -1){
            perror("read");
            exit(EXIT_FAILURE);
        }
        close(fd2);
        if(write(tarFd, fileContents, lbuff->st_size) == -1){
            perror("write");
            exit(EXIT_FAILURE);
        }
        free(fileContents);
    
        /*pad out the last block to
 * make sure we've written a full block*/
        if( (lbuff->st_size%BLOCK_SIZE) != 0){
            fileContents = calloc(lbuff->st_size % BLOCK_SIZE,
sizeof(uint8_t));
            if(fileContents == NULL){
                perror("calloc");
                exit(EXIT_FAILURE);
            }
            if(write(tarFd, fileContents,
BLOCK_SIZE-(lbuff->st_size % BLOCK_SIZE)) == -1){
                perror("write");
                exit(EXIT_FAILURE);
            }
            free(fileContents);
        }
    }

    free(head);


    /*if dir, then put in all the files*/
    if( S_ISDIR(lbuff->st_mode)){
        dir = opendir(file);
        if(dir == NULL){
            perror("opendir");
            exit(EXIT_FAILURE);
        }
        readdir(dir);
        readdir(dir);
        while( (df = readdir(dir))){
            fileDir =
            malloc((fnameLength+2+strlen(df->d_name))*sizeof(char));
            if(fileDir == NULL){
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            sprintf(fileDir, "%s%s", file, df->d_name);
            tapeFile(tarFd, fileDir);
            free(fileDir);
        }
        free(dir);
    }

    free(lbuff);
    close(fd);

}

int create_archive(char *tarfile, char **files, int numFiles) {
    /*create the tarfile if one is not
 * given, or truncate if it is not empty*/
    int fd = open(tarfile, O_WRONLY | O_TRUNC | O_CREAT,
      S_IRWXU | S_IRWXG | S_IRWXO);
    int i = 0;
    /*put two 0 blocks at the end of the tarfile*/
    uint8_t *end = calloc(BLOCK_SIZE*2, sizeof(uint8_t));


    if(fd == -1){
        perror("open: tar");
        exit(EXIT_FAILURE);
    }

    if(end == NULL){
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    /*put in every given file into the tarfile*/
    while(i<numFiles){
        tapeFile(fd, files[i++]);
    }

    /*write out the last two 0 blocks*/
    if(write(fd, end, BLOCK_SIZE*2) == -1){
        perror("write");
        exit(EXIT_FAILURE);
    }
    close(fd);
    free(end);

    return 1;
}

int main(int argc, char **argv) {
    char *tarfile;
    char **paths = NULL;
    int count;
    int new_size;
    int path_count;
    int i;
    int supplied_path;
    char **paths_copy;
    char *path_substring;
    char *new_path_piece;

    if (argc == 1) {
        fprintf(stderr, "Usage: mytar [ctx][v][S]f tarfile [ path [ ... ] ]\n");
        exit(1);
    }

    /* create an archive */
    if (strstr(argv[1], "c") != NULL) {
        if (t_flag == 1 || x_flag == 1) {
            fprintf(stderr,
                    "Usage: mytar [ctx][v][S]f tarfile [ path [ ... ] ]\n");
            exit(4);
        }
        c_flag = 1;
    }

    /* Print the table of contents of an archive */
    if (strstr(argv[1], "t") != NULL) {
        if (c_flag == 1 || x_flag == 1) {
            fprintf(stderr,
                    "Usage: mytar [ctx][v][S]f tarfile [ path [ ... ] ]\n");
            exit(5);
        }
        t_flag = 1;
    }

    /* Extract the contents of an archive */
    if (strstr(argv[1], "x") != NULL) {
        if (c_flag == 1 || t_flag == 1) {
            fprintf(stderr,
                    "Usage: mytar [ctx][v][S]f tarfile [ path [ ... ] ]\n");
            exit(6);
        }
        x_flag = 1;
    }

    /* Increases verbosity */
    if (strstr(argv[1], "v") != NULL) {
        v_flag = 1;
    }

    /* Be strict about standards compliance */
    if (strstr(argv[1], "S") != NULL) {
        S_flag = 1;
    }

    /* Specifies archive filename */
    if (strstr(argv[1], "f") != NULL) {
        f_flag = 1;
    }

    /* f option is required */
    if (!f_flag) {
        fprintf(stderr,
                "Usage: mytar [ctx][v][S]f tarfile [ path [ ... ] ]\n");
        exit(3);
    }

    if (argc < 3) {
        fprintf(stderr,
                "Usage: mytar [ctx][v][S]f tarfile [ path [ ... ] ]\n");
        exit(8);
    }

    tarfile = argv[2];

    paths = malloc(MALLOC_SIZE);
    if (!paths) {
        perror("malloc");
        exit(7);
    }
    count = 0;
    new_size = MALLOC_SIZE * 2;
    path_count = 0;
    for (i = 3; i < argc; i++) {
        if (count == MALLOC_SIZE) {
            paths = realloc(paths, new_size);
            count = 0;
            new_size += MALLOC_SIZE;
        }
        paths[i - 3] = argv[i];
        count++;
        path_count++;
    }

    paths_copy = malloc(path_count);
    for(i = 0; i < path_count; i++) {
        paths_copy[i] = strdup(paths[i]);
    }

    if (path_count > 0) {
        supplied_path = 1;
        for(i = 0; i < path_count; i++) {
            path_substring = strtok(paths[i], "/");
            if(strcmp(path_substring, paths_copy[i]) == 0)
                continue;
            printf("HeRE: %s\n", path_substring);
            mkdir(path_substring, S_IRUSR | S_IWUSR
                          | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
            while((new_path_piece = strtok(NULL, "/")) != NULL) {
                strcat(path_substring, "/\0");
                strcat(path_substring, new_path_piece);
            }
        }
    }


    /*
    for (i = 0; i < path_count; i++) {
        printf("%s\n", paths_copy[i]);
    }
     */
    if(c_flag == 1){
        create_archive(tarfile, paths, path_count);
    }

    if(t_flag == 1){
        print_archive(tarfile, paths, path_count);
    }

    if (x_flag == 1) {
        extract_archive(tarfile, paths_copy, supplied_path, path_count);
    }

    free(paths);
    return 0;
}
