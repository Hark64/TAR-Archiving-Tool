#ifndef ASGN4_MYTAR_H
#define ASGN4_MYTAR_H

uint32_t extract_special_int(const char *where, int len);

int insert_special_int(char *where, size_t size, int32_t val);

int extract_archive(char *tar_file, char **paths,
                    int supplied_path, int path_count);

int print_archive();

int create_archive();

#endif
