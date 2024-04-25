#ifndef UTILS_FILE_H_
#define UTILS_FILE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *file_concat_path(char *path, char *path2);

char *file_read_n_line(FILE *file, int n, int max_line_length);

uint8_t file_exists(char *path);

#endif
