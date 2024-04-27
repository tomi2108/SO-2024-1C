#ifndef UTILS_FILE_H_
#define UTILS_FILE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @fn    file_concat_path
 * @param path   Begining path
 * @param path2  Ending path
 * @return The concatenation of the paths
 * @brief Concatenates two file paths
 */
char *file_concat_path(char *path, char *path2);

/**
 * @fn     file_read_n_line
 * @param  file              File stream to read from
 * @param  n                 Line to read
 * @param  max_line_length   Max possible length of a line
 * @return A malloc'ed char* with the line read.
 * @brief  Reads then n'th line of a file stream
 */
char *file_read_n_line(FILE *file, int n, int max_line_length);

/**
 * @fn     file_read_next_line
 * @param  file              file stream to read from
 * @param  max_line_length   max possible length of a line
 * @return a malloc'ed char* with the line read.
 * @brief  Reads the next line of a file stream
 */
char *file_read_next_line(FILE *file, int max_line_length);

/**
 * @fn     file_exists
 * @param  path  Path to check existence
 * @return 1 if file exists, 0 otherwise
 * @brief  Checks if file exists in the file system
 */
uint8_t file_exists(char *path);

#endif
