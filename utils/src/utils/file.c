#include "file.h"
#include <fcntl.h>
#include <stdio.h>

char *file_concat_path(char *path, char *path2) {
  char *full_path = malloc(sizeof(char) * (1 + strlen(path) + strlen(path2)));
  memset(full_path, 0, 1 + strlen(path) + strlen(path2));
  strcat(full_path, path);
  strcat(full_path, path2);
  return full_path;
}

char *file_read_n_line(FILE *file, int n, int max_line_length) {
  char *line = malloc(max_line_length * sizeof(char));
  int i = 0;
  while (fgets(line, max_line_length, file)) {
    if (i == n) {
      line[strlen(line) - 1] = '\0';
      return line;
    }
    i++;
  }
  return NULL;
}

char *file_read_next_line(FILE *file, int max_line_length) {
  char *line = malloc(max_line_length * sizeof(char));
  fgets(line, max_line_length, file);
  line[strlen(line) - 1] = '\0';
  return line;
}

uint8_t file_exists(char *path) {
  int exists = access(path, F_OK);
  return exists == 0;
}

void file_create(char *path) {
  FILE *file = fopen(path, "w");
  fclose(file);
}

struct flock file_lock(int fd, short l_type, off_t l_start, off_t l_len) {
  struct flock lock = {.l_len = l_len,
                       .l_start = l_start,
                       .l_pid = getpid(),
                       .l_type = l_type,
                       .l_whence = SEEK_SET};
  fcntl(fd, F_SETLKW, lock);
  return lock;
}

void file_unlock(int fd, struct flock lock) {
  struct flock unlock = {.l_len = lock.l_len,
                         .l_start = lock.l_start,
                         .l_pid = getpid(),
                         .l_type = F_UNLCK,
                         .l_whence = SEEK_SET};
  fcntl(fd, F_SETLKW, unlock);
}
