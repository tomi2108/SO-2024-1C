#ifndef UTILS_COMMAND_H_
#define UTILS_COMMAND_H_

#include <string.h>

typedef enum {
  EXEC_SCRIPT,
  CREATE_PROCESS,
  FINISH_PROCESS,
  STOP_SCHEDULER,
  START_SCHEDULER,
  CHANGE_MULTIPROGRAMMING,
  PRINT_PROCESSES,
  READ_ADDR,
  UNKNOWN_COMMAND
} command_op;

command_op command_op_from_string(char *op);
#endif
