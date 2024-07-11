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
  PRINT_DIR,
  PRINT_RESOURCES,
  UNKNOWN_COMMAND
} command_op;

/**
 * @fn     command_op_from_string
 * @param  op String to convert
 * @return Command op representation of the string, UNKNOWN_COMMAND if
 * the string cannot be converted
 * @brief  Converts a string to command_op
 */
command_op command_op_from_string(char *op);
#endif
