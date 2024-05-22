#ifndef UTILS_IO_TYPE_H_
#define UTILS_IO_TYPE_H_

#include "instruction.h"
#include <string.h>

typedef enum {
  GEN,
  STDIN,
  STDOUT,
  DIALFS,
  UNKNOWN_IO,
} io_type;

io_type io_type_from_string(char *string);

int io_type_is_compatible(io_type type, instruction_op op);

int io_type_gen_is_compatible(instruction_op op);

int io_type_stdin_is_compatible(instruction_op op);

int io_type_stdout_is_compatible(instruction_op op);

int io_type_dialfs_is_compatible(instruction_op op);

#endif
