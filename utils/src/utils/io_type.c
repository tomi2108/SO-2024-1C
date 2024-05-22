#include "io_type.h"
#include "instruction.h"

io_type io_type_from_string(char *string) {
  if (strcmp(string, "generica") == 0)
    return GEN;
  if (strcmp(string, "stdin") == 0)
    return STDIN;
  if (strcmp(string, "stdout") == 0)
    return STDOUT;
  if (strcmp(string, "dialfs") == 0)
    return DIALFS;
  return UNKNOWN_IO;
}

int io_type_gen_is_compatible(instruction_op op) {
  if (op == IO_GEN_SLEEP)
    return 1;
  return 0;
}

int io_type_stdin_is_compatible(instruction_op op) {
  if (op == IO_STDIN_READ)
    return 1;
  return 0;
}

int io_type_stdout_is_compatible(instruction_op op) {
  if (op == IO_STDOUT_WRITE)
    return 1;
  return 0;
}

int io_type_dialfs_is_compatible(instruction_op op) {
  if (op == IO_FS_CREATE || op == IO_FS_READ || op == IO_FS_WRITE ||
      op == IO_FS_DELETE || op == IO_FS_TRUNCATE)
    return 1;
  return 0;
}

int io_type_is_compatible(io_type type, instruction_op op) {
  switch (type) {
  case GEN:
    return io_type_gen_is_compatible(op);
  case STDIN:
    return io_type_stdin_is_compatible(op);
  case STDOUT:
    return io_type_stdout_is_compatible(op);
  case DIALFS:
    return io_type_dialfs_is_compatible(op);
  default:
    return 0;
  }
}
