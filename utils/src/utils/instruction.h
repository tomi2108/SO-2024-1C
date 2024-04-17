
#ifndef UTILS_INSTRUCTION_H_
#define UTILS_INSTRUCTION_H_

#include <string.h>

typedef enum {
  SET,
  SUM,
  SUB,
  JNZ,
  IO_GEN_SLEEP,
  UNKNOWN_INSTRUCTION
} instruction_op;

char *instruction_op_to_string(instruction_op op);

instruction_op instruction_op_from_string(char *string);

#endif
