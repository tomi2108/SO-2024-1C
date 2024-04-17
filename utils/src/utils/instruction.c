#include "instruction.h"

char *instruction_op_to_string(instruction_op op) {
  switch (op) {
  case SET:
    return "SET";
  case SUM:
    return "SUM";
  case SUB:
    return "SUB";
  case JNZ:
    return "JNZ";
  case IO_GEN_SLEEP:
    return "IO_GEN_SLEEP";
  default:
    return "UNKNOW_INSTRUCTION";
  };
}

instruction_op instruction_op_from_string(char *op) {

  if (strcmp(op, "SET") == 0)
    return SET;
  if (strcmp(op, "SUM") == 0)
    return SUM;
  if (strcmp(op, "SUB") == 0)
    return SUB;
  if (strcmp(op, "JNZ") == 0)
    return JNZ;
  if (strcmp(op, "IO_GEN_SLEEP") == 0)
    return IO_GEN_SLEEP;
  return UNKNOWN_INSTRUCTION;
}
