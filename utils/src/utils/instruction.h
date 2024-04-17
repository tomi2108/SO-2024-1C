
#ifndef UTILS_INSTRUCTION_H_
#define UTILS_INSTRUCTION_H_

#include <commons/collections/list.h>
#include <string.h>

typedef enum {
  SET,
  SUM,
  SUB,
  JNZ,
  IO_GEN_SLEEP,
  UNKNOWN_INSTRUCTION
} instruction_op;

typedef enum { REGISTER, EXTENDED_REGISTER, NUMBER, STRING } param_type;

typedef struct {
  param_type type;
  void *value;
} param;

char *instruction_op_to_string(instruction_op op);

instruction_op instruction_op_from_string(char *string);

void instruction_set(t_list *params);

void instruction_sum(t_list *params);

void instruction_sub(t_list *params);

void instruction_jnz(t_list *params);

void instruction_io_gen_sleep(t_list *params, int socket);
#endif
