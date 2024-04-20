#ifndef UTILS_INSTRUCTION_H_
#define UTILS_INSTRUCTION_H_

#include "packet.h"
#include <commons/collections/list.h>
#include <stdint.h>
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

/**
 * @fn     instruction_op_to_string
 * @param  op Instruction operation to convert
 * @return String representation of the instruction operation
 * @brief  Converts an instruction_op to it's string representation
 */
char *instruction_op_to_string(instruction_op op);

/**
 * @fn     instruction_op_from_string
 * @param  string String to convert
 * @return Instruction op representation of the string, UNKNOWN_INSTRUCTION if
 * the string cannot be converted
 * @brief  Converts string to it's instruction_op representation
 */
instruction_op instruction_op_from_string(char *string);

/**
 * @fn     instruction_is_blocking
 * @param  op Instruction op to check if it is blocking
 * @return 1 if the instruction_op is blocking, 0 if not
 * @brief  Checks if a instruction_op is blocking
 */
int instruction_is_blocking(instruction_op op);

/**
 * @fn     instruction_set
 * @param  params Parameters to the SET instruction
 * @brief  SET instruction implementation
 */
void instruction_set(t_list *params);

/**
 * @fn     instruction_sum
 * @param  params Parameters to the SUM instruction
 * @brief  SUM instruction implementation
 */
void instruction_sum(t_list *params);

/**
 * @fn     instruction_sub
 * @param  params Parameters to the SUB instruction
 * @brief  SUB instruction implementation
 */
void instruction_sub(t_list *params);

/**
 * @fn     instruction_jnz
 * @param  params Parameters to the JNZ instruction
 * @param  pc     Program countrer
 * @brief  JNZ instruction implementation
 */
void instruction_jnz(t_list *params, uint32_t *pc);

/**
 * @fn     instruction_io_gen_sleep
 * @param  params Parameters to the IO_GEN_SLEEP instruction
 * @param  socket Socket to send the resolution of IO_GEN_SLEEP
 * @brief  IO_GEN_SLEEP instruction implementation
 */
void instruction_io_gen_sleep(t_list *params, int socket);
#endif
