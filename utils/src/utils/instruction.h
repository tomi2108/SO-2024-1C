#ifndef UTILS_INSTRUCTION_H_
#define UTILS_INSTRUCTION_H_

#include "packet.h"
#include "status.h"
#include <commons/collections/list.h>
#include <stdint.h>
#include <string.h>

typedef enum {
  SET,
  SUM,
  SUB,
  JNZ,
  MOV_IN,
  MOV_OUT,
  RESIZE,
  COPY_STRING,
  IO_GEN_SLEEP,
  IO_STDIN_READ,
  IO_STDOUT_WRITE,
  UNKNOWN_INSTRUCTION
} instruction_op;

typedef enum { REGISTER, NUMBER, STRING } param_type;

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

/**
 * @fn     instruction_mov_in
 * @param  params Parameters to the MOV_IN instruction
 * @param  socket Socket to send the resolution of MOV_IN
 * @param  physical_address Address to read from
 * @brief  MOV_IN instruction implementation
 */
void instruction_mov_in(t_list *params, int client_socket,
                        uint32_t physical_address, uint32_t pid);

/**
 * @fn     instruction_mov_out
 * @param  params Parameters to the MOV_OUT instruction
 * @param  socket Socket to send the resolution of MOV_OUT
 * @param  physical_address Address to read from
 * @brief  MOV_OUT instruction implementation
 */
void instruction_mov_out(t_list *params, int client_socket,
                         uint32_t physical_address, uint32_t pid);

int instruction_resize(t_list *params, int client_socket, uint32_t pid);

void instruction_copy_string(t_list *params, uint32_t *si, uint32_t *di);

void instruction_io_stdin(t_list *params, int socket,
                          uint32_t (*translate_addres)(uint32_t));

void instruction_io_stdout(t_list *params, int socket,
                           uint32_t (*translate_addres)(uint32_t));

#endif
