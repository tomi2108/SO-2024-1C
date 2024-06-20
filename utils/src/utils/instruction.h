#ifndef UTILS_INSTRUCTION_H_
#define UTILS_INSTRUCTION_H_

#include "buffer.h"
#include "connection.h"
#include "packet.h"
#include "process.h"
#include "status.h"
#include <commons/collections/list.h>
#include <commons/log.h>
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
  IO_FS_CREATE,
  IO_FS_DELETE,
  IO_FS_TRUNCATE,
  IO_FS_WRITE,
  IO_FS_READ,
  EXIT,
  WAIT,
  SIGNAL,
  UNKNOWN_INSTRUCTION
} instruction_op;

typedef enum { EXTENDED_REGISTER, REGISTER, NUMBER, STRING } param_type;

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
 * @fn     instruction_is_syscall
 * @param  op Instruction op to check if it is a syscall
 * @return 1 if the instruction_op is a syscall, 0 if not
 * @brief  Checks if a instruction_op is syscall
 */
int instruction_is_syscall(instruction_op op);

/**
 * @fn     instruction_is_io
 * @param  op Instruction op to check if it is an io call
 * @return 1 if the instruction_op is an io call, 0 if not
 * @brief  Checks if a instruction_op is an io call
 */
int instruction_is_io(instruction_op op);

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
void instruction_io_gen_sleep(t_list *params, packet_t *instruction_packet);

/**
 * @fn     instruction_mov_in
 * @param  params             Parameters to the MOV_IN instruction
 * @param  socket             Socket to send the resolution of MOV_IN
 * @param  logger             Logger to log the execution
 * @param  translate_address  Method to translate the address to physical
 * @param  pid                Pid from process
 * @brief  MOV_IN instruction implementation
 */
status_code instruction_mov_in(t_list *params, t_log *logger,
                               uint32_t (*translate_address)(uint32_t, uint32_t,
                                                             status_code *),
                               uint32_t pid, uint32_t page_size,
                               char *server_ip, char *server_port);

/**
 * @fn     instruction_mov_out
 * @param  params             Parameters to the MOV_OUT instruction
 * @param  socket             Socket to send the resolution of MOV_OUT
 * @param  logger             Logger to log the execution
 * @param  translate_address  Method to translate the address to physical
 * @param  pid                Pid from process
 * @brief  MOV_OUT instruction implementation
 */
status_code instruction_mov_out(
    t_list *params, t_log *logger,
    uint32_t (*translate_address)(uint32_t, uint32_t, status_code *),
    uint32_t pid, uint32_t page_size, char *server_ip, char *server_port);

/**
 * @fn     instruction_resize
 * @param  params  Parameters to the RESIZE instruction
 * @param  instruction_packet
 * @param  pid     Pid from process
 * @brief  RESIZE instruction implementation
 */
void instruction_resize(t_list *params, packet_t *instruction_packet,
                        uint32_t pid);

/**
 * @fn     instruction_copy_string
 * @param  params  Parameters to the COPY_STRING instruction
 * @param  si      si register
 * @param  di      di register
 * @brief  COPY_STRING instruction implementation
 */
status_code instruction_copy_string(
    t_list *params, char *server_ip, char *server_port, t_log *logger,
    uint32_t (*translate_address)(uint32_t, uint32_t, status_code *),
    uint32_t si, uint32_t di, uint32_t pid, uint32_t page_size);

/**
 * @fn     instruction_io_stdin
 * @param  params             Parameters to the IO_STDIN_READ instruction
 * @param  socket             Socket to send the resolution of IO_STDIN_READ
 * @param  translate_address  Method to translate the address to physical
 * @param  pid                Pid from process
 * @brief  IO_STDIN_READ instruction implementation
 */
status_code instruction_io_stdin(t_list *params, packet_t *instruction_packet,
                                 uint32_t (*translate_address)(uint32_t,
                                                               uint32_t,
                                                               status_code *),
                                 uint32_t pid, uint32_t page_size);

/**
 * @fn     instruction_io_stdout
 * @param  params             Parameters to the IO_STDOUT_WRITE instruction
 * @param  socket             Socket to send the resolution of IO_STDOUT_WRITE
 * @param  translate_address  Method to translate the address to physical
 * @param  pid                Pid from process
 * @brief  IO_STDOUT_WRITE instruction implementation
 */
status_code instruction_io_stdout(t_list *params, packet_t *instruction_packet,
                                  uint32_t (*translate_addres)(uint32_t,
                                                               uint32_t,
                                                               status_code *),
                                  uint32_t pid, uint32_t page_size);

/**
 * @fn     instruction_io_fs_create
 * @param  params             Parameters to the IO_FS_CREATE instruction
 * @param  socket             Socket to send the resolution of IO_FS_CREATE
 * @param  pid                Pid from process
 * @brief  IO_FS_CREATE instruction implementation
 */
void instruction_io_fs_create(t_list *parms, packet_t *instruction_packet,
                              t_log *logger, uint32_t pid);

void instruction_io_fs_delete(t_list *parms, packet_t *instruction_packet,
                              t_log *logger, uint32_t pid);

void instruction_io_fs_read(t_list *parms, packet_t *instruction_packet,
                            t_log *logger, uint32_t pid);

void instruction_io_fs_write(t_list *parms, packet_t *instruction_packet,
                             t_log *logger, uint32_t pid);

void instruction_io_fs_truncate(t_list *parms, packet_t *instruction_packet,
                                t_log *logger, uint32_t pid);

void instruction_wait(t_list *params, packet_t *instruction_packet,
                      t_log *logger, uint32_t pid);

void instruction_signal(t_list *params, packet_t *instruction_packet,
                        t_log *logger, uint32_t pid);

void instruction_exit();

#endif
