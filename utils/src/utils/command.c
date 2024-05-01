#include "command.h"

command_op command_op_from_string(char *op) {
  if (strcmp(op, "EJECUTAR_SCRIPT") == 0)
    return EXEC_SCRIPT;
  if (strcmp(op, "INICIAR_PROCESO") == 0)
    return CREATE_PROCESS;
  if (strcmp(op, "FINALIZAR_PROCESO") == 0)
    return FINISH_PROCESS;
  if (strcmp(op, "DETENER_PLANIFICACION") == 0)
    return STOP_SCHEDULER;
  if (strcmp(op, "INICIAR_PLANIFICACION") == 0)
    return START_SCHEDULER;
  if (strcmp(op, "MULTIPROGRAMACION") == 0)
    return CHANGE_MULTIPROGRAMMING;
  if (strcmp(op, "PROCESO_ESTADO") == 0)
    return PRINT_PROCESSES;
  // FOR DEBUGGING
  if (strcmp(op, "READ_ADDR") == 0)
    return READ_ADDR;
  return UNKNOWN_COMMAND;
}
