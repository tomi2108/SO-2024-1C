#ifndef UTILS_BUFFER_H_
#define UTILS_BUFFER_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint32_t size;
  uint32_t offset;
  void *stream;
} buffer_t;

/**
 * @fn     buffer_create
 * @return Created buffer or NULL if creation errors
 * @brief  Initializes empty buffer with size 0 and offset 0
 */
buffer_t *buffer_create(void);

/**
 * @fn    buffer_destroy
 * @param buffer Buffer to destroy
 * @brief Destroys the buffer freeing all memory
 */
void buffer_destroy(buffer_t *buffer);

/**
 * @fn     buffer_add
 * @param  buffer Buffer to add to
 * @param  data   Stream to add to the buffer
 * @param  size   Size of the stream in bytes to add to the buffer
 * @return 0 if adding was successful or -1 if error ocurred
 * @brief  Adds stream to buffer in the current position and adjusts size
 * accordingly
 */
int buffer_add(buffer_t *buffer, void *data, size_t size);

/**
 * @fn    buffer_read
 * @param buffer Buffer to read from
 * @param data   Stream to read to
 * @param size   Size in bytes to write to the data stream from the buffer
 * @brief Reads from buffer into data and adjusts offset accordingly
 */
void buffer_read(buffer_t *buffer, void *data, size_t size);

/**
 * @fn    buffer_add_uint32
 * @param buffer Buffer to add to
 * @param data   Data to add
 * @return 0 if adding was successful or -1 if error ocurred
 * @brief Adds an uint32 to the buffer
 */
int buffer_add_uint32(buffer_t *buffer, uint32_t data);

/**
 * @fn    buffer_add_uint8
 * @param buffer Buffer to add to
 * @param data   Data to add
 * @return 0 if adding was successful or -1 if error ocurred
 * @brief Adds an uint8 to the buffer
 */
int buffer_add_uint8(buffer_t *buffer, uint8_t data);

/**
 * @fn    buffer_add_string
 * @param buffer Buffer to add to
 * @param length Length of the string to add
 * @param string String to add
 * @return 0 if adding was successful or -1 if error ocurred
 * @brief Adds a string to the buffer
 */
int buffer_add_string(buffer_t *buffer, uint32_t length, char *string);

/**
 * @fn     buffer_read_uint8
 * @param  buffer Buffer to read from
 * @return Read data
 * @brief  Reads an uint8 from the buffer
 */
uint8_t buffer_read_uint8(buffer_t *buffer);

/**
 * @fn     buffer_read_uint32
 * @param  buffer Buffer to read from
 * @return Read data
 * @brief  Reads an uint32 from the buffer
 */
uint32_t buffer_read_uint32(buffer_t *buffer);

/**
 * @fn     buffer_read_string
 * @param  buffer Buffer to read from
 * @param  length Length of the string to read
 * @return Returns a malloc'ed pointer that will have to be free'd by the user
 * @brief  Reads a string from the buffer
 */
char *buffer_read_string(buffer_t *buffer, uint32_t length);

/**
 * @fn    buffer_dup
 * @param  buffer Buffer to duplicate
 * @return A new buffer that must be destroyed with buffer_destroy(1) or NULL if error ocurred
 * @brief  Creates a new buffer duplicated from the given buffer.
 */
buffer_t *buffer_dup(buffer_t *buffer);

#endif
