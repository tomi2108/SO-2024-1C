#ifndef UTILS_PERSON_H_
#define UTILS_PERSON_H_

#include "packet.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  uint32_t dni;
  uint8_t age;
  uint32_t passport;
  char *name;
} person_t;

/**
 * @fn     person_pack
 * @param  packet Packet where the person will be packed, created with
 * packet_create(1)
 * @param  person Person to pack
 * @return Modified packet
 * @brief  Packs a person inside a packet ready to be sent with packet_send(2)
 */
packet_t *person_pack(packet_t *packet, person_t person);

/**
 * @fn     person_unpack
 * @param  packet Packet containing the person packed with person_pack(2)
 * @return Person struct created from the packet
 * @brief  Unpacks a person from a packet packed with person_pack(2)
 */
person_t person_unpack(packet_t *packet);

#endif
