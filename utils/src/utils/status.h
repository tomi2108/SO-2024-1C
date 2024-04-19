#ifndef UTILS_STATUS_H_
#define UTILS_STATUS_H_

#include "packet.h"

typedef enum { ERROR, UNKNOWN_PACKET, NOT_FOUND, END_OF_FILE, OK } status_code;

/**
 * @fn     status_unpack
 * @param  packet Packet to read the status code from
 * @return Status code read
 * @brief  Reads the status code from a packet with type of STATUS, if the type
 * of the packet is not status returns UNKNOWN_PACKET
 */
status_code status_unpack(packet_t *packet);

/**
 * @fn     status_pack
 * @param  status_code Status code to assign to the created packet
 * @return Packet created or NULL if error ocurred
 * @brief  Creates a packet of type STATUS with the given status_code
 */
packet_t *status_pack(status_code status_code);
#endif
