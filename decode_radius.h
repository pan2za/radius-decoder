/*
 * decode_radius.h
 *
 * Authorization, Authentication: RFC 2865
 * Accounting: RFC 2866
 *
 * Author: Mehul Prajapati
 */

#ifndef _DECODE_RADIUS_H_
#define _DECODE_RADIUS_H_

/*
 * @Includes
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>
#include "radius.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * @Defines
 */
#define AUTHENTICATOR_LENGTH			16
#define RD_HDR_LENGTH					4
#define HDR_LENGTH						(RD_HDR_LENGTH + AUTHENTICATOR_LENGTH)
#define FRAMED_IP_ADDR_BUF_LEN_MAX		16
#define RADIUS_AUTH_SERVER_PORT_NO		1812
#define RADIUS_ACCT_SERVER_PORT_NO		1813

/*
 * @Data types
 */
typedef struct
{
	u_int8_t rh_code;
	u_int8_t rh_ident;
	u_int16_t rh_pktlength;
	u_int8_t authenticator[AUTHENTICATOR_LENGTH];

} radius_hdr;

typedef struct
{
	long long int imsi;
	unsigned int session_stop_id;

} radius_vsa_3gpp;

typedef struct
{
	radius_hdr rhdr;

	radius_vsa_3gpp rVsa3gpp;

	char framed_ip_addr[FRAMED_IP_ADDR_BUF_LEN_MAX];
	struct in_addr framed_ip_in_addr;

	u_int32_t hcr;
	u_int8_t acct_status;
	u_int8_t fwAction;

} radius_pkt;

/*
 * @Prototypes
 */
u_int8_t decode_radius_packet(const u_char *packet_data, radius_pkt *radius_pkt);


#endif //_DECODE_RADIUS_H
