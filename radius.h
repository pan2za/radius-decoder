/* $Id: radius.h,v 1.1.1.1 2004/09/21 15:56:44 iscjonm Exp $
 *
 * Copyright (C) 2004 The Trustees of the University of Pennsylvania
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _RADIUS_H
#define _RADIUS_H

struct radius_hdr {
  unsigned char code;		/* type of RADIUS packet */
  unsigned char ident;		/* "session" identifier */
  unsigned short len;		/* length in octets of entire packet
				   including RADIUS header */
  unsigned char auth[16];	/* authenticator field */
};

struct radius_attr {
  unsigned char type;		/* attribute type */
  unsigned char len;		/* attribute length in octets,
				   including type and length fields */

  unsigned char value[4];	/* for comparing Vendor ids */

  /* unsigned char value[2];	 note that value can be arbitrary
				   length, but we make it two bytes
				   for alignment purposes */
};

/*
 * @Defines
 */
#define pkt_ntoh16(p)   ((u_int16_t)                       \
                     ((u_int16_t)*((const u_int8_t *)(p)+0)<<8|  \
                      (u_int16_t)*((const u_int8_t *)(p)+1)<<0))

#define pkt_ntoh24(p)  ((u_int32_t)*((const u_int8_t *)(p)+0)<<16|  \
                     (u_int32_t)*((const u_int8_t *)(p)+1)<<8|   \
                     (u_int32_t)*((const u_int8_t *)(p)+2)<<0)

#define pkt_ntoh32(p)   ((u_int32_t)*((const u_int8_t *)(p)+0)<<24|  \
                     (u_int32_t)*((const u_int8_t *)(p)+1)<<16|  \
                     (u_int32_t)*((const u_int8_t *)(p)+2)<<8|   \
                     (u_int32_t)*((const u_int8_t *)(p)+3)<<0)

#define RADIUS_ACCESS_REQUEST       1
#define RADIUS_ACCESS_ACCEPT        2
#define RADIUS_ACCESS_REJECT        3
#define RADIUS_ACCT_REQUEST         4
#define RADIUS_ACCT_RESPONSE        5
#define RADIUS_ACCESS_CHALLENGE    11
#define RADIUS_STATUS_SERVER       12
#define RADIUS_STATUS_CLIENT       13
#define RADIUS_VSA_BUF_LEN_MAX     150
#define RADIUS_ATTR_HEADER_LEN     2


#define RADIUS_VENDOR_SPECIFIC_CODE								26
#define RADIUS_3GPP_VENDOR_ID									10415
#define RADIUS_3GPP_VENDOR_ATTR_TYPE_IMSI						1
#define RADIUS_3GPP_VENDOR_ATTR_TYPE_SESSION_STOP				11
#define RADIUS_ATTR_TYPE_FRAMED_IP_ADDR							8
#define RADIUS_ATTR_TYPE_CLASS									25
#define RADIUS_ATTR_ACCT_STATUS_TYPE							40
#define RADIUS_ATTR_ACCT_STATUS_START							1
#define RADIUS_ATTR_ACCT_STATUS_STOP							2
#define RADIUS_ATTR_ACCT_STATUS_INTRM_UPDATE					3
#define RADIUS_ATTR_ACCT_STATUS_ACCOUNT_ON						7
#define RADIUS_ATTR_ACCT_STATUS_ACCOUNT_OFF						8
#define RADIUS_ATTR_MIL_FW_ACTIVATE_REQ							1
#define RADIUS_ATTR_MIL_FW_DEACTIVATE_REQ						2
#define RADIUS_ATTR_3GPP_SESSION_STOP_VAL						0xFF

#define RADIUS_ATTR_FRAMED_IP_ADDR_STR				"Framed-IP-Address"
#define RADIUS_ATTR_VENDOR_SPECIFIC_STR				"Vendor-Specific"
#define RADIUS_ATTR_CLASS_STR						"Class"
#define RADIUS_ATTR_ACCT_STATUS_STR					"Acct-Status-Type"

#define RADIUS_VENDOR_NAME_3GPP_IMSI				"3GPP-IMSI"
#define RADIUS_VENDOR_NAME_3GPP_SESSION_STOP		"3GPP-Session-Stop-Indicator"
#define RADIUS_ATTR_CLASS_HCR						"HCR="
#define RADIUS_ATTR_CLASS_HCR_DELIM					':'
#define RADIUS_ATTR_VENDOR_MIL_FW_ACT				"MIL-Firewall-Action-Type"


/*
 * @Definitions
 */
typedef enum {
  RADIUS_ATTR_TEXT,
  RADIUS_ATTR_STRING,
  RADIUS_ATTR_ADDR,
  RADIUS_ATTR_UINT32,
  RADIUS_ATTR_TIME_T,
  RADIUS_ATTR_SPECIAL
} rad_format_t;

typedef enum {
	RADIUS_MIL_FW_ACTION_TYPE   		= 30,
	RADIUS_MIL_FW_ADDRESS_TYPE  		= 31,
	RADIUS_MIL_FW_RULE    				= 32,
	RADIUS_MIL_NAT_IP     				= 33,
	RADIUS_MIL_HHME_TIME_REF   			= 37,
	RADIUS_MIL_FW_RULE_TYPE   			= 38,
	RADIUS_MIL_MLANs     				= 39,
	RADIUS_MIL_UPDATE_FRAMEDIP_RULES  	= 40
} miipl_firewall_t;

struct rad_attr_desc {
  char *name;
  rad_format_t format;
  void (*print)(struct radius_attr *ra, void *arg);
  void *fmt_arg;
};

struct vendor_dict {
  unsigned int max_attr;
  struct rad_attr_desc *attrs;
};

extern char *rad_code_str(unsigned char code);
extern char *rad_attr_name(struct radius_attr *ra);
extern void rad_print_attr_val(struct radius_attr *ra, char *pBuf, unsigned int *pAttrVal);
extern void rad_init(void);
extern void rad_vendor_specific_attr_name(char *pVsaBuf);

#endif
