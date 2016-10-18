/* $Id: radius.c,v 1.1.1.1 2004/09/21 15:56:44 iscjonm Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "radius.h"
#include "hash_rad.h"

/* adding new attributes:
   if you are adding a vendor-specific attribute, look in vsa.c and
   mk_vsa_dicts.py.
   Otherwise, add your attribute to the rad_attrs array. update
   max_attr if necessary. The fields of the struct are:
     (1) attribute name to display
     (2) attribute type/format (e.g. int, text, binary string)
     (3) print function. if you specify NULL, you get the default
         formatter for the attribute type.
     (4) additional argument to print function. primarily used when
         the attribute is an integer, but there is a dictionary of 
         what the integers are. use rad_format_int_code as the
	 print function, and create a dictionary array as in the
	 examples below */

int verbose=2;

void rad_format_text(struct radius_attr *ra, void *arg);
void rad_format_string(struct radius_attr *ra, void *arg);
void rad_format_addr(struct radius_attr *ra, void *arg);
void rad_format_uint32(struct radius_attr *ra, void *arg);
void rad_format_time_t(struct radius_attr *ra, void *arg);

void rad_format_int_code(struct radius_attr *ra, void *map);
void rad_format_vsa(struct radius_attr *ra, void *arg);
void rad_format_chap_password(struct radius_attr *ra, void *arg);

void (*rad_default_formatters[6])(struct radius_attr *ra, void *arg) = {
  rad_format_text,
  rad_format_string,
  rad_format_addr,
  rad_format_uint32,
  rad_format_time_t,
  NULL,
};

/* Radius vsa buffer */
char rad_vsa_buf[RADIUS_VSA_BUF_LEN_MAX] = "";

char *rad_service_type_dict[] = {
  "",				/* highest known code */
  "Login",
  "Framed",
  "Callback Login",
  "Callback Framed",
  "Outbound",
  "Administrative",
  "NAS Prompt",
  "Authenticate Only",
  "Callback NAS Prompt",
  "Call Check",
  "Callback Administrative",
  NULL
};

char *rad_framed_protocol_dict[] = {
  "",
  "PPP",
  "SLIP",
  "AppleTalk Remote Access Protocol (ARAP)",
  "Gandalf proprietary SingleLink/MultiLink protocol",
  "Xylogics proprietary IPX/SLIP",
  "X.75 Synchronous",
  NULL
};

char *rad_framed_routing_dict[] = {
  "None",
  "Send routing packets",
  "Listen for routing packets",
  "Send and Listen",
  NULL
};  

char *rad_framed_compression_dict[] = {
  "None",
  "VJ TCP/IP header compression",
  "IPX header compression",
  "Stac-LZS compression",
  NULL
};

char *rad_login_service_dict[] = {
  "Telnet",
  "Rlogin",
  "TCP Clear",
  "PortMaster",
  "LAT",
  "X25-PAD",
  "X25-T3POS",
  "TCP Clear Quiet",
  NULL
};

char *rad_termination_action_dict[] = {
  "Default",
  "RADIUS-Request",
  NULL
};

char *rad_acct_status_type_dict[] = {
  "",
  "Start",
  "Stop",
  "Interim-Update",
  "", "", "",
  "Accounting-On",
  "Accounting-Off",
  "", "", "", "", "", "",
  "Failed",
  NULL
};

char *rad_acct_authentic_dict[] = {
  "",
  "RADIUS",
  "Local",
  "Remote",
  NULL
};

char *rad_acct_terminate_cause_dict[] = {
  "",
  "User Request",
  "Lost Carrier",
  "Lost Service",
  "Idle Timeout",
  "Session Timeout",
  "Admin Reset",
  "Admin Reboot",
  "Port Error",
  "NAS Error",
  "NAS Request",
  "NAS Reboot",
  "Port Unneeded",
  "Port Preempted",
  "Port Suspended",
  "Service Unavailable",
  "Callback",
  "User Error",
  "Host Request",
  NULL
};

char *rad_nas_port_type_dict[] = {
  "Async",
  "Sync",
  "ISDN Sync",
  "ISDN Async V.120",
  "ISDN Async V.110",
  "Virtual",
  "PIAFS",
  "HDLC Clear Channel",
  "X.25",
  "X.75",
  "G.3 Fax",
  "SDSL",
  "ADSL-CAP",
  "ADSL-DMT",
  "IDSL",
  "Ethernet",
  "xDSL",
  "Cable",
  "Wireless - Other",
  "Wireless - IEEE 802.11",
  NULL
};

/* see rad_attrs.c for these */
extern struct rad_attr_desc rad_attrs[];
extern unsigned int max_attr;

/* see vsa.c for these */
extern hash_table_t *vendor_dicts;

char *rad_code_str(unsigned char code) {
  switch(code) {
  case RADIUS_ACCESS_REQUEST: return("Access-Request");
  case RADIUS_ACCESS_ACCEPT: return("Access-Accept");
  case RADIUS_ACCESS_REJECT: return("Access-Reject");
  case RADIUS_ACCT_REQUEST: return("Accounting-Request");
  case RADIUS_ACCT_RESPONSE: return("Accounting-Response");
  case RADIUS_ACCESS_CHALLENGE: return("Access-Challenge");
  case RADIUS_STATUS_SERVER: return("Status-Server");
  case RADIUS_STATUS_CLIENT: return("Status-Client");
  default:
    return("?");
  }
}

void rad_format_text(struct radius_attr *ra, void *arg) {
  char *buf = NULL;
  char *cp = NULL;

  if (ra == NULL) return;
  if ((buf = malloc(ra->len - 2 + 1)) == NULL) return;
  memcpy(buf,&(ra->value[0]),ra->len - 2);
  buf[ra->len - 2] = '\0';
  cp = buf;
  while(*cp != '\0') {
    if (isprint(*cp)) {
      printf("%c",*cp);
    } else {
      printf("\\%03o",(unsigned char)(*cp));
    }
    cp++;
  }
  free(buf);
  fflush(stdout);
}

void rad_format_string(struct radius_attr *ra, void *arg) {
  unsigned int i;
  unsigned char c;
  
  if (ra == NULL) return;
  printf("<%d bytes>",ra->len - 2);
  if (verbose >= 2) {
    for(i=0; i<ra->len - 2; i++) {
      if (i % 16 == 0) printf("\n    ");
      c = ra->value[i];
      printf("%02x ",c);
    }
  }
  return;
}

void rad_format_addr(struct radius_attr *ra, void *arg) {
  struct in_addr a;
  
  if (ra == NULL) return;
  memcpy(&a, &(ra->value[0]), sizeof(a));
  printf("%s",inet_ntoa(a));
  return;
}

void rad_format_uint32(struct radius_attr *ra, void *arg) {
  unsigned int n;

  if (ra == NULL) return;
  memcpy(&n, &(ra->value[0]), sizeof(n));
  printf("%d",ntohl(n));
  return;
}

void rad_format_time_t(struct radius_attr *ra, void *arg) {
  time_t t;
  unsigned int n;
  
  if (ra == NULL) return;
  memcpy(&n, &(ra->value[0]), sizeof(n));
  t = (time_t)ntohl(n);
  printf("%s",asctime(localtime(&t)));
  return;
}

char *rad_attr_name(struct radius_attr *ra) {
  return rad_attrs[ra->type].name;
}

void rad_format_int_code(struct radius_attr *ra, void *arg) {
  char **map = arg;
  unsigned int maxval;
  unsigned int val;
  int i;

  if (arg == NULL || ra == NULL) return;
  memcpy(&val, &(ra->value[0]), sizeof(val));
  val = ntohl(val);

  for(i=0; map[i] != NULL; i++) {
    /* nop */;
  }
  maxval = i-1;
  if (val > maxval || strlen(map[val]) == 0) {
    printf("%d (unknown)",val);
    return;
  }
  printf("%d (%s)",val,map[val]);
  return;
}

void rad_format_vsa(struct radius_attr *ra, void *arg) {
  unsigned int vendor;
  struct rad_attr_desc *vendor_attr = NULL;
  void (*f)(struct radius_attr *ra, void *arg) = NULL;
  hash_table_t *vd;
  struct radius_attr *vsa;

  if (ra == NULL) return;
  memcpy(&vendor, &(ra->value[0]), sizeof(vendor));
  vendor = ntohl(vendor);
  if ((vd = hash_lookup(vendor_dicts, vendor)) == NULL) {
    printf("<unknown vendor %d>",vendor);
    return;
  }
  vsa = (struct radius_attr *)&(ra->value[4]);
  if ((vendor_attr = hash_lookup(vd, vsa->type)) == NULL) {
    printf("<unknown VSA %d:%d>",vendor,vsa->type);
    return;
  }
  printf("%s = ",vendor_attr->name);

  /* Copy attr and pass it to calling entity */
  strcpy((char *)arg, vendor_attr->name);

  f = vendor_attr->print;
  if (f != NULL) {
    (*f)(vsa, vendor_attr->fmt_arg);
    return;
  }
  f = rad_default_formatters[vendor_attr->format];
  if (f != NULL) {
    (*f)(vsa, NULL);
    return;
  }
  printf("<formatter not implemented>");
  return;
}

void rad_format_chap_password(struct radius_attr *ra, void *arg) {
  unsigned char id;
  if (ra == NULL) return;
  id = ra->value[2];
  printf("Id:%d, <%d bytes>",id,ra->len - 3);
}

void rad_vendor_specific_attr_name(char *pVsaBuf) {

	if (NULL == pVsaBuf) return;

	strcpy(pVsaBuf, rad_vsa_buf);
}

void rad_print_attr_val(struct radius_attr *ra, char *pBuf, unsigned int *pAttrVal) {
  void (*f)(struct radius_attr *ra, void *arg) = NULL;
  unsigned int vendorId = 0;

  if (ra == NULL || pBuf == NULL || pAttrVal == NULL) return;

  if (ra->type > max_attr) {
    printf("<unknown attribute %d>",ra->type);
    return;
  }
  /* first see if this attribute has a special formatter */
  f = rad_attrs[ra->type].print;
  if (f != NULL)
  {
    (*f)(ra, rad_attrs[ra->type].fmt_arg);

    /* Decode Vendor Attrs */
    if (RADIUS_VENDOR_SPECIFIC_CODE == ra->type)
    {
    	struct radius_attr *vsa;

    	/* Decode Vendor id octets */
		vendorId = pkt_ntoh32(&ra->value[0]);

		/* 3gpp */
		if (RADIUS_3GPP_VENDOR_ID == vendorId)
		{
			/* Skipping Vendor ID e.g.3GPP code - 10415 */
			vsa = (struct radius_attr *)&(ra->value[4]);

			switch (vsa->type) {
				/* IMSI */
				case RADIUS_3GPP_VENDOR_ATTR_TYPE_IMSI:
				case RADIUS_3GPP_VENDOR_ATTR_TYPE_SESSION_STOP:
				   memcpy(pBuf, &(vsa->value[0]), vsa->len - RADIUS_ATTR_HEADER_LEN);
				   pBuf[vsa->len - RADIUS_ATTR_HEADER_LEN] = '\0';
				   break;

				/* MIIPL Specific */
				case RADIUS_MIL_FW_ACTION_TYPE:
					pBuf[0] = vsa->value[0];
					pBuf[1] = '\0';
					break;

				/* Session stop */
				//case RADIUS_3GPP_VENDOR_ATTR_TYPE_SESSION_STOP:

					//*pAttrVal = vsa->value[0];
					//break;

				default:
					break;
			}
		}
    }
	else if (RADIUS_ATTR_ACCT_STATUS_TYPE == ra->type)
	{
		  /* Note - Decoding only last octet of status type */
		  pBuf[0] = ra->value[3] + '0';
		  pBuf[1] = '\0';
	}

    return;
  }

  /* otherwise, use the default formatter for its attribute format */
  f = rad_default_formatters[rad_attrs[ra->type].format];
  if (f != NULL)
  {
		(*f)(ra, NULL);

		/* Copy Framed IP */
		if (RADIUS_ATTR_TYPE_FRAMED_IP_ADDR == ra->type)
	    {
			struct in_addr a;
			memcpy(&a, &(ra->value[0]), sizeof(a));
			strcpy(pBuf, inet_ntoa(a));
	    }
		/* Copy Class whole attr string */
		else if (RADIUS_ATTR_TYPE_CLASS == ra->type)
		{
			   memcpy(pBuf, &(ra->value[0]), ra->len - RADIUS_ATTR_HEADER_LEN);
			   pBuf[ra->len - RADIUS_ATTR_HEADER_LEN] = '\0';
		}

	    return;
  }
  printf("<formatter not implemented>");
  return;
}

unsigned int find_attr(char *attr_name) {
  unsigned int i;
  for(i=0; i<= max_attr; i++) {
    if (strcmp(attr_name, rad_attrs[i].name) == 0) return i;
  }
  return 0;
}

/* defined in vsa.c */
extern void rad_vsa_init();

void rad_init(void) {
  rad_vsa_init();

  rad_attrs[find_attr("Vendor-Specific")].print = rad_format_vsa;
  rad_attrs[find_attr("Vendor-Specific")].fmt_arg =  rad_vsa_buf;	 /* Passing an argument to callback function */

  rad_attrs[find_attr("User-Password")].format = RADIUS_ATTR_STRING;

  rad_attrs[find_attr("CHAP-Password")].format = RADIUS_ATTR_SPECIAL;
  rad_attrs[find_attr("CHAP-Password")].print = rad_format_chap_password;
  rad_attrs[find_attr("Service-Type")].print = rad_format_int_code;
  rad_attrs[find_attr("Service-Type")].fmt_arg = rad_service_type_dict;
  rad_attrs[find_attr("Framed-Protocol")].print = rad_format_int_code;
  rad_attrs[find_attr("Framed-Protocol")].fmt_arg = rad_framed_protocol_dict;
  rad_attrs[find_attr("Framed-Routing")].print = rad_format_int_code;
  rad_attrs[find_attr("Framed-Routing")].fmt_arg = rad_framed_routing_dict;
  rad_attrs[find_attr("Framed-Compression")].print = rad_format_int_code;
  rad_attrs[find_attr("Framed-Compression")].fmt_arg =
    rad_framed_compression_dict;
  rad_attrs[find_attr("Login-Service")].print = rad_format_int_code;
  rad_attrs[find_attr("Login-Service")].fmt_arg = rad_login_service_dict;
  rad_attrs[find_attr("Termination-Action")].print = rad_format_int_code;
  rad_attrs[find_attr("Termination-Action")].fmt_arg = 
    rad_termination_action_dict;
  rad_attrs[find_attr("Acct-Status-Type")].print = rad_format_int_code;
  rad_attrs[find_attr("Acct-Status-Type")].fmt_arg = 
    rad_acct_status_type_dict;
  rad_attrs[find_attr("Acct-Authentic")].print = rad_format_int_code;
  rad_attrs[find_attr("Acct-Authentic")].fmt_arg = rad_acct_authentic_dict;
  rad_attrs[find_attr("Acct-Terminate-Cause")].print = rad_format_int_code;
  rad_attrs[find_attr("Acct-Terminate-Cause")].fmt_arg = 
    rad_acct_terminate_cause_dict;
  rad_attrs[find_attr("NAS-Port-Type")].print = rad_format_int_code;
  rad_attrs[find_attr("NAS-Port-Type")].fmt_arg = rad_nas_port_type_dict;

  /* make sure we didn't mess up anywhere above -- find_attr() returns
     0 if it couldn't find an attribute name, so if we had a typo on
     the attribute, we'll overwrite the first slot */
  if (rad_attrs[0].print != NULL) {
    fprintf(stderr,"%s:%d: attribute name typo in rad_init()\n",
	    __FILE__,__LINE__);
    exit(EXIT_FAILURE);
  }
}
