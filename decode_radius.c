//
//                       _oo0oo_
//                      o8888888o
//                      88" . "88
//                      (| -_- |)
//                      0\  =  /0
//                    ___/`---'\___
//                  .' \\|     |// '.
//                 / \\|||  :  |||// \
//                / _||||| -:- |||||- \
//               |   | \\\  -  /// |   |
//               | \_|  ''\---/''  |_/ |
//               \  .-\__  '-'  ___/-. /
//             ___'. .'  /--.--\  `. .'___
//          ."" '<  `.___\_<|>_/___.' >' "".
//         | | :  `- \`.;`\ _ /`;.`/ - ` : | |
//         \  \ `_.   \_ __\ /__ _/   .-` /  /
//     =====`-.____`.___ \_____/___.-`___.-'=====
//                       `=---='
//
//
//     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*
 * decode_radius.c
 *
 * Author: Mehul Prajapati
 */

/*
 * @Includes
 */
#include "decode_radius.h"
#include <string.h>
#include <stdlib.h>


/*
 * @Function Prototype
 */
static const u_int8_t* pkt_get_offset(const u_char *packet_data, const int offset);
u_int8_t pkt_get_uint8(const u_char *packet_data, const int offset);
u_int16_t pkt_get_uint16(const u_char *packet_data, const int offset);
void *pkt_memcpy(const u_char *packet_data, void *target, const int offset, size_t length);

/*
 * @Function definitions
 */
u_int8_t decode_radius_packet(const u_char *packet_data, radius_pkt *pRadiusPkt)
{
	u_int16_t idx, offset, pkt_len;
	u_int8_t hcrLen = 0;
	char hcr[20] = "";
	struct radius_attr *ra;
	char attrValBuf[RADIUS_VSA_BUF_LEN_MAX] = "";
	char vsaBuf[RADIUS_VSA_BUF_LEN_MAX] = "";
	char *pAttrName = NULL, *pHcrStart = NULL, *pHcrEnd = NULL;
	u_int32_t attrVal = 0;

	if (NULL == packet_data || NULL == pRadiusPkt)
	{
		printf("ERR: Packet data pointing to null\n");
		return false;
	}

	/* init */
	memset(pRadiusPkt, 0, sizeof(radius_pkt));

	/* Decode Radius packet header */
	pRadiusPkt->rhdr.rh_code = pkt_get_uint8(packet_data, 0);
	pRadiusPkt->rhdr.rh_ident = pkt_get_uint8(packet_data, 1);
	pRadiusPkt->rhdr.rh_pktlength = pkt_get_uint16(packet_data, 2);

	pkt_len = pRadiusPkt->rhdr.rh_pktlength;
	printf("%s Packet: identity: %x len: %x\n", rad_code_str(pRadiusPkt->rhdr.rh_code), \
			pRadiusPkt->rhdr.rh_ident, pRadiusPkt->rhdr.rh_pktlength);

	/* Decode auth */
	pkt_memcpy(packet_data, pRadiusPkt->rhdr.authenticator, 4, AUTHENTICATOR_LENGTH);

	printf("Auth: ");
	for (idx = 0; idx < AUTHENTICATOR_LENGTH; idx++)
	{
		printf("%x", *(pRadiusPkt->rhdr.authenticator + idx));
	}
	printf("\n");

	/* Set offset after header */
	offset = HDR_LENGTH;

	/* Attribute init */
	rad_init();

	/* Decode attributes */
	while (offset < pkt_len)
	{
		ra = (struct radius_attr *)(packet_data + offset);

		offset += ra->len;

		/* Clear buffers */
		memset(attrValBuf, 0x00, sizeof(attrValBuf));
		memset(vsaBuf, 0x00, sizeof(vsaBuf));

		/* Name of Attr */
		pAttrName = rad_attr_name(ra);
		printf("Attr: %s = ", pAttrName);

		/* Value of Attr */
		rad_print_attr_val(ra, attrValBuf, &attrVal);

		printf("\n");

		/* fill up attrs in data structure */
		if (!strcmp(pAttrName, RADIUS_ATTR_FRAMED_IP_ADDR_STR))
		{
			strcpy(pRadiusPkt->framed_ip_addr, attrValBuf);
			if (!inet_aton(pRadiusPkt->framed_ip_addr, &pRadiusPkt->framed_ip_in_addr)) return false;
		}
		else if (!strcmp(pAttrName, RADIUS_ATTR_VENDOR_SPECIFIC_STR))
		{
			/* vsa - 3gpp */
			rad_vendor_specific_attr_name(vsaBuf);

			/* IMSI */
			if (!strcmp(vsaBuf, RADIUS_VENDOR_NAME_3GPP_IMSI))
			{
				pRadiusPkt->rVsa3gpp.imsi = atoll(attrValBuf);
				if (!pRadiusPkt->rVsa3gpp.imsi) return false;
			}
			/* Fire-wall Action */
			else if (!strcmp(vsaBuf, RADIUS_ATTR_VENDOR_MIL_FW_ACT))
			{
				pRadiusPkt->fwAction = atoi(attrValBuf);
			}
			/* Session Stop */
			else if (!strcmp(vsaBuf, RADIUS_VENDOR_NAME_3GPP_SESSION_STOP))
			{
				pRadiusPkt->rVsa3gpp.session_stop_id = atoi(attrValBuf);
			}
		}
		/* Class string */
		else if (!strcmp(pAttrName, RADIUS_ATTR_CLASS_STR))
		{
			pHcrStart = strstr(attrValBuf, RADIUS_ATTR_CLASS_HCR);

			if (NULL != pHcrStart)
			{
				pHcrEnd = strchr(pHcrStart, RADIUS_ATTR_CLASS_HCR_DELIM);

				/* Parse HCR */
				if (NULL != pHcrEnd)
				{
					hcrLen = pHcrEnd - pHcrStart - strlen(RADIUS_ATTR_CLASS_HCR);
					memcpy(hcr, pHcrStart + strlen(RADIUS_ATTR_CLASS_HCR), hcrLen);
					hcr[hcrLen] = '\0';

					pRadiusPkt->hcr = atoi(hcr);
				}

			}
		}
		/* Acct Status string */
		else if (!strcmp(pAttrName, RADIUS_ATTR_ACCT_STATUS_STR))
		{
			pRadiusPkt->acct_status = atoi(attrValBuf);
		}
	}

	return true;
}

u_int8_t pkt_get_uint8(const u_char *packet_data, const int offset)
{
	const u_int8_t *ptr;

	if (offset < 0 || NULL == packet_data)
	{
		printf("ERR: Invalid input packet_data\n");
		return 0;
	}

	ptr = pkt_get_offset(packet_data, offset);

	if (!ptr)
	{
		return 0;
	}
	else
	{
		return *ptr;
	}
}

u_int16_t pkt_get_uint16(const u_char *packet_data, const int offset)
{
	const u_int8_t *ptr;

	if (offset < 0 || NULL == packet_data)
	{
		printf("ERR: Invalid input packet_data\n");
		return 0;
	}

	ptr = pkt_get_offset(packet_data, offset);

	if (!ptr)
	{
		return 0;
	}
	else
	{
		return pkt_ntoh16(ptr);
	}
}

static const u_int8_t* pkt_get_offset(const u_char *packet_data, const int offset)
{
	if (offset < 0 || NULL == packet_data)
	{
		printf("ERR: Invalid input packet_data or offset\n");
		return NULL;
	}

	return packet_data + offset;
}

void *pkt_memcpy(const u_char *packet_data, void *target, const int offset, size_t length)
{
	if (offset < 0 || NULL == packet_data || NULL == target)
	{
		printf("ERR: Invalid input packet_data or target str or offset\n");
		return NULL;
	}

	return memcpy(target, packet_data + offset, length);
}

