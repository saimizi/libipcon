/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#define IPCON_GENL_NAME		"ipcon"
#define IPCON_MAX_SRV_NAME_LEN	32

enum {
	IPCON_ATTR_REAL_SIZE,
	IPCON_ATTR_PORT_ID,
	IPCON_ATTR_SRV_NAME,
	IPCON_ATTR_SRV_GROUP,
	IPCON_ATTR_LAST
};

/* IPCON commands */
enum {
	IPCON_GET_SELFID = 0x11,
	IPCON_SRV_REG = 0x12,
	IPCON_SRV_UNREG = 0x13,
	IPCON_SRV_DUMP = 0x14,
	IPCON_SRV_RESLOVE = 0x15,
	IPCON_GROUP_RESLOVE = 0x16,
	IPCON_USER = 0x17,
	IPCON_MULICAST_EVENT = 0x18,
	MSG_MAX,
};

#endif
