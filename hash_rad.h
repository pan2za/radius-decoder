/* $Id: hash.h,v 1.1.1.1 2004/09/21 15:56:43 iscjonm Exp $
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

#ifndef _HASH_RAD_H
#define _HASH_RAD_H

struct list_elem {
  struct list_elem *next;
  unsigned int key;
  void *item;
};

typedef struct {
  unsigned int sz;
  struct list_elem **t;
} hash_table_t;

//-----------------------------//
/* for packet radius */
struct list_elem_rad {
  struct list_elem_rad *next;
  unsigned int key;
  char ipAddr[16];
  void *item;
};

typedef struct {
  unsigned int sz;
  struct list_elem_rad **t;
} hash_table_rad;

hash_table_t *hash_new(int num_items);
int hash_put(hash_table_t *t, unsigned int key, void *item);
void *hash_lookup(hash_table_t *t, unsigned int key);

/* for packet radius */
hash_table_rad *hash_new_radius(int num_items);
void *hash_lookup_radius(hash_table_rad *t, unsigned int key, char *pIpAddr);

int hash_put_radius(hash_table_rad *t, unsigned int key, char *pIpAddr, void *item);
int hash_remove_node_radius(hash_table_rad *t, unsigned int key, char *pIpAddr);


#endif
