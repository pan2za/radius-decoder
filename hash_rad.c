/* $Id: hash.c,v 1.1.1.1 2004/09/21 15:56:43 iscjonm Exp $
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
#  include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "hash_rad.h"

hash_table_t *hash_new(int num_items) {
  hash_table_t *t = NULL;
  int i;
  
  if ((t = malloc(sizeof(hash_table_t))) == NULL) goto err;
  if ((t->t = calloc(num_items, sizeof(struct list_elem *))) == NULL) goto err;
  t->sz = num_items;
  for(i=0; i<num_items; i++)
    t->t[i] = NULL;
  return t;

 err:
  if (t != NULL) {
    if (t->t != NULL) free(t->t);
    free(t);
  }
  return NULL;
}

int hash_put(hash_table_t *t, unsigned int key, void *item) {
  unsigned int idx = key % t->sz;
  struct list_elem *l = t->t[idx];
  int added = 0;
  
  /* see if it's already in there */
  while(l != NULL) {
    if (l->key == key) {
      /* found it, just update */
      l->item = item;
      added = 1;
      break;
    }
    l = l->next;
  }
  if (!added) {
    /* need to add a new entry */
    if ((l = malloc(sizeof(struct list_elem))) == NULL) return 0;
    l->next = t->t[idx];
    l->key = key;
    l->item = item;
    t->t[idx] = l;
  }
  return 1;
}

void *hash_lookup(hash_table_t *t, unsigned int key) {
  int idx = key % t->sz;
  struct list_elem *l = t->t[idx];

  while(l != NULL) {
    if (l->key == key) return l->item;
    l = l->next;
  }
  return NULL;
}


// ============================================================================
// ================== Packet Radius ===========================================
// ============================================================================
hash_table_rad *hash_new_radius(int num_items)
{
	  hash_table_rad *t = NULL;
	  int i;

	  if ((t = malloc(sizeof(hash_table_rad))) == NULL)
	  {
		  printf("ERROR: malloc failed in function: %s\n", __FUNCTION__);
		  goto err;
	  }

	  if ((t->t = calloc(num_items, sizeof(struct list_elem_rad *))) == NULL)
	  {
		  printf("ERROR: calloc failed in function: %s\n", __FUNCTION__);
		  goto err;
	  }

	  t->sz = num_items;

	  for (i = 0; i < num_items; i++)
		t->t[i] = NULL;

	  return t;

	 err:
	  if (t != NULL)
	  {
		if (t->t != NULL)
		{
			free(t->t);
		}

		free(t);
	  }

	  return NULL;
}


void *hash_lookup_radius(hash_table_rad *t, unsigned int key, char *pIpAddr)
{
	  unsigned int idx = 0;
	  struct list_elem_rad *l;

	  if (NULL == t || NULL == pIpAddr)
	  {
		  printf("ERROR: Invalid input in function: %s\n", __FUNCTION__);
		  return NULL;
	  }

	  idx = key % t->sz;
	  l = t->t[idx];

	  while (l != NULL)
	  {
			if (l->key == key)
			{
				/* node found */
				if (0 == strcmp(pIpAddr, l->ipAddr))
					return l->item;
			}

			l = l->next;
	  }

	  return NULL;
}


int hash_put_radius(hash_table_rad *t, unsigned int key, char *pIpAddr, void *item)
{
	  unsigned int idx = 0;
	  struct list_elem_rad *l = NULL;
	  int added = 0;

	  if (NULL == t || NULL == pIpAddr || NULL == item)
	  {
		  printf("ERROR: Invalid input in function: %s\n", __FUNCTION__);
		  return 0;
	  }

	  /* Map key according to hash table size */
	  idx = key % t->sz;
	  l = t->t[idx];
	  printf("INFO: Hash Key: %d\n", idx);

	  /* Update when same ip and key. So, new IMSI or Call status is available.
	  see if it's already in there */
	  while (l != NULL)
	  {
			if (l->key == key)
			{
			    /* found it, just update */
				if (0 == strcmp(pIpAddr, l->ipAddr))
				{
					if (NULL != l->item)
					{
						printf("INFO: Removing reference of old node\n");
						free(l->item);
						l->item = NULL;
					}

					l->item = item;				/* Update item */
					added = 1;
					printf("INFO: Updating node in hash table\n");
					break;
				}
			}

			l = l->next;
	  }

	  if (!added)
	  {
			/* need to add a new entry */
			if ((l = malloc(sizeof(struct list_elem_rad))) == NULL)
			{
				printf("ERROR: malloc failed for list_elem_rad\n");
				return 0;
			}

			l->next = t->t[idx];	/* Pointing to Head */
			l->key = key;
			l->item = item;
			strcpy(l->ipAddr, pIpAddr);
			t->t[idx] = l;			/* Update head to current */
	  }

	  return 1;
}

int hash_remove_node_radius(hash_table_rad *t, unsigned int key, char *pIpAddr)
{
	  unsigned int idx = 0;
	  struct list_elem_rad *l, *pHead = NULL, *pPrevElem = NULL;

	  if (NULL == t || NULL == pIpAddr)
	  {
		  printf("ERROR: Invalid input in function: %s\n", __FUNCTION__);
		  return 0;
	  }

	  idx = key % t->sz;
	  l = t->t[idx];
	  pHead = l;

	  while (l != NULL)
	  {
			if (l->key == key)
			{
				/* Node found */
				if (0 == strcmp(pIpAddr, l->ipAddr))
				{
					/* Is it the head node ? */
					if (pHead == l)		// Yes
					{
						/* Remove this node reference from list */
						t->t[idx] = t->t[idx]->next;

						if (NULL != l->item)
						{
							/* free all data */
							free(l->item);
							l->next = NULL;
							free(l);

							printf("INFO: Head Node having ip address: %s is removed from hash\n", pIpAddr);

							return 1;
						}
					}
					else // No
					{
						/* Remove this node reference from list */
						pPrevElem->next = l->next;

						if (NULL != l->item)
						{
							/* free all data */
							free(l->item);
							l->next = NULL;
							free(l);
							printf("INFO: Node having ip address: %s is removed from hash\n", pIpAddr);

							return 1;
						}
					}
				}
			}
			pPrevElem = l;
			l = l->next;
	  }

	  return 0;
}

