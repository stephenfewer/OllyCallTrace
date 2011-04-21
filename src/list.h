#ifndef LIST_H
#define LIST_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct _STACKDATA
{
	DWORD dwReturnLocation;
	DWORD dwCallerIP;
	DWORD dwReturnAddress;
} STACKDATA, * LPSTACKDATA;

typedef struct _LNODE
{
	LPSTACKDATA pStackData;
	struct _LNODE * Next;
	struct _LNODE * Prev;
} LNODE, *PLNODE;

typedef struct _LLIST
{
	PLNODE Tail;
	PLNODE Head;
	DWORD dwLength;
} LLIST, *PLLIST;


PLLIST ListNew( void );

PLNODE ListInsert( PLLIST, LPSTACKDATA );

void ListRemove( PLLIST, LPSTACKDATA );

void ListDelete( PLLIST );

LPSTACKDATA ListFind( PLLIST, DWORD );

#endif
