#include <stdlib.h>

#include "list.h"

PLLIST ListNew( void )
{
	PLLIST List  = (PLLIST)malloc( sizeof(LLIST) );
	List->Head    = NULL;
    List->Tail    = NULL;
	List->dwLength  = 0;
	return List;
}

PLNODE ListInsert( PLLIST List, LPSTACKDATA pStackData )
{
	PLNODE node = (PLNODE)malloc( sizeof(LNODE) );

	node->pStackData  = pStackData;
	node->Next  = NULL;
	node->Prev  = NULL;

	List->dwLength++;

    if ( List->Tail != NULL )
    {
	    List->Tail->Next = node;
		node->Prev = List->Tail;

		List->Tail = List->Tail->Next;
	}
	else
	{
		List->Head = node;
		List->Tail = node;
	}

	return List->Tail;
}

void ListRemove( PLLIST List, LPSTACKDATA pStackData )
{
	PLNODE node = List->Tail;

	if( pStackData == NULL )
		return;
	
	while( node != NULL )
	{
		if( node->pStackData == pStackData )
			break;
		node = node->Prev;
	}

	if( node )
	{
		if ( List->dwLength != 0 )
		{
			if ( --List->dwLength != 0 )
			{
				if ( List->Head == node )
				{
					List->Head = List->Head->Next;
					List->Head->Prev = NULL;
				}
				else if ( List->Tail == node )
				{
					List->Tail = List->Tail->Prev;
					List->Tail->Next = NULL;
				}
				else 
				{
					node->Next->Prev = node->Prev;
					node->Prev->Next = node->Next;
				}
			}
			else
			{
				List->Head = NULL;
				List->Tail = NULL;
			}

			free( node->pStackData );
			free( node );
		}
	}
}

void ListDelete( PLLIST List )
{
	PLNODE node;
	PLNODE tmp;

	if( List == NULL )
		return;

	node = List->Head;

	while( node != NULL )
	{
    	tmp = node->Next;
		free( node->pStackData );
		free( node );
	    node = tmp;
	}

	free( List );
}

LPSTACKDATA ListFind( PLLIST List, DWORD dwReturnLocation )
{
	PLNODE node = List->Tail;

	while( node != NULL )
	{
		if( node->pStackData->dwReturnLocation == dwReturnLocation )
			break;
		node = node->Prev;
	}

	if( node )
		return node->pStackData;
	else
		return NULL;
}


