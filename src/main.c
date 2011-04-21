//---------------------------------------------------------------------------
// OllyCallTrace - A Call Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
//
// Based on the stack_integrity_monitor.py script by pedram:
//     https://www.openrce.org/blog/view/723/Pin_Pointing_Stack_Smashes
//
//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "Plugin.h"
#include "list.h"
//---------------------------------------------------------------------------
#pragma link ".\\bin\\OllyDbg.lib"
//---------------------------------------------------------------------------
#define OLLYCT_NAME          "OllyCallTrace"
#define OLLYCT_VERSION       "1.0"
#define OLLYCT_ABOUT		 "By Stephen Fewer of Harmony Security (www.harmonysecurity.com)"
#define BUFFER_SIZE	         256
#define SYSTEM_ADDRESS       0x70000000
//---------------------------------------------------------------------------
typedef struct _LOGDATA
{
	DWORD dwAddress;
	DWORD dwSize;
	DWORD dwType;
	char cMessage[BUFFER_SIZE];
	char cHint[BUFFER_SIZE];
	BYTE bAlert;
	DWORD dwInstructionAddress;
} LOGDATA, * LPLOGDATA;
//---------------------------------------------------------------------------
HINSTANCE hDll               = NULL;
HANDLE hOllyWindow           = NULL;
PLLIST pList                 = NULL;
DWORD dwPreviousStackBase    = NULL;
DWORD dwMainModuleLimit      = NULL;
DWORD dwMainModuleBase       = NULL;
int iIndent                  = -1;
volatile BOOL bEnabled       = FALSE;
volatile BOOL bSkipDeepCalls = TRUE;
char cLogWindowClass[32]     = { 0 };
t_table logtable             = { 0 };
//---------------------------------------------------------------------------
int WINAPI DllEntryPoint( HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved )
{
  if( dwReason == DLL_PROCESS_ATTACH )
	hDll = hInstance;
  return 1;
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Plugindata( char cShortname[32] )
{
  strcpy( cShortname, OLLYCT_NAME );
  return PLUGIN_VERSION;
}
//---------------------------------------------------------------------------
int LogWindowGetText( char * cpBuffer, char * pMask, int * pSelect, t_sortheader * pHeader, int iColumn )
{
	int i = 0;
	LPLOGDATA pLogData = (LPLOGDATA)pHeader;

	if( iColumn == 0 )
	{
		*pSelect = DRAW_GRAY;
		i = snprintf( cpBuffer, BUFFER_SIZE, "%.8X", pLogData->dwInstructionAddress );
	}
	else if( iColumn == 1 )
	{
		i = snprintf( cpBuffer, BUFFER_SIZE, "%s", pLogData->cMessage );
		if( !pLogData->bAlert )
		{
			*pSelect = DRAW_MASK;
			if( pLogData->dwInstructionAddress > SYSTEM_ADDRESS )
				memset( pMask, DRAW_DIRECT|BROWN, i );
			else if( pLogData->dwInstructionAddress < dwMainModuleBase || pLogData->dwInstructionAddress > dwMainModuleLimit )
				memset( pMask, DRAW_DIRECT|GREEN, i );
			else
				memset( pMask, DRAW_DIRECT|BLUE, i );
		}
	}
	else if( iColumn == 2 )
	{
		*pSelect = DRAW_GRAY;
		i = snprintf( cpBuffer, BUFFER_SIZE, "%s", pLogData->cHint );
	}

	if( pLogData->bAlert )
		*pSelect = DRAW_HILITE;

	return i;
}
//---------------------------------------------------------------------------
void CreateLogWindow( void )
{
	if( logtable.bar.nbar == 0 )
	{
		logtable.bar.name[0]    = "Address";
		logtable.bar.defdx[0]   = 10;
		logtable.bar.mode[0]    = BAR_NOSORT;
		logtable.bar.name[1]    = "Call/Return";
		logtable.bar.defdx[1]   = 64;
		logtable.bar.mode[1]    = BAR_NOSORT;
		logtable.bar.name[2]    = "Hint";
		logtable.bar.defdx[2]   = 64;
		logtable.bar.mode[2]    = BAR_NOSORT;
		logtable.bar.nbar       = 3;
		logtable.mode           = TABLE_COPYMENU|TABLE_APPMENU|TABLE_SAVEPOS|TABLE_ONTOP;
		logtable.drawfunc       = LogWindowGetText;
	}
	Quicktablewindow( &logtable, 15, 3, cLogWindowClass, "OllyCallTrace - Log" );
}
//---------------------------------------------------------------------------
LRESULT CALLBACK LogWindowProc( HWND hw,UINT msg,WPARAM wp,LPARAM lp)
{
	LPLOGDATA pLogData;

	switch( msg )
	{
		case WM_DESTROY:
		case WM_MOUSEMOVE:
		case WM_LBUTTONDOWN:
		case WM_LBUTTONDBLCLK:
		case WM_LBUTTONUP:
		case WM_RBUTTONDOWN:
		case WM_RBUTTONDBLCLK:
		case WM_HSCROLL:
		case WM_VSCROLL:
		case WM_TIMER:
		case WM_SYSKEYDOWN:
		case WM_USER_SCR:
		case WM_USER_VABS:
		case WM_USER_VREL:
		case WM_USER_VBYTE:
		case WM_USER_STS:
		case WM_USER_CNTS:
		case WM_USER_CHGS:
		case WM_USER_MENU:
		case WM_KEYDOWN:
			return Tablefunction( &logtable, hw, msg, wp, lp );
		case WM_USER_DBLCLK:
			pLogData = (LPLOGDATA)Getsortedbyselection( &(logtable.data), logtable.data.selected );
			if ( pLogData != NULL )
				Setcpu( 0, pLogData->dwInstructionAddress, 0, 0, CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS );
			return 1;
		case WM_USER_CHALL:
		case WM_USER_CHMEM:
			InvalidateRect( hw, NULL, FALSE );
			return 0;
		case WM_PAINT:
			Painttable( hw, &logtable, LogWindowGetText );
			return 0;
		default: break;
	}
	return DefMDIChildProc( hw, msg, wp, lp );
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Plugininit( int iOllyVersion, HWND hWindow, DWORD * features )
{
	if( iOllyVersion < PLUGIN_VERSION )
		return -1;

	hOllyWindow = hWindow;

	bEnabled = FALSE;

	if( Createsorteddata( &(logtable.data), NULL, sizeof(LOGDATA), 64, NULL, NULL ) != 0 )
		return -1;

	if( Registerpluginclass( cLogWindowClass, NULL, hDll, LogWindowProc ) < 0 )
	{
		Destroysorteddata( &(logtable.data) );
		return -1;
	}

	pList = ListNew();

	Addtolist( 0, 0, "%s plugin v%s", OLLYCT_NAME, OLLYCT_VERSION );
	Addtolist( 0, -1, "  %s", OLLYCT_ABOUT );

	return 0;
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Plugindestroy( void )
{
	Unregisterpluginclass( cLogWindowClass );
	Destroysorteddata( &(logtable.data) );
	ListDelete( pList );
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Pluginreset( void )
{
	bEnabled = FALSE;
	Destroysorteddata( &(logtable.data) );
	if( Createsorteddata( &(logtable.data), NULL, sizeof(LOGDATA), 64, NULL, NULL ) == 0 )
	{
		ListDelete( pList );
		pList = ListNew();
	}
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Pluginmenu( int iOrigin, char cData[4096], LPVOID lpItem )
{
	switch( iOrigin )
	{
		case PM_MAIN:
			strcpy( cData, "0 &Enable/Disable,1 &View Log,|2 &About" );
			return 1;
		default:
			break;
	}
	return 0;
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Pluginaction( int iOrigin, int iAction, LPVOID lpItem )
{
	char cBuffer[BUFFER_SIZE];
	t_module *  m;

	if( iOrigin == PM_MAIN )
	{
		switch( iAction )
		{
			// Enable/Disable
			case 0:
				if( bEnabled )
					bEnabled = FALSE;
				else
					bEnabled = TRUE;

				m = Findmodule( Plugingetvalue( VAL_MAINBASE ) );
				if( m != NULL )
				{
					dwMainModuleBase = m->codebase;
					dwMainModuleLimit = m->codebase + m->codesize;
				}
				else
				{
					dwMainModuleBase = NULL;
					dwMainModuleLimit = NULL;
				}
				Flash( "%s %s.", OLLYCT_NAME, ( bEnabled ? "Enabled" : "Disabled" ) );
				break;

			// View Log
			case 1:
				CreateLogWindow();
				break;

			// About
			case 2:
				snprintf( cBuffer, BUFFER_SIZE, "%s v%s\n%s", OLLYCT_NAME, OLLYCT_VERSION, OLLYCT_ABOUT );
				MessageBox( hOllyWindow, cBuffer, "About", MB_OK|MB_ICONINFORMATION );
				break;

			default:
				break;
		}
	}
}
//---------------------------------------------------------------------------
int  _export cdecl ODBG_Pausedex( int iReason, int iExtData, t_reg * pRegisters, DEBUG_EVENT * pDebugEvent )
{
	int iCommandLenth, iStepMode, i;
	DWORD dwReturnAddress, dwSkipAddress;
	char cBuffer[BUFFER_SIZE], cSymbol[BUFFER_SIZE];
	t_disasm DisasmCommand;
	BYTE bInstStr[MAXCMDSIZE];
	LPSTACKDATA pStackData;
	LPLOGDATA pLogData;

	// only continue if OllyCallTrace is enabled
	if( !bEnabled || pRegisters == NULL )
		return 0;

	// read in the command at the current EIP
	iCommandLenth = Readcommand( pRegisters->ip, (PCHAR)bInstStr );
	if( iCommandLenth == 0 )
		return 0;

	// disassemble it...
	iCommandLenth = Disasm( bInstStr, MAXCMDSIZE, pRegisters->ip, NULL, &DisasmCommand, DISASM_ALL, Getcputhreadid() );
	if( iCommandLenth == 0 )
		return 0;

	// by default we want to single step...
	iStepMode = STEP_IN;
	dwSkipAddress = 0;

	switch( DisasmCommand.cmdtype )
	{
		// process a call...
		case C_CAL:
			dwReturnAddress = pRegisters->ip + iCommandLenth;

			// step over any 'deep' calls into system dll's
			if( bSkipDeepCalls && dwReturnAddress > SYSTEM_ADDRESS )
			{
				iStepMode = STEP_OVER;
			}
			else
			{
				iIndent++;

				memset( cBuffer, 0x00, BUFFER_SIZE );
				for( i=0 ; i<iIndent*4 ; i++ )
					cBuffer[i] = ' ';

				pLogData = (LPLOGDATA)malloc( sizeof(LOGDATA) );
				memset( pLogData, 0, sizeof(LOGDATA) );

				pLogData->dwInstructionAddress = pRegisters->ip;

				if( Decodeaddress( DisasmCommand.jmpaddr, 0, ADC_VALID|ADC_JUMP, cSymbol, BUFFER_SIZE, NULL ) == 0 )
					snprintf( cSymbol, BUFFER_SIZE, "%.8X", DisasmCommand.jmpaddr );
				snprintf( pLogData->cMessage, BUFFER_SIZE, "%sCall to %s", cBuffer, cSymbol );

				if( Decodeaddress( dwReturnAddress, 0, ADC_VALID|ADC_JUMP, cSymbol, BUFFER_SIZE, NULL ) == 0 )
					snprintf( cSymbol, BUFFER_SIZE, "%.8X", dwReturnAddress );
				snprintf( pLogData->cHint, BUFFER_SIZE, "Should return to %s", cSymbol );

				Addsorteddata( &(logtable.data), pLogData );

				pStackData = (LPSTACKDATA)malloc( sizeof(STACKDATA) );
				pStackData->dwCallerIP = pRegisters->ip;
				pStackData->dwReturnLocation = pRegisters->r[REG_ESP] - 4;
				pStackData->dwReturnAddress  = dwReturnAddress;
				ListInsert( pList, pStackData );
			}

			break;

		// process a return...
		case C_RET:
			pStackData = ListFind( pList, pRegisters->r[REG_ESP] );

			memset( cBuffer, 0x00, BUFFER_SIZE );
			for( i=0 ; i<iIndent*4 ; i++ )
				cBuffer[i] = ' ';

			pLogData = (LPLOGDATA)malloc( sizeof(LOGDATA) );
			memset( pLogData, 0, sizeof(LOGDATA) );
			pLogData->dwInstructionAddress = pRegisters->ip;

			if( Decodeaddress( DisasmCommand.jmpaddr, 0, ADC_VALID|ADC_JUMP, cSymbol, BUFFER_SIZE, NULL ) == 0 )
				snprintf( cSymbol, BUFFER_SIZE, "%.8X", DisasmCommand.jmpaddr );

			if( pStackData == NULL )
			{
				snprintf( pLogData->cMessage, BUFFER_SIZE, "%sReturn to %s", cBuffer, cSymbol );
				snprintf( pLogData->cHint, BUFFER_SIZE, "Failed to find corresponding call" );
				pLogData->bAlert = TRUE;
			}
			else if( pStackData->dwReturnAddress != DisasmCommand.jmpaddr )
			{
				snprintf( pLogData->cMessage, BUFFER_SIZE, "%sReturn to %s", cBuffer, cSymbol );
				snprintf( pLogData->cHint, BUFFER_SIZE, "Should be returning to 0x%.8X, called from 0x%.8X", pStackData->dwReturnAddress, pStackData->dwCallerIP );
				pLogData->bAlert = TRUE;
			}
			else
			{
				snprintf( pLogData->cMessage, BUFFER_SIZE, "%sReturn to %s", cBuffer, cSymbol );
				snprintf( pLogData->cHint, BUFFER_SIZE, "" );
			}

			Addsorteddata( &(logtable.data), pLogData );

			ListRemove( pList, pStackData );

			iIndent--;
			break;

		// step over any repeating instructions...
		case C_REP:
			iStepMode = STEP_SKIP;
			dwSkipAddress = pRegisters->ip + iCommandLenth;
			break;

		default:
			break;
	}

	// resume execution...
	Go( 0, dwSkipAddress, iStepMode, 1, 1 );

	return 0;
}
//---------------------------------------------------------------------------
