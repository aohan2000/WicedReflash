/*++
Copyright (c) 2014 Cypress Semiconductor Corporation. All Rights Reserved.

Module Name:

Global.h

Abstract:

Declare data type and other global definitions and functions.

Environment:

User mode

Revision History:

--*/
#ifndef _GLOBAL_H_
#define _GLOBAL_H_

typedef unsigned char	CY_U8;
typedef unsigned short	CY_U16;
typedef unsigned int	CY_U32;
typedef void *		CY_PTR;
#include <windows.h>
typedef ULONGLONG CY_U64;
typedef int CY_RESULT;

static __inline CY_U64 CPU_TO_BE64(CY_U64 x)
{
    CY_U8 *p = (CY_U8 *)&x;
    return ((CY_U64)p[0] << 56) |
        ((CY_U64)p[1] << 48) |
        ((CY_U64)p[2] << 40) |
        ((CY_U64)p[3] << 32) |
        ((CY_U64)p[4] << 24) |
        ((CY_U64)p[5] << 16) |
        ((CY_U64)p[6] << 8) |
        p[7];
}

static __inline CY_U32 CPU_TO_BE32(CY_U32 x)
{
    CY_U8 *p = (CY_U8 *)&x;
    return ((CY_U32)p[0] << 24) |
        ((CY_U32)p[1] << 16) |
        ((CY_U32)p[2] << 8) | p[3];
}

static __inline CY_U16 CPU_TO_BE16(CY_U16 x)
{
    return ((CY_U8)x << 8) | (x >> 8);
}

#define BE16_TO_CPU(x) CPU_TO_BE16(x)
#define BE32_TO_CPU(x) CPU_TO_BE32(x)
#define BE64_TO_CPU(x) CPU_TO_BE64(x)


/*
CY_RESULT value
*/
#define CY_ERROR_SUCCESS 0
#define CY_ERROR_FAILURE -1
#define CY_ERROR_NOT_EXIST -2
#define CY_ERROR_ILLEGAL_OPT -3
#define CY_ERROR_ILLEGAL_OPT_PARAM -4
#define CY_ERROR_SMALL_BUFFER -5
#define CY_ERROR_IOCTL -6
#define CY_ERROR_TIMEOUT -7
#define CY_ERROR_MEMORY_LACK -8
#define CY_ERROR_NOT_SUPPORT -9
#define CY_ERROR_FILE_ACCESS -10
#define CY_ERROR_VERSION -11
#define CY_ERROR_FORMAT -12


#if 1

extern int dbg;

#pragma warning(disable:4127)

#define TDebugPrint(fmt, ...) \
	do {\
			TCHAR *__p = (TCHAR*)fmt;\
			int __level;\
			if (__p[0]==_T('<') && __p[2]==_T('>')) {\
				__level = __p[1] - _T('0');\
				__p += 3;\
			} else\
				__level = 7;\
			if (dbg >= __level){\
				_tprintf(__p, ##__VA_ARGS__);\
			}\
		} while (0)

#define DebugPrint(fmt, ...) \
	do {\
			CHAR *__p = (CHAR*)fmt;\
			int __level;\
			if (__p[0]=='<' && __p[2]=='>') {\
				__level = __p[1] - '0';\
				__p += 3;\
			} else\
				__level = 7;\
			if (dbg >= __level){\
				printf(__p, ##__VA_ARGS__);\
			}\
		} while (0)


#define CY_ASSERT(X) \
	if(!(X)){\
		printf("CY_ASSERT at %s:%d\n", __FILE__, __LINE__);\
		while(1){\
			Sleep(1000);\
		}\
	}

#else

#define TDebugPrint(fmt, ...) 
#define DebugPrint(fmt, ...)
#define CY_ASSERT(X)

#endif

class Log;

class Global
{
public:
    static CY_U32 IntFromHexTStr(LPCTSTR pChars, int& err);
    static CY_U32 IntFromHexStr(LPCSTR pChars, int& err);
    static LPCSTR IntFromStrPrefix(LPCSTR pChars, int& err, int& result);
    static CY_U16 ComputeCrc(CY_U8 *buf, CY_U32 size);
    static CY_U32 ComputeCrc32(CY_U32 crc, CY_U8* buf, CY_U32 len);
    static CY_U8 SUM(CY_U8 *buf, CY_U32 size);
    static void DumpBuffer(CY_U8* pData, CY_U32 len);
    static int DecodeHexStr(LPCSTR pChars, CY_U8* pDecodedBytes);
    static void PressEnterToContinue();
};

#endif