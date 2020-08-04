/*++
Copyright (c) 2014 Cypress Semiconductor Corporation. All Rights Reserved.

Module Name:

CyAcdGen5.h

Abstract:

Common header file

Environment:

User mode

Revision History:

--*/
#pragma once

#include "Global.h"

#pragma pack(push)
#pragma pack(1)

#define WHEX_ROW_START_CHAR ':'
#define WHEX_ROW_TYPE_DATA 0
#define WHEX_ROW_TYPE_END 1 //End Of File
#define WHEX_ROW_TYPE_EXT_SEGMENT_ADDR 2    //16bit segment base address. << 4 + offset
#define WHEX_ROW_TYPE_START_SEGMENT_ADDR 3  //32bit. CS(first 2bytes):IP(latter 2bytes)
#define WHEX_ROW_TYPE_EXT_LINEAR_ADDR 4     //16bit. The two encoded, big endian data bytes specify the upper 16 bits of the 32 bit absolute address for all subsequent type 00 records.
#define WHEX_ROW_TYPE_START_LINEAR_ADDR 5   //32bit. The four data bytes represent the 32-bit value loaded into the EIP register of the 80386 and higher CPU.

#define WHEX_MAX_PAYLOAD_SIZE 0xFB
#define WHEX_HEADER_SIZE 5

#define INVALID_ADDR_VALUE 0xCCCCCCCC

//https://en.wikipedia.org/wiki/Intel_HEX
typedef struct _WICED_HEX_ROW {
    CY_U8 StartChar;    //Start Code
    CY_U8 DataSize;     //Byte Count
    CY_U16 OffsetAddr;   //Offset Address in big endian
    CY_U8 RowType;      //Record type
    CY_U8 Data[WHEX_MAX_PAYLOAD_SIZE + 1]; //Add a checksum
}WICED_HEX_ROW, *PWICED_HEX_ROW;

#pragma pack(pop)

class FwFileWicedHex
{
private:
    int rowCount;
    int allocatedRows;
    PWICED_HEX_ROW pRows;
    UINT8 maxWriteSize;
    UINT32 totalPayloadSize;
    UINT32 nonDataRowCount;
    CY_U64 newBDAddr;

public:
    bool ReCalc(int genCheckSum);
    //Start RAM address was written to. If it is minidriver hex file, this address will be launched before download config hex file.
    UINT32 launchAddress;
    FwFileWicedHex();
    virtual CY_RESULT Load(LPCTSTR fileName);
    virtual UINT8 GetDLMaxWriteSize() { return maxWriteSize; };
    virtual ~FwFileWicedHex();
    CY_U32 GetRowCount();
    PWICED_HEX_ROW FwFileWicedHex::GetRow(int index);
    CY_RESULT UpdateBDAddress(CY_U64 BDAddr);
    void DumpPrint();
    CY_RESULT FwFileWicedHex::GenEmptyHex(UINT32 startAddr, UINT32 len);
};

