/*++
Copyright (c) 2014 Cypress Semiconductor Corporation. All Rights Reserved.

Module Name:

FwFileWicedHex.cpp

Abstract:



Environment:

User mode

Revision History:

--*/
#include <tchar.h>
#include <basetyps.h>
#include <stdlib.h>
#include <stdio.h>
#include <wtypes.h>
#include "FwFileWicedHex.h"

#define HEX_ROW_SIZE(_PHexRow_) (WHEX_HEADER_SIZE + (_PHexRow_)->DataSize + 1)

FwFileWicedHex::FwFileWicedHex()
{
    allocatedRows = 256;
    pRows = (PWICED_HEX_ROW)calloc(allocatedRows, sizeof(WICED_HEX_ROW));
    rowCount = 0;
    maxWriteSize = 0;
    totalPayloadSize = 0;
    nonDataRowCount = 0;
    launchAddress = INVALID_ADDR_VALUE; //Invalid addrr.
    newBDAddr = 0;
}

FwFileWicedHex::~FwFileWicedHex()
{
    if (pRows) free(pRows);
    pRows = NULL;
    allocatedRows = 0;
    rowCount = 0;
    maxWriteSize = 0;
    totalPayloadSize = 0;
    nonDataRowCount = 0;
}

CY_RESULT FwFileWicedHex::Load(LPCTSTR fwFileName)
{
    CY_RESULT ret = CY_ERROR_FAILURE;
    FILE* f;
    CHAR buffer[528];
    CHAR* pRowBuf;
    int count;
    PWICED_HEX_ROW pHexRow;

    if (
#ifdef UNICODE
        _wfopen_s(&f, fwFileName, _T("r"))
#else
        fopen_s(&f, fwFileName, "r")
#endif
        )
    {
        TDebugPrint(_T("<0>Failed to open the file: \"%s\". (%d)\n"), fwFileName, GetLastError());
        return CY_ERROR_FILE_ACCESS;
    }

    rowCount = 0;

    pRowBuf = fgets(buffer, sizeof(buffer), f);

    while (pRowBuf)
    {
        if (rowCount >= allocatedRows)
        {
            pRows = (PWICED_HEX_ROW)realloc(pRows, (allocatedRows + 10) * sizeof(WICED_HEX_ROW));
            if (!pRows)
            {
				TDebugPrint(_T("<0>Expand rows from %d to %d FAILED.\n"), allocatedRows, allocatedRows + 16);
                ret = CY_ERROR_MEMORY_LACK;
                goto error;
            }
			TDebugPrint(_T("Expand rows from %d to %d.\n"), allocatedRows, allocatedRows + 16);
            allocatedRows += 10;
        }

        //Chech start record ":"
        if (strlen(pRowBuf) < 1 || pRowBuf[0] != WHEX_ROW_START_CHAR)
        {
			TDebugPrint(_T("<1>Ignore WICED HEX file row [%d]. Invalid start char 0x%02X or Invalid string count %d.\n"), rowCount, pRowBuf[0], strlen(pRowBuf));

            pRowBuf = fgets(buffer, sizeof(buffer), f);

            continue;
        }

        //Start record ":" needn't decoding
        count = 1 + Global::DecodeHexStr(pRowBuf + 1, (PBYTE)(pRowBuf + 1));

        if (count < WHEX_HEADER_SIZE)
        {
			TDebugPrint(_T("<0>Failed to decode WICED HEX file row [%d]. Header size error %d.\n"), rowCount, count);
            ret = CY_ERROR_FORMAT;
            goto error;
        }

        pHexRow = (PWICED_HEX_ROW)pRowBuf;

        //Check row size
        if (count != HEX_ROW_SIZE(pHexRow) || pHexRow->DataSize > WHEX_MAX_PAYLOAD_SIZE)
        {
			TDebugPrint(_T("<0>Failed to decode WICED HEX file row [%d]. Data size error read %d (%d).\n"), rowCount, count, (WHEX_HEADER_SIZE + pHexRow->DataSize + 1));
            ret = CY_ERROR_FORMAT;
            goto error;
        }

        //Check sum
        CY_U8 sum = Global::SUM((CY_U8*)pRowBuf + 1, HEX_ROW_SIZE(pHexRow) - 1);
        if (sum) {
			TDebugPrint(_T("<0>Check sum error on row %d.\n"), rowCount);
            ret = CY_ERROR_FORMAT;
            goto error;
        }

        //Saved
        memcpy(&pRows[rowCount], pRowBuf, count);

        if (pHexRow->RowType == WHEX_ROW_TYPE_DATA)
        {
            if (pHexRow->DataSize > maxWriteSize)
                maxWriteSize = pHexRow->DataSize;
            totalPayloadSize += pHexRow->DataSize;
        }
        else
        {
            nonDataRowCount++;
        }

        rowCount++;
        pRowBuf = fgets(buffer, sizeof(buffer), f);
    }

    if (ReCalc(FALSE))
        ret = CY_ERROR_SUCCESS;
    else
        ret = CY_ERROR_FAILURE;

error:
    fclose(f);
    return ret;
}

CY_RESULT FwFileWicedHex::GenEmptyHex(UINT32 startAddr, UINT32 len)
{
    CY_RESULT ret = CY_ERROR_FAILURE;
    PWICED_HEX_ROW pHexRow;

    UINT16* pU16;
    this->maxWriteSize = 64;
    this->totalPayloadSize += len;
    nonDataRowCount = 2;
    rowCount = len / 64 + ((len % 64)?3:2);//Header offset row + end row

    if (rowCount >= allocatedRows)
    {
        pRows = (PWICED_HEX_ROW)realloc(pRows, (allocatedRows + 10) * sizeof(WICED_HEX_ROW));
        if (!pRows)
        {
            TDebugPrint(_T("<0>Expand rows from %d to %d FAILED.\n"), allocatedRows, allocatedRows + 16);
            return CY_ERROR_MEMORY_LACK;
        }
        TDebugPrint(_T("Expand rows from %d to %d.\n"), allocatedRows, allocatedRows + 16);
    }
    memset(pRows, 0, sizeof(WICED_HEX_ROW) * allocatedRows);
    pHexRow = pRows;
    pHexRow->StartChar = ':';
    pHexRow->DataSize = 2;
    //pHexRow->OffsetAddr = CPU_TO_BE16(startAddr & 0xFFFF);
    pHexRow->OffsetAddr = 0;
    pHexRow->RowType = WHEX_ROW_TYPE_EXT_LINEAR_ADDR;
    pU16 = (UINT16*)pHexRow->Data;
    *pU16 = CPU_TO_BE16((startAddr & 0xFFFF0000) >> 16);
    pHexRow++;

    UINT16 offset = startAddr & 0xFFFF;
    UINT16 remain = len;
    
    for (int i = 0; remain > 0; i++)
    {
        pHexRow->StartChar = ':';
        pHexRow->DataSize = remain > this->maxWriteSize ? this->maxWriteSize : remain;
        pHexRow->OffsetAddr = CPU_TO_BE16(offset);
        pHexRow->RowType = WHEX_ROW_TYPE_DATA;
        offset += pHexRow->DataSize;
        remain -= pHexRow->DataSize;
        pHexRow ++;
    }
    pHexRow->StartChar = ':';
    pHexRow->DataSize = 0;
    pHexRow->OffsetAddr = 0;
    pHexRow->RowType = WHEX_ROW_TYPE_END;
    if (ReCalc(TRUE))
    {
        TDebugPrint(_T("<6>Clear data hex was created.\n"));
        return CY_ERROR_SUCCESS;
    }
    return CY_ERROR_FAILURE;
}

CY_U32 FwFileWicedHex::GetRowCount()
{
    return rowCount;
}

PWICED_HEX_ROW FwFileWicedHex::GetRow(int index)
{
    if (index < rowCount)
        return &pRows[index];
    return NULL;
}

void FwFileWicedHex::DumpPrint()
{
    if (rowCount <= 0)
    {
        printf("Invalid WICED HEX file.\n");
        return;
    }

    for (int row = 0; row < rowCount; row++)
    {
        WICED_HEX_ROW hexRow = pRows[row];
        PUCHAR pData = (PUCHAR)(&hexRow);
        printf("%c", pData[0]);
        for (int i = 1; i < HEX_ROW_SIZE(&hexRow); i++)
        {
            printf("%02X", pData[i]);
        }
        printf("\n");
    }
}

CY_RESULT FwFileWicedHex::UpdateBDAddress(CY_U64 BDAddr)
{
    if (BDAddr > 0xFFFFFFFFFFFFULL)
    {
        return CY_ERROR_FORMAT;
    }

    newBDAddr = BDAddr;
    
    if (ReCalc(TRUE))
    {
        newBDAddr = 0;
        TDebugPrint(_T("<6>BDAddress was updated.\n"));
        return CY_ERROR_SUCCESS;
    }
        
	TDebugPrint(_T("<1>Failed to update BDAddress.\n"));

    newBDAddr = 0;

    return CY_ERROR_FORMAT;
}

bool FwFileWicedHex::ReCalc(int genCheckSum)
{
    PWICED_HEX_ROW pHexRow;

    UINT8 _maxWriteSize = this->maxWriteSize;
    UINT32 _totalPayloadSize = this->totalPayloadSize;
    UINT32 _nonDataRowCount = this->nonDataRowCount;

    maxWriteSize = 0;
    totalPayloadSize = 0;
    nonDataRowCount = 0;

    for (int i = 0; i < rowCount; i++)
    {
        pHexRow = &pRows[i];

        if (genCheckSum)
        {
            /*
            * Check if it is for BDAddress. Now support BCM20739/BCM20706.
            */
            if (newBDAddr && i < 4)
            {
                CY_U8* p = NULL;
                if (pHexRow->RowType == 0 && pHexRow->OffsetAddr == 0)
                {
                    if (pHexRow->DataSize == 0x42 && !memcmp("BRCMcfgS", pHexRow->Data, 8))
                    {
                        //BCM20739 hex
                        p = pHexRow->Data + 0x1A;
                    }
                    else if (pHexRow->DataSize == 0x28)
                    {
                        //BCM20706 hex
                        p = pHexRow->Data + 0x15;
                    }
                }

                if (p)
                {
                    memcpy(p, &newBDAddr, 6);
                }
            }
            pHexRow->Data[pHexRow->DataSize] = 0x100 - Global::SUM(((CY_U8*)pHexRow) + 1, HEX_ROW_SIZE(pHexRow) - 2);
        }
        else if (Global::SUM(((CY_U8*)pHexRow) + 1, HEX_ROW_SIZE(pHexRow) - 1))
        {
			TDebugPrint(_T("<0>Row[%d] checksum error.\n"), rowCount);
            return false;
        }

        if (pHexRow->RowType == WHEX_ROW_TYPE_DATA)
        {
            if (pHexRow->DataSize > maxWriteSize)
                maxWriteSize = pHexRow->DataSize;
            totalPayloadSize += pHexRow->DataSize;
        }
        else
        {
            nonDataRowCount++;
        }
    }

	TDebugPrint(_T("<6>RowCnt = %d, nonDataRowCnt = %d, Payload = %d, MaxWriteSize = %d.\n"), rowCount, nonDataRowCount, totalPayloadSize, maxWriteSize);

    if (_totalPayloadSize != totalPayloadSize)
    {
		TDebugPrint(_T("<0>Error! Total payload insistent %d -> %d.\n"), _totalPayloadSize, totalPayloadSize);
    }
    return true;
}
