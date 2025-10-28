// WicedReflash.cpp : Defines the entry point for the console application.
//
#include <WinSock2.h>
#include <conio.h>
#include "tchar.h"
#include "WicedReflashCom.h"
#include "hci_control_api.h"
#include "FwFileWicedHex.h"
#include "Global.h"

#define HCI       0
#define WICED_HCI 1

int dbg = 7;
int DumpFlag = 0;
UINT32 DumpOffset = 0;
UINT32 DumpLength = 0;
int InRecoverMode = 0;
int Simulate = 0;

typedef struct _BLOCK_CRC
{
    UINT32 StartAddr;
    UINT32 Size;
    UINT32 Crc;
}BLOCK_CRC, *PBLOCK_CRC;

typedef enum _VERIFY_METHOD
{
    VERIFY_NONE,    //Don't verify
    VERIFY_DATA,    //Read all data and verify
    VERIFY_CRC      //Check CRC
}VERIFY_METHOD;

typedef unsigned char UINT8;

UINT8 in_buffer[1024];
int port_num = 9;
/*
BCM706 Baud_rate:
    Recover mode    : 3000000
    Application mode: Depend on the transport_cfg setting in application. So must probe buad_rate.
*/
int baud_rate = 115200;
bool baud_rate_set = false;//Indicate baudrate was specified by user.

int cts_flow_ctrl = 0;
bool cts_flow_ctrl_set = false;//Indicate CTS_flow_ctrl was specified by user.

static int execute_download_hcd(UINT8 maxWriteSize, char *minidriverPathname, char *configPathname, bool onlyEraseChip, VERIFY_METHOD verifyMethod, CY_U64 BDAddr);
static int execute_download_hex(UINT8 maxWriteSize, char *minidriverPathname, char *configPathname, bool onlyEraseChip, VERIFY_METHOD verifyMethod, CY_U64 BDAddr);
typedef int(*PDownloadProc) (UINT8 maxWriteSize, char *minidriverPathname, char *configPathname, bool onlyEraseChip, VERIFY_METHOD verifyMethod, CY_U64 BDAddr);

typedef struct _REFALSH_PARAMETERS
{
    PDownloadProc pDownloadProc;
    char* ModuleName;
    char* MiniDrvPath;
    int BaudRate;       //0 -- Auto detect (TBD)
    int FlowCtrlEnable;//Flow control enable
    int MaxWriteSize;
    UINT32 EraseAddr;   //SFlash erase address
    UINT32 MiniDrvAddr; //0 -- Auto set; Address for launch minidriver
    UINT32 AppAddr;     //Address for launch application
    VERIFY_METHOD VerifyMethod;
    bool BringAppFromHCIMode;//Only for bring BCM20719 from HCI mode to App mode after programming.
    UINT32 DS2Offset;
    UINT32 FlashMappedAddr;
}REFALSH_PARAMETERS, *PREFALSH_PARAMETERS;

REFALSH_PARAMETERS ReflashParams[] = {
    {
        execute_download_hex,
        "CYW20719_SFlash",
        "minidrvs\\BCM920719EVAL_Q40\\minidriver-20739A0-uart.hex",
        115200,
        1,
        240,
        0xFCBEEEEF,
        0,
        0xFFFFFFFF,
        VERIFY_CRC,  //719 supports Calc CRC command
        0,
        0x7E000,
        0x00500000
    },

    {
        execute_download_hex,
        "CYW20706_SFlash",
        "minidrvs\\BCM920706_P49\\uart.hex",
        115200,
        1,
        249,
        0xFF000000,
        0,
        0,
        VERIFY_DATA,
        0,
        0x3E000, //248k
        0xFF000000
    },

    {
        execute_download_hex,
        "CYW20737_SFlash",
        "minidrvs\\BCM920737TAG_Q32\\uart_DISABLE_EEPROM_WP_PIN1.hex",
        115200,
        0,
        251,
        0xFF000000,
        0,
        0,
        VERIFY_CRC,
        0,
        0xE000, //56k
        0xFF000000
    },

    {
        execute_download_hcd,
        "CYW20706_RAM",
        NULL,
        115200,
        1,
        0,
        INVALID_ADDR_VALUE,
        0,
        0,
        VERIFY_NONE,
        0,
        0,
        0x00200000,
    },
};

PREFALSH_PARAMETERS pReflashParams = NULL;

//
// print hexadecimal digits of an array of bytes formatted as: 
// 0000 < 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F >
// 0010 < 10 11 12 13 14 15 16 1718 19 1A 1B 1C 1D 1E 1F >
//
void HexDump(LPBYTE p, DWORD dwLen)
{
    if (dbg < 7)
        return;
    for (DWORD i = 0; i < dwLen; ++i)
    {
        if (i % 16 == 0)
            printf("%04X <", i);
        printf(" %02X", p[i]);
        if ((i + 1) % 16 == 0)
            printf(" >\n");
    }
    if ((dwLen % 16) != 0)
        printf(" >\n");
}

void HexDump2(LPBYTE p, DWORD dwLen)
{
    for (DWORD i = 0; i < dwLen; ++i)
    {
        if (i % 16 == 0)
            printf("%08X <", i);
        printf(" %02X", p[i]);
        if ((i + 1) % 16 == 0)
            printf(" >\n");
    }

    if ((dwLen % 16) != 0)
        printf(" >\n");
}

static BOOL send_hci_command(ComHelper *p_port, LPBYTE cmd, DWORD cmd_len, LPBYTE expected_evt, DWORD evt_len, bool compare = true)
{
    if (cmd)
    {
        // write HCI Command
        TDebugPrint(_T("Sending HCI Command:\n"));
        HexDump(cmd, cmd_len);

        p_port->Write(cmd, cmd_len);
    }

    if (!expected_evt || evt_len == 0)
    {
        return TRUE;
    }
    // read HCI response header
    DWORD dwRead = p_port->Read((LPBYTE)&in_buffer[0], 3);

    // read HCI response payload
    if (dwRead == 3 && in_buffer[2] > 0)
        dwRead += p_port->Read((LPBYTE)&in_buffer[3], in_buffer[2]);

    TDebugPrint(_T("Received HCI Event:\n"));
    HexDump(in_buffer, dwRead);

    if (!compare)
    {
        if (dwRead <= evt_len)
        {
            memset(expected_evt, 0, evt_len);

            memcpy(expected_evt, in_buffer, dwRead);

            TDebugPrint(_T("Success %d bytes.\n"), dwRead);

            return TRUE;
        }
        else
        {
            TDebugPrint(_T("<0>Outbuf is too small %d < %d.\n"), evt_len, dwRead);

            return FALSE;
        }
    }
    else if (dwRead == evt_len)
    {
        if (memcmp(in_buffer, expected_evt, evt_len) == 0)
        {
            TDebugPrint(_T("send_hci_command succeeded.\n"));
            return TRUE;
        }
        else
        {
            TDebugPrint(_T("Expected HCI Event:\n"));
            HexDump(expected_evt, evt_len);
        }
    }

    TDebugPrint(_T("<0>send_hci_command and compare failed.\n"));
    return FALSE;
}

/*
* Use BlueZ to send "Set AFH Channel Classification" commad format should be:
*    hcitool cmd 0x03 0x003F 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0x7F
* Please refer to Bluetooth spec Vol 2, E:7.4.2
*Opened COM44 at speed: 115200.
*Sending HCI Command:
*0000 < 01 3F 0C 0A FF FF FF FF FF FF FF FF FF 7F >
*Received HCI Event:
*0000 < 04 0E 04 01 3F 0C 00 >
*/
static int execute_SET_AFH_CHANNELS(ComHelper* p_port)
{
    BOOL res, opened = FALSE;

    if (p_port == NULL)
    {
        p_port = new ComHelper;
        if (!p_port->OpenPort(port_num, baud_rate, cts_flow_ctrl))
        {
            TDebugPrint(_T("<0>Open COM%d port Failed, baud %d.\n"), port_num, baud_rate);
            delete p_port;
            return 0;
        }
        opened = TRUE;
    }
    UINT8 hci_set_afh_channels[] = { 0x01, 0x3F, 0x0C, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F };
    UINT8 hci_set_afh_channels_cmd_complete_event[] = { 0x04, 0x0e, 0x04, 0x01, 0x3F, 0x0C, 0x00 };

    res = send_hci_command(p_port, hci_set_afh_channels, sizeof(hci_set_afh_channels), hci_set_afh_channels_cmd_complete_event, sizeof(hci_set_afh_channels_cmd_complete_event));
    if (opened)
        delete p_port;
    if (res)
        TDebugPrint(_T("<6>\nHCI_SET_AFH_CHANNELS succeeded.\n"));
    else
        TDebugPrint(_T("<6>\nHCI_SET_AFH_CHANNELS failed\n"));
    return res;
}

static int execute_reset(ComHelper *p_port)
{
    BOOL res, opened = FALSE;

    if (p_port == NULL)
    {
        p_port = new ComHelper;
        if (!p_port->OpenPort(port_num, baud_rate, cts_flow_ctrl))
        {
            TDebugPrint(_T("<0>Open COM%d port Failed, baud %d.\n"), port_num, baud_rate);
            delete p_port;
            return 0;
        }
        opened = TRUE;
    }
    UINT8 hci_reset[] = { 0x01, 0x03, 0x0c, 0x00 };
    UINT8 hci_reset_cmd_complete_event[] = { 0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00 };

    res = send_hci_command(p_port, hci_reset, sizeof(hci_reset), hci_reset_cmd_complete_event, sizeof(hci_reset_cmd_complete_event));
    if (opened)
        delete p_port;
    if (res)
        TDebugPrint(_T("<6>\nHCI_Reset succeeded.\n"));
    else
        TDebugPrint(_T("<6>\nHCI_Reset failed\n"));
    return res;
}

static void print_usage_reset(bool full)
{
    printf("Usage:\n\tWicedReflash reset COMx [baudrate] [CTS] [VERBOSE]\n");
    printf("\tSends HCI_RESET comand to device.\n");
}

static void print_usage_read(bool full)
{
    printf("Usage:\n\tWicedReflash read COMx [baudrate] [CTS] [VERBOSE] HEX_RAM_ADDRESS length\n");
    printf("\tRead lenght bytes from RAM_ADDRESS.\n");
}

static void print_usage_parse_hex(bool full)
{
    printf("Usage:\n\tWicedReflash parse_hex [max_payload_size] hex_file_name\n");
    printf("\tParse hex file and display address and length.\n");
}

static void print_usage_download(bool full)
{
    printf("Usage:\n\tWicedReflash command COMx [baudrate] [CTS] [VERBOSE[x]] ModuleName fw_pathname [BDAddress] [minidrv_pathname]\n");
    printf("\tcommand:\n");
    printf("\t\tdownload   -- Program hex file in download mode (Send downloadMiniDriver command).\n");
    printf("\t\trecover    -- Program hex file in recover mode (Send downloadMiniDriver command).\n");
    printf("\t\terase      -- Only execute erasing chip.\n");
    printf("\t\tdump1      -- Dump DS1 config data by address and length in firmware hex file in download mode.\n");
    printf("\t\tdump2      -- Dump DS2 config data by address and length in firmware hex file in download mode.\n");
    printf("\t\tdump1r     -- Dump DS1 config data by address and length in firmware hex file in recover mode.\n");
    printf("\t\tdump2r     -- Dump DS2 config data by address and length in firmware hex file in recover mode.\n");

    printf("\tOptions:\n");
    printf("\t\tCTS        -- Enable CTS flow control.\n");
    printf("\t\tVERBOSEx   -- Specify debug output level.\n");
    printf("\t\tModuleName -- ");

    for (int i = 0; i < sizeof(ReflashParams) / sizeof(REFALSH_PARAMETERS); i++)
    {
        if (i == 0)
            printf("%s", ReflashParams[i].ModuleName);
        else
            printf(" | %s", ReflashParams[i].ModuleName);
    }
    printf("\n");
    printf("\t\tfw_pathname-- Firmware HEX or HCD file.\n");
    printf("\t\tBDAddress  -- BDA to be programmed ( 0 : Ignore this parameter).\n");
    printf("\t\tminidrv_pathname-- Specify the minidriver HEX file. Default minidrivers are in minidrvs folder.\n");
}

static void print_usage_gen_hex(bool full)
{
    printf("Usage:\n\tWicedReflash gen_hex offset length\n");
    printf(" Generate and print an hex file used to clear the flash (offset:length)\n");
}

static void print_usage_dump(bool full)
{
    printf("Usage:\n\tWicedReflash command COMx [baudrate] [CTS] [VERBOSE[x]] ModuleName [Offset] [Length] [minidrv_pathname]\n");
    printf("\tcommand:\n");
    printf("\t\tdump       -- Dump flash data in download mode.\n");
    printf("\t\tdumpr      -- Dump flash data in recover mode.\n");

    printf("\tOptions:\n");
    printf("\t\tCTS        -- Enable CTS flow control.\n");
    printf("\t\tVERBOSEx   -- Specify debug output level.\n");
    printf("\t\tModuleName -- ");

    for (int i = 0; i < sizeof(ReflashParams) / sizeof(REFALSH_PARAMETERS); i++)
    {
        if (i == 0)
            printf("%s", ReflashParams[i].ModuleName);
        else
            printf(" | %s", ReflashParams[i].ModuleName);
    }
    printf("\n");
    printf("\t\tOffset     -- Flash offset address in hex. Default is 0. If >= 0x200000 this address will be used as flash memory mapped address.\n");
    printf("\t\tLength     -- Dump size in hex. Default is 0. If == 0 it will brief SS1/SS2/VS1/VS2/DS1/DS2 data.\n");
    printf("\t\tminidrv_pathname-- Specify the minidriver HEX file. Default minidrivers are in minidrvs folder.\n");
}

BOOL SendDownloadMinidriver(ComHelper *p_port)
{
    BYTE arHciCommandTx[] = { 0x01, 0x2E, 0xFC, 0x00 };
    BYTE arBytesExpectedRx[] = { 0x04, 0x0E, 0x04, 0x01, 0x2E, 0xFC, 0x00 };

    return (send_hci_command(p_port, arHciCommandTx, sizeof(arHciCommandTx), arBytesExpectedRx, sizeof(arBytesExpectedRx)));
}

BOOL SendUpdateBaudRate(ComHelper *p_port, int newBaudRate)
{
    BYTE arHciCommandTx[] = { 0x01, 0x18, 0xFC, 0x06, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA };
    BYTE arBytesExpectedRx[] = { 0x04, 0x0E, 0x04, 0x01, 0x18, 0xFC, 0x00 };

    arHciCommandTx[6] = newBaudRate & 0xff;
    arHciCommandTx[7] = (newBaudRate >> 8) & 0xff;
    arHciCommandTx[8] = (newBaudRate >> 16) & 0xff;
    arHciCommandTx[9] = (newBaudRate >> 24) & 0xff;

    return (send_hci_command(p_port, arHciCommandTx, sizeof(arHciCommandTx), arBytesExpectedRx, sizeof(arBytesExpectedRx)));
}

BOOL SendLaunchRamAddr(ComHelper *p_port, UINT32 address)
{
    BYTE arHciCommandTx[] = { 0x01, 0x4E, 0xFC, 0x04, 0x00, 0x00, 0x22, 0x00 };
    BYTE arBytesExpectedRx[] = { 0x04, 0x0E, 0x04, 0x01, 0x4E, 0xFC, 0x00 };

    arHciCommandTx[4] = address & 0xff;
    arHciCommandTx[5] = (address >> 8) & 0xff;
    arHciCommandTx[6] = (address >> 16) & 0xff;
    arHciCommandTx[7] = (address >> 24) & 0xff;

    return (send_hci_command(p_port, arHciCommandTx, sizeof(arHciCommandTx), arBytesExpectedRx, sizeof(arBytesExpectedRx)));
}

BOOL SendChipErase(ComHelper *p_port, UINT32 address)
{
    BYTE arHciCommandTx[] = { 0x01, 0xCE, 0xFF, 0x04, 0xEF, 0xEE, 0xBE, 0xFC };
    BYTE arBytesExpectedRxTmpl[] = { 0x04, 0x0E, 0x04, 0x01, 0xCE, 0xFF, 0x00 };
    BYTE arEventBytes[7] = { 0, };
    BYTE arChipEraseInProgressEvt[] = { 0x04, 0xFF, 0x01, 0xCE };
    arHciCommandTx[4] = address & 0xff;
    arHciCommandTx[5] = (address >> 8) & 0xff;
    arHciCommandTx[6] = (address >> 16) & 0xff;
    arHciCommandTx[7] = (address >> 24) & 0xff;

    TDebugPrint(_T("<6>Executing -- erasing chip\n"));

    BOOL ret = send_hci_command(p_port, arHciCommandTx, sizeof(arHciCommandTx), arEventBytes, sizeof(arEventBytes), false);

    while (ret)
    {
        if (!memcmp(arEventBytes, arChipEraseInProgressEvt, sizeof(arChipEraseInProgressEvt)))
        {
            TDebugPrint(_T("<6>Chip erase in progress...\n"));
        }
        else if (!memcmp(arEventBytes, arBytesExpectedRxTmpl, sizeof(arBytesExpectedRxTmpl)))
        {
            return TRUE;
        }

        memset(arEventBytes, 0, sizeof(arEventBytes));

        ret = send_hci_command(p_port, NULL, 0, arEventBytes, sizeof(arEventBytes), false);
    }

    return ret;
}

BOOL SendReadAndVerifyRam(ComHelper *p_port, UINT32 address, PBYTE data, BYTE len, bool compare, bool onlyWriteCmd = false)
{
    //size = 0xFF
    BYTE arHciCommandTx[] = { 0x01, 0x4D, 0xFC, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    //Response_size = 0xFF + 7 = 262
    BYTE arBytesExpectedRx[263] = { 0x04, 0x0E, 0xF4, 0x01, 0x4D, 0xFC, 0x00 };

    if (len > 0xff)
    {
        TDebugPrint(_T("<0>READ_RAM command size error. size = %d (0xFF).\n"), len);

        return false;
    }

    arHciCommandTx[4] = address & 0xff;
    arHciCommandTx[5] = (address >> 8) & 0xff;
    arHciCommandTx[6] = (address >> 16) & 0xff;
    arHciCommandTx[7] = (address >> 24) & 0xff;
    arHciCommandTx[8] = len;

    arBytesExpectedRx[2] = (byte)(len + 4);
    arBytesExpectedRx[6] = 0;
    memcpy(arBytesExpectedRx + 7, data, len);

    if (send_hci_command(p_port, arHciCommandTx, sizeof(arHciCommandTx), onlyWriteCmd ? 0 : arBytesExpectedRx, len + 7, compare))
    {
        if (!compare)
        {
            memcpy(data, arBytesExpectedRx + 7, len);
        }
        return true;
    }

    return false;
}

/********************************************************************************************************
* Recommended firmware upgrade 4 MBit Serila flash offsets
* -------------------------------------------------------------------------------------------------------------------
* |  SS1 (4K @ 0)  |  Fail safe area(4K @ 0x1000)  |  VS1 (4K @ 0x2000)  | VS2 (4K @ 0x3000)  | DS1 (248K @ 0x4000)  | DS2 (248K @ 0x42000)
*  -------------------------------------------------------------------------------------------------------------------
*******************************************************************************************************/

/********************************************************************************************************
* Recommended firmware upgrade 8 MBit Serila flash offsets (OSRAM 20719)
* -------------------------------------------------------------------------------------------------------------------
* |  SS1 (4K @ 0)  |  Fail safe area(4K @ 0x1000)  |  VS1 (4K @ 0x2000)  | VS2 (4K @ 0x3000)  | DS1 (504K @ 0x4000)  | DS2 (504K @ 0x82000)
*******************************************************************************************************/

BOOL SendWriteRam(ComHelper *p_port, UINT32 address, PBYTE data, BYTE size, bool readAndCompare)
{
    if (Simulate)
    {
        TDebugPrint(_T("Download hex successfully had written %d bytes to address 0x%08X.\n"), size, address);
        return true;
    }

    if (readAndCompare)
    {
        if (DumpFlag)
        {
            UINT32 offset = 0;

            //dump SS2 and DS2
            if (DumpFlag == 2)
            {
                UINT32 flashOff = address & 0xFFFFF;
                if (flashOff < 0x1000)
                {
                    offset = 0x1000;
                }
                else if (flashOff < (pReflashParams->DS2Offset + 16 * 1024))
                {
                    offset = pReflashParams->DS2Offset;
                }
            }
            //printf("====>>0x%08X: ", address + offset);
            //HexDump2(data, size);
            BOOL ret = SendReadAndVerifyRam(p_port, address + offset, data, size, false);
            //printf("====<<0x%08X: ", address + offset);
            //HexDump2(data, size);
            return ret;
        }
        else
        {
            return SendReadAndVerifyRam(p_port, address, data, size, true);
        }
    }
    //size max value = 0xFF - 4 = 0xFB
    //command_size = 0xFB + 8 = 259
    BYTE arHciCommandTx[259] = { 0x01, 0x4C, 0xFC, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    BYTE arBytesExpectedRx[] = { 0x04, 0x0E, 0x04, 0x01, 0x4C, 0xFC, 0x00 };

    if ((8 + size > sizeof(arHciCommandTx)) || (size + 4 > 0xFF))
    {
        TDebugPrint(_T("<0>WRITE_RAM command size error. size = %d (0xFB).\n"), size);

        return false;
    }
    arHciCommandTx[3] = (BYTE)(4 + size);
    arHciCommandTx[4] = address & 0xff;
    arHciCommandTx[5] = (address >> 8) & 0xff;
    arHciCommandTx[6] = (address >> 16) & 0xff;
    arHciCommandTx[7] = (address >> 24) & 0xff;

    memcpy(&arHciCommandTx[8], data, size);

    if (send_hci_command(p_port, arHciCommandTx, size + 8, arBytesExpectedRx, sizeof(arBytesExpectedRx)))
    {
        TDebugPrint(_T("Download hex successfully had written %d bytes to address 0x%08X.\n"), size, address);
        return TRUE;
    }
    return FALSE;
}

BOOL VerifyCRC(ComHelper *p_port, PBLOCK_CRC pBlockCrc)
{
    TDebugPrint(_T("<6>VerifyCRC  checking %d bytes starting at 0x%08X     Expecting CRC value 0x%08X\n"),
        pBlockCrc->Size, pBlockCrc->StartAddr, pBlockCrc->Crc);

    BYTE arHciCommandTx[12] = { 0x01, 0xCC, 0xFC, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    BYTE arBytesExpectedRx[11] = { 0x04, 0x0E, 0x08, 0x01, 0xCC, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00 };

    //Start address
    arHciCommandTx[4] = pBlockCrc->StartAddr & 0xff;
    arHciCommandTx[5] = (pBlockCrc->StartAddr >> 8) & 0xff;
    arHciCommandTx[6] = (pBlockCrc->StartAddr >> 16) & 0xff;
    arHciCommandTx[7] = (pBlockCrc->StartAddr >> 24) & 0xff;

    //Size
    arHciCommandTx[8] = pBlockCrc->Size & 0xff;
    arHciCommandTx[9] = (pBlockCrc->Size >> 8) & 0xff;
    arHciCommandTx[10] = (pBlockCrc->Size >> 16) & 0xff;
    arHciCommandTx[11] = (pBlockCrc->Size >> 24) & 0xff;

    //Excepted CRC data
    arBytesExpectedRx[7] = pBlockCrc->Crc & 0xff;
    arBytesExpectedRx[8] = (pBlockCrc->Crc >> 8) & 0xff;
    arBytesExpectedRx[9] = (pBlockCrc->Crc >> 16) & 0xff;
    arBytesExpectedRx[10] = (pBlockCrc->Crc >> 24) & 0xff;

    if (send_hci_command(p_port, arHciCommandTx, sizeof(arHciCommandTx), arBytesExpectedRx, sizeof(arBytesExpectedRx)))
    {
        TDebugPrint(_T("<6>Verify CRC data successfully. FW return 0x%08X.\n"), *((ULONG*)(arBytesExpectedRx + 7)));
        return TRUE;
    }

    TDebugPrint(_T("<0>Failed to verify CRC data. FW return 0x%08X.\n"), *((ULONG*)(arBytesExpectedRx + 7)));

    return FALSE;
}
#define RESET_BLOCK_CRC(_pblock, _startAddr) do {\
            memset((_pblock), 0, sizeof(BLOCK_CRC));\
            (_pblock)->StartAddr = _startAddr;\
            }while(0);

BOOL WriteFwBinary(ComHelper *p_port, UINT8 maxWriteSize, int stage, UINT32 address, PBYTE data, BYTE size, VERIFY_METHOD verifyMethod)
{
    static BLOCK_CRC blockCrc = { 0, };
    static UINT32 nextAddr = 0;
    static UINT8 bufferedData[WHEX_MAX_PAYLOAD_SIZE * 2] = { 0, };
    static UINT16 bufferedSize = 0;
    UINT16 writtenCount;

    if (maxWriteSize == 0) //Program each line in hex one by one.
        maxWriteSize = size;

    //The first row to be written
    if (stage == 0)
    {
        nextAddr = address;
        memset(bufferedData, 0, sizeof(bufferedData));
        bufferedSize = 0;
        if (verifyMethod == VERIFY_CRC)
        {
            RESET_BLOCK_CRC(&blockCrc, address);
        }
    }

    if ((maxWriteSize > WHEX_MAX_PAYLOAD_SIZE) || ((size + bufferedSize) > sizeof(bufferedData)))
    {
        TDebugPrint(_T("<0>Buffered size is small. %d\n"), size);
        return FALSE;
    }

    //Check if address is continuous
    if (address != (nextAddr + bufferedSize))
    {
        //Flush buffered data
        if (bufferedSize)
        {
            if (!SendWriteRam(p_port, nextAddr, bufferedData, (UINT8)bufferedSize, (verifyMethod == VERIFY_DATA)))
                return FALSE;

            if (verifyMethod == VERIFY_CRC)
            {
                if (!blockCrc.Size)
                {
                    blockCrc.StartAddr = nextAddr;
                }
                blockCrc.Crc = Global::ComputeCrc32(blockCrc.Crc, bufferedData, bufferedSize);
                blockCrc.Size += bufferedSize;
                if (!VerifyCRC(p_port, &blockCrc))
                {
                    return FALSE;
                }
                RESET_BLOCK_CRC(&blockCrc, address);
            }
        }

        nextAddr = address;
        bufferedSize = 0;
        memset(bufferedData, 0, sizeof(bufferedData));
    }

    //Buffer incoming data
    memcpy(bufferedData + bufferedSize, data, size);
    bufferedSize += size;

    //Write maxWriteSizes bytes.
    writtenCount = 0;

    while (maxWriteSize && (bufferedSize >= maxWriteSize))
    {
        if (maxWriteSize && !SendWriteRam(p_port, nextAddr, bufferedData + writtenCount, maxWriteSize, (verifyMethod == VERIFY_DATA)))
            return FALSE;

        if (verifyMethod == VERIFY_CRC)
        {
            if (!blockCrc.Size)
            {
                blockCrc.StartAddr = nextAddr;
            }
            blockCrc.Crc = Global::ComputeCrc32(blockCrc.Crc, bufferedData + writtenCount, maxWriteSize);
            blockCrc.Size += maxWriteSize;
        }

        nextAddr += maxWriteSize;
        bufferedSize -= maxWriteSize;
        writtenCount += maxWriteSize;
    }

    //Flush if it the last data
    if (stage == 2 && bufferedSize)
    {
        if (bufferedSize)
        {
            if (!SendWriteRam(p_port, nextAddr, bufferedData + writtenCount, (UINT8)bufferedSize, (verifyMethod == VERIFY_DATA)))
                return FALSE;
        }
        if (verifyMethod == VERIFY_CRC)
        {
            if (!blockCrc.Size)
            {
                blockCrc.StartAddr = nextAddr;
            }
            blockCrc.Crc = Global::ComputeCrc32(blockCrc.Crc, bufferedData + writtenCount, bufferedSize);
            blockCrc.Size += bufferedSize;
            if (blockCrc.Size > 0 && !VerifyCRC(p_port, &blockCrc))
            {
                return FALSE;
            }
            RESET_BLOCK_CRC(&blockCrc, nextAddr + bufferedSize);
        }

        nextAddr += bufferedSize;
        writtenCount += bufferedSize;
        bufferedSize -= bufferedSize;
    }

    if (DumpFlag && size && verifyMethod == VERIFY_DATA)
    {
        if (size != writtenCount || bufferedSize != 0)
        {
            TDebugPrint(_T("<0>====ERROR===0x%08X: size = %d written = %d bufferedSize = %d.\n"), address, size, writtenCount, bufferedSize);
        }
        memcpy(data, bufferedData, size);
#if 0
        printf("====>>0x%08X: ", address);
        HexDump2(data, size);
        printf("====<<0x%08X: ", address);
        HexDump2(bufferedData, writtenCount);
#endif
    }

    //Move remaining data to the buffer header.
    if (writtenCount && bufferedSize)
    {
        memcpy(bufferedData, bufferedData + writtenCount, bufferedSize);
    }

    return TRUE;
}

static int execute_download_hex_file(ComHelper* pSerialPort, UINT8 maxWriteSize, FwFileWicedHex*  pHexFile, VERIFY_METHOD verifyMethod)
{
    UINT32 segmentAddr = 0;
    UINT32 addr = 0;
    PWICED_HEX_ROW pRow;
    int endRow = 0, i;
    PUINT16 pU16;
    PUINT32 pU32;

    WriteFwBinary(pSerialPort, maxWriteSize, 0, 0, 0, 0, verifyMethod);

    int rowCount = pHexFile->GetRowCount();
    for (i = 0; i < rowCount; i++)
    {
        pRow = pHexFile->GetRow(i);
        if (!pRow)
        {
            TDebugPrint(_T("<0>Failed to get hex row[%d] data.\n"), i);
            return false;
        }

        switch (pRow->RowType)
        {
        case WHEX_ROW_TYPE_EXT_SEGMENT_ADDR:
            pU16 = (PUINT16)pRow->Data;
            segmentAddr = BE16_TO_CPU(*pU16);
            segmentAddr = segmentAddr << 4;
            TDebugPrint(_T("Extended Segment Address(2) -> Set Segment Addr to 0x%08X\n"), segmentAddr);
            break;
        case WHEX_ROW_TYPE_START_SEGMENT_ADDR: //CS:IP
            pU16 = (PUINT16)pRow->Data;
            segmentAddr = BE16_TO_CPU(*pU16);
            segmentAddr = segmentAddr << 4;
            pU16++;
            segmentAddr += BE16_TO_CPU(*pU16);
            TDebugPrint(_T("Start Segment Address(3) -> Set Segment Addr to 0x%08X\n"), segmentAddr);
            break;
        case WHEX_ROW_TYPE_EXT_LINEAR_ADDR:
            pU16 = (PUINT16)pRow->Data;
            segmentAddr = BE16_TO_CPU(*pU16);
            segmentAddr = segmentAddr << 16;
            TDebugPrint(_T("Extended Linear Address(4) ->Set Segment Addr to 0x%08X\n"), segmentAddr);
            break;
        case WHEX_ROW_TYPE_START_LINEAR_ADDR:
            pU32 = (PUINT32)pRow->Data;
            segmentAddr = BE32_TO_CPU(*pU32);
            TDebugPrint(_T("Start Linear Address(5) ->Set Segment Addr to 0x%08X\n"), segmentAddr);
            break;
        case WHEX_ROW_TYPE_DATA:
            addr = BE16_TO_CPU(pRow->OffsetAddr) + segmentAddr;
            TDebugPrint(_T("WriteFwBinary %d bytes to addr 0x%08X....\n"), pRow->DataSize, addr);
            if (!WriteFwBinary(pSerialPort, maxWriteSize, DumpFlag ? 2 : 1, addr, pRow->Data, pRow->DataSize, verifyMethod))
            {
                TDebugPrint(_T("<0>WRITE_RAM Failed at Row[%d].\n"), i);
                return 0;
            }
            if (pHexFile->launchAddress == INVALID_ADDR_VALUE)
            {
                pHexFile->launchAddress = addr;
            }
            break;
        case WHEX_ROW_TYPE_END:
            endRow = i;
            break;
        default:
            TDebugPrint(_T("<0>Unknown row type at Row[%d].\n"), i);
            break;
        }
    }

    WriteFwBinary(pSerialPort, maxWriteSize, 2, 0, 0, 0, verifyMethod);

    if (endRow + 1 != rowCount)
    {
        TDebugPrint(_T("<0>Unknown row type at Row[%d].\n"), i);
        return false;
    }

    TDebugPrint(_T("<6>Write hex file data Successfully.\n"));

    if (DumpFlag && verifyMethod == VERIFY_DATA)
    {
        TDebugPrint(_T("<6>Dumping hex from flash.\n"));
        if (!pHexFile->ReCalc(0))
        {
            TDebugPrint(_T("<0>CheckSum Fail.\n"));
            pHexFile->ReCalc(1);
        }
        else
        {
            TDebugPrint(_T("<6>CheckSum Succ.\n"));
        }
        pHexFile->DumpPrint();
    }

    return true;
}

bool BringBCMToAppModeFromHCIMode(ComHelper* pSerialPort)
{
    bool enterAppMode = false;
    int count = 0;

    while (count++ < 10)
    {
        //
        // BCM20739 needs at least 8 seconds after downloading. But only one second before the first reset in HCI mode.
        //
        SendReadAndVerifyRam(pSerialPort, 0, 0, 0, false, true);

        Sleep(1000);
    }

    TDebugPrint(_T("<6>Please check if application running.\n"));

    return true;

}

static BOOL SendHcdRecord(ComHelper *p_port, ULONG nAddr, ULONG nHCDRecSize, BYTE * arHCDDataBuffer)
{
    BYTE arHciCommandTx[261] = { 0x01, 0x4C, 0xFC, 0x00 };
    BYTE arBytesExpectedRx[] = { 0x04, 0x0E, 0x04, 0x01, 0x4C, 0xFC, 0x00 };

    arHciCommandTx[3] = (BYTE)(4 + nHCDRecSize);
    arHciCommandTx[4] = (nAddr & 0xff);
    arHciCommandTx[5] = (nAddr >> 8) & 0xff;
    arHciCommandTx[6] = (nAddr >> 16) & 0xff;
    arHciCommandTx[7] = (nAddr >> 24) & 0xff;
    memcpy(&arHciCommandTx[8], arHCDDataBuffer, nHCDRecSize);

    TDebugPrint(_T("sending record at:0x%x.\n"), nAddr);
    return (send_hci_command(p_port, arHciCommandTx, 4 + 4 + nHCDRecSize, arBytesExpectedRx, sizeof(arBytesExpectedRx), TRUE));
}

static BOOL ReadNextHCDRecord(FILE * fHCD, ULONG * nAddr, ULONG * nHCDRecSize, UINT8 * arHCDDataBuffer, BOOL * bIsLaunch)
{
    const   int HCD_LAUNCH_COMMAND = 0x4E;
    const   int HCD_WRITE_COMMAND = 0x4C;
    const   int HCD_COMMAND_BYTE2 = 0xFC;

    BYTE     arRecHeader[3];
    BYTE     byRecLen;
    BYTE     arAddress[4];

    *bIsLaunch = FALSE;

    if (fread(arRecHeader, 1, 3, fHCD) != 3)               // Unexpected EOF
        return false;

    byRecLen = arRecHeader[2];

    if ((byRecLen < 4) || (arRecHeader[1] != HCD_COMMAND_BYTE2) ||
        ((arRecHeader[0] != HCD_WRITE_COMMAND) && (arRecHeader[0] != HCD_LAUNCH_COMMAND)))
    {
        TDebugPrint(_T("<0>Wrong HCD file format trying to read the command information.\n"));
        return FALSE;
    }

    if (fread(arAddress, sizeof(arAddress), 1, fHCD) != 1)      // Unexpected EOF
    {
        TDebugPrint(_T("<0>Wrong HCD file format trying to read 32-bit address.\n"));
        return FALSE;
    }

    *nAddr = arAddress[0] + (arAddress[1] << 8) + (arAddress[2] << 16) + (arAddress[3] << 24);

    *bIsLaunch = (arRecHeader[0] == HCD_LAUNCH_COMMAND);

    *nHCDRecSize = byRecLen - 4;

    if (*nHCDRecSize > 0)
    {
        if (fread(arHCDDataBuffer, 1, *nHCDRecSize, fHCD) != *nHCDRecSize)   // Unexpected EOF
        {
            TDebugPrint(_T("<0>Not enough HCD data bytes in record.\n"));
            return FALSE;
        }
    }

    return TRUE;
}

static int dump_data(ComHelper& SerialPort, int dumpFromFlash = 1)
{
    BYTE* pBuf;
    UINT32 MemAddr = DumpOffset;
    UINT32 Addr;
    int size = (int)DumpLength;
    int brief = 0;

    if (!size)
    {
        size = 0x200;
        brief = 1;
    }

    BYTE* buf = new BYTE[size];
    int maxReadSize;
    if (pReflashParams->MaxWriteSize > 256)
    {
        maxReadSize = 256;
    }
    else if (pReflashParams->MaxWriteSize > 128)
    {
        maxReadSize = 128;
    }
    else if (pReflashParams->MaxWriteSize > 64)
    {
        maxReadSize = 64;
    }
    else if (pReflashParams->MaxWriteSize > 0)
    {
        maxReadSize = pReflashParams->MaxWriteSize;
    }
    else
    {
        maxReadSize = 64;
    }

    pBuf = buf;
    memset(pBuf, 0, size);
    if (MemAddr < 0x200000)
    {
        MemAddr |= pReflashParams->FlashMappedAddr;
    }

    if (!brief)
    {
        Addr = MemAddr;
        TDebugPrint(_T("<6>Dump data from from 0x%08X len 0x%04X:\n"), Addr, size);
        for (int i = 0; i < size; i += maxReadSize)
        {
            if (SendReadAndVerifyRam(&SerialPort, Addr, pBuf, maxReadSize, false))
            {
                TDebugPrint(_T("Succeed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
            }
            else
            {
                TDebugPrint(_T("<0>Failed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
                return 0;
            }
            Addr += maxReadSize;
            pBuf += maxReadSize;
        }
        TDebugPrint(_T("<0>\n"), Addr, size);
        HexDump2(buf, size);
    }
    else
    {
        UINT32 SS1 = 0x0;
        UINT32 SS2 = 0x1000;
        UINT32 VS1 = 0x2000;
        UINT32 VS2 = 0x3000;
        UINT32 DS1 = 0x4000;
        UINT32 DS2 = 0x42000;
        //Dump 1K SS1
        pBuf = buf;
        memset(buf, 0, size);
        Addr = MemAddr + SS1;
        TDebugPrint(_T("<6>Dump SS1 from 0x%08X len 0x%04X:\n"), Addr, size);
        for (int i = 0; i < size; i += maxReadSize)
        {
            if (SendReadAndVerifyRam(&SerialPort, Addr, pBuf, maxReadSize, false))
            {
                TDebugPrint(_T("Succeed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
            }
            else
            {
                TDebugPrint(_T("<0>Failed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
                return 0;
            }
            Addr += maxReadSize;
            pBuf += maxReadSize;
        }
        TDebugPrint(_T("<6>\n"));
        HexDump2(buf, size);

        //Dump 1K SS2
        pBuf = buf;
        memset(buf, 0, size);
        Addr = MemAddr + SS2;
        TDebugPrint(_T("<6>Dump SS2 from 0x%08X len 0x%04X:\n"), Addr, size);
        for (int i = 0; i < size; i += maxReadSize)
        {
            if (SendReadAndVerifyRam(&SerialPort, Addr, pBuf, maxReadSize, false))
            {
                TDebugPrint(_T("Succeed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
            }
            else
            {
                TDebugPrint(_T("<0>Failed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
                delete buf;
                return 0;
            }
            Addr += maxReadSize;
            pBuf += maxReadSize;
        }
        TDebugPrint(_T("<6>\n"));
        HexDump2(buf, size);
        //Dump 1K VS1
        pBuf = buf;
        memset(buf, 0, size);
        Addr = MemAddr + VS1;
        TDebugPrint(_T("<6>Dump VS1 from 0x%08X len 0x%04X:\n"), Addr, size);
        for (int i = 0; i < size; i += maxReadSize)
        {
            if (SendReadAndVerifyRam(&SerialPort, Addr, pBuf, maxReadSize, false))
            {
                TDebugPrint(_T("Succeed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
            }
            else
            {
                TDebugPrint(_T("<0>Failed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
                delete buf;
                return 0;
            }
            Addr += maxReadSize;
            pBuf += maxReadSize;
        }
        TDebugPrint(_T("<6>\n"));
        HexDump2(buf, size);

        //Dump 4K VS2
        pBuf = buf;
        memset(buf, 0, size);
        Addr = MemAddr + VS2;
        TDebugPrint(_T("<6>Dump VS2 from 0x%08X len 0x%04X:\n"), Addr, size);
        for (int i = 0; i < size; i += maxReadSize)
        {
            if (SendReadAndVerifyRam(&SerialPort, Addr, pBuf, maxReadSize, false))
            {
                TDebugPrint(_T("Succeed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
            }
            else
            {
                TDebugPrint(_T("<0>Failed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
                delete buf;
                return 0;
            }
            Addr += maxReadSize;
            pBuf += maxReadSize;
        }
        TDebugPrint(_T("<6>\n"));
        HexDump2(buf, size);

        //Dump 4K DS1
        pBuf = buf;
        Addr = MemAddr + DS1;
        memset(buf, 0, size);
        TDebugPrint(_T("<6>Dump DS1 from 0x%08X len 0x%04X:\n"), Addr, size);
        for (int i = 0; i < size; i += maxReadSize)
        {
            if (SendReadAndVerifyRam(&SerialPort, Addr, pBuf, maxReadSize, false))
            {
                TDebugPrint(_T("Succeed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
            }
            else
            {
                TDebugPrint(_T("<0>Failed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
                delete buf;
                return 0;
            }
            Addr += maxReadSize;
            pBuf += maxReadSize;
        }
        TDebugPrint(_T("<6>\n"));
        HexDump2(buf, size);

        //Dump 4K DS2
        pBuf = buf;
        Addr = MemAddr + DS2;
        memset(buf, 0, size);
        TDebugPrint(_T("<6>Dump DS2 from 0x%08X len 0x%04X:\n"), Addr, size);
        for (int i = 0; i < size; i += maxReadSize)
        {
            if (SendReadAndVerifyRam(&SerialPort, Addr, pBuf, maxReadSize, false))
            {
                TDebugPrint(_T("Succeed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
            }
            else
            {
                TDebugPrint(_T("<0>Failed to READ_RAM from 0x%08X len 0x%04X\n"), Addr, maxReadSize);
                delete buf;
                return 0;
            }
            Addr += maxReadSize;
            pBuf += maxReadSize;
        }
        TDebugPrint(_T("<6>\n"));
        HexDump2(buf, size);
    }

    delete buf;
    return 1;
}

static int execute_download_hcd(UINT8 maxWriteSize, char *minidriverPathname, char *configPathname, bool onlyEraseChip, VERIFY_METHOD verifyMethod, CY_U64 BDAddr)
{
    ComHelper SerialPort;
    FILE *          fHCD = NULL;
    LONG            nVeryFirstAddress = 0;

    onlyEraseChip = false;
    verifyMethod = VERIFY_NONE;
    maxWriteSize = 0;
    minidriverPathname = NULL;

    if (configPathname)
    {
        fopen_s(&fHCD, configPathname, "rb");
        if (!fHCD)
        {
            TDebugPrint(_T("<0>Failed to open HCD file %s.\n"), configPathname);
            return 0;
        }
    }

    if (!SerialPort.OpenPort(port_num, baud_rate, cts_flow_ctrl))
    {
        TDebugPrint(_T("<0>Open COM%d port Failed, baud %d.\n"), port_num, baud_rate);
        return 0;
    }

    /*
    * Sleeping 10ms is needed, otherwise the immediately following HCI command can't get any response.
    */
    Sleep(10);

    if (!execute_reset(&SerialPort))
    {
        SerialPort.ClosePort();

        TDebugPrint(_T("<0>Failed to HCI Reset.\n"));

        return 0;
    }

    /*
    * For BCM20706, must send this command otherwise app can't launch after programming.
    */
    if (!SendDownloadMinidriver(&SerialPort))
    {
        TDebugPrint(_T("<0>Failed to send DOWNLOAD_MINIDRIVER command.\n"));

        if (fHCD)
            fclose(fHCD);

        return 0;
    }

    if (DumpFlag == 3)
    {
        return dump_data(SerialPort, 0);
    }

    TDebugPrint(_T("<6>\nDownloading HCD configuration...\n"));

    ULONG   nAddr, nHCDRecSize;
    BYTE    arHCDDataBuffer[256];
    BOOL    bIsLaunch = FALSE;

    while (ReadNextHCDRecord(fHCD, &nAddr, &nHCDRecSize, arHCDDataBuffer, &bIsLaunch))
    {
        if (bIsLaunch)
        {
            SendLaunchRamAddr(&SerialPort, nAddr);

            TDebugPrint(_T("<6>\nChip reset to address %08X succeeded.\n"), nAddr);

            break;
        }
        else if (!SendHcdRecord(&SerialPort, nAddr, nHCDRecSize, arHCDDataBuffer))
        {
            TDebugPrint(_T("<0>\nFailed to send hcd portion at %x.\n"), nAddr);

            break;
        }
    }

    if (fHCD)
        fclose(fHCD);

    if (bIsLaunch)
    {
        TDebugPrint(_T("<6>Completed successfully.\n"));

        return 1;
    }
    else
    {
        return 0;
    }
}

static int execute_download_hex(UINT8 maxWriteSize, char *minidriverPathname, char *configPathname, bool onlyEraseChip, VERIFY_METHOD verifyMethod, CY_U64 BDAddr)
{
    FwFileWicedHex minidrvFile, configFile;
    ComHelper SerialPort;

    if (!SerialPort.OpenPort(port_num, baud_rate, cts_flow_ctrl))
    {
        TDebugPrint(_T("<0>Open COM%d port Failed, baud %d.\n"), port_num, baud_rate);
        return 0;
    }

    if (onlyEraseChip)
    {
        if (!minidriverPathname)
        {
            TDebugPrint(_T("<0>Minidriver is needed.\n"));
            return 0;
        }

        if (DumpFlag || pReflashParams->EraseAddr == INVALID_ADDR_VALUE)
        {
            TDebugPrint(_T("<0>Chip erase is not supported.\n"));
            return 0;
        }
    }

    if (minidriverPathname && (CY_ERROR_SUCCESS != minidrvFile.Load(minidriverPathname)))
    {
        TDebugPrint(_T("<0>Invalid minidriver hex file.\n"));

        return 0;
    }

    if (configPathname && CY_ERROR_SUCCESS != configFile.Load(configPathname))
    {
        TDebugPrint(_T("<0>Invalid config hex file.\n"));

        return 0;
    }

    if (BDAddr && (CY_ERROR_SUCCESS != configFile.UpdateBDAddress(BDAddr)))
    {
        TDebugPrint(_T("<0>Failed to update BD Address in hex file.\n"));

        return 0;
    }

    if (!execute_reset(&SerialPort))
    {
        SerialPort.ClosePort();

        TDebugPrint(_T("<0>Failed to HCI Reset.\n"));

        return 0;
    }

    TDebugPrint(_T("<6>HCI Reset success.\n"));

    /*
    * WICED-Studio-4.1\wiced_tools\wmbt.exe always send download minidriver command regardless of downloading minidriver.
    * But by my test on BCM20706 RAM (without sflash), it is not needed to send this command if no minidriver is needed.
    * So only send this command if minidriver is needed.
    * [NOTE] EEPROM is not tested. Perhaps this command should be sent but minidriver is not needed.
    */
    /*
    if (!SendDownloadMinidriver(&SerialPort))
    {
        printf("Failed to send DOWNLOAD_MINIDRIVER command.\n");

        return 0;
    }
    */


    if (minidriverPathname)
    {
        /*
         * 737 Enter "Recover" or "Download" or "Application" mode by the follow condition table
         *                                      Rx-High     Rx-Low
         * HasValidAppConfigInFlash             Download    Application
         * NoValidAppConfigInFlash              Recover     Download
         * [Note] Rx will be set to high if USB-UART is connected.
         *
         *  RecoverMode:  Doesn't support download minidriver command.
         *                  Can't send download minidriver command before downloading minidriver.
         *                  Enter this mode with new flash on MTK test.
         *
         *  DownloadMode: Must send download minidriver command before downloading minidriver.
         *
         *  By defaut, MTK for 737 assumes 737 enters recover mode. If download fails then use download mode.
         */

        if (!InRecoverMode && !SendDownloadMinidriver(&SerialPort))
        {
            TDebugPrint(_T("<0>Failed to send DOWNLOAD_MINIDRIVER command. Ignore\n"));

            //return 0;
        }

        TDebugPrint(_T("<6>Download minidriver...\n"));

        if (!execute_download_hex_file(&SerialPort, maxWriteSize, &minidrvFile, VERIFY_NONE))
        {
            TDebugPrint(_T("<0>Failed to send download minidriver hex file.\n"));

            return 0;
        }

        if (minidrvFile.launchAddress != INVALID_ADDR_VALUE)
        {
            if (!SendLaunchRamAddr(&SerialPort, minidrvFile.launchAddress))
            {
                TDebugPrint(_T("<0>Failed to Launch minidriver at 0x%08X.\n"), minidrvFile.launchAddress);

                return 0;
            }
            else
            {
                TDebugPrint(_T("<6>Launch minidriver at  0x%08X succeeded.\n"), minidrvFile.launchAddress);
                if (DumpFlag == 3)
                {
                    return dump_data(SerialPort);
                }
            }
        }

    }

    if (!DumpFlag && pReflashParams->EraseAddr != INVALID_ADDR_VALUE && !SendChipErase(&SerialPort, pReflashParams->EraseAddr))
    {
        TDebugPrint(_T("<0>Failed to erase chip at at 0x%08X.\n"), pReflashParams->EraseAddr);

        return 0;
    }
    else
    {
        //This description is not correct. 737 supports ChipErase command.
        //BCM20737 doesn't support ChipErase command. I think it uses dedicated minidriver to do erase instead.
        //Chipload.exe in WICED_2.2.3 wait about 5 seconds. But by my test, download can also success without waiting.
        //Sleep(5000); 
        TDebugPrint(_T("<6>Erase chip successfully.\n"));
    }

    if (!onlyEraseChip)
    {
        TDebugPrint(_T("<6>Download configuration...\n"));

        if (DumpFlag)
        {
            verifyMethod = VERIFY_DATA;
        }
        else
        {
            if (!execute_download_hex_file(&SerialPort, maxWriteSize, &configFile, (verifyMethod == VERIFY_CRC) ? VERIFY_CRC : VERIFY_NONE))
            {
                TDebugPrint(_T("<0>Failed to send download config hex file.\n"));

                return 0;
            }
        }

        if ((verifyMethod == VERIFY_DATA) && !execute_download_hex_file(&SerialPort, maxWriteSize, &configFile, VERIFY_DATA))
        {
            TDebugPrint(_T("<0>Failed to verify config hex file.\n"));

            return 0;
        }
    }
    else
    {
        return 1;
    }

    if (pReflashParams->AppAddr != INVALID_ADDR_VALUE &&
        !SendLaunchRamAddr(&SerialPort, pReflashParams->AppAddr))
    {
        TDebugPrint(_T("<0>Failed to reset chip to address at 0x%08X.\n"), pReflashParams->AppAddr);

        return 0;
    }
    else
        TDebugPrint(_T("<0>Chip reset to address %08X succeeded.\n"), pReflashParams->AppAddr);

    TDebugPrint(_T("<6>Completed successfully.\n"));

    if (pReflashParams->BringAppFromHCIMode)
        BringBCMToAppModeFromHCIMode(&SerialPort);

    return 1;
}

static int execute_simulate_download_hex(UINT8 maxWriteSize, char *configPathname)
{
    FwFileWicedHex configFile;

    if (configPathname && CY_ERROR_SUCCESS != configFile.Load(configPathname))
    {
        TDebugPrint(_T("<0>Invalid config hex file.\n"));

        return 0;
    }

    if (!execute_download_hex_file(NULL, maxWriteSize, &configFile, VERIFY_NONE))
    {
        TDebugPrint(_T("<0>Failed to send download config hex file.\n"));

        return 0;
    }

    return 1;
}
#define MFID_MIN_VALUE 00000001
#define MFID_MAX_VALUE 99999998
static int INVALID_MFIDS[] = { /*00000000,*/ 11111111, 22222222, 33333333, 44444444, 55555555, 77777777, 66666666, 88888888/*, 99999999*/, 12345678, 87654321 };

int IsValidMFiID(int id)
{
    if ((id < MFID_MIN_VALUE) || (id > MFID_MAX_VALUE))
    {
        return FALSE;
    }

    for (int i = 0; i < sizeof(INVALID_MFIDS) / sizeof(int); i++)
    {
        if (id == INVALID_MFIDS[i])
            return FALSE;
    }

    return TRUE;
}

static int execute_read_ram(ComHelper *p_port, UINT32 address, int len)
{
    BOOL res, opened = FALSE;
    UCHAR* buf = new UCHAR[len];

    if (p_port == NULL)
    {
        p_port = new ComHelper;
        if (!p_port->OpenPort(port_num, baud_rate, cts_flow_ctrl))
        {
            TDebugPrint(_T("<0>Open COM%d port Failed, baud %d.\n"), port_num, baud_rate);
            delete p_port;
            return 0;
        }
        opened = TRUE;
    }

    res = execute_reset(p_port);

    if (res)
    {
        memset(buf, 0, len);
        SendReadAndVerifyRam(p_port, address, buf, len, false);
        TDebugPrint(_T("Data from address 0x%0X:.\n"), address);
        HexDump(buf, len);
        if (len == 4 && address == 0x500C00)
        {
            int* pID = (int*)buf;
            if (IsValidMFiID(*pID))
            {
                TDebugPrint(_T("<6>MFi-ID: %08d\n"), *pID);
            }
            else
            {
                TDebugPrint(_T("<6>Invalid MFi-ID.\n"));
            }

        }
    }

    if (opened)
        delete p_port;
    if (buf)
        delete buf;
    return res;
}

bool InitFixedParamFromArg(_TCHAR* arg)
{
    //check if it is baudrate
    int val = 0;

    if ((_stscanf_s(arg, _T("%d"), &val) == 1) && val > 0)
    {
        baud_rate_set = true;
        baud_rate = val;
        return true;
    }

    if (!_tcsncicmp(arg, _T("VERBOSE"), 7))
    {
        if (_stscanf_s(arg + 7, _T("%d"), &val) == 1)
        {
            dbg = val;
        }
        else
        {
            dbg = 7;
        }
        return true;
    }

    if (!_tcsicmp(arg, _T("CTS")))
    {
        cts_flow_ctrl = 1;
        cts_flow_ctrl_set = true;
        return true;
    }

    return false;
}

int _tmain(int argc, _TCHAR* argv[])
{
    int rx_frequency = 0;
    int tx_frequency = 0;
    int pattern = 0;
    int length = 0;
    bool onlyErase = false;
    int i = 0;

    if (argc < 2)
    {
        print_usage_download(true);
        print_usage_dump(true);
        return 0;
    }

    if (_stricmp(argv[1], "gen_hex") == 0)
    {
        if (argc != 4)
        {
            print_usage_gen_hex(true);
            return - 1;
        }
        FwFileWicedHex emptyHex;
        int err = 0;
        UINT32 addr = Global::IntFromHexStr(argv[2], err);
        if (err && addr == 0)
        {
            TDebugPrint(_T("<0>Invalid HEX address value.\n"));
            print_usage_gen_hex(true);
            return -1;
        }
        UINT32 len = Global::IntFromHexStr(argv[3], err);
        if (!len)
        {
            TDebugPrint(_T("<0>Invalid HEX length value.\n"));
            print_usage_gen_hex(true);
            return -1;
        }

        emptyHex.GenEmptyHex(addr, len);
        emptyHex.DumpPrint();
        return 0;
    }

    if (argc >= 3 && _stricmp(argv[1], "parse_hex") == 0)
    {
        Simulate = 1;
        dbg = 7;
        UINT8 maxWriteSize = 0;
        char *configPathname;
        if (argc > 3)
        {
            maxWriteSize = atoi(argv[2]);
            configPathname = argv[3];
        }
        else
        {
            configPathname = argv[2];
        }
        int ret = execute_simulate_download_hex(maxWriteSize, configPathname);
        return ret;
    }

    if (argc >= 3)
    {
        while (argv[2][i])
        {
            argv[2][i] = toupper(argv[2][i]);
            i++;
        }
        _stscanf_s(argv[2], _T("COM%d"), &port_num);

        for (int cnt = 0; argc >= 4 && cnt < 3; cnt++)
        {
            if (InitFixedParamFromArg(argv[3]))
            {
                for (i = 3; i < argc - 1; i++)
                {
                    argv[i] = argv[i + 1];
                }
                argc--;
                continue;
            }
            break;
        }
    }
    

    if (_stricmp(argv[1], "recover") == 0)
    {
        argv[1] = "download";
        InRecoverMode = 1;
    }
    else if (_stricmp(argv[1], "erase") == 0)
    {
        argv[1] = "download";
        onlyErase = 1;
    }
    else if (_stricmp(argv[1], "dump") == 0)
    {
        argv[1] = "download";
        DumpFlag = 3;
    }
    else if (_stricmp(argv[1], "dumpr") == 0)
    {
        argv[1] = "download";
        InRecoverMode = 1;
        DumpFlag = 3;
    }
    else if (_stricmp(argv[1], "dump1") == 0)
    {
        argv[1] = "download";
        DumpFlag = 1;
    }
    else if (_stricmp(argv[1], "dump2") == 0)
    {
        argv[1] = "download";
        DumpFlag = 2;
    }
    else if (_stricmp(argv[1], "dump1r") == 0)
    {
        argv[1] = "download";
        DumpFlag = 1;
        InRecoverMode = 1;
    }
    else if (_stricmp(argv[1], "dump2r") == 0)
    {
        argv[1] = "download";
        DumpFlag = 2;
        InRecoverMode = 1;
    }

    if ((argc >= 2) && (_stricmp(argv[1], "reset") == 0))
    {
        if (argc == 3)
        {
            return (execute_reset(NULL));
        }
        print_usage_reset(true);
        return 0;
    }
    if ((argc >= 2) && (_stricmp(argv[1], "read") == 0))
    {
        if (argc == 5)
        {
            int err = 0;
            UINT32 addr = Global::IntFromHexStr(argv[3], err);
            if (err && addr == 0)
            {
                TDebugPrint(_T("<0>Invalid HEX address value.\n"));
                print_usage_read(true);
                return 0;
            }
            int len = atoi(argv[4]);
            if (!len)
            {
                TDebugPrint(_T("<0>Invalid data length value.\n"));
                print_usage_read(true);
                return 0;
            }

            return (execute_read_ram(NULL, addr, len));
        }
        print_usage_read(true);
        return 0;
    }
    else if ((argc >= 2) && (_stricmp(argv[1], "download") == 0))
    {
        if ((!onlyErase && argc >= 5) || (onlyErase && argc >= 4) || (DumpFlag == 3 && argc >= 4))
        {
            char* configPathname = NULL;
            char* moduleName = argv[3];
            char* minidrvPathname = NULL;

            for (int i = 0; i < sizeof(ReflashParams) / sizeof(REFALSH_PARAMETERS); i++)
            {
                if (strlen(moduleName) > 3 && _stricmp(moduleName + 3, ReflashParams[i].ModuleName + 3) == 0)
                {
                    pReflashParams = ReflashParams + i;
                    break;
                }
            }

            if (pReflashParams)
            {
                if (onlyErase && pReflashParams->EraseAddr == INVALID_ADDR_VALUE)
                {
                    TDebugPrint(_T("<0>Chip erase is not supported.\n"));
                    return -1;
                }

                CY_U64 BDAddr = 0;
                minidrvPathname = pReflashParams->MiniDrvPath;
                if (DumpFlag == 3)
                {
                    int err = 0;
                    configPathname = NULL;
                    if (argc >= 5)
                    {
                        DumpOffset = Global::IntFromHexStr(argv[4], err);
                        if (err)
                        {
                            TDebugPrint(_T("<0>Invalid HEX offset value.\n"));
                            print_usage_dump(true);
                            return 0;
                        }
                    }
                    if (argc >= 6)
                    {
                        err = 0;
                        DumpLength = Global::IntFromHexStr(argv[5], err);
                        if (err)
                        {
                            TDebugPrint(_T("<0>Invalid HEX length value.\n"));
                            print_usage_dump(true);
                            return 0;
                        }
                    }
                }
                else
                {
                    if (argc >= 5)
                        configPathname = (argv[4]);

                    if (argc >= 6)
                    {
                        if (strlen(argv[5]) <= 12)
                        {
                            char BDAddrBuf[14];
                            memset(BDAddrBuf, 0, sizeof(BDAddrBuf));
                            BDAddrBuf[0] = '0';
                            memcpy(BDAddrBuf + strlen(argv[5]) % 2, argv[5], strlen(argv[5]));

                            int count = Global::DecodeHexStr(BDAddrBuf, (PBYTE)(&BDAddr) + 2);
                            if (count >= 1 && count <= 6)
                            {
                                BDAddr = CPU_TO_BE64(BDAddr);
                            }
                            else
                            {
                                print_usage_download(true);
                                return 0;
                            }
                        }
                    }
                }

                if (argc >= 7)
                {
                    minidrvPathname = argv[6];
                }
                if (!baud_rate_set)
                    baud_rate = pReflashParams->BaudRate;
                if (!cts_flow_ctrl_set)
                    cts_flow_ctrl = pReflashParams->FlowCtrlEnable;
                int ret = (pReflashParams->pDownloadProc(pReflashParams->MaxWriteSize, minidrvPathname, configPathname, onlyErase, pReflashParams->VerifyMethod, BDAddr));
                return ret;
            }
        }

        print_usage_download(true);
        return 0;
    }
    else
    {
        print_usage_download(false);
        printf("\n");
        print_usage_dump(false);
        printf("\n");
        print_usage_reset(false);
        printf("\n");
        print_usage_read(false);
        printf("\n");
        print_usage_parse_hex(false);
    }
    return 0;
}

