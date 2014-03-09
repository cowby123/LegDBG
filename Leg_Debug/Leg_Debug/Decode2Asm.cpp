// Decode2Asm.cpp: implementation of the CDecode2Asm class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <string>
#include <iostream>
#include <stdio.h>

using namespace std;

#define BEA_ENGINE_STATIC  // 指明使用靜態Lib庫
#define BEA_USE_STDCALL    // 指明使用stdcall調用約定

#ifdef __cplusplus


extern "C"{
#endif


#include "beaengine-win64/headers/BeaEngine.h"
#pragma comment(lib, "beaengine-win64\\Win64\\Lib\\BeaEngine64.lib")


#ifdef __cplusplus
};
#endif


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

/*void
__stdcall
Decode2Asm(IN PBYTE pCodeEntry,
           OUT char* strAsmCode,
           OUT UINT* pnCodeSize,
           LONGLONG nAddress)
{
  DISASSEMBLY Disasm; // Creates an Disasm Struct
  // Pointer to linear address
  char *Linear = (char *)pCodeEntry;// Points to the address of array to decode.
  // Index of opcoded to decode
  DWORD       Index = 0; 
  Disasm.Address = nAddress; // Common Entry Point (usually default..)
  FlushDecoded(&Disasm);     // 清空反匯編結構體
  
  // Decode instruction
  Decode(&Disasm,
    Linear,
    &Index);
  
  strcpy(strAsmCode, Disasm.Assembly);

  if(strstr((char *)Disasm.Opcode, ":"))
  {
	  Disasm.OpcodeSize++;
 	  char ch =' ';
 	  strncat(strAsmCode,&ch,sizeof(char));
  }

  strcat(strAsmCode,Disasm.Remarks);
  *pnCodeSize = Disasm.OpcodeSize;
  
  // Clear all information
  FlushDecoded(&Disasm);
  
  return;
}*/


void
__stdcall
Decode2AsmOpcode(IN PBYTE pCodeEntry,   // 需要解析指令地址
OUT char* strAsmCode,        // 得到反匯編指令信息
OUT char* strOpcode,         // 解析機器碼信息
OUT UINT* pnCodeSize,        // 解析指令長度
LONGLONG nAddress){
	char *StartCodeSection = (char*)pCodeEntry;
	char *EndCodeSection = (char*)pCodeEntry + 20;
	DISASM MyDisasm;
	unsigned int len;
	int i = 0;
	int aError = 0;
	int buf = 0;
	char lpBuffer2[50] = { 0 };
	char lpBuffer3[50] = { 0 };
	BYTE lpBuffer[16] = { 0 };
	BYTE lpBuffer1[16] = { 0 };
	char szTemp[MAX_PATH] = { 0 };
	/*初始化DISASM結構*/
	(void)memset(&MyDisasm, 0, sizeof(DISASM));
	/*初始化EIP*/
	MyDisasm.EIP = (LONGLONG)StartCodeSection;
	// 取出解析后的指令信息
	/*初始化虛擬地址*/
	MyDisasm.VirtualAddr = (LONGLONG)nAddress;

	


	/*設置為64位元*/
	MyDisasm.Archi = 64;

	/*DISASM循環解析代碼*/



	//設置安全鎖
	MyDisasm.SecurityBlock = (long)(EndCodeSection - StartCodeSection);
	len = Disasm(&MyDisasm);

	if (len == OUT_OF_BLOCK){
		aError = true;
	}
	else if (len == UNKNOWN_OPCODE){
		aError = true;
	}
	else{

		strcpy_s(strAsmCode,63,MyDisasm.CompleteInstr);

		//strcpy_s(strOpcode,len, (char*)pCodeEntry);

		// 取出指令說明信息

		// 設置指令長度
		*pnCodeSize = len;
		for (int j = 0; j < 50; j++){
			lpBuffer2[j] = 0x30;
		
		}
		for (int i = 0; i < len; i++){
			buf = *(pCodeEntry+i);
			_itoa_s(buf, lpBuffer2, 16);
			lpBuffer3[i*2] = lpBuffer2[0];
			if (lpBuffer2[1] == 0x00){ lpBuffer2[1] = 0x30; }
			lpBuffer3[i * 2 + 1] = lpBuffer2[1];
		}
		
		//lpBuffer3[len * 2 + 2] = '/n';

		//_itoa_s(buf, lpBuffer2, 16);
		strcpy_s(strOpcode, 25, lpBuffer3);
		MyDisasm.EIP = MyDisasm.EIP + len;
		MyDisasm.VirtualAddr = MyDisasm.VirtualAddr + len;

	}

}

