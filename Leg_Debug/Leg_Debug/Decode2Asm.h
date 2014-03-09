// Decode2Asm.h: interface for the CDecode2Asm class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_DECODE2ASM_H__7AE15245_B351_41F6_B8B2_09D157829988__INCLUDED_)
#define AFX_DECODE2ASM_H__7AE15245_B351_41F6_B8B2_09D157829988__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/*// 無機器碼解析
extern "C"
void
__stdcall
Decode2Asm(IN PBYTE pCodeEntry,   // 需要解析指令地址
           OUT char* strAsmCode,  // 得到反匯編指令信息
           OUT UINT* pnCodeSize,  // 解析指令長度
           LONGLONG nAddress);  
		   */
// 帶機器碼解析 
void
__stdcall
Decode2AsmOpcode(IN PBYTE pCodeEntry,   // 需要解析指令地址
OUT char* strAsmCode,        // 得到反匯編指令信息
OUT char* strOpcode,         // 解析機器碼信息
OUT UINT* pnCodeSize,        // 解析指令長度
LONGLONG nAddress);

#endif // !defined(AFX_DECODE2ASM_H__7AE15245_B351_41F6_B8B2_09D157829988__INCLUDED_)
