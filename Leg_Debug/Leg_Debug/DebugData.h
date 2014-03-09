// DebugData.h: interface for the CDebugData class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_DEBUGDATA_H__80BE350B_6F26_41DA_B22D_CA024071BE5A__INCLUDED_)
#define AFX_DEBUGDATA_H__80BE350B_6F26_41DA_B22D_CA024071BE5A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//用與存儲與被調試進程相關的信息
typedef struct  TargetProcess_info
{
	//保存被調試進程的句柄
	HANDLE hProcess;
	//保存被調試線程的句柄
	HANDLE hThread;
	//保存被調試進程的ID
	DWORD dwProcessId;
	//保存被調試線程的ID
	DWORD dwThreadId;
	//入口點地址
	LPTHREAD_START_ROUTINE OepAddress;
	//保存入口點首地址數據
	BYTE OriginalCode;
	//用于設置INT3斷點的CC
	BYTE bCC;

}TARGET_PROCESS_INFO;

//INT3斷點結構體
typedef struct INT3BREAKPOINT
{
	//斷點地址
	LONGLONG dwAddress;
	//斷點首字節數據
	BYTE  bOriginalCode;
	//是否是永久斷點 永久斷點需要恢復 一次性斷點如：go address 此時為一次性斷點 
	//OEP處的斷點也是一次性斷點,不需要在恢復為斷點
	BOOL  isForever;

}INT3_BP;

//保存需要被恢復為INT3斷點的地址
typedef struct RECOVER_BREAKPOINT
{
	//需要重新恢復為斷點的地址(永久斷點)
	LONGLONG dwAddress;
	// 是否需要被恢復為斷點
	BOOL  isNeedRecover;
	//原字節 //用于恢復斷點
	BYTE  bOrginalCode;
}RECOVER_BP;

//dr7調試控制寄存器
typedef union _Tag_DR7
{
	struct __DRFlag
	{
		unsigned int L0 : 1;
		unsigned int G0 : 1;
		unsigned int L1 : 1;
		unsigned int G1 : 1;
		unsigned int L2 : 1;
		unsigned int G2 : 1;
		unsigned int L3 : 1;
		unsigned int G3 : 1;
		unsigned int Le : 1;
		unsigned int Ge : 1;
		unsigned int b : 3;
		unsigned int gd : 1;
		unsigned int a : 2;
		unsigned int rw0 : 2;
		unsigned int len0 : 2;
		unsigned int rw1 : 2;
		unsigned int len1 : 2;
		unsigned int rw2 : 2;
		unsigned int len2 : 2;
		unsigned int rw3 : 2;
		unsigned int len3 : 2;
	} DRFlag;
	DWORD dwDr7;
}DR7;

//DR0-DR3的使用情況
typedef struct _DR_USE
{
	BOOL Dr0;
	BOOL Dr1;
	BOOL Dr2;
	BOOL Dr3;

} DR_USE;

//要恢復的硬件斷點結構體
typedef struct RECOVER_HARD_BREAKPOINT
{
	//要恢復的調試寄存器編號 0-3 //如為-1表示沒有要恢復的 
	//想來想去就一個成員,暈
	DWORD dwIndex;

}RECOVER_HARDBP;

//內存斷點結構體

typedef struct MEMORYBREAKPOINT
{
	//地址
	LONGLONG dwBpAddress;
	//長度
	DWORD dwLength;
	//類型 是訪問斷點還是寫入斷點 
	DWORD dwAttribute;
	//內存頁保存頁的首地址數組 一個斷點跨幾個內存頁,最大5個分頁!在多就腦殘了
	DWORD dwMemPage[5];
	//記錄占的分頁數
	DWORD dwNumPage;



}MEM_BP;

//內存分頁結構體(僅限有斷點的分頁)

typedef struct MEMORYPAGE
{
	//內存頁的首地址
	LONGLONG dwBaseAddress;
	//原訪問屬性
	DWORD dwProtect;


}MEM_BP_PAGE;

//要恢復的內存頁屬性

typedef struct _RECOVER_MEMPAGE
{
	//內存首地址
	LONGLONG dwBaseAddress;
	//內存頁斷點的保護屬性(不是原保護屬性)
	DWORD dwProtect;
	//是否需要恢復
	BOOL  isNeedRecover;
}RECOVER_MEMPAGE;


//導出函數地址表
typedef struct _EXPORT_FUN_INFO
{
	//函數地址
	LONGLONG dwAddress;
	//DLL名稱
	char  szDLLName[40];

	char  szFunName[280];


}EXPORT_FUN_INFO;


//指令記錄結構體
typedef struct _OPCODE_RECORD
{
	//指令地址
	LONGLONG dwAddress;

}OPCODE_RECORD;

//模塊信息 用于顯示標題即當前位于那個模塊
typedef struct _MODULE_INFO
{
	//模塊名
	char szModuleName[200];
	//模塊基址
	LONGLONG dwBaseAddress;
	//模塊大小
	LONGLONG dwSize;

}MODULE_INFO;













#endif // !defined(AFX_DEBUGDATA_H__80BE350B_6F26_41DA_B22D_CA024071BE5A__INCLUDED_)
