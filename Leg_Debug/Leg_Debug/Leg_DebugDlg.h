
// Leg_DebugDlg.h : 標頭檔
//

#pragma once
#include "afxwin.h"
#include "DebugData.h"
#include "afxcmn.h"
#include "Decode2Asm.h"

// CLeg_DebugDlg 對話方塊
class CLeg_DebugDlg : public CDialogEx
{
// 建構
public:
	CLeg_DebugDlg(CWnd* pParent = NULL);	// 標準建構函式
	
// 對話方塊資料
	enum { IDD = IDD_LEG_DEBUG_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支援


// 程式碼實作
protected:
	HICON m_hIcon;

	// 產生的訊息對應函式
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnOpen();
	//初始化調適線程
	char m_szFilePath[MAX_PATH];
	//判斷是否為f9模式
	BOOL m_IsGo;
	//是否是自動F7模式 自動步入
	BOOL m_IsAutoF7;
	//debugger是否處於debug狀況
	BOOL m_isDebuging;
	//被調試進程信息結構體
	TARGET_PROCESS_INFO m_tpInfo;
	//可執行文件的路徑
	//char m_SzFilePath[MAX_PATH];
	//標志 判斷是否要重新枚舉模塊 當有DLL加載時,置為TRUE 此時需要更新模塊信息表
	BOOL m_GetModule;
	//導出函數映射表  用函數地址做索引 這樣查詢快
	CMap<LONGLONG, LONGLONG&, EXPORT_FUN_INFO, EXPORT_FUN_INFO&> m_ExFunList;
	//函數名與地址對應 用于在函數入口下API斷點
	CMap<CString, LPCTSTR, LONGLONG, LONGLONG&> m_Fun_Address;
	//用映射表記錄已經運行了的指令地址 這樣可以過濾重復指令(如循環等)
	CMap<LONGLONG, LONGLONG&, OPCODE_RECORD, OPCODE_RECORD&> m_Opcode;
	//是否OEP
	bool m_IsOepBP;
	//對DLL導出函數進行反匯編
	void DisassemblerExcFun(char* szFunName);
	//處理U命令 如果沒有地址就從以前的地址接著U 在單步或者斷點異常中再把這個地址設為當前EIP的值
	void ON_U_COMMAND(LONGLONG dwAddress);
	//獲得要被刪除的硬件斷點的調試寄存器編號 返回-1表示沒找到
	int GetDeletedDrIndex(LONGLONG dwAddress, CONTEXT ct);
	//去掉命令的左邊和右邊的空格字符
	BOOL Kill_SPACE(char* szCommand);
	//刪除硬件斷點
	void DeleteHardBP(LONGLONG dwAddress);
	//處理B命令
	void Handle_B_Command(char* szCommand);
	//用戶設置斷點
	void UserSetBP(HANDLE hProcess, LONGLONG dwBpAddress, BYTE bCCode);
	//用戶命令的處理函數
	void Handle_User_Command(char* szCommand);
	//判斷是否是單步步過模式 如果是則要在斷點異常中輸出寄存器和指令
	BOOL m_IsF8;
	//是否是自動F8模式 自動單步步過
	BOOL m_IsAutoF8;
	//刪除永久斷點
	BOOL m_isDelete;
	//INT3斷點鏈表
	CList<INT3_BP, INT3_BP&> m_Int3BpList;
	//需要被重新恢復為INT3斷點的結構體
	RECOVER_BP m_Recover_BP;
	//刪除用戶斷點
	void DeleteUserBP(HANDLE hProcess, LONGLONG dwBpAddress);
	//模塊信息表 用于顯示標題用 即當前指令在哪個模塊
	CList<MODULE_INFO, MODULE_INFO&> m_Module;
    //記錄U命令的當前地址
	LONGLONG m_Uaddress;
public:
	//得到可執行文件的路徑
	void GetExeFilePath(char* szFilePath);
	//映射文件 并檢查PE有效性以及是不是EXE文件
	BOOL MapPEFile();
	//輸出錯誤信息 
	void GetErrorMessage(DWORD dwErrorCode);
	//處理加載DLL事件
	void ON_LOAD_DLL_DEBUG_EVENT(HANDLE hFile, LPVOID pBase);
	//得到加載DLL時的路徑
	void GetFileNameFromHandle(HANDLE hFile, LPVOID pBase);
	//處理eb函數
	void CLeg_DebugDlg::ChangeByte(HANDLE hProcess, LONGLONG dwAddress, byte chby);
	// 獲得導入表函數地址
	BOOL GetExportFunAddress(HANDLE hFile, char* pDll, LPVOID pBase);
	//參數一 導入表的RVA 參數2區塊表的數目 參數3區塊表的首地址
	DWORD RvaToFileOffset(DWORD dwRva, DWORD dwSecNum, PIMAGE_SECTION_HEADER pSec);
	//打開文件初始化
	bool OnInitial(char* lpszFilename);
	//處理 CREATE_PROCESS_DEBUG_EVENT 事件的函數 
	DWORD ON_CREATE_PROCESS_DEBUG_EVENT(DWORD dwProcessId, DWORD dwThreadId, LPTHREAD_START_ROUTINE lpOepAddress);
	//輸出ASM
	void ShowAsm(LONGLONG dwAddress);
	//讀取記憶體
	BOOL OnReadMemory(IN LONGLONG dwAdderss, OUT BYTE* lpBuffer, DWORD dwSize);
	//解析ASM
	void DisassembleCode(char* StartCodeSection, char* EndCodeSection, LONGLONG virtual_Address);
	//顯示暫存器
	void ShowRegData();

	//取得線程
	BOOL OnGetThreadContext(CONTEXT *pctThreadContext);
	//更新DLL列表
	void GetDllInfoFromHandle(HANDLE hFile, LPVOID pBase);
	//顯示記憶體內容
	void ShowMemoryData(LONGLONG dwAddress);
	BOOL OnIsAddressIsValid(LONGLONG dwAddress);
	//F9
	void ON_VK_F9();
	//處理斷點
	LONGLONG ON_EXCEPTION_BREAKPOINT(LONGLONG dwExpAddress);
	//回復段點
	void RecoverBP(HANDLE hProcess, LONGLONG dwBpAddress, BYTE bOrignalCode);
	//
	void ReduceEIP();
	//判斷是否是用戶設置的INT3斷點 通過查詢INT3鏈表 
	BOOL isUserBP(LONGLONG dwBpAddress);
	//枚舉斷點
	void ListBP();
	//F8鍵的處理函數 單步步過
	void ON_VK_F8();
	//刪除內存斷點
	void DeleteMemBP(LONGLONG dwBpAddress);
	//F7鍵的處理函數 單步步入
	void ON_VK_F7();
	//找到符合的內存斷點信息并返回 參數類型為引用 并從鏈表中刪除此元素
	BOOL FindMemBPInformation(MEM_BP& mBP, LONGLONG dwBpAddress);
	//先判斷有沒有另一個內存斷點在這個分頁上,如果存在就修改為另一個斷點所要求的屬性
	//參數 內存頁的首地址
	BOOL ModifyPageProtect(LONGLONG dwBaseAddress);
	//設置斷點  斷點地址 0xCC 用于永久斷點重新恢復為斷點
	void DebugSetBp(HANDLE hProcess, LONGLONG dwBpAddress, BYTE bCCode);
	//單步異常處理函數  參數異常地址
	LONGLONG ON_EXCEPTION_SINGLE_STEP(LONGLONG dwExpAddress);
	//在反匯編窗口顯示匯編代碼  參數 要高亮的指令地址
	void ShowAsmInWindow(LONGLONG dwStartAddress);
	//找到原始內存頁鏈表的對應屬性并傳出 引用類型
	BOOL FindMemOriginalProtect(MEMORY_BASIC_INFORMATION& mbi);
	//跳出函數  僅適用于MOV EBP ,ESP指令之后 POP EBP之前 利用堆棧原理讀取返回地址
	void StepOutFromFun();
	//設置調試器標題(在調試什么程序,以及當前指令在哪個模塊)
	//參數為當前指令地址
	void SetDebuggerTitle(LONGLONG dwAddress);
	//刪除所有斷點 用于記錄指令
	void DeleteAllBreakPoint();
	//自動步入
	void OnAutostepinto();
	//F9執行
	void OnRun();
	//熱鍵F6
	void OnAutostepout();
	//判斷地址是否重復下內存斷點
	BOOL FindMemBP(LONGLONG dwBpAddress);
	//設置硬件斷點 參數 地址 屬性 長度
	//dwAttribute 0表示執行斷點 3表示訪問斷點 1 表示寫入斷點
	//dwLength 取值 1 2 4
	void SetHardBP(LONGLONG dwBpAddress, LONGLONG dwAttribute, LONGLONG dwLength);
	//獲得當前加載模塊信息
	//截獲消息
	BOOL PreTranslateMessage(MSG* pMsg);
	BOOL GetCurrentModuleList(HANDLE hProcess);
	//根據要顯示的指令地址 判斷當前指令地址數組中是否有 若有就返回其下標 否則返回-1
	LONGLONG IsFindAsmAddress(LONGLONG dwStartAddress);
	//判斷地址和長度占了幾個分頁并加入內存分頁表 并把斷點也加入斷點鏈表
	BOOL AddMemBpPage(LONGLONG dwBpAddress, LONGLONG dwLength, MEMORY_BASIC_INFORMATION mbi, LONGLONG dwAttribute, MEM_BP& mbp);
	//判斷解析指令中的函數調用
	BOOL IsExportFun(char* szBuffer, EXPORT_FUN_INFO& expFun);
	//判斷某一頁首地址是否存在于頁鏈表中
	BOOL FindMemPage(LONGLONG dwBaseAddress);
	//設置內存斷點  dwAttribute 1表示寫入斷點 3表示訪問斷點
	void SetMemBP(LONGLONG dwBpAddress, LONGLONG dwAttribute, LONGLONG dwLength);
	//使硬件斷點暫時無效
	void InvalidHardBP(LONGLONG dwBpAddress);
	//判斷地址是否有效
	BOOL IsAddressValid(LONGLONG dwAddress, MEMORY_BASIC_INFORMATION& mbi);
	//顯示堆棧
	void ShowStack();
	//返回當前可用的調試寄存器
	int FindFreeDebugRegister();
	//G命令處理
	void ON_G_COMMAND(LONGLONG dwAddress);
	//恢復硬件斷點 參數為 調試寄存器的編號
	void RecoverHBP(DWORD dwIndex);
	//判斷單步異常是否是硬件斷點引起的 傳出參數 斷點地址
	BOOL IfStepHard(LONGLONG& dwBPAddress);
	//把記錄寫入文件  參數 指令地址 指令緩沖 不顯示機器碼 了,
	//顯示了在文本文件中不好對齊 
	void WriteOpcodeToFile(LONGLONG dwAddress, char* szAsm);
	//反匯編窗口顯示的指令地址
	LONGLONG m_AsmAddress[22];
	//創建的用于指令記錄的文件句柄
	HANDLE m_hFile;
	//要恢復的硬件斷點
	//要恢復的內存頁
	RECOVER_MEMPAGE m_Recover_Mpage;
	BOOL m_isMoreMem;
	//調試寄存器Dr0-Dr3的使用情況
	DR_USE m_Dr_Use;
	RECOVER_HARDBP m_Recover_HBP;
	//內存斷點鏈表
	CList<MEM_BP, MEM_BP&> m_MemBpList;
	//保存要改變屬性的數組 取 1 3個元素值,其他的任意
	DWORD m_Attribute[4];
	//內存頁鏈表
	CList<MEM_BP_PAGE, MEM_BP_PAGE&> m_MemPageList;
	//
	CListBox m_Result;
	CListCtrl m_AsmList;
	afx_msg void OnBnClickedButton1();
	CListCtrl m_ctl_RegList;
	CListCtrl m_ctl_DllList;
	afx_msg void OnBnClickedButton2();
//	LONGLONG m_dwMemoryAddress;
	CListCtrl m_ctl_DataList;
	afx_msg void OnBnClickedButton3();
	CListCtrl m_Stack;
	afx_msg void OnBnClickedButton4();
	CEdit m_command;
	afx_msg void OnEnChangeEdit2();
	CEdit m_asm_adr;
	CEdit m_dwMemoryAddress;
};
