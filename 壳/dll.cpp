#include "PEtools.h"
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")
typedef struct SHARE
{
	long old_oep;
	long tls_rva;
	long reloca_rva;
	long import_rva;
	DWORD_PTR new_oep_va;
}_SHARE, * _PSHARE;

extern "C" _declspec(dllexport)_SHARE share;

void start_execute();
_SHARE share{ 0,0,0,0,(DWORD_PTR)start_execute };

using MyGetModuleHandleA = HMODULE(WINAPI*)(LPCTSTR);
using MyVirtualProtect = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using MyMessageBoxA = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
MyGetModuleHandleA get_module = nullptr;
MyVirtualProtect vir_protect = nullptr;
MyMessageBoxA message_box = nullptr;

bool init_func()
{
	HMODULE hmod_kernel = LoadLibraryA("kernel32.dll");
	HMODULE hmod_user = LoadLibraryA("user32.dll");
	if (hmod_kernel == NULL || hmod_user == NULL)return false;
	get_module = (MyGetModuleHandleA)GetProcAddress(hmod_kernel, "GetModuleHandleA");
	vir_protect = (MyVirtualProtect)GetProcAddress(hmod_kernel, "VirtualProtect");
	message_box = (MyMessageBoxA)GetProcAddress(hmod_user, "MessageBoxA");
	return true;

}void start_execute()
{
	_asm pushad
	if (!init_func())return;

	DWORD_PTR imagebase = (DWORD_PTR)get_module(NULL);
	PEtools tools((LPVOID)imagebase);

	//	原本程序的重定位
	tools.repair_reloc(0x400000, imagebase, share.reloca_rva);

	//	手动修复exe的导入表
	tools.repair_import(share.import_rva);

	//	手动exe的TLS回调
	tools.load_TLS(share.tls_rva, imagebase);

	//	壳执行
	message_box(0, 0, 0, 0);

	DWORD_PTR oep = share.old_oep + imagebase;
	_asm popad
	_asm jmp oep
}