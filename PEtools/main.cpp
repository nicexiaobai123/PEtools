#include "PEtools.h"
#include<cstdlib>

int WINAPI MyMessageBoxA(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType){

	printf("%x\n", (long)hWnd);
	printf("%s\n", lpText);
	return MessageBoxW(0, 0, 0, 0);
}
// IAT hook
void iat_hook()
{
	long base = (long)GetModuleHandle(NULL);
	PEtools pe((PVOID)base);
	PDWORD p_old_addr = (PDWORD)pe.iat_index("MessageBoxA");
	long new_addr = (long)MyMessageBoxA;
	long old_addr = *p_old_addr;

	DWORD old_protect{ 0 };
	VirtualProtect((PVOID)p_old_addr, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect);
	*p_old_addr = new_addr;
	VirtualProtect((PVOID)p_old_addr, 0x1000, old_protect, &old_protect);

	MessageBoxA(0, "teszt", 0, 0);
}

// 移动导入表测试，合并后才能成功移动，不知道为啥；
// 主要是测试文件 inject.exe 出错,其他没问题
void move_import_test()
{
	PEtools pe("inject.exe");
	if (!pe.is_success())
	{
		cout << "pe初始化失败" << endl;
		system("pause");
		return ;
	}
	char* buff = new char[0x2000]{ 0 };
	pe.increase_section(".newsec", buff, 0x2000, 0xC0000040);
	long rva = pe.get_rva_bysecname(".newsec");
	pe.combine_section(".rdata", ".rsrc");
	pe.move_import_table(rva);
	pe.to_file("D:\\123.exe");
	delete[] buff;
}

// 移动重定位
void move_relo_test()
{
	PEtools pe("Fate.exe");
	if (!pe.is_success())
	{
		cout << "pe初始化失败" << endl;
		system("pause");
	}
	char* buff = new char[0x2000]{ 0 };
	pe.increase_section(".newsec", buff, 0x1000, 0xC0000040);
	long rva = pe.get_rva_bysecname(".newsec");
	if (pe.move_relocate_table(rva))
	{
		cout << "修改重定位成功" << endl;
	}
	pe.to_file("D:\\123.exe");
}

int main()
{
	PVOID base = (PVOID)GetModuleHandleA(NULL);
	PEtools pe("Fate.exe");
	if (!pe.is_success())
	{
		cout << "pe初始化失败" << endl;
		system("pause");
		return 0;
	}
	//cout << hex << pe.funcaddr_rva(1) << endl;
	//char opcode[] = { 0x90,0x90 ,0x90,0x90};

	//bool ret = pe.combine_section(".text", ".data",".newtt");
	//if (ret) { cout << "合并成功" << endl; }

	//pe.to_imagebuffer();
	//pe.to_file("D:\\123.exe");

	if (pe.repair_import()) {
		cout << "修复成功" << endl;
	}
	system("pause");
	return 0;
}