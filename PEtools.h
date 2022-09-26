#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
using namespace std;

class PEtools
{
private:
	bool init_filename_data(const string& file_name);
	bool init_pe_data(PVOID buffer);
	bool init_pe_data(const PEtools& pet);
	// 得到严格的imagesize
	DWORD get_real_imagesize() {
		DWORD sec_begin = pfirst_section_header[pfile_header->NumberOfSections - 1].VirtualAddress;
		DWORD sec_size = pfirst_section_header[pfile_header->NumberOfSections - 1].Misc.VirtualSize;
		return  to_sectionAlignment(sec_begin + sec_size);
	}
public:
	// rva转foa
	DWORD rva_to_foa(DWORD rva);
	// foa转rva
	DWORD foa_to_rva(DWORD foa);
	// 转文件对齐
	DWORD to_fileAlignment(DWORD number);
	// 转内存对齐
	DWORD to_sectionAlignment(DWORD number);
	// filebuffer 转 imagebuffer
	bool to_imagebuffer();
	// 是否是32位PE文件
	bool is_32PE() const {
		if (pfile_header->Machine == IMAGE_FILE_MACHINE_I386) return true;
		else return false;
	}

public:
	DWORD get_relocate_rva()const { return poption_header->DataDirectory[5].VirtualAddress; }
	DWORD get_tlsrva()const { return poption_header->DataDirectory[9].VirtualAddress; }
	DWORD get_export_rva()const { return poption_header->DataDirectory[0].VirtualAddress; }
	DWORD get_import_rva()const { return poption_header->DataDirectory[1].VirtualAddress; }

	void set_import(DWORD rva) { poption_header->DataDirectory[1].VirtualAddress = rva; }
	void set_relocate(DWORD rva) { poption_header->DataDirectory[5].VirtualAddress = rva; }
	void set_tlsrva(DWORD rva) { poption_header->DataDirectory[9].VirtualAddress = rva; }

	void set_oep(DWORD rva) { poption_header->AddressOfEntryPoint = rva; }
	DWORD get_oep()const { return poption_header->AddressOfEntryPoint; }
	DWORD_PTR get_imagebase()const { return poption_header->ImageBase;}

	DWORD get_filesize()const { return file_size; }
	DWORD get_imagesize()const { return poption_header->SizeOfImage; }
	PVOID get_pebuffer()const { return pe_buff; }
	PVOID get_loadbuffer()const { return load_pe_buff; }

public:
	// 判断初始化是否成功
	bool is_success()const { return init_flag; }
	// 通过节名得到rva
	DWORD get_rva_bysecname(const string& sec_name);
	// 保存至文件
	bool to_file(const string& file_name);
	// 获取函数地址rva，导出表解析
	DWORD funcaddr_rva(const string& func_name);
	// 获取函数地址 文件下全地址
	DWORD_PTR funcaddr_fva(const string& func_name) { return funcaddr_rva(func_name) + (DWORD_PTR)pe_buff; }
	// 获取函数地址，导出表解析 序号获取
	DWORD_PTR funcaddr_rva(DWORD func_ordinal);
	DWORD_PTR funcaddr_fva(DWORD func_ordinal) { return funcaddr_rva(func_ordinal) + (DWORD_PTR)pe_buff; }
	// 增加节 参数：节名称、节内容、大小、属性
	bool increase_section(const string& sec_name, const PVOID sec_buffer, DWORD buff_size, DWORD character);
	// 合并节 参数：合并的第一个节、合并的最后一个节; 可改名和增加属性
	bool combine_section(const string& fsection_name, const string& lsection_name,
		const string& new_secname = string(""), DWORD extra_character = 0);
	// 移动导入表    参数：目标位置rva (浅移动) 
	bool move_import_table(DWORD des_rva);
	// 移动重定位表  参数：目标位置rva
	bool move_relocate_table(DWORD des_rva);

public:	// ====  可用于 load_buff的方法  ====
	// 手动加载导入表	可PE的文件状态和内存状态
	bool repair_import(DWORD import_rva = 0);
	// 修复导入表offset
	bool repair_import_offset(DWORD_PTR cur_start_pos, DWORD_PTR pre_start_pos = 0, DWORD import_rva = 0);
	// 手动加载重定位   可PE的文件状态和内存状态
	// 参数：原来的imagebase、当前imagebase、重定位rva(默认)
	bool repair_reloc(DWORD_PTR pre_imagebase, DWORD_PTR cur_imagebase, DWORD relo_rva = 0);
	// 修复重定位中的偏移  可PE的文件状态和内存状态
	// 参数：当前起始位置
	bool repair_relo_offset(DWORD_PTR cur_start_pos, DWORD_PTR pre_start_pos = 0, DWORD relo_rva = 0);
	// 获取函数在iat表中的索引   内存状态
	// 可用于 IAT hook，导入表解析
	DWORD_PTR iat_index(const string& func_name);
	// 手动加载tls
	bool load_TLS(DWORD tls_rva, DWORD_PTR imagebase);

protected:
	// tls回调函数类型
	using tls_callback = void (NTAPI*)(PVOID, DWORD_PTR, PVOID);

protected:
	bool init_flag;
	DWORD file_size;
	char* pe_buff;
	PVOID load_pe_buff;
	string file_name;
	PIMAGE_DOS_HEADER pdos_header;
	PIMAGE_NT_HEADERS pnt_header;
	PIMAGE_FILE_HEADER pfile_header;
	PIMAGE_OPTIONAL_HEADER poption_header;
	PIMAGE_SECTION_HEADER pfirst_section_header;

public:
	PEtools() = default;
	PEtools(PVOID buffer)	// PEtools pet(0x40000);
		:load_pe_buff(buffer), file_size(0),
		file_name("temp.exe"), pe_buff(nullptr)
	{
		init_flag = init_pe_data(load_pe_buff);
	}
	PEtools(const string& file_name)	// PEtools pet("temp.exe");
		:pe_buff(nullptr), file_size(0), file_name(file_name),
		load_pe_buff(nullptr)
	{
		init_flag = init_filename_data(file_name);
		init_flag = init_pe_data(pe_buff);
	}
	PEtools(const PEtools& pet)
		:pe_buff(nullptr), file_size(pet.file_size),
		file_name(pet.file_name), load_pe_buff(pet.load_pe_buff)
	{
		init_flag = init_pe_data(pet);
	}
	PEtools(PEtools&& pet)noexcept
		:pe_buff(pet.pe_buff), file_size(pet.file_size),
		file_name(pet.file_name), load_pe_buff(pet.load_pe_buff)
	{
		// 移动到现在
		init_flag = true;
		pdos_header = pet.pdos_header;
		pnt_header = pet.pnt_header;
		pfile_header = pet.pfile_header;
		poption_header = pet.poption_header;
		pfirst_section_header = pet.pfirst_section_header;
		// 删除以前
		pet.pe_buff = nullptr;
		pet.file_size = 0;
		pet.pdos_header = 0;
		pet.pnt_header = 0;
		pet.pfile_header = 0;
		pet.poption_header = 0;
		pet.pfirst_section_header = 0;
	}
	PEtools& operator=(const PEtools& pet)
	{
		if (this != &pet)
		{
			if (pe_buff != nullptr) delete[]pe_buff;
			pe_buff = nullptr;
			load_pe_buff = pet.load_pe_buff;
			file_size = pet.file_size;
			file_name = pet.file_name;
			init_pe_data(pet);
		}
		return *this;
	}
	PEtools& operator=(PEtools&& pet)noexcept
	{
		if (this != &pet)
		{
			if (pe_buff != nullptr) delete[]pe_buff;
			pe_buff = pet.pe_buff;
			load_pe_buff = pet.load_pe_buff;
			file_size = pet.file_size;
			file_name = pet.file_name;
			// 删除以前
			pet.pe_buff = nullptr;
			pet.load_pe_buff = nullptr;
			pet.file_size = 0;
		}
		return *this;
	}
	~PEtools()
	{
		if (pe_buff != nullptr) delete[]pe_buff;
	}
};

//  这个继承只是让一些成员公有化
class PEGet :public PEtools
{
public:
	PEGet() = default;
	PEGet(const string& file_name) :PEtools(file_name)
	{	}
public:
	using PEtools::pdos_header;
	using PEtools::pfile_header;
	using PEtools::poption_header;
	using PEtools::pfirst_section_header;
};