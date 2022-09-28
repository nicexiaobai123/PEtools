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
public:
	PEtools() = default;
	PEtools(PVOID buffer)		//类似 PEtools pet(0x40000);
		:load_pe_buff(buffer), file_size(0),
		file_name("temp.exe"), pe_buff(nullptr)
	{
		init_flag = init_pe_data(load_pe_buff);
	}
	PEtools(const string& file_name)
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
private:
	long get_real_imagesize() {
		long sec_begin = pfirst_section_header[pfile_header->NumberOfSections - 1].VirtualAddress;
		long sec_size = pfirst_section_header[pfile_header->NumberOfSections - 1].Misc.VirtualSize;
		return  to_sectionAlignment(sec_begin + sec_size);
	}
public:
	// rva转foa
	long rva_to_foa(long rva);
	// foa转rva
	long foa_to_rva(long foa);
	// 转文件对齐
	long to_fileAlignment(long number);
	// 转内存对齐
	long to_sectionAlignment(long number);
	// filebuffer 转 imagebuffer
	bool to_imagebuffer();
public:
	// 重定位表32位在第5个 ，64位在第7个
	long get_relocate_rva()const { return poption_header->DataDirectory[5].VirtualAddress; }
	long get_tlsrva()const { return poption_header->DataDirectory[9].VirtualAddress; }
	long get_export_rva()const { return poption_header->DataDirectory[0].VirtualAddress; }
	long get_import_rva()const { return poption_header->DataDirectory[1].VirtualAddress; }

	void set_import(long rva) { poption_header->DataDirectory[1].VirtualAddress = rva; }
	void set_relocate(long rva) { poption_header->DataDirectory[5].VirtualAddress = rva; }
	void set_tlsrva(long rva) { poption_header->DataDirectory[9].VirtualAddress = rva; }
	void set_oep(long rva) { poption_header->AddressOfEntryPoint = rva; }

	long get_oep()const { return poption_header->AddressOfEntryPoint; }
	long imagebase()const { return poption_header->ImageBase; }
	long get_filesize()const { return file_size; }
	long get_imagesize()const { return poption_header->SizeOfImage; }
	PVOID get_filebuffer()const { return pe_buff; }
	PVOID get_loadbuffer()const { return load_pe_buff; }
public:
	bool is_success()const { return init_flag; }
	long get_rva_bysecname(const string& sec_name);
	bool to_file(const string& file_name);				// 保存到文件
	long funcaddr_rva(const string& func_name);			// 获取函数地址，导出表解析
	long funcaddr_fva(const string& func_name) { return funcaddr_rva(func_name) + (long)pe_buff; }
	long funcaddr_rva(long func_ordinal);				// 获取函数地址，导出表解析 序号获取
	long funcaddr_fva(long func_ordinal) { return funcaddr_rva(func_ordinal) + (long)pe_buff; }
	bool increase_section(const string& sec_name, const PVOID sec_buffer, long buff_size, long character);
	bool combine_section(const string& fsection_name, const string& lsection_name,
		const string& new_secname = string(""), long extra_character = 0);
	bool move_import_table(long des_rva);
	bool move_relocate_table(long des_rva);

public:		// 用于 load_buff的方法
	bool repair_import(long import_rva = 0);
	bool repair_import_offset(long cur_start_pos, long pre_start_pos = 0, long import_rva = 0);	// 修复导入表offset
	bool repair_reloc(long pre_imagebase, long cur_imagebase, long relo_rva = 0);
	bool repair_relo_offset(long cur_start_pos, long pre_start_pos = 0, long relo_rva = 0);
	long iat_index(const string& func_name);			// 可用于 IAT hook，导入表解析
	bool load_TLS(long tls_rva, long imagebase);

public:
	using tls_callback = void (NTAPI*)(PVOID, DWORD, PVOID);

private:
	bool init_flag;
	long file_size;
	char* pe_buff;
	PVOID load_pe_buff;
	string file_name;
	PIMAGE_DOS_HEADER pdos_header;
	PIMAGE_NT_HEADERS pnt_header;
	PIMAGE_FILE_HEADER pfile_header;
	PIMAGE_OPTIONAL_HEADER poption_header;
	PIMAGE_SECTION_HEADER pfirst_section_header;
};

//  备用 控制台打印
class PEConsolePrint :public PEtools
{

};