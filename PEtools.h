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
	// �õ��ϸ��imagesize
	DWORD get_real_imagesize() {
		DWORD sec_begin = pfirst_section_header[pfile_header->NumberOfSections - 1].VirtualAddress;
		DWORD sec_size = pfirst_section_header[pfile_header->NumberOfSections - 1].Misc.VirtualSize;
		return  to_sectionAlignment(sec_begin + sec_size);
	}
public:
	// rvaתfoa
	DWORD rva_to_foa(DWORD rva);
	// foaתrva
	DWORD foa_to_rva(DWORD foa);
	// ת�ļ�����
	DWORD to_fileAlignment(DWORD number);
	// ת�ڴ����
	DWORD to_sectionAlignment(DWORD number);
	// filebuffer ת imagebuffer
	bool to_imagebuffer();
	// �Ƿ���32λPE�ļ�
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
	// �жϳ�ʼ���Ƿ�ɹ�
	bool is_success()const { return init_flag; }
	// ͨ�������õ�rva
	DWORD get_rva_bysecname(const string& sec_name);
	// �������ļ�
	bool to_file(const string& file_name);
	// ��ȡ������ַrva�����������
	DWORD funcaddr_rva(const string& func_name);
	// ��ȡ������ַ �ļ���ȫ��ַ
	DWORD_PTR funcaddr_fva(const string& func_name) { return funcaddr_rva(func_name) + (DWORD_PTR)pe_buff; }
	// ��ȡ������ַ����������� ��Ż�ȡ
	DWORD_PTR funcaddr_rva(DWORD func_ordinal);
	DWORD_PTR funcaddr_fva(DWORD func_ordinal) { return funcaddr_rva(func_ordinal) + (DWORD_PTR)pe_buff; }
	// ���ӽ� �����������ơ������ݡ���С������
	bool increase_section(const string& sec_name, const PVOID sec_buffer, DWORD buff_size, DWORD character);
	// �ϲ��� �������ϲ��ĵ�һ���ڡ��ϲ������һ����; �ɸ�������������
	bool combine_section(const string& fsection_name, const string& lsection_name,
		const string& new_secname = string(""), DWORD extra_character = 0);
	// �ƶ������    ������Ŀ��λ��rva (ǳ�ƶ�) 
	bool move_import_table(DWORD des_rva);
	// �ƶ��ض�λ��  ������Ŀ��λ��rva
	bool move_relocate_table(DWORD des_rva);

public:	// ====  ������ load_buff�ķ���  ====
	// �ֶ����ص����	��PE���ļ�״̬���ڴ�״̬
	bool repair_import(DWORD import_rva = 0);
	// �޸������offset
	bool repair_import_offset(DWORD_PTR cur_start_pos, DWORD_PTR pre_start_pos = 0, DWORD import_rva = 0);
	// �ֶ������ض�λ   ��PE���ļ�״̬���ڴ�״̬
	// ������ԭ����imagebase����ǰimagebase���ض�λrva(Ĭ��)
	bool repair_reloc(DWORD_PTR pre_imagebase, DWORD_PTR cur_imagebase, DWORD relo_rva = 0);
	// �޸��ض�λ�е�ƫ��  ��PE���ļ�״̬���ڴ�״̬
	// ��������ǰ��ʼλ��
	bool repair_relo_offset(DWORD_PTR cur_start_pos, DWORD_PTR pre_start_pos = 0, DWORD relo_rva = 0);
	// ��ȡ������iat���е�����   �ڴ�״̬
	// ������ IAT hook����������
	DWORD_PTR iat_index(const string& func_name);
	// �ֶ�����tls
	bool load_TLS(DWORD tls_rva, DWORD_PTR imagebase);

protected:
	// tls�ص���������
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
		// �ƶ�������
		init_flag = true;
		pdos_header = pet.pdos_header;
		pnt_header = pet.pnt_header;
		pfile_header = pet.pfile_header;
		poption_header = pet.poption_header;
		pfirst_section_header = pet.pfirst_section_header;
		// ɾ����ǰ
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
			// ɾ����ǰ
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

//  ����̳�ֻ����һЩ��Ա���л�
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