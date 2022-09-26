#include "PEtools.h"

//
// ==================================== ���ܷ���  ====================================
//	��Щ�����Ǹ������ܷ���
//  һЩ��ʼ����foaתrva��filebufferתimagebuffer�� �ļ����롢�ڴ���롢ת�浽�ļ�
//  ���ֳ�ʼ������: PETool(�ļ�·��)��PETool(�ڴ��ַ)
// ==================================================================================
//

// ����ռ��ȡ�ļ�����
bool PEtools::init_filename_data(const string& file_name)
{
	// ���ļ�
	HANDLE hfile{ 0 };
	hfile = CreateFileA(file_name.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfile == INVALID_HANDLE_VALUE) { return false; }

	// �õ���С
	DWORD size{ 0 };
	size = GetFileSize(hfile, NULL);
	file_size = static_cast<DWORD>(size);
	pe_buff = new char[file_size] {0};
	if (pe_buff == nullptr)
	{
		CloseHandle(hfile);
		return false;
	}

	// ����ռ�
	BOOL ret = false;
	int real_size{ 0 };
	ret = ReadFile(hfile, pe_buff, file_size, (PDWORD)&real_size, 0);
	if (!ret)
	{
		delete[] pe_buff;
		pe_buff = nullptr;
	}
	CloseHandle(hfile);
	return true;
}

// ��ʼ�� PE����
bool PEtools::init_pe_data(PVOID buffer)
{
	pdos_header = 0;
	pnt_header = 0;
	pfile_header = 0;
	poption_header = 0;
	pfirst_section_header = 0;
	if (buffer == nullptr)
	{
		return false;
	}
	pdos_header = (PIMAGE_DOS_HEADER)(buffer);
	if (pdos_header->e_magic != 0x5A4D)
	{
		return false;
	}
	pnt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)pdos_header + pdos_header->e_lfanew);
	if (pnt_header->Signature != 0x4550)
	{
		return false;
	}
	pfile_header = &pnt_header->FileHeader;
	poption_header = &pnt_header->OptionalHeader;
	pfirst_section_header = IMAGE_FIRST_SECTION(pnt_header);
	return true;
}

// ��ʼ��PE����,�ڴ�copy
bool PEtools::init_pe_data(const PEtools& pet)
{
	pdos_header = 0;
	pnt_header = 0;
	pfile_header = 0;
	poption_header = 0;
	pfirst_section_header = 0;
	if (pet.pe_buff == nullptr)
	{
		return false;
	}
	// �ڴ�����
	pe_buff = new char[pet.file_size]{ 0 };
	memcpy(pe_buff, pet.pe_buff, pet.file_size);

	// pe����
	if (pe_buff == nullptr)
	{
		return false;
	}
	pdos_header = (PIMAGE_DOS_HEADER)(pe_buff);
	if (pdos_header->e_magic != 0x5A4D)
	{
		return false;
	}
	pnt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)pdos_header + pdos_header->e_lfanew);
	if (pnt_header->Signature != 0x4550)
	{
		return false;
	}
	pfile_header = &pnt_header->FileHeader;
	poption_header = &pnt_header->OptionalHeader;
	pfirst_section_header = IMAGE_FIRST_SECTION(pnt_header);
	return true;
}

// rva ת���� foa
DWORD PEtools::rva_to_foa(DWORD rva)
{
	if (pe_buff == nullptr) { return 0; }
	PIMAGE_SECTION_HEADER psection = pfirst_section_header;
	DWORD foa = 0;
	for (size_t i = 0; i < pfile_header->NumberOfSections; i++)
	{
		if (psection->VirtualAddress <= rva &&
			rva < psection->VirtualAddress + psection->Misc.VirtualSize)
		{
			foa = rva - psection->VirtualAddress + psection->PointerToRawData;
			break;
		}
		psection++;
	}
	return foa;
}

// foa ת���� rva
DWORD PEtools::foa_to_rva(DWORD foa)
{
	if (pe_buff == nullptr) { return 0; }
	PIMAGE_SECTION_HEADER psection = pfirst_section_header;
	DWORD rva = 0;
	for (size_t i = 0; i < pfile_header->NumberOfSections; i++)
	{
		if (psection->PointerToRawData <= foa &&
			foa <= psection->PointerToRawData + psection->SizeOfRawData)
		{
			rva = foa - psection->PointerToRawData + psection->VirtualAddress;
			break;
		}
		psection++;
	}
	return rva;
}

// ����תΪ �ļ�����
DWORD PEtools::to_fileAlignment(DWORD number)
{
	DWORD ret_number{ 0 };
	if (pe_buff == nullptr) { return 0; }
	if (poption_header->FileAlignment == 0) { return 0; }
	if (number % poption_header->FileAlignment == 0)
	{
		ret_number = number;
	}
	else
	{
		ret_number = (number / poption_header->FileAlignment + 1) * poption_header->FileAlignment;
	}
	return ret_number;
}

// ����תΪ �ڴ����
DWORD PEtools::to_sectionAlignment(DWORD number)
{
	DWORD ret_number{ 0 };
	if (pe_buff == nullptr) { return 0; }
	if (poption_header->SectionAlignment == 0) { return 0; }
	if (number % poption_header->SectionAlignment == 0)
	{
		ret_number = number;
	}
	else
	{
		ret_number = (number / poption_header->SectionAlignment + 1) * poption_header->SectionAlignment;
	}
	return ret_number;
	return 0;
}

// �õ��ڵ�rva��ͨ��������
DWORD PEtools::get_rva_bysecname(const string& sec_name)
{
	if (pe_buff == nullptr) { return 0; }
	if (sec_name.empty() || sec_name.length() > 8) { return 0; }
	PIMAGE_SECTION_HEADER ptemp_section = pfirst_section_header;
	for (size_t i = 0; i < pfile_header->NumberOfSections; i++)
	{
		char* name = (char*)ptemp_section[i].Name;
		if (strcmp(name, sec_name.c_str()) == 0)
			return ptemp_section[i].VirtualAddress;
	}
	return 0;
}

// ======	�ı���ԭ��PE	 ======
// filebuffer to imagebuffer
bool PEtools::to_imagebuffer()
{
	if (pe_buff == nullptr) { return false; }

	//����ʵimagesize����ռ䣬������ʹ���ܻᳬ������
	DWORD_PTR real_imagesize = get_real_imagesize();
	char* image_buff = new char[real_imagesize] {0};
	if (image_buff == nullptr) { return false; }

	// image-buffer��ʼ��
	memcpy(image_buff, pe_buff, poption_header->SizeOfHeaders);
	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)image_buff;
	PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)(image_buff + pdos->e_lfanew);
	PIMAGE_FILE_HEADER pfile = &pnt->FileHeader;
	PIMAGE_SECTION_HEADER pfsec = IMAGE_FIRST_SECTION(pnt);
	PIMAGE_SECTION_HEADER plsec = &pfsec[pfile->NumberOfSections - 1];
	for (size_t i = 0; i < pfile->NumberOfSections; i++)
	{
		char* src = (char*)((DWORD_PTR)image_buff + pfsec[i].VirtualAddress);
		char* des = (char*)((DWORD_PTR)pe_buff + pfirst_section_header[i].PointerToRawData);
		memcpy(src, des, pfirst_section_header[i].SizeOfRawData);
		pfsec[i].PointerToRawData = pfsec[i].VirtualAddress;
	}
	delete[] pe_buff;
	pe_buff = image_buff;
	image_buff = nullptr;
	init_pe_data(pe_buff);

	// �޸��ļ���С
	file_size = plsec->PointerToRawData + plsec->SizeOfRawData;
	return true;
}

// ��buffer ��������ݱ��浽�ļ�
bool PEtools::to_file(const string& file_name)
{
	HANDLE hfile = NULL;
	bool ret = false;
	hfile = CreateFileA(file_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfile == NULL) { return false; }
	ret = WriteFile(hfile, pe_buff, file_size, NULL, 0);
	if (!ret)
	{
		CloseHandle(hfile);
		return false;
	}
	CloseHandle(hfile);
	return true;
}

//
// ==================================== ��ѯ��Ϣ ====================================
//	��Щ���������޸�ԭ�е�PE�ṹ��ֻ�ǲ�ѯ��Ϣʱʹ��
//  ���з��� iat_index ��PETool(�ڴ��ַ)������PE����ʹ�õķ������ǵ�������
//  ����funcaddr_rva �����أ��Ǹ��ݵ����š�������������ȡ������ַrva���ǵ��������
//  
// ==================================================================================
//

// ���ݵ�����ȡ��������
DWORD_PTR PEtools::iat_index(const string& func_name)
{
	// ���ж��Ƿ��ڴ���ģ����load_pe_buff�Ƿ���ֵ
	if (func_name.empty() || load_pe_buff == nullptr) { return 0; }
	DWORD_PTR import_rva = get_import_rva();
	if (import_rva == 0) { return 0; }

	DWORD_PTR iat_func_index = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImport = nullptr;
	PIMAGE_THUNK_DATA pThunk_Original = nullptr;
	PIMAGE_THUNK_DATA pThunk_First = nullptr;
	PIMAGE_IMPORT_BY_NAME pImportByName = nullptr;

	pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)load_pe_buff + import_rva);
	while (pImport->Name != 0)
	{
		pThunk_Original = (PIMAGE_THUNK_DATA)((DWORD_PTR)load_pe_buff + pImport->OriginalFirstThunk);
		// IAT��
		pThunk_First = (PIMAGE_THUNK_DATA)((DWORD_PTR)load_pe_buff + pImport->FirstThunk);
		while (pThunk_Original->u1.Ordinal != 0)
		{
			// ��λ��Ϊ1 �����Ƶ����
			if (!IMAGE_SNAP_BY_ORDINAL(pThunk_First->u1.Ordinal))
			{
				DWORD_PTR name_rva = pThunk_Original->u1.AddressOfData;
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)load_pe_buff + name_rva);
				if (strcmp(func_name.c_str(), pImportByName->Name) == 0)
				{
					iat_func_index = (DWORD_PTR)pThunk_First;
				}
			}
			pThunk_Original++;
			pThunk_First++;
		}
		pImport++;
	}
	return iat_func_index;
}

// ��ȡ������ַ�����������
DWORD PEtools::funcaddr_rva(const string& func_name)
{
	DWORD export_rva = get_export_rva();
	if (func_name.empty() || export_rva == 0 || pe_buff == nullptr) { return 0; }

	//������
	DWORD export_foa = rva_to_foa(export_rva);
	PIMAGE_EXPORT_DIRECTORY pExport = nullptr;
	pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pe_buff + export_foa);

	// ������
	DWORD func_foa = rva_to_foa(pExport->AddressOfFunctions);
	DWORD name_foa = rva_to_foa(pExport->AddressOfNames);
	DWORD ordinal_foa = rva_to_foa(pExport->AddressOfNameOrdinals);
	PDWORD pFunc = (PDWORD)((DWORD_PTR)pe_buff + func_foa);
	PDWORD pName = (PDWORD)((DWORD_PTR)pe_buff + name_foa);
	PDWORD pOrdinal = (PDWORD)((DWORD_PTR)pe_buff + ordinal_foa);

	for (size_t i = 0; i < pExport->NumberOfNames; i++)
	{
		DWORD fname_foa = rva_to_foa(pName[i]);
		char* fname = (char*)((DWORD_PTR)pe_buff + fname_foa);
		if (strcmp(func_name.c_str(), fname) == 0)
		{
			return pFunc[pOrdinal[i]];
		}
	}
	return 0;
}

// ͨ�������Ż�ȡ������ַ�����������
DWORD_PTR PEtools::funcaddr_rva(DWORD func_ordinal)
{
	DWORD export_rva = get_export_rva();
	if (export_rva == 0 || pe_buff == nullptr) { return 0; }

	// ������
	DWORD export_foa = rva_to_foa(export_rva);
	PIMAGE_EXPORT_DIRECTORY pExport = nullptr;
	pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pe_buff + export_foa);

	// ������
	DWORD_PTR func_foa = rva_to_foa(pExport->AddressOfFunctions);
	DWORD_PTR name_foa = rva_to_foa(pExport->AddressOfNames);
	DWORD_PTR ordinal_foa = rva_to_foa(pExport->AddressOfNameOrdinals);
	PDWORD_PTR pFunc = (PDWORD_PTR)((DWORD_PTR)pe_buff + func_foa);
	PDWORD_PTR pName = (PDWORD_PTR)((DWORD_PTR)pe_buff + name_foa);
	PDWORD_PTR pOrdinal = (PDWORD_PTR)((DWORD_PTR)pe_buff + ordinal_foa);

	for (size_t i = 0; i < pExport->NumberOfNames; i++)
	{
		if (pOrdinal[i] == func_ordinal)
		{
			// ������� - Base = index
			DWORD_PTR index = pOrdinal[i] - pExport->Base;
			return pFunc[index];
		}
	}
	return 0;
}

//
// ================================== ���޸�PE�ļ� ===================================
//	��Щ�������޸�ԭ�е�PE�ṹ��
//  ��ʼ��PEToolʱ��������ʽ��PETool(�ļ�·��)��PETool(�ڴ��ַ)����Щ��������PETool(�ļ�·��)��ʽ
//  ������һ��������to_imagebuffer�������������������ڴ���������޸ĵ�pe_buff����û��load_pe_buff
// 
// ==================================================================================
//

// ���ӽ�
bool PEtools::increase_section(const string& sec_name, const PVOID sec_buffer, DWORD buff_size, DWORD character)
{
	// �ж�ֵ�Ƿ���ȷ
	if (sec_name.empty() || sec_buffer == nullptr || buff_size == 0) { return false; }
	if (pe_buff == nullptr) { return false; }
	if (sec_name.length() > 8) { return false; }

	// �жϽڱ��Ƿ��Ƿ��пռ����  ������ͷ
	DWORD_PTR sec_number = pfile_header->NumberOfSections;
	DWORD_PTR section_lpos = ((DWORD_PTR)&pfirst_section_header[sec_number - 1]
		- (DWORD_PTR)pe_buff + IMAGE_SIZEOF_SECTION_HEADER);
	DWORD_PTR sizeof_headers = poption_header->SizeOfHeaders;
	if ((sizeof_headers - section_lpos) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		return false;
	}

	// �ж��Ƿ��н������봫��Ľ�������ͬ
	PIMAGE_SECTION_HEADER pjudge_sec = pfirst_section_header;
	for (int i = 0; i < pfile_header->NumberOfSections; i++)
	{
		if (strcmp((char*)pjudge_sec[i].Name, sec_name.c_str()) == 0) {
			return false;
		}
	}

	// Ҫ������ imagesize = �ڴ����( ԭʼimagesize + ��С )
	PIMAGE_SECTION_HEADER plsection_temp = &pfirst_section_header[pfile_header->NumberOfSections - 1];
	DWORD real_imagesize = plsection_temp->VirtualAddress + plsection_temp->Misc.VirtualSize;
	real_imagesize = to_sectionAlignment(real_imagesize);				// ԭ���Ķ���
	real_imagesize = to_sectionAlignment(real_imagesize + buff_size);	// ���϶�����ٶ���

	// ���³�ʼ��
	// file_size = �ļ����� (file_size + ��С)
	// �ļ���С���ļ���С���ڴ��С���ڴ��С
	DWORD old_fileSize = file_size;
	file_size = to_fileAlignment(file_size + buff_size);
	char* temp_buff = new char[file_size] { 0 };
	if (temp_buff == nullptr)
	{
		file_size = old_fileSize;
		return false;
	}
	memcpy(temp_buff, pe_buff, old_fileSize);
	delete[] pe_buff;
	pe_buff = temp_buff;
	temp_buff = nullptr;
	init_flag = init_pe_data(pe_buff);
	if (!init_flag) { return false; }

	// ��ӽ� 
	// ���ڵ�VirtualAddress�Ƕ�����
	PIMAGE_SECTION_HEADER plast_section = &pfirst_section_header[pfile_header->NumberOfSections - 1];
	PIMAGE_SECTION_HEADER pnew_section = &pfirst_section_header[pfile_header->NumberOfSections];
	DWORD lfile_pos = plast_section->PointerToRawData + plast_section->SizeOfRawData;

	memcpy(pnew_section, plast_section, IMAGE_SIZEOF_SECTION_HEADER);
	memcpy((char*)pnew_section->Name, sec_name.c_str(), sec_name.length() + 1);
	memcpy((char*)pe_buff + lfile_pos, sec_buffer, buff_size);
	pnew_section->Characteristics = character;
	pnew_section->VirtualAddress =
		to_sectionAlignment(plast_section->VirtualAddress + plast_section->Misc.VirtualSize);
	pnew_section->Misc.VirtualSize = buff_size;
	pnew_section->PointerToRawData = plast_section->PointerToRawData + plast_section->SizeOfRawData;
	pnew_section->SizeOfRawData = to_fileAlignment(buff_size);

	// �޸�ȫ������
	pfile_header->NumberOfSections += 1;
	poption_header->SizeOfImage = real_imagesize;

	return true;
}

// �ϲ���
bool PEtools::combine_section(const string& fsection_name, const string& lsection_name
	, const string& new_secname, DWORD extra_character)
{
	// �ж�ֵ�Ƿ���ȷ
	if (fsection_name.empty() || lsection_name.empty())
	{
		return false;
	}
	if (fsection_name.length() > 8 || lsection_name.length() > 8 || new_secname.length() > 8)
	{
		return false;
	}
	if (pe_buff == nullptr) { return false; }

	// filebuffer ת���� imagebuffer
	if (!to_imagebuffer()) { return false; }

	// ȷ���ϲ��ĵ�һ���ں����һ����
	PIMAGE_SECTION_HEADER ptemp_section = pfirst_section_header;
	PIMAGE_SECTION_HEADER pfirst_combine = nullptr;
	PIMAGE_SECTION_HEADER plast_combine = nullptr;
	for (size_t i = 0; i < pfile_header->NumberOfSections; i++)
	{
		char* sec_name = (char*)ptemp_section[i].Name;
		if (strcmp(sec_name, fsection_name.c_str()) == 0)
		{
			pfirst_combine = &ptemp_section[i];
			continue;
		}
		if (strcmp(sec_name, lsection_name.c_str()) == 0)
		{
			plast_combine = &ptemp_section[i];
			continue;
		}
	}
	if (pfirst_combine == nullptr || plast_combine == nullptr || pfirst_combine >= plast_combine)
	{
		return false;
	}

	// �ϲ�
	DWORD_PTR combine_number = ((DWORD_PTR)plast_combine - (DWORD_PTR)pfirst_combine) / IMAGE_SIZEOF_SECTION_HEADER;// Ҫ�ϲ�������
	DWORD_PTR sec_number = pfile_header->NumberOfSections;
	pfile_header->NumberOfSections -= (WORD)combine_number;		// �޸Ľ�����
	PIMAGE_SECTION_HEADER plast_sec = &pfirst_section_header[sec_number - 1];
	while (combine_number)
	{
		// ���Ժϲ�
		pfirst_combine->Characteristics |= (&pfirst_combine[1])->Characteristics;
		// �����¸��ڵ�vir_size �� file_size���ĸ���ѡ�ĸ�
		// pe�ļ��Ѿ�������״̬���ϲ��������ں�� VirtualSize == SizeOfRawData
		// ȷ��pe�ļ�����ȷ���У��� �ý��ļ����������ݼ��ص��ڴ� (ϵͳ����SizeOfRawData���ļ�ÿ���ڸ��Ƶ��ڴ�)
		// ÿ���ڵ� viraddr+VirtualSize(�����) == �¸��ڵ�viraddr
		// ÿ���ڵ� PointerToRawData + SizeOfRawData(�����) == �¸��ڵ� PointerToRawData
		DWORD max_size =
			(&pfirst_combine[1])->Misc.VirtualSize > (&pfirst_combine[1])->SizeOfRawData ?
			(&pfirst_combine[1])->Misc.VirtualSize : (&pfirst_combine[1])->SizeOfRawData;

		DWORD start_addr = pfirst_combine->VirtualAddress;

		pfirst_combine->Misc.VirtualSize = (&pfirst_combine[1])->VirtualAddress + max_size - start_addr;	// �ؼ�

		pfirst_combine->SizeOfRawData = pfirst_combine->Misc.VirtualSize;

		for (int i = 1; i < sec_number - 1; i++)
		{
			memcpy(&pfirst_combine[i], &pfirst_combine[i + 1], IMAGE_SIZEOF_SECTION_HEADER);
		}
		memset(plast_sec, 0, IMAGE_SIZEOF_SECTION_HEADER);
		plast_sec--;
		combine_number--;
	}

	// �޸����ƺ��������
	PIMAGE_SECTION_HEADER ptemp_sec = pfirst_section_header;
	if (!new_secname.empty())
	{
		char* src_name = (char*)ptemp_sec->Name;
		memcpy(src_name, new_secname.c_str(), new_secname.length() + 1);
	}
	if (extra_character)
	{
		ptemp_sec->Characteristics |= extra_character;
	}
	return true;
}

// �ƶ������
bool PEtools::move_import_table(DWORD des_rva)
{
	if (pe_buff == nullptr) { return false; }
	DWORD import_foa = rva_to_foa(get_import_rva());
	DWORD des_foa = rva_to_foa(des_rva);
	if (des_foa == 0 || import_foa == 0) { return false; }

	// �õ���С
	PIMAGE_IMPORT_DESCRIPTOR p_import = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pe_buff + import_foa);
	PIMAGE_IMPORT_DESCRIPTOR ptemp_import = p_import;
	PIMAGE_IMPORT_DESCRIPTOR target_pos = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pe_buff + des_foa);
	while (ptemp_import->Name != 0) { ptemp_import++; }
	ptemp_import++;																// ��һ���ձ�
	DWORD_PTR import_size = (DWORD_PTR)ptemp_import - (DWORD_PTR)p_import;		// ��С
	if (des_foa + import_size > file_size)return false;							// ����

	// �ƶ�
	memcpy(target_pos, p_import, import_size);
	memset(p_import, 0, import_size);
	set_import(des_rva);
	return true;
}

// �ƶ��ض�λ��
bool PEtools::move_relocate_table(DWORD des_rva)
{
	if (pe_buff == nullptr) { return false; }
	DWORD relocate_foa = rva_to_foa(get_relocate_rva());
	DWORD des_foa = rva_to_foa(des_rva);
	if (des_foa == 0 || relocate_foa == 0) { return false; }

	// �õ���С
	PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pe_buff + relocate_foa);
	PIMAGE_BASE_RELOCATION ptemp_relp = p_relocate;
	while (ptemp_relp->VirtualAddress != 0)
	{
		ptemp_relp = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)ptemp_relp + ptemp_relp->SizeOfBlock);
	}
	DWORD_PTR relo_size = (DWORD_PTR)ptemp_relp - (DWORD_PTR)p_relocate + 8;	// ��С�����8���������
	if ((des_foa + relo_size) >= file_size)return false;						// ����

	// �ƶ�
	PVOID target_pos = (PVOID)((DWORD_PTR)pe_buff + des_foa);
	memcpy(target_pos, p_relocate, relo_size);
	memset(p_relocate, 0, relo_size);
	set_relocate(des_rva);
	return true;
}

//
// ==================================  �ֹ��޸�  ===================================
// �ֹ��޸����ܻᷢ�������������
// 1���Լ������ļ�PE��Ȼ�������ڴ棬��ʱ�����������ض�λ���޸������������ pe_buff
// 2��PEԭ���ͱ����ص��ڴ����ˣ�������״̬����ʼ��PETool��ʱ���õ���PETool(�ڴ��ַ),���������load_pe_buff
// ===============================================================================
// 

// �޸��ض�λ��
bool PEtools::repair_reloc(DWORD_PTR pre_imagebase, DWORD_PTR cur_imagebase, DWORD rva)
{
	if (pe_buff != nullptr) {
		DWORD relo_rva = rva != 0 ? rva : get_relocate_rva();
		DWORD relo_foa = rva_to_foa(relo_rva);
		if (relo_foa == 0) { return false; }

		PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pe_buff + relo_foa);
		PIMAGE_BASE_RELOCATION ptemp_relp = p_relocate;
		while (ptemp_relp->VirtualAddress != 0)
		{
			for (size_t i = 0; i < (ptemp_relp->SizeOfBlock - 8) / 2; i++)
			{
				short* data = (short*)((DWORD_PTR)ptemp_relp + 8);
				// ��λΪ3���ǿ��޸�
				if ((data[i] & 0x3000) == 0x3000)
				{
					DWORD repair_rva = ptemp_relp->VirtualAddress + (data[i] & 0xFFF);
					DWORD repair_foa = rva_to_foa(repair_rva);
					PDWORD_PTR repair_pos = (PDWORD_PTR)((DWORD_PTR)pe_buff + repair_foa);
					*repair_pos = *repair_pos - pre_imagebase + cur_imagebase;
				}
			}
			ptemp_relp = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)ptemp_relp + ptemp_relp->SizeOfBlock);
		}
		return true;
	}
	else if (load_pe_buff != nullptr) {
		DWORD relo_rva = rva != 0 ? rva : get_relocate_rva();
		if (relo_rva == 0) { return false; }

		PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)load_pe_buff + relo_rva);
		PIMAGE_BASE_RELOCATION ptemp_relp = p_relocate;
		while (ptemp_relp->VirtualAddress != 0)
		{
			for (size_t i = 0; i < (ptemp_relp->SizeOfBlock - 8) / 2; i++)
			{
				short* data = (short*)((DWORD_PTR)ptemp_relp + 8);
				// ��λΪ3���ǿ��޸�
				if ((data[i] & 0x3000) == 0x3000)
				{
					DWORD repair_rva = ptemp_relp->VirtualAddress + (data[i] & 0xFFF);
					PDWORD_PTR repair_pos = (PDWORD_PTR)((DWORD_PTR)load_pe_buff + repair_rva);
					// �ڴ�����
					DWORD old_protect = 0;
					VirtualProtect(repair_pos, 0x4, PAGE_EXECUTE_READWRITE, &old_protect);
					*repair_pos = *repair_pos - pre_imagebase + cur_imagebase;
					VirtualProtect(repair_pos, 0x4, old_protect, &old_protect);
				}
			}
			ptemp_relp = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)ptemp_relp + ptemp_relp->SizeOfBlock);
		}
		return true;
	}
	return false;
}

// �޸������
bool PEtools::repair_import(DWORD rva)
{
	if (pe_buff != nullptr) {
		DWORD import_rva = rva != 0 ? rva : get_import_rva();
		DWORD import_foa = rva_to_foa(import_rva);
		if (import_foa == 0) { return false; }

		// ����� 
		PIMAGE_IMPORT_DESCRIPTOR p_import = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pe_buff + import_foa);
		PIMAGE_THUNK_DATA pThunk_First = nullptr;
		while (p_import->Name != 0)
		{
			char* dllname = (char*)((DWORD_PTR)pe_buff + rva_to_foa(p_import->Name));
			HMODULE hmod = LoadLibraryA(dllname);
			if (hmod == NULL)return false;

			// IAT
			pThunk_First = (PIMAGE_THUNK_DATA)((DWORD_PTR)pe_buff + rva_to_foa(p_import->FirstThunk));
			while (pThunk_First->u1.Ordinal != 0)
			{
				// �޸�	�ļ�PE��ʽ����Ҫ�޸��ڴ�����VirtualProtect
				if (!IMAGE_SNAP_BY_ORDINAL(pThunk_First->u1.Ordinal))
				{
					DWORD data_foa = rva_to_foa(pThunk_First->u1.AddressOfData);
					PIMAGE_IMPORT_BY_NAME pby_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pe_buff + data_foa);
					char* func_name = pby_name->Name;
					*(PDWORD_PTR)pThunk_First = (DWORD_PTR)GetProcAddress(hmod, func_name);
				}
				else
				{
					*(PDWORD_PTR)pThunk_First = (DWORD_PTR)GetProcAddress(hmod, (LPCSTR)(pThunk_First->u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
				}
				pThunk_First++;
			}
			p_import++;
		}
		return true;
	}
	else if (load_pe_buff != nullptr) {
		DWORD import_rva = rva != 0 ? rva : get_import_rva();
		if (import_rva == 0) { return false; }

		// ����� 
		PIMAGE_IMPORT_DESCRIPTOR p_import = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)load_pe_buff + import_rva);
		PIMAGE_THUNK_DATA pThunk_First = nullptr;
		PIMAGE_THUNK_DATA pThunk_orgin = nullptr;

		while (p_import->Name != 0)
		{
			char* dllname = (char*)((DWORD_PTR)load_pe_buff + p_import->Name);
			HMODULE hmod = LoadLibraryA(dllname);
			if (hmod == NULL)return false;

			// IATû�޸�֮ǰFirstThunk == OriginalFirstThunk
			// OriginalFirstThunk���ܱ����Ƴ�0,������FirstThunk�����޸�
			pThunk_First = (PIMAGE_THUNK_DATA)((DWORD_PTR)load_pe_buff + p_import->FirstThunk);
			while (pThunk_First->u1.Ordinal != 0)
			{
				// �޸�
				if (!IMAGE_SNAP_BY_ORDINAL(pThunk_First->u1.Ordinal))
				{
					PIMAGE_IMPORT_BY_NAME pby_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)load_pe_buff + pThunk_First->u1.Ordinal);
					char* func_name = pby_name->Name;
					// �ڴ�����
					DWORD old_protect = 0;
					VirtualProtect(pThunk_First, 0x4, PAGE_EXECUTE_READWRITE, &old_protect);
					*(PDWORD_PTR)pThunk_First = (DWORD_PTR)GetProcAddress(hmod, func_name);
					VirtualProtect(pThunk_First, 0x4, old_protect, &old_protect);
				}
				else
				{
					DWORD old_protect = 0;
					VirtualProtect(pThunk_First, 0x4, PAGE_EXECUTE_READWRITE, &old_protect);
					*(PDWORD_PTR)pThunk_First = (DWORD_PTR)GetProcAddress(hmod, (LPCSTR)(pThunk_First->u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
					VirtualProtect(pThunk_First, 0x4, old_protect, &old_protect);
				}
				pThunk_First++;
			}
			p_import++;
		}
		return true;
	}
	return false;
}

// �ֶ�����TLS
bool PEtools::load_TLS(DWORD tls_rva, DWORD_PTR imagebase)
{
	if (load_pe_buff != nullptr) {
		if (tls_rva == 0) { return false; }
		PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)load_pe_buff + tls_rva);
		PEtools::tls_callback* callback = (PEtools::tls_callback*)tls_dir->AddressOfCallBacks;
		//PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks;
		while (*callback)
		{
			(*callback)((PVOID)imagebase, DLL_PROCESS_ATTACH, NULL);
			callback++;
		}
		return true;
	}
	return false;
}

//
// ==================================  �޸�ƫ��  ==================================
//	�޸�ƫ����Ҫ�޸�offset
//	����PE����ʼ��ַ��0�仯����0x33000��PE��Ӧ�ı����ض�λ��������е�rva�Ͳ�����ȷ
//  ��Ҫ���ڿǳ��򣺵�����ӵ������ڣ���ʼλ�þ��������ڵ���ʼ��������0
// ===============================================================================
//

// �޸��ض�λ������rva
bool PEtools::repair_relo_offset(DWORD_PTR cur_start_pos, DWORD_PTR pre_start_pos, DWORD rva)
{
	if (load_pe_buff == nullptr) { return false; }
	DWORD_PTR pre_pos = pre_start_pos != 0 ? pre_start_pos : 0;
	DWORD_PTR relo_rva = rva != 0 ? rva : get_relocate_rva();
	if (relo_rva == 0) { return false; }

	PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)load_pe_buff + relo_rva);
	PIMAGE_BASE_RELOCATION ptemp_relp = p_relocate;
	while (ptemp_relp->VirtualAddress != 0)
	{
		// �޸� VirtualAddress
		ptemp_relp->VirtualAddress = ptemp_relp->VirtualAddress + cur_start_pos;

		ptemp_relp = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)ptemp_relp + ptemp_relp->SizeOfBlock);
	}
	return true;
}

// �޸����������rva
bool PEtools::repair_import_offset(DWORD_PTR cur_start_pos, DWORD_PTR pre_start_pos, DWORD rva)
{
	if (load_pe_buff == nullptr) return false;
	DWORD_PTR pre_pos = pre_start_pos != 0 ? pre_start_pos : 0;
	DWORD_PTR import_rva = rva != 0 ? rva : get_import_rva();
	if (import_rva == 0) return false;

	PIMAGE_IMPORT_DESCRIPTOR p_import = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)load_pe_buff + import_rva);
	// PIMAGE_IMPORT_DESCRIPTOR ptemp_impt = p_import;

	while (p_import->Name != 0)
	{
		PDWORD_PTR pthunk_data = (PDWORD_PTR)((DWORD_PTR)load_pe_buff + p_import->OriginalFirstThunk);
		while (*pthunk_data != 0)
		{
			// �޸�ÿ��Сoffset
			if (!IMAGE_SNAP_BY_ORDINAL(*pthunk_data)) {
				*pthunk_data = *pthunk_data + cur_start_pos;
			}
			pthunk_data++;
		}
		p_import->FirstThunk = p_import->FirstThunk + cur_start_pos;
		p_import->Name = p_import->Name + cur_start_pos;
		p_import->OriginalFirstThunk = p_import->OriginalFirstThunk + cur_start_pos;

		p_import++;
	}
	return true;
}