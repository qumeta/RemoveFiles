// RemoveFiles.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <string>
using namespace std;

#include <Windows.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <strsafe.h>

DWORD AddAceToObjectsSecurityDescriptor(
	LPTSTR pszObjName,          // name of object
	SE_OBJECT_TYPE ObjectType,  // type of object
	LPTSTR pszTrustee,          // trustee for new ACE
	TRUSTEE_FORM TrusteeForm,   // format of trustee structure
	DWORD dwAccessRights,       // access mask for new ACE
	ACCESS_MODE AccessMode,     // type of ACE
	DWORD dwInheritance         // inheritance flags for new ACE
)
{
	DWORD dwRes = 0;
	PACL pOldDACL = NULL, pNewDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea;

	if (NULL == pszObjName)
		return ERROR_INVALID_PARAMETER;

	// Get a pointer to the existing DACL.

	dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, &pOldDACL, NULL, &pSD);
	if (ERROR_SUCCESS != dwRes) {
		printf("GetNamedSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for the new ACE. 

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = dwAccessRights;
	ea.grfAccessMode = AccessMode;
	ea.grfInheritance = dwInheritance;
	ea.Trustee.TrusteeForm = TrusteeForm;
	ea.Trustee.ptstrName = pszTrustee;

	dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetEntriesInAcl Error %u\n", dwRes);
		goto Cleanup;
	}

	// Attach the new ACL as the object's DACL.

	dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, pNewDACL, NULL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetNamedSecurityInfo %s Error %u\n", pszObjName, dwRes);
		goto Cleanup;
	}

Cleanup:

	if (pSD != NULL)
		LocalFree((HLOCAL)pSD);
	if (pNewDACL != NULL)
		LocalFree((HLOCAL)pNewDACL);

	return dwRes;
}

bool GranAccess(LPTSTR path, LPTSTR role)
{
	DWORD dword = AddAceToObjectsSecurityDescriptor(
		path,
		SE_FILE_OBJECT,						// ObjectType
		role,						// pszTrustee
		TRUSTEE_IS_NAME,					// TrusteeForm
		SYNCHRONIZE | WRITE_DAC | WRITE_OWNER | DELETE | STANDARD_RIGHTS_READ | STANDARD_RIGHTS_WRITE | SPECIFIC_RIGHTS_ALL,				// dwAccessRights
		SET_ACCESS,							// AccessMode
		CONTAINER_INHERIT_ACE);				// dwInheritance

	return (dword == ERROR_SUCCESS);
}

void ListFiles(TCHAR* path)
{
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER filesize;

	HANDLE hFind = INVALID_HANDLE_VALUE;

	TCHAR szDir[MAX_PATH];

	StringCchCopy(szDir, MAX_PATH, path);
	StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

	hFind = FindFirstFile(szDir, &ffd);

	if (INVALID_HANDLE_VALUE == hFind)
	{
		return;
	}

	do
	{
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (strncmp(ffd.cFileName, ".", 1) && strncmp(ffd.cFileName, "..", 2))
			{
				TCHAR szSubDir[MAX_PATH];

				StringCchCopy(szSubDir, MAX_PATH, path);
				StringCchCat(szSubDir, MAX_PATH, TEXT("\\"));
				StringCchCat(szSubDir, MAX_PATH, ffd.cFileName);

				ListFiles(szSubDir);
			}
		}
		else
		{
			TCHAR szFile[MAX_PATH];

			StringCchCopy(szFile, MAX_PATH, path);
			StringCchCat(szFile, MAX_PATH, TEXT("\\"));
			StringCchCat(szFile, MAX_PATH, ffd.cFileName);

			if (!GranAccess(szFile, (LPSTR)"Everyone"))
			{
				filesize.LowPart = ffd.nFileSizeLow;
				filesize.HighPart = ffd.nFileSizeHigh;
				printf("  %s   %ld bytes\n", szFile, filesize.QuadPart);
			}

			DeleteFile(szFile);
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	FindClose(hFind);

	GranAccess(path, (LPSTR)"Everyone");
}

int main(int argc, TCHAR* argv[])
{
	size_t length_of_arg;

	if (argc != 2)
	{
		printf("\nUsage: %s <directory name>\n", argv[0]);
		return (-1);
	}

	StringCchLength(argv[1], MAX_PATH, &length_of_arg);

	if (length_of_arg > (MAX_PATH - 3))
	{
		printf("\nDirectory path is too long.\n");
		return (-1);
	}

	printf("\nTarget directory is %s\n\n", argv[1]);


	ListFiles(argv[1]);

	return 0;
}