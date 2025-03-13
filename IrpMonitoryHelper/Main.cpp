#include <Windows.h>
#include <iostream>
#include "Header.h"

DWORD numBytesWritten = 0;
BOOL isSuccess;


int main(int argc, const char** argv)
{
	USHORT choice;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	std::cout << "HELLO\nWelcome to the IRP Monitor Tool. Crafted by 0xefe4.\n";
	while(true)
	{ 
		std::cout << "CHOOSE WHAT TO DO:\n  \
			1) Create an empty text file (SHOULD BE DONE FIRST BEFORE ALL)\n \
			2) Write a random string into that text file \n \
			3) Read that data into a Buffer and display it \n \
			4) Close the handle and reopen it \n \
			5) Delete the file \n \
			6) to Exit \n\n \
			Enter your Answer: \n";

		std::cin >> choice;

		switch (choice)
		{
		case 1:
			hFile = IMHCreate();
			break;
		case 2: 
			IMHWrite(hFile);
			break;
		case 3:
			IMHRead(hFile);
			break;
		case 4:
			hFile = IMHCloseAndCreate(hFile);
			break;
		case 5:
			IMHDeleteFile(hFile);
			break;
		case 6:
			goto OUTOFLOOP;
		default:
			break;
		}

	}

OUTOFLOOP:
	return 0;
}

HANDLE IMHCreate()
{
	HANDLE hFile;

	hFile = CreateFile(L"TestFile.txt", GENERIC_ALL, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-]ERROR: while creating the file, error code : " << GetLastError() << std::endl;
		return INVALID_HANDLE_VALUE;
	}
	std::cout << "[+] Creating file is done.\n";
	
	return hFile;
}

VOID IMHWrite(
	HANDLE hFile
)
{
	std::string buffer = "this is a test buffer..";
	BOOL isSuccess;

	isSuccess = WriteFile(hFile, buffer.c_str(), buffer.size(), &numBytesWritten, NULL);

	if (!isSuccess)
	{
		std::cout << "[-]ERROR: couldn't write into the file, error code : " << GetLastError() << std::endl;
		return;
	}

	std::cout << "[+] Writting file is done.\n";

}

VOID IMHRead(
	HANDLE hFile
)
{
	std::string inputString(100, '\0');

	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

	isSuccess = ReadFile(hFile, (LPVOID)inputString.c_str(), inputString.size(), &numBytesWritten, NULL);

	if (!isSuccess)
	{
		std::cout << "[-]ERROR: couldn't read the file, error code : " << GetLastError() << std::endl;
		return;
	}

	std::cout << "[+] Reading file is done.\n";
	std::cout << "The Data is : " << inputString << " With size of " << numBytesWritten << std::endl;

}

HANDLE IMHCloseAndCreate(
	HANDLE hFile
)
{
	// try to close the handle..
	bool succ = CloseHandle(hFile);
	if (succ)
		std::cout << "[+] Closing Handle to file is done.\n";
	else
		std::cout << "[-] ERROR while closing the handle to the file, error code : " << GetLastError() << std::endl;

	Sleep(3000);

	// now try to open a handle to the same file again ..

	hFile = CreateFile(L"TestFile.txt", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-]ERROR: while openning the handle for the second time, error code : " << GetLastError() << std::endl;
		return INVALID_HANDLE_VALUE;
	}

	std::cout << "[+] Openning Handle to file Second Time is done.\n";
	return hFile;
}

VOID IMHDeleteFile(
	HANDLE hFile
)
{
	CloseHandle(hFile);

	isSuccess = DeleteFileW(L"TestFile.txt");
	if (!isSuccess)
	{
		std::cout << "[-]ERROR: Couldn't delete the file, error code : " << GetLastError() << std::endl;
		return;
	}

	std::cout << "[+] DELETE THE FILE IS DONE.\n";

}