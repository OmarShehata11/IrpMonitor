#pragma once

HANDLE IMHCreate();

VOID IMHWrite(
	HANDLE hFile
);

VOID IMHRead(
	HANDLE hFile
);

HANDLE IMHCloseAndCreate(
	HANDLE hFile
);

VOID IMHDeleteFile(
	HANDLE hFile
);