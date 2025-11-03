#include <iostream>
#include <conio.h>    // For _kbhit() and _getch()
#include <Windows.h>  // For Windows API functions
#include <shellapi.h> // For ShellExecuteEx()

// 콘솔 제어 이벤트를 처리하는 핸들러 함수
// 이 함수는 Ctrl+C, 창 닫기 등의 이벤트를 가로챕니다.
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
        // CTRL_C_EVENT: Ctrl+C 키 입력
        // CTRL_CLOSE_EVENT: 콘솔 창 닫기 버튼 클릭
        // CTRL_BREAK_EVENT: Ctrl+Break 키 입력
        // CTRL_LOGOFF_EVENT: 사용자 로그오프
        // CTRL_SHUTDOWN_EVENT: 시스템 종료
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            // 의도된 종료(x 키 입력)가 아니므로, 이벤트를 처리했다고 알리고 종료를 막습니다.
            std::cout << "\n[System] Exit is disabled. Press 'x' to quit." << std::endl;
            return TRUE; // TRUE를 반환하면 시스템이 프로그램을 종료하지 않습니다.

        default:
            // 다른 이벤트는 기본 처리기에 맡깁니다.
            return FALSE;
    }
}

// 콘솔 창의 닫기 버튼(X)을 비활성화하는 함수
void DisableCloseButton() {
    // 현재 콘솔 창의 핸들(고유 식별자)을 가져옵니다.
    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow == NULL) {
        std::cerr << "Error: Could not get console window handle." << std::endl;
        return;
    }

    // 콘솔 창의 시스템 메뉴를 가져옵니다.
    HMENU sysMenu = GetSystemMenu(consoleWindow, FALSE);
    if (sysMenu == NULL) {
        std::cerr << "Error: Could not get system menu." << std::endl;
        return;
    }

    // 시스템 메뉴에서 '닫기(SC_CLOSE)' 항목을 제거하여 버튼을 비활성화합니다.
    DeleteMenu(sysMenu, SC_CLOSE, MF_BYCOMMAND);
}

// 현재 프로세스가 관리자 권한으로 실행 중인지 확인하는 함수
BOOL IsRunningAsAdmin() {
    BOOL fIsAdmin = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            fIsAdmin = elevation.TokenIsElevated;
        }
    }

    if (hToken) {
        CloseHandle(hToken);
        hToken = NULL;
    }

    return fIsAdmin;
}

int main() {
    // 0. 관리자 권한이 없으면 권한 상승을 요청하고 재시작합니다.
    if (!IsRunningAsAdmin()) {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.lpVerb = L"runas"; // 관리자 권한으로 실행
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_SHOWNORMAL;

            if (!ShellExecuteEx(&sei)) {
                DWORD dwError = GetLastError();
                if (dwError == ERROR_CANCELLED) {
                    // 사용자가 UAC 프롬프트를 거부한 경우
                    std::cout << "Administrator privileges are required to run this program." << std::endl;
                } else {
                    std::cout << "Failed to elevate privileges. Error code: " << dwError << std::endl;
                }
                return 1; // 권한 상승 실패 시 종료
            }
        }
        return 0; // 새로운 프로세스가 시작되었으므로 현재 프로세스는 종료
    }

    // 1. 콘솔 제어 핸들러를 등록하여 Ctrl+C 등의 이벤트를 가로챕니다.
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        std::cerr << "Error: Could not set control handler." << std::endl;
        return 1;
    }

    // 2. 콘솔 창의 닫기 버튼을 비활성화합니다.
    DisableCloseButton();

    std::cout << "Program started. Press any key to display it." << std::endl;
    std::cout << "Press 'x' to exit." << std::endl;

    char key_input;
    while (true) {
        // _kbhit() : 키보드 입력이 있는지 확인 (non-blocking)
        if (_kbhit()) {
            // _getch() : 버퍼 없이 바로 키 입력 값을 가져옴
            key_input = _getch();
            std::cout << "You pressed: " << key_input << std::endl;

            // 'x' 또는 'X'가 입력되면 루프를 탈출하여 프로그램을 종료합니다.
            if (key_input == 'x' || key_input == 'X') {
                break;
            }
        }
    }

    std::cout << "\nExiting program..." << std::endl;
    return 0;
}