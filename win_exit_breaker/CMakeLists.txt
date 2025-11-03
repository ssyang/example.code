# CMake 최소 요구 버전을 지정합니다. 3.10 이상이면 충분합니다.
cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름과 사용할 언어를 설정합니다.
project(win_exit_breaker CXX)

# C++ 표준을 17로 설정합니다. (선택 사항이지만 좋은 습관입니다)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 실행 파일(executable)을 생성합니다.
# add_executable(<실행 파일 이름> <소스 파일 목록>)
add_executable(win_exit_breaker win_exit_breaker.cpp)

# 이 코드는 Windows API를 사용하므로, Windows에서만 빌드되도록 설정합니다.
if(NOT WIN32)
    message(FATAL_ERROR "This project can only be built on Windows.")
endif()

# Windows에서 유니코드 문자 집합을 사용하도록 설정합니다.
# 이렇게 하면 wchar_t, L"string" 같은 유니코드 타입과
# GetModuleFileNameW, ShellExecuteExW 같은 API 함수가 올바르게 연결됩니다.
add_compile_definitions(UNICODE _UNICODE)

# 참고: user32.lib, kernel32.lib 같은 표준 Windows 라이브러리는
# Visual Studio의 CMake 툴체인에서 자동으로 링크되므로 명시적으로 추가할 필요가 없습니다.