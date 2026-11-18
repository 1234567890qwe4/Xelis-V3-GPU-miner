@echo off
setlocal
echo Building xelis-v3-miner for Windows (CUDA sm_60/sm_80/sm_86/sm_89/sm_90a/sm_120a)...

if exist build (
    echo Cleaning previous build directory...
    rmdir /s /q build
)
mkdir build
cd build

echo Configuring with CMake (auto-detecting Visual Studio 2026 / 2022)...
cmake .. -A x64 -DENABLE_CUDA=ON -DCMAKE_CUDA_FLAGS="--allow-unsupported-compiler"
if %errorlevel% neq 0 (
    echo Retrying CMake without -A x64...
    cd ..
    rmdir /s /q build
    mkdir build
    cd build
    cmake .. -DENABLE_CUDA=ON -DCMAKE_CUDA_FLAGS="--allow-unsupported-compiler"
    if %errorlevel% neq 0 (
        echo CMake configuration failed. Ensure CUDA Toolkit, Visual Studio C++ Desktop workload, and OpenSSL are installed.
        exit /b 1
    )
)

cmake --build . --config Release -j
if %errorlevel% neq 0 (
    echo Build failed.
    exit /b 1
)

if exist Release\xelis-v3-miner.exe (
    echo Build succeeded: build\Release\xelis-v3-miner.exe ^& build\Release\xelis-v3-hashgen.exe
) else (
    echo Build succeeded: build\xelis-v3-miner.exe
)
