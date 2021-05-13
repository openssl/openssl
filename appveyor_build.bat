IF %COMPILER%==msys2 (
    @echo on
    SET "PATH=C:\msys64\mingw64\bin;%PATH%"
    bash -lc "cd ${APPVEYOR_BUILD_FOLDER} && mkdir build && cd build && cmake .. -GNinja -DOQS_DIST_BUILD=ON -DOQS_ENABLE_SIG_SPHINCS=OFF -DOQS_ENABLE_SIG_RAINBOW=OFF -DBUILD_SHARED_LIBS=%BUILD_SHARED% -DOQS_USE_OPENSSL=%OQS_USE_OPENSSL% && ninja"
)
IF %COMPILER%==msvc2019 (
    @echo on
    CALL "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && cd liboqs && mkdir build && cd build && cmake .. -GNinja -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_INSTALL_PREFIX=%APPVEYOR_BUILD_FOLDER%/oqs -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF && ninja -v && ninja install && cd .. && cd ..
    set "PATH=C:\Strawberry\perl\bin;%PATH%"
    perl Configure %TARGET% %SHARED%
    perl configdata.pm --dump
    CALL "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    nmake
    nmake tests
)
