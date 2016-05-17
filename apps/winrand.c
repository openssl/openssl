/*
 * Copyright 1998-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Usage: winrand [filename]
 *
 * Collects entropy from mouse movements and other events and writes
 * random data to filename or .rnd
 */

#include <windows.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
const char *filename;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   PSTR cmdline, int iCmdShow)
{
    static char appname[] = "OpenSSL";
    HWND hwnd;
    MSG msg;
    WNDCLASSEX wndclass;
    char buffer[200];

    if (cmdline[0] == '\0')
        filename = RAND_file_name(buffer, sizeof buffer);
    else
        filename = cmdline;

    RAND_load_file(filename, -1);

    wndclass.cbSize = sizeof(wndclass);
    wndclass.style = CS_HREDRAW | CS_VREDRAW;
    wndclass.lpfnWndProc = WndProc;
    wndclass.cbClsExtra = 0;
    wndclass.cbWndExtra = 0;
    wndclass.hInstance = hInstance;
    wndclass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground = (HBRUSH) GetStockObject(WHITE_BRUSH);
    wndclass.lpszMenuName = NULL;
    wndclass.lpszClassName = appname;
    wndclass.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassEx(&wndclass);

    hwnd = CreateWindow(appname, OPENSSL_VERSION_TEXT,
                        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                        CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, hInstance,
                        NULL);

    ShowWindow(hwnd, iCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc;
    PAINTSTRUCT ps;
    RECT rect;
    static int seeded = 0;

    switch (iMsg) {
    case WM_PAINT:
        hdc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rect);
        DrawText(hdc, "Seeding the PRNG. Please move the mouse!", -1,
                 &rect, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        EndPaint(hwnd, &ps);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    if (RAND_event(iMsg, wParam, lParam) == 1 && seeded == 0) {
        seeded = 1;
        if (RAND_write_file(filename) <= 0)
            MessageBox(hwnd, "Couldn't write random file!",
                       "OpenSSL", MB_OK | MB_ICONERROR);
        PostQuitMessage(0);
    }

    return DefWindowProc(hwnd, iMsg, wParam, lParam);
}
