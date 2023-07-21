#pragma once

#ifndef WindowManager_h
#define WindowManager_h

#include <windows.h>
#include <vector>
#include <d2d1.h>
#pragma comment(lib, "d2d1.lib")


template <class T> void SafeRelease(T** ppT)
{
    if (*ppT)
    {
        (*ppT)->Release();
        *ppT = NULL;
    }
}

class Window
{
public:
    Window(LONG top, LONG bot, LONG right, LONG left);
    Window(const Window&) = delete;
    Window& operator =(const Window&) = delete;
    ~Window();

    HRESULT CreateGraphicsResources();
    void DiscardGraphicsResources();
    void Render();
    void CalculateLayout();

    bool ProcessMessages();

    ID2D1Factory* pFactory;
    ID2D1HwndRenderTarget* pRenderTarget;
    ID2D1SolidColorBrush* pBrush;
    Window* pRenderFocus;
    HRESULT hr;
    RECT winSize;
    static LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
private:
    LRESULT CALLBACK LocWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    HINSTANCE m_hInstance;
    HWND m_hMainWnd;
};
#endif