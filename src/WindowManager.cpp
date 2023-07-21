#include "WindowManager.h"

void Window::CalculateLayout()
{
    if (pRenderTarget != NULL)
    {
        D2D1_SIZE_F size = pRenderTarget->GetSize();
        const float x = size.width / 2;
        const float y = size.height / 2;

    }
}

HRESULT Window::CreateGraphicsResources()
{
    HRESULT hr = S_OK;
    if (pRenderTarget == NULL)
    {
        RECT rc;
        GetClientRect(m_hMainWnd, &rc);

        D2D1_SIZE_U size = D2D1::SizeU(rc.right, rc.bottom);

        hr = pFactory->CreateHwndRenderTarget(
            D2D1::RenderTargetProperties(),
            D2D1::HwndRenderTargetProperties(m_hMainWnd, size),
            &pRenderTarget);

        if (SUCCEEDED(hr))
        {
            const D2D1_COLOR_F color = D2D1::ColorF(1.0f, 1.0f, 1.0f);
            hr = pRenderTarget->CreateSolidColorBrush(color, &pBrush);
            if (SUCCEEDED(hr))
            {
                CalculateLayout();
            }
        }
    }
    return hr;
}

D2D1_RECT_F addRect(D2D1_RECT_F r1, D2D1_RECT_F r2) {
    D2D1_RECT_F r3 = D2D1::RectF(r1.left + r2.left, r1.top + r2.top, r1.right + r2.right, r1.bottom + r2.bottom);
    return r3;
}

void Window::Render()
{
    HRESULT hr = CreateGraphicsResources();
    if (SUCCEEDED(hr))
    {
        PAINTSTRUCT ps;

        D2D1_RECT_F fWinSize = D2D1::RectF(winSize.left, winSize.top, winSize.right, winSize.bottom);

        BeginPaint(m_hMainWnd, &ps);

        pRenderTarget->BeginDraw();

        //Clear screen
        pRenderTarget->Clear();

        hr = pRenderTarget->EndDraw();
        if (FAILED(hr) || hr == D2DERR_RECREATE_TARGET)
        {
            DiscardGraphicsResources();
        }
        EndPaint(m_hMainWnd, &ps);
    }
}

void Window::DiscardGraphicsResources()
{
    SafeRelease(&pRenderTarget);
    SafeRelease(&pBrush);
}

Window::Window(LONG top, LONG bot, LONG right, long left)
    : m_hInstance(GetModuleHandle(nullptr))
{
    winSize.top = top;
    winSize.bottom = bot;
    winSize.right = right;
    winSize.left = left;

    // D2D1_FACTORY_TYPE_SINGLE_THREADED and D2D1_FACTORY_TYPE_MULTI_THREADED are both options
    HRESULT hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &pFactory);

    pRenderFocus = this;

    const wchar_t* CLASS_NAME = L"Hugos Window Class";

    WNDCLASS wndClass = {};
    wndClass.lpszClassName = CLASS_NAME;
    wndClass.hInstance = m_hInstance;
    wndClass.hIcon = LoadIcon(NULL, IDI_WINLOGO);
    wndClass.hCursor = LoadCursor(NULL, IDC_ARROW);
    wndClass.lpfnWndProc = WindowProc;

    RegisterClass(&wndClass);

    DWORD style = WS_OVERLAPPEDWINDOW;//WS_CAPTION | WS_MINIMIZEBOX | WS_SYSMENU;

    AdjustWindowRect(&winSize, style, false);

    m_hMainWnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"Window",
        style,
        winSize.left,
        winSize.top,
        winSize.right - winSize.left,
        winSize.bottom - winSize.top,
        NULL,
        NULL,
        m_hInstance,
        NULL
    );

    ShowWindow(m_hMainWnd, SW_SHOW);
}

Window::~Window()
{
    const wchar_t* CLASS_NAME = L"Hugos Window Class";

    UnregisterClass(CLASS_NAME, m_hInstance);
}

bool Window::ProcessMessages()
{
    MSG msg = {};
    while (PeekMessage(&msg, nullptr, 0u, 0u, PM_REMOVE))
    {
        if (msg.message == WM_QUIT)
        {
            return false;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return true;
}

LRESULT CALLBACK Window::WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Window* me = reinterpret_cast<Window*>(GetWindowLongPtr(hWnd, GWLP_USERDATA));
    if (me) return me->LocWndProc(hWnd, uMsg, wParam, lParam);
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}



LRESULT CALLBACK Window::LocWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg)
    {
    case WM_CREATE:
        break;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;
    case WM_SIZE:

    case WM_PAINT:
        pRenderFocus->Render();
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}
