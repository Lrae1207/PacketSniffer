#include <string>
#include <iostream>
#include <ctime>
#include "WindowManager.h"

int main() {
    RECT winSize;
    Window* pWindow = new Window(100,1000,1500,100);

    std::cout << "Opening Window." << std::endl;

    bool running = true;
    while (running)
    {
        if (!pWindow->ProcessMessages())
        {
            std::cout << "Closing Window.";
            running = false;
        }
    }

    delete pWindow;

    return 0;
}