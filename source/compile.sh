# Compiles and executes the program
if [ ! -f "./sniffer.cpp" ]
then
    echo "sniffer.cpp not found"
    exit 1
fi

if [ ! -f "./sniffer.hpp" ]
then
    echo "sniffer.hpp not found"
    exit 1
fi

if [ ! -f "./colors.hpp" ]
then
    echo "colors.hpp not found"
    exit 1
fi

if [ ! -f "./tcp_seq.h" ]
then
    echo "tcp_seq.h not found"
    exit 1
fi

echo Compiling...

g++ sniffer.cpp sniffer.hpp colors.hpp -lpcap -o "execfile"

if [ $? -eq 0 ]:
then
    echo "Compilation successful"
    echo -n "Execute it? y/n? "
    input=""
    read input
    if [ $input = "y" ]
    then
        sudo ./"execfile"
    fi
else
    echo "Compilation failed"
fi
