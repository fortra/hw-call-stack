CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
OPTIONS := -masm=intel -Wall -I include -DDEBUG

hw_call_stack: clean
	$(CC_x64) source/hw_breakpoint.c source/dinvoke.c source/spoof_callstack.c source/syscalls.c source/main.c -o dist/hw_call_stack.x64.exe $(OPTIONS)
	$(CC_x86) source/hw_breakpoint.c source/dinvoke.c source/spoof_callstack.c source/syscalls.c source/main.c -o dist/hw_call_stack.x86.exe $(OPTIONS)

clean:
	rm -f dist/*
