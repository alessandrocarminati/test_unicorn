all: arm64.c
	gcc arm64.c -o arm64 -lelf -lunicorn
