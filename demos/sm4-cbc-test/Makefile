CC = gcc
CFLAGS = -Wall -O2 -I"D:/msys64/usr/local/ssl/include"
LDFLAGS = -L"D:/msys64/usr/local/lib" -L"D:/msys64/usr/local/lib64" -lssl -lcrypto -lm

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = $(BIN_DIR)/sm4_cbc_test

$(shell mkdir -p $(OBJ_DIR) 2>nul)
$(shell mkdir -p $(BIN_DIR) 2>nul)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TARGET)
	$(TARGET)

clean:
	rmdir /s /q $(OBJ_DIR) 2>nul
	rmdir /s /q $(BIN_DIR) 2>nul
	del /q logs\*.json 2>nul

.PHONY: all test clean