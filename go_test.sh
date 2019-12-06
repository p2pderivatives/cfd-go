if [ -z "$GO_EXEC_PATH" ]; then
GO_EXEC_PATH=go
fi
LD_LIBRARY_PATH=./build/Release $GO_EXEC_PATH test
