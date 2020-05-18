if [ -z "$GO_EXEC_PATH" ]; then
GO_EXEC_PATH=go
fi
LD_LIBRARY_PATH=./build/Release $GO_EXEC_PATH test -coverprofile=cover.out
// LD_LIBRARY_PATH=./build/Release $GO_EXEC_PATH tool cover -html=cover.out -o cover.html
LD_LIBRARY_PATH=./build/Release $GO_EXEC_PATH tool cover -func=cover.out -o cover.txt
