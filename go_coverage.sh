if [ -z "$GO_EXEC_PATH" ]; then
GO_EXEC_PATH=go
fi
LIB_PATH=./build/Release:../build/Release:../../build/Release

LD_LIBRARY_PATH=$LIB_PATH $GO_EXEC_PATH test -coverprofile=cover.out . ./types/... ./apis/... ./service/... ./tests -v
LD_LIBRARY_PATH=$LIB_PATH $GO_EXEC_PATH tool cover -html=cover.out -o cover.html
LD_LIBRARY_PATH=$LIB_PATH $GO_EXEC_PATH tool cover -func=cover.out -o cover.txt
