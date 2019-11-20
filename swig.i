%module cfdgo
%{
#include "external/cfd/include/cfdc/cfdcapi_common.h"
%}

%insert(cgo_comment_typedefs) %{
#cgo LDFLAGS: -L/usr/local/lib -L${SRCDIR}/build/Release -L${SRCDIR}/build/Debug -lcfd
%}

%include "external/cfd/include/cfdc/cfdcapi_common.h"

%insert(go_wrapper) %{
/**
 * Get supported function.
 */
func CfdGoGetSupportedFunction() (func_flag uint64, _swig_ret int) {
	func_flag_value := SwigcptrUint64_t(uintptr(unsafe.Pointer(&func_flag)))
	ret := CfdGetSupportedFunction(func_flag_value)
	return func_flag, ret
}

/**
 * Create cfd handle.
 */
func CfdGoCreateHandle() (handle uintptr, _swig_ret int) {
	ret := CfdCreateHandle(&handle)
	return handle, ret
}

/**
 * Get last error message.
 * param: handle   cfd handle
 */
func CfdGoGetLastErrorMessage(handle uintptr) (message string, _swig_ret int) {
	ret := CfdGetLastErrorMessage(handle, &message)
	// Do not use the Free API as it will be released by Go-GC.
	return message, ret
}

%}

