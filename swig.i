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
 * param: 
 */
func CfdGoGetLastErrorMessage(handle uintptr) (message string, _swig_ret int) {
	var err_msg string
	message = ""
	ret := CfdGetLastErrorMessage(handle, &err_msg)
	if ret == 0 {
		message += err_msg
		CfdFreeStringBuffer(err_msg)
	}
	return message, ret
}

%}

