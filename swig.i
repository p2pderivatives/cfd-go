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
%}

