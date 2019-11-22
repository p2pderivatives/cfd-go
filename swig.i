%module cfdgo
%{
#include "cfdc/cfdcapi_common.h"
#include "cfdc/cfdcapi_address.h"
%}

%typemap(argout) (char **) {
    if ($1 && *$1) {
        $input->n = strlen(*$1);
    }
}

%insert(cgo_comment_typedefs) %{
#cgo CFLAGS: -I./external/cfd/include -I../cfd/include
#cgo LDFLAGS: -L/usr/local/lib -L${SRCDIR}/build/Release -L${SRCDIR}/build/Debug -lcfd
%}

%include "external/cfd/include/cfdc/cfdcapi_common.h"
%include "external/cfd/include/cfdc/cfdcapi_address.h"

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

%insert(go_wrapper) %{
/**
 * Create Address.
 * param: handle         cfd handle
 * param: hash_type      hash type (p2pkh, p2sh, etc...)
 * param: pubkey         pubkey (pubkey hash only)
 * param: redeem_script  redeem script (script hash only)
 * param: network_type   network type
 */
func CfdGoCreateAddress(handle uintptr, hash_type int, pubkey string, redeem_script string, network_type int) (address string, locking_script string, p2sh_segwit_locking_script string, _swig_ret int) {
    ret := CfdCreateAddress(handle, hash_type, pubkey, redeem_script, network_type, &address, &locking_script, &p2sh_segwit_locking_script)
    return address, locking_script, p2sh_segwit_locking_script, ret
}

/*
func CfdGoCreateMultisigScript(handle uintptr, network_type int, hash_type int, pubkeys []string, require_num uint32) (address string, redeem_script string, witness_script string, _swig_ret int) {

func CfdInitializeMultisigScript(arg1 uintptr, arg2 int, arg3 int, arg4 *uintptr) (_swig_ret int) {
func CfdAddMultisigScriptData(arg1 uintptr, arg2 uintptr, arg3 string) (_swig_ret int) {
func CfdFinalizeMultisigScript(arg1 uintptr, arg2 uintptr, arg3 Uint32_t, arg4 *string, arg5 *string, arg6 *string) (_swig_ret int) {
func CfdFreeMultisigScriptHandle(arg1 uintptr, arg2 uintptr) (_swig_ret int) {

}
*/

%}
