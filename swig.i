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
 * return: funcFlag    function flag.
 * return: _swig_ret   error code
 */
func CfdGoGetSupportedFunction() (funcFlag uint64, _swig_ret int) {
	funcFlagValue := SwigcptrUint64_t(uintptr(unsafe.Pointer(&funcFlag)))
	ret := CfdGetSupportedFunction(funcFlagValue)
	return funcFlag, ret
}

/**
 * Create cfd handle.
 * return: handle      cfd handle
 * return: _swig_ret   error code
 */
func CfdGoCreateHandle() (handle uintptr, _swig_ret int) {
	ret := CfdCreateHandle(&handle)
	return handle, ret
}

/**
 * Get last error message.
 * param: handle   cfd handle
 * return: message     last error message
 * return: _swig_ret   error code
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
 * param: handle        cfd handle
 * param: hashType      hash type (p2pkh, p2sh, etc...)
 * param: pubkey        pubkey (pubkey hash only)
 * param: redeemScript  redeem script (script hash only)
 * param: networkType   network type
 * return: address                  address string
 * return: lockingScript            locking script
 * return: p2shSegwitLockingScript  p2sh-segwit witness program
 * return: _swig_ret                error code
 */
func CfdGoCreateAddress(handle uintptr, hashType int, pubkey string, redeemScript string, networkType int) (address string, lockingScript string, p2shSegwitLockingScript string, _swig_ret int) {
    ret := CfdCreateAddress(handle, hashType, pubkey, redeemScript, networkType, &address, &lockingScript, &p2shSegwitLockingScript)
    return address, lockingScript, p2shSegwitLockingScript, ret
}

/**
 * Create multisig script and address.
 * param: handle        cfd handle
 * param: networkType   network type
 * param: hashType      hash type (p2sh, p2wsh, etc...)
 * param: pubkeys       pubkey list (max 15 key)
 * param: requireNum    pubkey require signature
 * return: address        address string
 * return: redeemScript   redeem script
 * return: witnessScript  witness script
 * return: _swig_ret      error code
 */
func CfdGoCreateMultisigScript(handle uintptr, networkType int, hashType int, pubkeys []string, requireNum uint32) (address string, redeemScript string, witnessScript string, _swig_ret int) {
	var multisigHandle uintptr
	ret := CfdInitializeMultisigScript(handle, networkType, hashType, &multisigHandle)
	if ret == (int)(KCfdSuccess) {
		for i := 0; i < len(pubkeys); i++ {
			ret = CfdAddMultisigScriptData(handle, multisigHandle, pubkeys[i])
			if ret != (int)(KCfdSuccess) {
				break
			}
		}

		if ret == (int)(KCfdSuccess) {
			reqNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&requireNum)))
			ret = CfdFinalizeMultisigScript(handle, multisigHandle, reqNumPtr, &address, &redeemScript, &witnessScript)
		}

		freeRet := CfdFreeMultisigScriptHandle(handle, multisigHandle)
		if ret == (int)(KCfdSuccess) {
			ret = freeRet
		}
	}
	return address, redeemScript, witnessScript, ret
}

/**
 * Descriptor data struct.
 */
type CfdDescriptorData struct {
	depth uint32
	scriptType int
	lockingScript string
	address string
	hashType int
	redeemScript string
	keyType int
	pubkey string
	extPubkey string
	extPrivkey string
	isMultisig bool
}

/**
 * Descriptor key data struct.
 */
type CfdDescriptorKeyData struct {
	keyType int
	pubkey string
	extPubkey string
	extPrivkey string
}

/**
 * Parse Output Descriptor.
 * param: handle               cfd handle
 * param: descriptor           output descriptor
 * param: networkType          network type
 * param: bip32DerivationPath  derive path
 * return: descriptorDataList  descriptor data struct list
 * return: multisigList        multisig key struct list
 * return: _swig_ret           error code
 */
func CfdGoParseDescriptor(handle uintptr, descriptor string, networkType int, bip32DerivationPath string) (descriptorDataList []CfdDescriptorData, multisigList []CfdDescriptorKeyData, _swig_ret int) {
	var descriptorHandle uintptr
	var maxIndex uint32
	maxIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxIndex)))
	ret := CfdParseDescriptor(handle, descriptor, networkType, bip32DerivationPath, &descriptorHandle, maxIndexPtr)
	if ret == (int)(KCfdSuccess) {
		var maxMultisigKeyNum uint32
		lastMultisigFlag := false
		keyNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxMultisigKeyNum)))
		for i := uint32(0); i <= maxIndex; i++ {
			var data CfdDescriptorData
			var maxNum uint32
			maxNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxNum)))
			depthPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&(data.depth))))
			index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
			ret = CfdGetDescriptorData(handle, descriptorHandle, index, maxNumPtr,
					depthPtr, &data.scriptType, &data.lockingScript,
					&data.address, &data.hashType, &data.redeemScript,
					&data.keyType, &data.pubkey, &data.extPubkey, &data.extPrivkey,
					&data.isMultisig, keyNumPtr)
			if ret != (int)(KCfdSuccess) {
				break
			}
			descriptorDataList = append(descriptorDataList, data)
			lastMultisigFlag = data.isMultisig
		}

		if lastMultisigFlag && (ret == (int)(KCfdSuccess)) {
			for i := uint32(0); i < maxMultisigKeyNum; i++ {
				var keyData CfdDescriptorKeyData
				index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
				ret = CfdGetDescriptorMultisigKey(handle, descriptorHandle,
						index, &keyData.keyType, &keyData.pubkey,
						&keyData.extPubkey, &keyData.extPrivkey)
				if ret != (int)(KCfdSuccess) {
					break
				}
				multisigList = append(multisigList, keyData)
			}
		}

		freeRet := CfdFreeDescriptorHandle(handle, descriptorHandle)
		if ret == (int)(KCfdSuccess) {
			ret = freeRet
		}
	}
	return descriptorDataList, multisigList, ret
}

/**
 * Get multisig pubkeys address.
 * param: handle        cfd handle
 * param: redeemScript  multisig script
 * param: networkType   network type
 * param: hashType      hash type (p2sh, p2wsh, etc...)
 * return: addressList  address list
 * return: pubkeyList   pubkey list
 * return: _swig_ret    error code
 */
func CfdGoGetAddressesFromMultisig(handle uintptr, redeemScript string, networkType int, hashType int) (addressList []string, pubkeyList []string, _swig_ret int) {
	var multisigHandle uintptr
	var maxKeyNum uint32
	maxKeyNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxKeyNum)))

	ret := CfdGetAddressesFromMultisig(handle, redeemScript, networkType,
			hashType, &multisigHandle, maxKeyNumPtr)
	if ret == (int)(KCfdSuccess) {
		for i := uint32(0); i < maxKeyNum; i++ {
			var pubkey string
			var address string
			index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
			ret = CfdGetAddressFromMultisigKey(handle, multisigHandle,
					index, &address, &pubkey)
			if ret != (int)(KCfdSuccess) {
				break
			}
			addressList = append(addressList, address)
			pubkeyList = append(pubkeyList, pubkey)
		}

		freeRet := CfdFreeAddressesMultisigHandle(handle, multisigHandle)
		if ret == (int)(KCfdSuccess) {
			ret = freeRet
		}
	}
	return addressList, pubkeyList, ret
}

%}
