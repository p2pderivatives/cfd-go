%module cfdgo
%{
#include "cfdc/cfdcapi_common.h"
#include "cfdc/cfdcapi_address.h"
#include "cfdc/cfdcapi_elements_address.h"
#include "cfdc/cfdcapi_elements_transaction.h"
#include "cfdc/cfdcapi_key.h"
#include "cfdc/cfdcapi_script.h"
#include "cfdc/cfdcapi_transaction.h"
%}

%typemap(argout) (char **) {
    if ($1 && *$1) {
        $input->n = strlen(*$1);
    }
}

%insert(cgo_comment_typedefs) %{
#cgo CXXFLAGS: -I./external/cfd/include -I../cfd/include
#cgo LDFLAGS: -L/usr/local/lib -L${SRCDIR}/build/Release -L${SRCDIR}/build/Debug -lcfd -lcfdcore -lunivalue -lwally
%}

%include "external/cfd/include/cfdc/cfdcapi_common.h"
%include "external/cfd/include/cfdc/cfdcapi_address.h"
%include "external/cfd/include/cfdc/cfdcapi_elements_address.h"
%include "external/cfd/include/cfdc/cfdcapi_elements_transaction.h"
%include "external/cfd/include/cfdc/cfdcapi_key.h"
%include "external/cfd/include/cfdc/cfdcapi_script.h"
%include "external/cfd/include/cfdc/cfdcapi_transaction.h"

%go_import("fmt", "strings")
%insert(go_wrapper) %{
/**
 * Convert return code to golang built-in error struct.
 * param: retCode   return code from cfd
 * return: err      built-in error struct.
 */
func convertCfdErrorCode(retCode int) (err error) {
	switch retCode {
		case (int)(KCfdSuccess):
			return nil
		case (int)(KCfdUnknownError):
			err = fmt.Errorf("CFD Error: Unknown error occered.: errorCode=[%d]", retCode)
		case (int)(KCfdInternalError):
			err = fmt.Errorf("CFD Error: Internal error occered.: errorCode=[%d]", retCode)
		case (int)(KCfdMemoryFullError):
			err = fmt.Errorf("CFD Error: Memory is full.: errorCode=[%d]", retCode)
		case (int)(KCfdIllegalArgumentError):
			err = fmt.Errorf("CFD Error: Illegal argument passed.: errorCode=[%d]", retCode)
		case (int)(KCfdIllegalStateError):
			err = fmt.Errorf("CFD Error: Illegal state api call.: errorCode=[%d]", retCode)
		case (int)(KCfdOutOfRangeError):
			err = fmt.Errorf("CFD Error: Out of range access occered.: errorCode=[%d]", retCode)
		case (int)(KCfdInvalidSettingError):
			err = fmt.Errorf("CFD Error: Invalid setting api call.: errorCode=[%d]", retCode)
		case (int)(KCfdConnectionError):
			err = fmt.Errorf("CFD Error: Connection error occered.: errorCode=[%d]", retCode)
		case (int)(KCfdDiskAccessError):
			err = fmt.Errorf("CFD Error: Disk access error occered.: errorCode=[%d]", retCode)
	}
	return
}

/**
 * Convert handle and error code to Golang built-in error.
 * detail: if handle is nil, return fixed message by the error code.
 * param: retCode   cfd return code.
 * param: handle    cfd handle.
 * return: err      built-in error struct.
 */
func convertCfdError(retCode int, handle uintptr) (err error) {
	if retCode == (int)(KCfdSuccess) {
		return
	}

	var errorMsg string
	if handle ==  uintptr(0) {
		err = convertCfdErrorCode(retCode)
	} else if ret := CfdGetLastErrorMessage(handle, &errorMsg); ret != (int)(KCfdSuccess) {
		err = convertCfdErrorCode(retCode)
	} else {
		err = fmt.Errorf("CFD Error: messaga=[%s], code=[%d]", errorMsg, retCode)
	}
	return
}

/**
 * Get supported function.
 * return: funcFlag    function flag.
 * return: err         error struct
 */
func CfdGoGetSupportedFunction() (funcFlag uint64, err error) {
	funcFlagValue := SwigcptrUint64_t(uintptr(unsafe.Pointer(&funcFlag)))
	ret := CfdGetSupportedFunction(funcFlagValue)
	err = convertCfdError(ret, uintptr(0))
	return funcFlag, err
}

/**
 * Create cfd handle.
 * return: handle      cfd handle. release: CfdGoFreeHandle
 * return: err         error struct
 */
func CfdGoCreateHandle() (handle uintptr, err error) {
	ret := CfdCreateSimpleHandle(&handle)
	err = convertCfdError(ret, handle)
	return handle, err
}

/**
 * Free cfd handle.
 * param: handle       cfd handle
 * return: err         error struct
 */
func CfdGoFreeHandle(handle uintptr) (err error) {
	ret := CfdFreeHandle(handle)
	err = convertCfdError(ret, uintptr(0))
	return
}

/**
 * Get last error message.
 * param: handle   cfd handle
 * return: message     last error message
 * return: err         error
 */
func CfdGoGetLastErrorMessage(handle uintptr) (message string, err error) {
	ret := CfdGetLastErrorMessage(handle, &message)
	// Do not use the Free API as it will be released by Go-GC.
	err = convertCfdError(ret, handle)
	return message, err
}

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
 * return: err                      error
 */
func CfdGoCreateAddress(handle uintptr, hashType int, pubkey string, redeemScript string, networkType int) (address string, lockingScript string, p2shSegwitLockingScript string, err error) {
	ret := CfdCreateAddress(handle, hashType, pubkey, redeemScript, networkType, &address, &lockingScript, &p2shSegwitLockingScript)
	err = convertCfdError(ret, handle)
	return address, lockingScript, p2shSegwitLockingScript, err
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
 * return: err            error
 */
func CfdGoCreateMultisigScript(handle uintptr, networkType int, hashType int, pubkeys []string, requireNum uint32) (address string, redeemScript string, witnessScript string, err error) {
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

	if ret == (int)(KCfdSuccess) {
		return address, redeemScript, witnessScript, err
	} else {
		err = convertCfdError(ret, handle)
		return "", "", "", err
	}
}

/**
 * Descriptor data struct.
 */
type CfdDescriptorData struct {
	Depth uint32
	ScriptType int
	LockingScript string
	Address string
	HashType int
	RedeemScript string
	KeyType int
	Pubkey string
	ExtPubkey string
	ExtPrivkey string
	IsMultisig bool
}

/**
 * Descriptor key data struct.
 */
type CfdDescriptorKeyData struct {
	KeyType int
	Pubkey string
	ExtPubkey string
	ExtPrivkey string
}

/**
 * Parse Output Descriptor.
 * param: handle               cfd handle
 * param: descriptor           output descriptor
 * param: networkType          network type
 * param: bip32DerivationPath  derive path
 * return: descriptorDataList  descriptor data struct list
 * return: multisigList        multisig key struct list
 * return: err                 error
 */
func CfdGoParseDescriptor(handle uintptr, descriptor string, networkType int, bip32DerivationPath string) (descriptorDataList []CfdDescriptorData, multisigList []CfdDescriptorKeyData, err error) {
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
			depthPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&(data.Depth))))
			index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
			ret = CfdGetDescriptorData(handle, descriptorHandle, index, maxNumPtr,
					depthPtr, &data.ScriptType, &data.LockingScript,
					&data.Address, &data.HashType, &data.RedeemScript,
					&data.KeyType, &data.Pubkey, &data.ExtPubkey, &data.ExtPrivkey,
					&data.IsMultisig, keyNumPtr)
			if ret != (int)(KCfdSuccess) {
				break
			}
			descriptorDataList = append(descriptorDataList, data)
			lastMultisigFlag = data.IsMultisig
		}

		if lastMultisigFlag && (ret == (int)(KCfdSuccess)) {
			for i := uint32(0); i < maxMultisigKeyNum; i++ {
				var keyData CfdDescriptorKeyData
				index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
				ret = CfdGetDescriptorMultisigKey(handle, descriptorHandle,
						index, &keyData.KeyType, &keyData.Pubkey,
						&keyData.ExtPubkey, &keyData.ExtPrivkey)
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
	if ret == (int)(KCfdSuccess) {
		return descriptorDataList, multisigList, err
	} else {
		err = convertCfdError(ret, handle)
		return []CfdDescriptorData{}, []CfdDescriptorKeyData{}, err
	}
}

/**
 * Get multisig pubkeys address.
 * param: handle        cfd handle
 * param: redeemScript  multisig script
 * param: networkType   network type
 * param: hashType      hash type (p2sh, p2wsh, etc...)
 * return: addressList  address list
 * return: pubkeyList   pubkey list
 * return: err          error
 */
func CfdGoGetAddressesFromMultisig(handle uintptr, redeemScript string, networkType int, hashType int) (addressList []string, pubkeyList []string, err error) {
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
	if ret == (int)(KCfdSuccess) {
		return addressList, pubkeyList, err
	} else {
		err = convertCfdError(ret, handle)
		return []string{}, []string{}, err
	}
}

/**
 * Get address from locking script.
 * param: handle         cfd handle
 * param: lockingScript  locking script
 * param: networkType    network type
 * param: hashType       hash type (p2sh, p2wsh, etc...)
 * return: address       address
 * return: err           error
 */
func CfdGoGetAddressFromLockingScript(handle uintptr, lockingScript string, networkType int) (address string, err error) {
	ret := CfdGetAddressFromLockingScript(handle, lockingScript, networkType, &address)
	err = convertCfdError(ret, handle)
	return address, err
}

/**
 * Get initialized confidential transaction.
 * param: handle        cfd handle
 * param: version       transaction version
 * param: locktime      locktime
 * return: txHex        transaction hex
 * return: err          error
 */
func CfdGoInitializeConfidentialTx(handle uintptr, version uint32, locktime uint32) (txHex string, err error) {
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&locktime)))
	ret := CfdInitializeConfidentialTx(handle, versionPtr, locktimePtr, &txHex)
	err = convertCfdError(ret, handle)
	return txHex, err
}

/**
 * Add txin to confidential transaction.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * param: txid          txid
 * param: vout          vout
 * param: sequence      sequence
 * return: outputTxHex  output transaction hex
 * return: err          error
 */
func CfdGoAddConfidentialTxIn(handle uintptr, txHex string, txid string, vout uint32, sequence uint32) (outputTxHex string, err error) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdAddConfidentialTxIn(handle, txHex, txid, voutPtr, sequencePtr, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add txout to confidential transaction.
 * param: handle              cfd handle
 * param: txHex               transaction hex
 * param: asset               asset
 * param: satoshiAmount       amount by satoshi
 * param: valueCommitment     amount by commitment bytes.
 * param: address             destination address
 * param: directLockingScript  locking script for direct insert.
 * param: nonce               confidential nonce
 * return: outputTxHex        output transaction hex
 * return: err                error
 */
func CfdGoAddConfidentialTxOut(handle uintptr, txHex string, asset string, satoshiAmount int64, valueCommitment string, address string, directLockingScript string, nonce string) (outputTxHex string, err error) {
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddConfidentialTxOut(handle, txHex, asset, satoshiPtr, valueCommitment, address, directLockingScript, nonce, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Update txout of confidential transaction.
 * param: handle              cfd handle
 * param: txHex               transaction hex
 * param: index               txout index
 * param: asset               asset
 * param: satoshiAmount       amount by satoshi
 * param: valueCommitment     amount by commitment bytes.
 * param: address             destination address
 * param: directLockingScript  lockingScript for direct insert.
 * param: nonce               confidential nonce
 * return: outputTxHex        output transaction hex
 * return: err                error
 */
func CfdGoUpdateConfidentialTxOut(handle uintptr, txHex string, index uint32, asset string, satoshiAmount int64, valueCommitment string, address string, directLockingScript string, nonce string) (outputTxHex string, err error) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdUpdateConfidentialTxOut(handle, txHex, indexPtr, asset, satoshiPtr, valueCommitment, address, directLockingScript, nonce, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * TxData data struct.
 */
type CfdTxData struct {
	Txid string
	Wtxid string
	WitHash string
	Size uint32
	Vsize uint32
	Weight uint32
	Version uint32
	LockTime uint32
}

/**
 * Get confidential transaction data.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * return: data         transaction data
 * return: err          error
 */
func CfdGoGetConfidentialTxData(handle uintptr, txHex string) (data CfdTxData, err error) {
	sizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Size)))
	vsizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Vsize)))
	weightPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Weight)))
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.LockTime)))
	ret := CfdGetConfidentialTxInfo(handle, txHex, &data.Txid, &data.Wtxid, &data.WitHash, sizePtr, vsizePtr, weightPtr, versionPtr, locktimePtr)
	err = convertCfdError(ret, handle)
	return data, err
}

/**
 * Get txin on confidential transaction.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * param: index         txin index
 * return: txid         txid
 * return: vout         vout
 * return: sequence     sequence
 * return: scriptSig    unlockingScript
 * return: err          error
 */
func CfdGoGetConfidentialTxIn(handle uintptr, txHex string, index uint32) (txid string, vout uint32, sequence uint32, scriptSig string, err error) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdGetConfidentialTxIn(handle, txHex, indexPtr, &txid, voutPtr, sequencePtr, &scriptSig)
	err = convertCfdError(ret, handle)
	return txid, vout, sequence, scriptSig, err
}

/**
 * Get witness stack on confidential transaction input.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * param: txinIndex     txin index
 * param: stackIndex    witness stack index
 * return: stackData    witness stack data
 * return: err          error
 */
func CfdGoGetConfidentialTxInWitness(handle uintptr, txHex string, txinIndex uint32, stackIndex uint32) (stackData string, err error) {
	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	stackIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&stackIndex)))
	ret := CfdGetConfidentialTxInWitness(handle, txHex, txinIndexPtr, stackIndexPtr, &stackData)
	err = convertCfdError(ret, handle)
	return stackData, err
}

/**
 * Get txin issuance on confidential transaction.
 * param: handle            cfd handle
 * param: txHex             transaction hex
 * param: index             txin index
 * return: entropy          blinding asset entropy
 * return: nonce            blinding nonce
 * return: assetAmount      asset amount value
 * return: assetValue       asset commitment value
 * return: tokenAmount      token amount value
 * return: tokenValue       token commitment value
 * return: assetRangeproof  asset rangeproof
 * return: tokenRangeproof  token rangeproof
 * return: err              error
 */
func CfdGoGetTxInIssuanceInfo(handle uintptr, txHex string, index uint32) (entropy string, nonce string, assetAmount int64, assetValue string, tokenAmount int64, tokenValue string, assetRangeproof string, tokenRangeproof string, err error) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	assetAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetAmount)))
	tokenAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenAmount)))
	ret := CfdGetTxInIssuanceInfo(handle, txHex, indexPtr, &entropy, &nonce, assetAmountPtr, &assetValue, tokenAmountPtr, &tokenValue, &assetRangeproof, &tokenRangeproof)
	err = convertCfdError(ret, handle)
	return entropy, nonce, assetAmount, assetValue, tokenAmount, tokenValue, assetRangeproof, tokenRangeproof, err
}

/**
 * Get txout on confidential transaction.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * param: index         txin index
 * return: asset            asset
 * return: satoshiAmount    amount by satoshi
 * return: valueCommitment  amount by commitment bytes.
 * return: nonce            confidential nonce
 * return: lockingScript    locking script
 * return: surjectionProof  asset surjection proof.
 * return: rangeproof       amount rangeproof.
 * return: err              error
 */
func CfdGoGetConfidentialTxOut(handle uintptr, txHex string, index uint32) (asset string, satoshiAmount int64, valueCommitment string, nonce string, lockingScript string, surjectionProof string, rangeproof string, err error) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdGetConfidentialTxOut(handle, txHex, indexPtr, &asset, satoshiPtr, &valueCommitment, &nonce, &lockingScript, &surjectionProof, &rangeproof)
	err = convertCfdError(ret, handle)
	return asset, satoshiAmount, valueCommitment, nonce, lockingScript, surjectionProof, rangeproof, err
}

/**
 * Get txin count on confidential transaction.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * return: count        txin count
 * return: err          error
 */
func CfdGoGetConfidentialTxInCount(handle uintptr, txHex string) (count uint32, err error) {
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxInCount(handle, txHex, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Get witness stack count on confidential transaction input.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * param: txinIndex     txin index
 * return: count        witness stack count
 * return: err          error
 */
func CfdGoGetConfidentialTxInWitnessCount(handle uintptr, txHex string, txinIndex uint32) (count uint32, err error) {
	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxInWitnessCount(handle, txHex, txinIndexPtr, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Get txout count on confidential transaction.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * return: count        txout count
 * return: err          error
 */
func CfdGoGetConfidentialTxOutCount(handle uintptr, txHex string) (count uint32, err error) {
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxOutCount(handle, txHex, countPtr)
	err = convertCfdError(ret, handle)
	return count, err
}

/**
 * Set reissuance asset to confidential transaction.
 * param: handle               cfd handle
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: assetSatoshiAmount   generate asset amount
 * param: blindingNonce        blinding nonce
 * param: entropy              entropy
 * param: address              destination address
 * param: directLockingScript  txout locking script on direct.
 * return: asset               generate asset
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoSetRawReissueAsset(handle uintptr, txHex string, txid string, vout uint32, assetSatoshiAmount int64, blindingNonce string, entropy string, address string, directLockingScript string) (asset string, outputTxHex string, err error) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetSatoshiAmount)))
	ret := CfdSetRawReissueAsset(handle, txHex, txid, voutPtr, satoshiPtr, blindingNonce, entropy, address, directLockingScript, &asset, &outputTxHex)
	err = convertCfdError(ret, handle)
	return asset, outputTxHex, err
}

/**
 * Get issuance blinding key.
 * param: handle               cfd handle
 * param: masterBlindingKey    master blinding key
 * param: txid                 utxo txid
 * param: vout                 utxo vout
 * return: blindingKey         issuance blinding key
 * return: err                 error
 */
func CfdGoGetIssuanceBlindingKey(handle uintptr, masterBlindingKey string, txid string, vout uint32) (blindingKey string, err error) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdGetIssuanceBlindingKey(handle, masterBlindingKey, txid, voutPtr, &blindingKey)
	err = convertCfdError(ret, handle)
	return blindingKey, err
}

/**
 * Get blind transaction handle.
 * param: handle               cfd handle
 * return: blindHandle         blindTx handle. release: CfdGoFreeBlindHandle
 * return: err                 error
 */
func CfdGoInitializeBlindTx(handle uintptr) (blindHandle uintptr, err error) {
	ret := CfdInitializeBlindTx(handle, &blindHandle)
	err = convertCfdError(ret, handle)
	return blindHandle, err
}

/**
 * Add blind transaction txin data.
 * param: handle               cfd handle
 * param: blindHandle          blindTx handle
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: asset                utxo asset
 * param: assetBlindFactor     utxo asset blind factor
 * param: valueBlindFactor     utxo amount blind factor
 * param: satoshiAmount        utxo amount
 * param: assetKey             issuance asset blinding key
 * param: tokenKey             issuance token blinding key
 * return: err                 error
 */
func CfdGoAddBlindTxInData(handle uintptr, blindHandle uintptr, txid string, vout uint32, asset string, assetBlindFactor string, valueBlindFactor string, satoshiAmount int64, assetKey string, tokenKey string) (err error) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddBlindTxInData(handle, blindHandle, txid, voutPtr, asset, assetBlindFactor, valueBlindFactor, satoshiPtr, assetKey, tokenKey)
	err = convertCfdError(ret, handle)
	return err
}

/**
 * Add blind transaction txout data.
 * param: handle               cfd handle
 * param: blindHandle          blindTx handle
 * param: index                txout index
 * param: confidentialKey      confidential key
 * return: err                 error
 */
func CfdGoAddBlindTxOutData(handle uintptr, blindHandle uintptr, index uint32, confidentialKey string) (err error) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdAddBlindTxOutData(handle, blindHandle, indexPtr, confidentialKey)
	err = convertCfdError(ret, handle)
	return err
}

/**
 * Generate blind transaction.
 * param: handle               cfd handle
 * param: blindHandle          blindTx handle
 * param: txHex                transaction hex
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoFinalizeBlindTx(handle uintptr, blindHandle uintptr, txHex string) (outputTxHex string, err error) {
	ret := CfdFinalizeBlindTx(handle, blindHandle, txHex, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Free blind handle.
 * param: handle               cfd handle
 * param: blindHandle          blindTx handle
 * return: err                 error
 */
func CfdGoFreeBlindHandle(handle uintptr, blindHandle uintptr) (err error) {
	ret := CfdFreeBlindHandle(handle, blindHandle)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Add sign data to confidential transaction.
 * param: handle               cfd handle
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: isWitness            insert sign data to witness stack
 * param: signDataHex          sign data hex
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxSign(handle uintptr, txHex string, txid string, vout uint32, isWitness bool, signDataHex string, clearStack bool) (outputTxHex string, err error) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddConfidentialTxSign(handle, txHex, txid, voutPtr, isWitness, signDataHex, clearStack, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Convert to der encode, and add sign data to confidential transaction.
 * param: handle               cfd handle
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: isWitness            insert sign data to witness stack
 * param: signDataHex          sign data hex
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxDerSign(handle uintptr, txHex string, txid string, vout uint32, isWitness bool, signDataHex string, sighashType int, sighashAnyoneCanPay bool, clearStack bool) (outputTxHex string, err error) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddConfidentialTxDerSign(handle, txHex, txid, voutPtr, isWitness, signDataHex, sighashType, sighashAnyoneCanPay, clearStack, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Add multisig sign data to confidential transaction.
 * param: handle               cfd handle
 * param: multiSignHandle      multisig sign handle
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type
 * param: witnessScript        witness script (p2wsh, p2sh-p2wsh)
 * param: redeemScript         redeem script (p2sh, p2sh-p2wsh)
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoFinalizeElementsMultisigSign(handle uintptr, multiSignHandle uintptr, txHex string, txid string, vout uint32, hashType int, witnessScript string, redeemScript string, clearStack bool) (outputTxHex string, err error) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdFinalizeElementsMultisigSign(handle, multiSignHandle, txHex, txid, voutPtr, hashType, witnessScript, redeemScript, clearStack, &outputTxHex)
	err = convertCfdError(ret, handle)
	return outputTxHex, err
}

/**
 * Create sighash from confidential transaction.
 * param: handle               cfd handle
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: hashType             hash type
 * param: pubkey               pubkey (p2pkh, p2wpkh, p2sh-p2wpkh)
 * param: redeemScript         redeem script (p2Sh, p2wsh, p2sh-p2wsh)
 * param: satoshiAmount        amount by satoshi
 * param: valueCommitment      amount by commitment bytes.
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoCreateConfidentialSighash(handle uintptr, txHex string, txid string, vout uint32, hashType int, pubkey string, redeemScript string, satoshiAmount int64, valueCommitment string, sighashType int, sighashAnyoneCanPay bool) (sighash string, err error) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdCreateConfidentialSighash(handle, txHex, txid, voutPtr, hashType, pubkey, redeemScript, satoshiPtr, valueCommitment, sighashType, sighashAnyoneCanPay, &sighash)
	err = convertCfdError(ret, handle)
	return sighash, err
}

/**
 * Unblind txout on confidential transaction.
 * param: handle               cfd handle
 * param: txHex                transaction hex
 * param: index                txout index
 * param: blindingKey          blinding key
 * return: asset               asset
 * return: satoshiAmount       satoshi amount
 * return: assetBlindFactor    asset blind factor
 * return: valueBlindFactor    amount blind factor
 * return: err                 error
 */
func CfdGoUnblindTxOut(handle uintptr, txHex string, index uint32, blindingKey string) (asset string, satoshiAmount int64, assetBlindFactor string, valueBlindFactor string, err error) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdUnblindTxOut(handle, txHex, indexPtr, blindingKey, &asset, satoshiPtr, &assetBlindFactor, &valueBlindFactor)
	err = convertCfdError(ret, handle)
	return asset, satoshiAmount, assetBlindFactor, valueBlindFactor, err
}

/**
 * Unblind txin issuance on confidential transaction.
 * param: handle                  cfd handle
 * param: txHex                   transaction hex
 * param: index                   txin index
 * param: assetBlindingKey        asset blinding key
 * param: tokenBlindingKey        token blinding key
 * return: asset                  asset
 * return: assetAmount            asset amount
 * return: assetBlindFactor       issueAsset asset blind factor
 * return: assetValueBlindFactor  issueAsset value blind factor
 * return: token                  token
 * return: tokenAmount            token amount
 * return: tokenBlindFactor       issueToken asset blind factor
 * return: tokenValueBlindFactor  issueToken value blind factor
 * return: err                 error
 */
func CfdGoUnblindIssuance(handle uintptr, txHex string, index uint32, assetBlindingKey string, tokenBlindingKey string) (asset string, assetAmount int64, assetBlindFactor string, assetValueBlindFactor string, token string, tokenAmount int64, tokenBlindFactor string, tokenValueBlindFactor string, err error) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	assetSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetAmount)))
	tokenSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenAmount)))
	ret := CfdUnblindIssuance(handle, txHex, indexPtr, assetBlindingKey, tokenBlindingKey, &asset, assetSatoshiPtr, &assetBlindFactor, &assetValueBlindFactor, &token, tokenSatoshiPtr, &tokenBlindFactor, &tokenValueBlindFactor)
	err = convertCfdError(ret, handle)
	return asset, assetAmount, assetBlindFactor, assetValueBlindFactor, token, tokenAmount, tokenBlindFactor, tokenValueBlindFactor, err
}

/**
 * Generate multisig sign handle.
 * param: handle               cfd handle
 * return: multisigSignHandle  multisig sign handle. release: CfdGoFreeMultisigSignHandle
 * return: err                 error
 */
func CfdGoInitializeMultisigSign(handle uintptr) (multisigSignHandle uintptr, err error) {
	ret := CfdInitializeMultisigSign(handle, &multisigSignHandle)
	err = convertCfdError(ret, handle)
	return multisigSignHandle, err
}

/**
 * Add multisig sign data.
 * param: handle                  cfd handle
 * param: multisigSignHandle      multisig sign handle
 * param: signature            signature
 * param: relatedPubkey        signature related pubkey
 * return: err                 error
 */
func CfdGoAddMultisigSignData(handle uintptr, multisigSignHandle uintptr, signature string, relatedPubkey string) (err error) {
	ret := CfdAddMultisigSignData(handle, multisigSignHandle, signature, relatedPubkey)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Convert to der encode, and add multisig sign data.
 * param: handle               cfd handle
 * param: multisigSignHandle      multisig sign handle
 * param: signature            signature
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * param: relatedPubkey        signature related pubkey
 * return: err                 error
 */
func CfdGoAddMultisigSignDataToDer(handle uintptr, multisigSignHandle uintptr, signature string, sighashType int, sighashAnyoneCanPay bool, relatedPubkey string) (err error) {
	ret := CfdAddMultisigSignDataToDer(handle, multisigSignHandle, signature, sighashType, sighashAnyoneCanPay, relatedPubkey)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Free multisig sign handle.
 * param: handle               cfd handle
 * param: multisigSignHandle   multisig sign handle
 * return: err                 error
 */
func CfdGoFreeMultisigSignHandle(handle uintptr, multisigSignHandle uintptr) (err error) {
	ret := CfdFreeMultisigSignHandle(handle, multisigSignHandle)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Create confidential address.
 * param: handle                cfd handle
 * param: address               address
 * param: confidentialKey       confidential key
 * return: confidentialAddress  confidential address
 * return: err                  error
 */
func CfdGoCreateConfidentialAddress(handle uintptr, address string, confidentialKey string) (confidentialAddress string, err error) {
	ret := CfdCreateConfidentialAddress(handle, address, confidentialKey, &confidentialAddress)
	err = convertCfdError(ret, handle)
	return confidentialAddress, err
}

/**
 * Get address and confidentialKey from confidentialAddress.
 * param: handle               cfd handle
 * param: confidentialAddress  confidential address
 * return: address             address
 * return: confidentialKey     confidential key
 * return: networkType         network type
 * return: err                 error
 */
func CfdGoParseConfidentialAddress(handle uintptr, confidentialAddress string) (address string, confidentialKey string, networkType int, err error) {
	ret := CfdParseConfidentialAddress(handle, confidentialAddress,
			&address, &confidentialKey, &networkType)
	err = convertCfdError(ret, handle)
	return address, confidentialKey, networkType, err
}

/**
 * Calculate ec-signature from privkey.
 * param: handle               cfd handle
 * param: sighash              signatufe hash
 * param: privkeyHex           privkey hex (Specify either privkeyHex or privkeyWif)
 * param: privkeyWif           privkey WIF (Specify either privkeyHex or privkeyWif)
 * param: wifNetworkType       network type (for privkey WIF)
 * param: hasGrindR            grind-r flag
 * return: signature           signature
 * return: err                 error
 */
func CfdGoCalculateEcSignature(handle uintptr, sighash string, privkeyHex string, privkeyWif string, wifNetworkType int, hasGrindR bool) (signature string, err error) {
	ret := CfdCalculateEcSignature(handle, sighash, privkeyHex, privkeyWif, wifNetworkType, hasGrindR, &signature)
	err = convertCfdError(ret, handle)
	return signature, err
}

/**
 * Encode ec signature by der encoding.
 * param: handle                  cfd handle.
 * param: signature               compact format signature.
 * param: sighashType             sighash type.
 * param: sighash_anyone_can_pay  flag of signing only the current input.
 * return: derSignature   signature encoded by der encodeing.
 * return: err            error
 */
func CfdGoEncodeSignatureByDer(handle uintptr, signature string, sighashType int, sighash_anyone_can_pay bool) (derSignature string, err error) {
	ret := CfdEncodeSignatureByDer(handle, signature, sighashType, sighash_anyone_can_pay, &derSignature)
	err = convertCfdError(ret, handle)
	return
}

/**
 * Create key pair.
 * param: handle          cfd handle.
 * param: isCompress      pubkey compressed.
 * param: networkType     privkey wif network type.
 * return: pubkey         pubkey.
 * return: privkeyHex     privkey hex.
 * return: privkeyWif     privkey wif.
 * return: err            error
 */
func CfdGoCreateKeyPair(handle uintptr, isCompress bool, networkType int) (pubkey string, privkeyHex string, privkeyWif string, err error) {
	ret := CfdCreateKeyPair(handle, isCompress, networkType, &pubkey, &privkeyHex, &privkeyWif)
	err = convertCfdError(ret, handle)
	return pubkey, privkeyHex, privkeyWif, err
}

/**
 * Get privkey from WIF.
 * param: handle          cfd handle.
 * param: privkeyWif      privkey wif.
 * param: networkType     privkey wif network type.
 * return: privkeyHex     privkey hex.
 * return: err            error
 */
func CfdGoGetPrivkeyFromWif(handle uintptr, privkeyWif string, networkType int) (privkeyHex string, err error) {
	ret := CfdGetPrivkeyFromWif(handle, privkeyWif, networkType, &privkeyHex)
	err = convertCfdError(ret, handle)
	return privkeyHex, err
}

/**
 * Get pubkey from privkey.
 * param: handle          cfd handle.
 * param: privkeyHex      privkey hex. (or privkeyWif)
 * param: privkeyWif      privkey wif. (or privkeyHex)
 * param: isCompress      pubkey compressed.
 * return: pubkey         pubkey hex.
 * return: err            error
 */
func CfdGoGetPubkeyFromPrivkey(handle uintptr, privkeyHex string, privkeyWif string, isCompress bool) (pubkey string, err error) {
	ret := CfdGetPubkeyFromPrivkey(handle, privkeyHex, privkeyWif, isCompress, &pubkey)
	err = convertCfdError(ret, handle)
	return pubkey, err
}

/**
 * Create extkey from seed.
 * param: handle          cfd handle.
 * param: seed            seed data(hex).
 * param: networkType     network type.
 * param: keyType         extkey type.
 * return: extkey         extkey.
 * return: err            error
 */
func CfdGoCreateExtkeyFromSeed(handle uintptr, seed string, networkType int, keyType int) (extkey string, err error) {
	ret := CfdCreateExtkeyFromSeed(handle, seed, networkType, keyType, &extkey)
	err = convertCfdError(ret, handle)
	return extkey, err
}

/**
 * Create extkey from parent path.
 * param: handle          cfd handle.
 * param: extkey          parent extkey.
 * param: path            bip32 key path.(ex: 0/0h/0'/0)
 * param: networkType     network type.
 * param: keyType         extkey type.
 * return: childExtkey    child extkey.
 * return: err            error
 */
func CfdGoCreateExtkeyFromParentPath(handle uintptr, extkey string, path string, networkType int, keyType int) (childExtkey string, err error) {
	ret := CfdCreateExtkeyFromParentPath(handle, extkey, path, networkType, keyType, &childExtkey)
	err = convertCfdError(ret, handle)
	return childExtkey, err
}

/**
 * Create extpubkey from extprivkey.
 * param: handle          cfd handle.
 * param: extkey          ext privkey.
 * param: networkType     network type.
 * return: extPubkey      ext pubkey.
 * return: err            error
 */
func CfdGoCreateExtPubkey(handle uintptr, extkey string, networkType int) (extPubkey string, err error) {
	ret := CfdCreateExtPubkey(handle, extkey, networkType, &extPubkey)
	err = convertCfdError(ret, handle)
	return extPubkey, err
}

/**
 * Get privkey from extprivkey.
 * param: handle          cfd handle.
 * param: extkey          ext privkey.
 * param: networkType     network type.
 * return: privkeyHex     privkey hex.
 * return: privkeyWif     privkey wif.
 * return: err            error
 */
func CfdGoGetPrivkeyFromExtkey(handle uintptr, extkey string, networkType int) (privkeyHex string, privkeyWif string, err error) {
	ret := CfdGetPrivkeyFromExtkey(handle, extkey, networkType, &privkeyHex, &privkeyWif)
	err = convertCfdError(ret, handle)
	return privkeyHex, privkeyWif, err
}

/**
 * Get pubkey from extkey.
 * param: handle          cfd handle.
 * param: extkey          extkey.
 * param: networkType     network type.
 * return: pubkey         pubkey.
 * return: err            error
 */
func CfdGoGetPubkeyFromExtkey(handle uintptr, extkey string, networkType int) (pubkey string, err error) {
	ret := CfdGetPubkeyFromExtkey(handle, extkey, networkType, &pubkey)
	err = convertCfdError(ret, handle)
	return pubkey, err
}

/**
 * Parse script items from script.
 * param: handle          cfd handle.
 * param: script          script.
 * return: scriptItems    script items.
 * return: err            error
 */
func CfdGoParseScript(handle uintptr, script string) (scriptItems []string, err error) {
	cfdErrHandle := handle
	if handle == uintptr(0) {
		errHandle, err := CfdGoCreateHandle()
		if err != nil {
			return nil, err
		}
		defer CfdGoFreeHandle(errHandle)
		cfdErrHandle = errHandle
	}
	var scriptItemHandle uintptr
	var itemNum uint32
	itemNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&itemNum)))
	var ret int

	if ret = CfdParseScript(cfdErrHandle, script, &scriptItemHandle, itemNumPtr); ret == (int)(KCfdSuccess) {
		scriptItems = make([]string, 0, itemNum)
		for i := uint32(0); i < itemNum; i++ {
			var item string
			index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
			if ret = CfdGetScriptItem(cfdErrHandle, scriptItemHandle, index, &item); ret == (int)(KCfdSuccess) {
				scriptItems = append(scriptItems, item)
			}
		}

		if freeRet := CfdFreeScriptItemHandle(cfdErrHandle, scriptItemHandle); ret == (int)(KCfdSuccess) {
			ret = freeRet
		}
	}
	
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
		scriptItems = nil
	}
	return
}

/**
 * Convert script asm to hex.
 * param: handle          cfd handle.
 * param: scriptAsm       script assembly string.
 * return: script         hex encodeed script.
 * return: err            error
 */
func CfdGoConvertScriptAsmToHex(handle uintptr, scriptAsm string) (script string, err error) {
	if ret := CfdConvertScriptAsmToHex(handle, scriptAsm, &script); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, handle)
		script = ""
	}

	return
}

/**
 * Create script from script items.
 * param: handle          cfd handle.
 * param: scriptItems     array of script element string.
 * return: script         hex encoded script.
 * return: err            error
 */
func CfdGoCreateScript(handle uintptr, scriptItems []string) (script string, err error) {
	scriptAsm := strings.Join(scriptItems, " ");
	script, err = CfdGoConvertScriptAsmToHex(handle, scriptAsm);

	return
}

/**
 * Multisig sign data struct.
 */
type CfdMultisigSignData struct {
	Signature string
	IsDerEncode bool
	SighashType int
	SighashAnyoneCanPay bool
	RelatedPubkey string
}

/**
 * Create multisig scriptsig.
 * param: handle          cfd handle.
 * param: signItems       array of multisig sign data struct.
 * param: redeemScript    hex encoded multisig script.
 * return: scriptsig      hex encoded script.
 * return: err            error
 */
func CfdGoCreateMultisigScriptSig(handle uintptr, signItems []CfdMultisigSignData, redeemScript string) (scriptsig string, err error) {
	scriptsig = ""
	cfdErrHandle := handle
	if handle == uintptr(0) {
		errHandle, err := CfdGoCreateHandle()
		if err != nil {
			return "", err
		}
		defer CfdGoFreeHandle(errHandle)
		cfdErrHandle = errHandle
	}

	var multisigHandle uintptr
	ret := CfdInitializeMultisigScriptSig(cfdErrHandle, &multisigHandle)
	if ret != (int)(KCfdSuccess) {
		return "", convertCfdError(ret, cfdErrHandle)
	}
	defer CfdFreeMultisigScriptSigHandle(cfdErrHandle, multisigHandle)

	for i := 0; i < len(signItems); i++ {
		if signItems[i].IsDerEncode {
			ret = CfdAddMultisigScriptSigDataToDer(cfdErrHandle, multisigHandle,
					signItems[i].Signature, signItems[i].SighashType,
					signItems[i].SighashAnyoneCanPay, signItems[i].RelatedPubkey)
		} else {
			ret = CfdAddMultisigScriptSigData(cfdErrHandle, multisigHandle,
					signItems[i].Signature, signItems[i].RelatedPubkey)
		}
		if ret != (int)(KCfdSuccess) {
			break
		}
	}

	if ret == (int)(KCfdSuccess) {
		ret = CfdFinalizeMultisigScriptSig(cfdErrHandle, multisigHandle, redeemScript, &scriptsig)
	}
	return scriptsig, convertCfdError(ret, cfdErrHandle)
}
%}
