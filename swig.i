%module cfdgo
%{
#include "cfdc/cfdcapi_common.h"
#include "cfdc/cfdcapi_address.h"
#include "cfdc/cfdcapi_elements_address.h"
#include "cfdc/cfdcapi_elements_transaction.h"
#include "cfdc/cfdcapi_transaction.h"
#include "cfdc/cfdcapi_key.h"
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
%include "external/cfd/include/cfdc/cfdcapi_elements_address.h"
%include "external/cfd/include/cfdc/cfdcapi_elements_transaction.h"
%include "external/cfd/include/cfdc/cfdcapi_transaction.h"
%include "external/cfd/include/cfdc/cfdcapi_key.h"

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

	if ret == (int)(KCfdSuccess) {
		return address, redeemScript, witnessScript, ret
	} else {
		return "", "", "", ret
	}
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
	if ret == (int)(KCfdSuccess) {
		return descriptorDataList, multisigList, ret
	} else {
		return []CfdDescriptorData{}, []CfdDescriptorKeyData{}, ret
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
	if ret == (int)(KCfdSuccess) {
		return addressList, pubkeyList, ret
	} else {
		return []string{}, []string{}, ret
	}
}

/**
 * Get initialized confidential transaction.
 * param: handle        cfd handle
 * param: version       transaction version
 * param: locktime      locktime
 * return: txHex        transaction hex
 * return: _swig_ret    error code
 */
func CfdGoInitializeConfidentialTx(handle uintptr, version uint32, locktime uint32) (txHex string, _swig_ret int) {
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&locktime)))
	ret := CfdInitializeConfidentialTx(handle, versionPtr, locktimePtr, &txHex)
	return txHex, ret
}

/**
 * Add txin to confidential transaction.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * param: txid          txid
 * param: vout          vout
 * param: sequence      sequence
 * return: outputTxHex  output transaction hex
 * return: _swig_ret    error code
 */
func CfdGoAddConfidentialTxIn(handle uintptr, txHex string, txid string, vout uint32, sequence uint32) (outputTxHex string, _swig_ret int) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdAddConfidentialTxIn(handle, txHex, txid, voutPtr, sequencePtr, &outputTxHex)
	return outputTxHex, ret
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
 * return: _swig_ret          error code
 */
func CfdGoAddConfidentialTxOut(handle uintptr, txHex string, asset string, satoshiAmount int64, valueCommitment string, address string, directLockingScript string, nonce string) (outputTxHex string, _swig_ret int) {
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddConfidentialTxOut(handle, txHex, asset, satoshiPtr, valueCommitment, address, directLockingScript, nonce, &outputTxHex)
	return outputTxHex, ret
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
 * return: _swig_ret          error code
 */
func CfdGoUpdateConfidentialTxOut(handle uintptr, txHex string, index uint32, asset string, satoshiAmount int64, valueCommitment string, address string, directLockingScript string, nonce string) (outputTxHex string, _swig_ret int) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdUpdateConfidentialTxOut(handle, txHex, indexPtr, asset, satoshiPtr, valueCommitment, address, directLockingScript, nonce, &outputTxHex)
	return outputTxHex, ret
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
 * return: _swig_ret    error code
 */
func CfdGoGetConfidentialTxIn(handle uintptr, txHex string, index uint32) (txid string, vout uint32, sequence uint32, scriptSig string, _swig_ret int) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdGetConfidentialTxIn(handle, txHex, indexPtr, &txid, voutPtr, sequencePtr, &scriptSig)
	return txid, vout, sequence, scriptSig, ret
}

/**
 * Get txin issuance on confidential transaction.
 * param: handle            cfd handle
 * param: txHex             transaction hex
 * param: index             txin index
 * return: entropy          blinding asset entropy
 * return: nonce            blinding nonce
 * return: assetValue       asset amount
 * return: tokenValue       token amount
 * return: assetRangeproof  asset rangeproof
 * return: tokenRangeproof  token rangeproof
 * return: _swig_ret        error code
 */
func CfdGoGetTxInIssuanceInfo(handle uintptr, txHex string, index uint32) (entropy string, nonce string, assetValue string, tokenValue string, assetRangeproof string, tokenRangeproof string, _swig_ret int) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdGetTxInIssuanceInfo(handle, txHex, indexPtr, &entropy, &nonce, &assetValue, &tokenValue, &assetRangeproof, &tokenRangeproof)
	return entropy, nonce, assetValue, tokenValue, assetRangeproof, tokenRangeproof, ret
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
 * return: _swig_ret        error code
 */
func CfdGoGetConfidentialTxOut(handle uintptr, txHex string, index uint32) (asset string, satoshiAmount int64, valueCommitment string, nonce string, lockingScript string, surjectionProof string, rangeproof string, _swig_ret int) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdGetConfidentialTxOut(handle, txHex, indexPtr, &asset, satoshiPtr, &valueCommitment, &nonce, &lockingScript, &surjectionProof, &rangeproof)
	return asset, satoshiAmount, valueCommitment, nonce, lockingScript, surjectionProof, rangeproof, ret
}

/**
 * Get txin count on confidential transaction.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * return: count        txin count
 * return: _swig_ret    error code
 */
func CfdGoGetConfidentialTxInCount(handle uintptr, txHex string) (count uint32, _swig_ret int) {
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxInCount(handle, txHex, countPtr)
	return count, ret
}

/**
 * Get txout count on confidential transaction.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * return: count        txout count
 * return: _swig_ret    error code
 */
func CfdGoGetConfidentialTxOutCount(handle uintptr, txHex string) (count uint32, _swig_ret int) {
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxOutCount(handle, txHex, countPtr)
	return count, ret
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
 * return: _swig_ret           error code
 */
func CfdGoSetRawReissueAsset(handle uintptr, txHex string, txid string, vout uint32, assetSatoshiAmount int64, blindingNonce string, entropy string, address string, directLockingScript string) (asset string, outputTxHex string, _swig_ret int) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetSatoshiAmount)))
	ret := CfdSetRawReissueAsset(handle, txHex, txid, voutPtr, satoshiPtr, blindingNonce, entropy, address, directLockingScript, &asset, &outputTxHex)
	return asset, outputTxHex, ret
}

/**
 * Get issuance blinding key.
 * param: handle               cfd handle
 * param: masterBlindingKey    master blinding key
 * param: txid                 utxo txid
 * param: vout                 utxo vout
 * return: blindingKey         issuance blinding key
 * return: _swig_ret           error code
 */
func CfdGoGetIssuanceBlindingKey(handle uintptr, masterBlindingKey string, txid string, vout uint32) (blindingKey string, _swig_ret int) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdGetIssuanceBlindingKey(handle, masterBlindingKey, txid, voutPtr, &blindingKey)
	return blindingKey, ret
}

/**
 * Get blind transaction handle.
 * param: handle               cfd handle
 * return: blindHandle         blindTx handle. release: CfdFreeBlindHandle
 * return: _swig_ret           error code
 */
func CfdGoInitializeBlindTx(handle uintptr) (blindHandle uintptr, _swig_ret int) {
	ret := CfdInitializeBlindTx(handle, &blindHandle)
	return blindHandle, ret
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
 * return: _swig_ret           error code
 */
func CfdGoAddBlindTxInData(handle uintptr, blindHandle uintptr, txid string, vout uint32, asset string, assetBlindFactor string, valueBlindFactor string, satoshiAmount int64, assetKey string, tokenKey string) (_swig_ret int) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddBlindTxInData(handle, blindHandle, txid, voutPtr, asset, assetBlindFactor, valueBlindFactor, satoshiPtr, assetKey, tokenKey)
	return ret
}

/**
 * Add blind transaction txout data.
 * param: handle               cfd handle
 * param: blindHandle          blindTx handle
 * param: index                txout index
 * param: confidentialKey      confidential key
 * return: _swig_ret           error code
 */
func CfdGoAddBlindTxOutData(handle uintptr, blindHandle uintptr, index uint32, confidentialKey string) (_swig_ret int) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdAddBlindTxOutData(handle, blindHandle, indexPtr, confidentialKey)
	return ret
}

/**
 * Generate blind transaction.
 * param: handle               cfd handle
 * param: blindHandle          blindTx handle
 * param: txHex                transaction hex
 * return: outputTxHex         output transaction hex
 * return: _swig_ret           error code
 */
func CfdGoFinalizeBlindTx(handle uintptr, blindHandle uintptr, txHex string) (outputTxHex string, _swig_ret int) {
	ret := CfdFinalizeBlindTx(handle, blindHandle, txHex, &outputTxHex)
	return outputTxHex, ret
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
 * return: _swig_ret           error code
 */
func CfdGoAddConfidentialTxSign(handle uintptr, txHex string, txid string, vout uint32, isWitness bool, signDataHex string, clearStack bool) (outputTxHex string, _swig_ret int) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddConfidentialTxSign(handle, txHex, txid, voutPtr, isWitness, signDataHex, clearStack, &outputTxHex)
	return outputTxHex, ret
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
 * return: _swig_ret           error code
 */
func CfdGoAddConfidentialTxDerSign(handle uintptr, txHex string, txid string, vout uint32, isWitness bool, signDataHex string, sighashType int, sighashAnyoneCanPay bool, clearStack bool) (outputTxHex string, _swig_ret int) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddConfidentialTxDerSign(handle, txHex, txid, voutPtr, isWitness, signDataHex, sighashType, sighashAnyoneCanPay, clearStack, &outputTxHex)
	return outputTxHex, ret
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
 * return: _swig_ret           error code
 */
func CfdGoFinalizeElementsMultisigSign(handle uintptr, multiSignHandle uintptr, txHex string, txid string, vout uint32, hashType int, witnessScript string, redeemScript string, clearStack bool) (outputTxHex string, _swig_ret int) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdFinalizeElementsMultisigSign(handle, multiSignHandle, txHex, txid, voutPtr, hashType, witnessScript, redeemScript, clearStack, &outputTxHex)
	return outputTxHex, ret
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
 * return: outputTxHex         output transaction hex
 * return: _swig_ret           error code
 */
func CfdGoCreateConfidentialSighash(handle uintptr, txHex string, txid string, vout uint32, hashType int, pubkey string, redeemScript string, satoshiAmount int64, valueCommitment string, sighashType int, sighashAnyoneCanPay bool) (sighash string, _swig_ret int) {
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdCreateConfidentialSighash(handle, txHex, txid, voutPtr, hashType, pubkey, redeemScript, satoshiPtr, valueCommitment, sighashType, sighashAnyoneCanPay, &sighash)
	return sighash, ret
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
 * return: _swig_ret           error code
 */
func CfdGoUnblindTxOut(handle uintptr, txHex string, index uint32, blindingKey string) (asset string, satoshiAmount int64, assetBlindFactor string, valueBlindFactor string, _swig_ret int) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdUnblindTxOut(handle, txHex, indexPtr, blindingKey, &asset, satoshiPtr, &assetBlindFactor, &valueBlindFactor)
	return asset, satoshiAmount, assetBlindFactor, valueBlindFactor, ret
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
 * return: _swig_ret           error code
 */
func CfdGoUnblindIssuance(handle uintptr, txHex string, index uint32, assetBlindingKey string, tokenBlindingKey string) (asset string, assetAmount int64, assetBlindFactor string, assetValueBlindFactor string, token string, tokenAmount int64, tokenBlindFactor string, tokenValueBlindFactor string, _swig_ret int) {
	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	assetSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetAmount)))
	tokenSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenAmount)))
	ret := CfdUnblindIssuance(handle, txHex, indexPtr, assetBlindingKey, tokenBlindingKey, &asset, assetSatoshiPtr, &assetBlindFactor, &assetValueBlindFactor, &token, tokenSatoshiPtr, &tokenBlindFactor, &tokenValueBlindFactor)
	return asset, assetAmount, assetBlindFactor, assetValueBlindFactor, token, tokenAmount, tokenBlindFactor, tokenValueBlindFactor, ret
}

/**
 * Generate multisig sign handle.
 * param: handle               cfd handle
 * return: multisigSignHandle  multisig sign handle
 * return: _swig_ret           error code
 */
func CfdGoInitializeMultisigSign(handle uintptr) (multisigSignHandle uintptr, _swig_ret int) {
	ret := CfdInitializeMultisigSign(handle, &multisigSignHandle)
	return multisigSignHandle, ret
}

/**
 * Add multisig sign data.
 * param: handle                  cfd handle
 * param: multisigSignHandle      multisig sign handle
 * param: signature            signature
 * param: relatedPubkey        signature related pubkey
 * return: _swig_ret           error code
 */
func CfdGoAddMultisigSignData(handle uintptr, multisigSignHandle uintptr, signature string, relatedPubkey string) (_swig_ret int) {
	return CfdAddMultisigSignData(handle, multisigSignHandle, signature, relatedPubkey)
}

/**
 * Convert to der encode, and add multisig sign data.
 * param: handle               cfd handle
 * param: multisigSignHandle      multisig sign handle
 * param: signature            signature
 * param: sighashType          sighash type
 * param: sighashAnyoneCanPay  sighash anyone can pay flag
 * param: relatedPubkey        signature related pubkey
 * return: _swig_ret           error code
 */
func CfdGoAddMultisigSignDataToDer(handle uintptr, multisigSignHandle uintptr, signature string, sighashType int, sighashAnyoneCanPay bool, relatedPubkey string) (_swig_ret int) {
	return CfdAddMultisigSignDataToDer(handle, multisigSignHandle, signature, sighashType, sighashAnyoneCanPay, relatedPubkey)
}

/**
 * Create confidential address.
 * param: handle                cfd handle
 * param: address               address
 * param: confidentialKey       confidential key
 * return: confidentialAddress  confidential address
 * return: _swig_ret            error code
 */
func CfdGoCreateConfidentialAddress(handle uintptr, address string, confidentialKey string) (confidentialAddress string, _swig_ret int) {
	ret := CfdCreateConfidentialAddress(handle, address, confidentialKey, &confidentialAddress)
	return confidentialAddress, ret
}

/**
 * Get address and confidentialKey from confidentialAddress.
 * param: handle               cfd handle
 * param: confidentialAddress  confidential address
 * return: address             address
 * return: confidentialKey     confidential key
 * return: networkType         network type
 * return: _swig_ret           error code
 */
func CfdGoParseConfidentialAddress(handle uintptr, confidentialAddress string) (address string, confidentialKey string, networkType int, _swig_ret int) {
	ret := CfdParseConfidentialAddress(handle, confidentialAddress,
			&address, &confidentialKey, &networkType)
	return address, confidentialKey, networkType, ret
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
 * return: _swig_ret           error code
 */
func CfdGoCalculateEcSignature(handle uintptr, sighash string, privkeyHex string, privkeyWif string, wifNetworkType int, hasGrindR bool) (signature string, _swig_ret int) {
	ret := CfdCalculateEcSignature(handle, sighash, privkeyHex, privkeyWif, wifNetworkType, hasGrindR, &signature)
	return signature, ret
}

/**
 * Create key pair.
 * param: handle          cfd handle.
 * param: isCompress      pubkey compressed.
 * param: networkType     privkey wif network type.
 * return: pubkey         pubkey.
 * return: privkeyHex     privkey hex.
 * return: privkeyWif     privkey wif.
 * return: _swig_ret      error code
 */
func CfdGoCreateKeyPair(handle uintptr, isCompress bool, networkType int) (pubkey string, privkeyHex string, privkeyWif string, _swig_ret int) {
	ret := CfdCreateKeyPair(handle, isCompress, networkType, &pubkey, &privkeyHex, &privkeyWif)
	return pubkey, privkeyHex, privkeyWif, ret
}

/**
 * Get privkey from WIF.
 * param: handle          cfd handle.
 * param: privkeyWif      privkey wif.
 * param: networkType     privkey wif network type.
 * return: privkeyHex     privkey hex.
 * return: _swig_ret      error code
 */
func CfdGoGetPrivkeyFromWif(handle uintptr, privkeyWif string, networkType int) (privkeyHex string, _swig_ret int) {
	ret := CfdGetPrivkeyFromWif(handle, privkeyWif, networkType, &privkeyHex)
	return privkeyHex, ret
}

/**
 * Get pubkey from privkey.
 * param: handle          cfd handle.
 * param: privkeyHex      privkey hex. (or privkeyWif)
 * param: privkeyWif      privkey wif. (or privkeyHex)
 * param: isCompress      pubkey compressed.
 * return: pubkey         pubkey hex.
 * return: _swig_ret      error code
 */
func CfdGoGetPubkeyFromPrivkey(handle uintptr, privkeyHex string, privkeyWif string, isCompress bool) (pubkey string, _swig_ret int) {
	ret := CfdGetPubkeyFromPrivkey(handle, privkeyHex, privkeyWif, isCompress, &pubkey)
	return pubkey, ret
}

/**
 * Create extkey from seed.
 * param: handle          cfd handle.
 * param: seed            seed data(hex).
 * param: networkType     network type.
 * param: keyType         extkey type.
 * return: extkey         extkey.
 * return: _swig_ret      error code
 */
func CfdGoCreateExtkeyFromSeed(handle uintptr, seed string, networkType int, keyType int) (extkey string, _swig_ret int) {
	ret := CfdCreateExtkeyFromSeed(handle, seed, networkType, keyType, &extkey)
	return extkey, ret
}

/**
 * Create extkey from parent path.
 * param: handle          cfd handle.
 * param: extkey          parent extkey.
 * param: path            bip32 key path.(ex: 0/0h/0'/0)
 * param: networkType     network type.
 * param: keyType         extkey type.
 * return: childExtkey    child extkey.
 * return: _swig_ret      error code
 */
func CfdGoCreateExtkeyFromParentPath(handle uintptr, extkey string, path string, networkType int, keyType int) (childExtkey string, _swig_ret int) {
	ret := CfdCreateExtkeyFromParentPath(handle, extkey, path, networkType, keyType, &childExtkey)
	return childExtkey, ret
}

/**
 * Create extpubkey from extprivkey.
 * param: handle          cfd handle.
 * param: extkey          ext privkey.
 * param: networkType     network type.
 * return: extPubkey      ext pubkey.
 * return: _swig_ret      error code
 */
func CfdGoCreateExtPubkey(handle uintptr, extkey string, networkType int) (extPubkey string, _swig_ret int) {
	ret := CfdCreateExtPubkey(handle, extkey, networkType, &extPubkey)
	return extPubkey, ret
}

/**
 * Get privkey from extprivkey.
 * param: handle          cfd handle.
 * param: extkey          ext privkey.
 * param: networkType     network type.
 * return: privkeyHex     privkey hex.
 * return: privkeyWif     privkey wif.
 * return: _swig_ret      error code
 */
func CfdGoGetPrivkeyFromExtkey(handle uintptr, extkey string, networkType int) (privkeyHex string, privkeyWif string, _swig_ret int) {
	ret := CfdGetPrivkeyFromExtkey(handle, extkey, networkType, &privkeyHex, &privkeyWif)
	return privkeyHex, privkeyWif, ret
}

/**
 * Get pubkey from extkey.
 * param: handle          cfd handle.
 * param: extkey          extkey.
 * param: networkType     network type.
 * return: pubkey         pubkey.
 * return: _swig_ret      error code
 */
func CfdGoGetPubkeyFromExtkey(handle uintptr, extkey string, networkType int) (pubkey string, _swig_ret int) {
	ret := CfdGetPubkeyFromExtkey(handle, extkey, networkType, &pubkey)
	return pubkey, ret
}

%}
