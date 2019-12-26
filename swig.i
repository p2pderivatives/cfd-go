%module cfdgo
%{
#include "cfdc/cfdcapi_common.h"
#include "cfdc/cfdcapi_address.h"
#include "cfdc/cfdcapi_coin.h"
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
#cgo CXXFLAGS: -I./external/cfd/include -I../cfd/include -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -L/usr/local/lib64 -L${SRCDIR}/build/Release -L${SRCDIR}/build/Debug -lcfd -lcfdcore -lunivalue -lwally
%}

%include "external/cfd/include/cfdc/cfdcapi_common.h"
%include "external/cfd/include/cfdc/cfdcapi_address.h"
%include "external/cfd/include/cfdc/cfdcapi_coin.h"
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
		err = fmt.Errorf("CFD Error: message=[%s], code=[%d]", errorMsg, retCode)
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
 * Clone cfd handle.
 * param: handle       cfd source handle
 * return: handle      cfd handle. release: CfdGoFreeHandle
 * return: err         error struct
 */
func CfdGoCloneHandle(sourceHandle uintptr) (handle uintptr, err error) {
	ret := CfdCloneHandle(sourceHandle, &handle)
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
 * Copy and free cfd handle.
 * param: parentHandle  cfd parent handle
 * param: handle        cfd free handle
 * return: err          error struct
 */
func CfdGoCopyAndFreeHandle(parentHandle uintptr, handle uintptr) (err error) {
	CfdCopyErrorState(handle, parentHandle)
	err = CfdGoFreeHandle(handle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdCreateAddress(cfdErrHandle, hashType, pubkey, redeemScript, networkType, &address, &lockingScript, &p2shSegwitLockingScript)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	var multisigHandle uintptr
	ret := CfdInitializeMultisigScript(cfdErrHandle, networkType, hashType, &multisigHandle)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
		return
	}
	defer CfdFreeMultisigScriptHandle(cfdErrHandle, multisigHandle)

	for i := 0; i < len(pubkeys); i++ {
		ret = CfdAddMultisigScriptData(cfdErrHandle, multisigHandle, pubkeys[i])
		if ret != (int)(KCfdSuccess) {
			break
		}
	}

	if ret == (int)(KCfdSuccess) {
		reqNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&requireNum)))
		ret = CfdFinalizeMultisigScript(cfdErrHandle, multisigHandle, reqNumPtr, &address, &redeemScript, &witnessScript)
	}

	if ret == (int)(KCfdSuccess) {
		return address, redeemScript, witnessScript, err
	} else {
		err = convertCfdError(ret, cfdErrHandle)
		return "", "", "", err
	}
}

/**
 * Descriptor data struct.
 */
type CfdDescriptorData struct {
	// depth (0 - )
	Depth uint32
	// script type. (CfdDescriptorScriptType)
	ScriptType int
	// locking script.
	LockingScript string
	// address string. (for ScriptType not KCfdDescriptorScriptRaw)
	Address string
	// hash type. (CfdHashType)
	HashType int
	// redeem script. (for ScriptType KCfdDescriptorScriptSh or KCfdDescriptorScriptWsh)
	RedeemScript string
	// key type. (see CfdDescriptorKeyData.KeyType)
	KeyType int
	// pubkey
	Pubkey string
	// extend pubkey
	ExtPubkey string
	// extend privkey
	ExtPrivkey string
	// has multisig
	IsMultisig bool
	// number of multisig require signatures
	ReqSigNum uint32
}

/**
 * Descriptor key data struct.
 */
type CfdDescriptorKeyData struct {
	// key type. (CfdDescriptorKeyType)
	// - KCfdDescriptorKeyNull
	// - KCfdDescriptorKeyPublic
	// - KCfdDescriptorKeyBip32
	// - KCfdDescriptorKeyBip32Priv
	KeyType int
	// pubkey
	Pubkey string
	// extend pubkey
	ExtPubkey string
	// extend privkey
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	var descriptorHandle uintptr
	var maxIndex uint32
	maxIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxIndex)))
	ret := CfdParseDescriptor(cfdErrHandle, descriptor, networkType, bip32DerivationPath, &descriptorHandle, maxIndexPtr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
		return
	}
	defer CfdFreeDescriptorHandle(cfdErrHandle, descriptorHandle)

	var maxMultisigKeyNum uint32
	lastMultisigFlag := false
	keyNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxMultisigKeyNum)))
	for i := uint32(0); i <= maxIndex; i++ {
		var data CfdDescriptorData
		var maxNum uint32
		maxNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxNum)))
		depthPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&(data.Depth))))
		index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		reqSigNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&(data.ReqSigNum))))
		ret = CfdGetDescriptorData(cfdErrHandle, descriptorHandle, index, maxNumPtr,
				depthPtr, &data.ScriptType, &data.LockingScript,
				&data.Address, &data.HashType, &data.RedeemScript,
				&data.KeyType, &data.Pubkey, &data.ExtPubkey, &data.ExtPrivkey,
				&data.IsMultisig, keyNumPtr, reqSigNumPtr)
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
			ret = CfdGetDescriptorMultisigKey(cfdErrHandle, descriptorHandle,
					index, &keyData.KeyType, &keyData.Pubkey,
					&keyData.ExtPubkey, &keyData.ExtPrivkey)
			if ret != (int)(KCfdSuccess) {
				break
			}
			multisigList = append(multisigList, keyData)
		}
	}

	if ret == (int)(KCfdSuccess) {
		return descriptorDataList, multisigList, err
	} else {
		err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	var multisigHandle uintptr
	var maxKeyNum uint32
	maxKeyNumPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&maxKeyNum)))

	ret := CfdGetAddressesFromMultisig(cfdErrHandle, redeemScript, networkType,
			hashType, &multisigHandle, maxKeyNumPtr)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
		return
	}
	defer CfdFreeAddressesMultisigHandle(cfdErrHandle, multisigHandle)

	for i := uint32(0); i < maxKeyNum; i++ {
		var pubkey string
		var address string
		index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		ret = CfdGetAddressFromMultisigKey(cfdErrHandle, multisigHandle,
				index, &address, &pubkey)
		if ret != (int)(KCfdSuccess) {
			break
		}
		addressList = append(addressList, address)
		pubkeyList = append(pubkeyList, pubkey)
	}

	if ret == (int)(KCfdSuccess) {
		return addressList, pubkeyList, err
	} else {
		err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdGetAddressFromLockingScript(cfdErrHandle, lockingScript, networkType, &address)
	err = convertCfdError(ret, cfdErrHandle)
	return address, err
}

/**
 * UTXO struct.
 */
type CfdUtxo struct {
	// utxo txid
	Txid string
	// utxo vout
	Vout uint32
	// amount
	Amount int64
	// asset
	Asset string
	// output descriptor
	Descriptor string
	// is issuance output
	IsIssuance bool
	// is blind issuance output
	IsBlindIssuance bool
	// is peg-in output
	IsPegin bool
	// peg-in bitcoin tx size (require when IsPegin is true)
	PeginBtcTxSize uint32
	// fedpegscript hex (require when IsPegin is true)
	FedpegScript string
}

/**
 * Selection target amount struct.
 */
type CfdTargetAmount struct {
	// amount
	Amount int64
	// asset
	Asset string
}

/**
 * CoinSelection option data struct.
 */
type CfdCoinSelectionOption struct {
	// fee asset
	FeeAsset string
	// tx-fee amount
	TxFeeAmount int64
	// effective feerate
	EffectiveFeeRate float64
	// longterm feerate
	LongTermFeeRate float64
	// dust feerate
	DustFeeRate float64
	// knapsack min change value
	KnapsackMinChange int64
}

/**
 * Create CfdCoinSelectionOption struct set default value.
 * return: option        CoinSelection option
 */
func NewCfdCoinSelectionOption() CfdCoinSelectionOption {
	option := CfdCoinSelectionOption{}
	option.EffectiveFeeRate = float64(20.0)
	option.LongTermFeeRate = float64(-1.0)
	option.DustFeeRate = float64(-1.0)
	option.KnapsackMinChange = int64(-1)
	return option
}

/**
 * Select coins.
 * param: handle         cfd handle
 * param: utxos          utxo array
 * param: targetAmounts  target amount array
 * param: option         option for coinSelection
 * return: selectUtxos   select coins
 * return: totalAmounts  select amount by asset
 * return: utxoFee       fee by utxo
 * return: err           error
 */
func CfdGoCoinSelection(handle uintptr, utxos []CfdUtxo, targetAmounts []CfdTargetAmount, option CfdCoinSelectionOption) (selectUtxos []CfdUtxo, totalAmounts []CfdTargetAmount, utxoFee int64, err error) {
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	var coinSelectHandle uintptr
	utxoCount := (uint32)(len(utxos))
	amountCount := (uint32)(len(targetAmounts))
	utxoCountBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&utxoCount)))
	amountCountBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&amountCount)))
	txFeeAmountBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.TxFeeAmount)))
	knapsackMinChangeBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&option.KnapsackMinChange)))
	ret := CfdInitializeCoinSelection(cfdErrHandle, utxoCountBuf,
				amountCountBuf, option.FeeAsset, txFeeAmountBuf,
				option.EffectiveFeeRate, option.LongTermFeeRate, option.DustFeeRate,
				knapsackMinChangeBuf, &coinSelectHandle)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
		return
	}
	defer CfdFreeCoinSelectionHandle(cfdErrHandle, coinSelectHandle)

	for i := int32(0); i < (int32)(utxoCount); i++ {
		indexBuf := SwigcptrInt32_t(uintptr(unsafe.Pointer(&i)))
		voutBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&utxos[i].Vout)))
		amoutBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&utxos[i].Amount)))
		ret = CfdAddCoinSelectionUtxo(cfdErrHandle, coinSelectHandle, indexBuf, utxos[i].Txid, voutBuf, amoutBuf, utxos[i].Asset, utxos[i].Descriptor)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, cfdErrHandle)
			return
		}
	}

	for i := uint32(0); i < amountCount; i++ {
		indexBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		amoutBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&targetAmounts[i].Amount)))
		ret = CfdAddCoinSelectionAmount(cfdErrHandle, coinSelectHandle, indexBuf, amoutBuf, targetAmounts[i].Asset)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, cfdErrHandle)
			return
		}
	}

	utxoFeeBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&utxoFee)))
	ret = CfdFinalizeCoinSelection(cfdErrHandle, coinSelectHandle, utxoFeeBuf)
	if ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
		return
	}

	for i := uint32(0); i < utxoCount; i++ {
		utxoIndex := int32(0)
		indexBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		utxoIndexBuf := SwigcptrInt32_t(uintptr(unsafe.Pointer(&utxoIndex)))
		ret = CfdGetSelectedCoinIndex(cfdErrHandle, coinSelectHandle, indexBuf, utxoIndexBuf)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, cfdErrHandle)
			return
		}
		if utxoIndex < 0 {
			break
		}
		selectUtxos = append(selectUtxos, utxos[utxoIndex])
	}

	for i := uint32(0); i < amountCount; i++ {
		amount := int64(0)
		indexBuf := SwigcptrUint32_t(uintptr(unsafe.Pointer(&i)))
		amountBuf := SwigcptrInt64_t(uintptr(unsafe.Pointer(&amount)))
		ret = CfdGetSelectedCoinAssetAmount(cfdErrHandle, coinSelectHandle, indexBuf, amountBuf)
		if ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, cfdErrHandle)
			return
		}
		totalAmounts = append(totalAmounts, targetAmounts[i])
		totalAmounts[i].Amount = amount
	}
	return
}

/**
 * EstimateFee Input data struct.
 */
type CfdEstimateFeeInput struct {
	// utxo data
	Utxo CfdUtxo
	// is issuance input
	IsIssuance bool
	// is blind issuance input
	IsBlindIssuance bool
	// is peg-in input
	IsPegin bool
	// peg-in bitcoin tx size (require when IsPegin is true)
	PeginBtcTxSize uint32
	// fedpegscript hex (require when IsPegin is true)
	FedpegScript string
}

/**
 * EstimateFee option data struct.
 */
type CfdEstimateFeeOption struct {
	// effective feerate
	EffectiveFeeRate float64
	// use elements chain
	UseElements bool
	// fee asset
	FeeAsset string
	// Require blinding or not
	RequireBlind bool 
}

/**
 * Create CfdEstimateFeeOption struct set default value.
 * return: option        EstimateFeeOption
 */
func NewCfdEstimateFeeOption() CfdEstimateFeeOption {
	option := CfdEstimateFeeOption{}
	option.EffectiveFeeRate = float64(20.0)
	option.UseElements = true
	option.FeeAsset = ""
	option.RequireBlind = true
	return option
}

/**
 * Estimate fee amount.
 * param: handle        cfd handle
 * param: txHex         transaction hex
 * param: inputs        inputs to set in the transaction
 * param: option        options for fee estimation
 * return: totalFee     total fee value when all utxos set to input.
 *     (totalFee = txFee + utxoFee)
 * return: txFee        base transaction fee value.
 * return: inputFee     fee value all of input set.
 */
func CfdGoEstimateFee(handle uintptr, txHex string, inputs []CfdEstimateFeeInput, option CfdEstimateFeeOption) (totalFee, txFee, inputFee int64, err error) {
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	var estimateFeeHandle uintptr
	if ret := CfdInitializeEstimateFee(handle, &estimateFeeHandle,
			option.UseElements); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
		return
	}
	defer CfdFreeEstimateFeeHandle(handle, estimateFeeHandle)

	for _, input := range inputs {
		vout := SwigcptrUint32_t(uintptr(unsafe.Pointer(&input.Utxo.Vout)))
		peginBtcTxSize := SwigcptrUint32_t(uintptr(unsafe.Pointer(&input.PeginBtcTxSize)))
		if ret := CfdAddTxInForEstimateFee(
				handle, estimateFeeHandle, input.Utxo.Txid, vout, input.Utxo.Descriptor, 
				input.Utxo.Asset, input.IsIssuance, input.IsBlindIssuance, input.IsPegin,
				peginBtcTxSize, input.FedpegScript); ret != (int)(KCfdSuccess) {
			err = convertCfdError(ret, cfdErrHandle)
			return
		}
	}

	var txFeeWork, inputFeeWork int64
	txFeeWorkPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&txFeeWork)))
	inputFeeWorkPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&inputFeeWork)))
	if ret := CfdFinalizeEstimateFee(handle, estimateFeeHandle, txHex,
			option.FeeAsset, txFeeWorkPtr, inputFeeWorkPtr, option.RequireBlind,
			option.EffectiveFeeRate); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
		return
	}

	totalFee = txFeeWork + inputFeeWork
	txFee = txFeeWork
	inputFee = inputFeeWork
	return
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&locktime)))
	ret := CfdInitializeConfidentialTx(cfdErrHandle, versionPtr, locktimePtr, &txHex)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdAddConfidentialTxIn(cfdErrHandle, txHex, txid, voutPtr, sequencePtr, &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddConfidentialTxOut(cfdErrHandle, txHex, asset, satoshiPtr, valueCommitment, address, directLockingScript, nonce, &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdUpdateConfidentialTxOut(cfdErrHandle, txHex, indexPtr, asset, satoshiPtr, valueCommitment, address, directLockingScript, nonce, &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
	return outputTxHex, err
}

/**
 * TxData data struct.
 */
type CfdTxData struct {
	// txid
	Txid string
	// witness txid
	Wtxid string
	// witness hash
	WitHash string
	// size
	Size uint32
	// virtual size
	Vsize uint32
	// weight
	Weight uint32
	// version
	Version uint32
	// locktime
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	sizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Size)))
	vsizePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Vsize)))
	weightPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Weight)))
	versionPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.Version)))
	locktimePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&data.LockTime)))
	ret := CfdGetConfidentialTxInfo(cfdErrHandle, txHex, &data.Txid, &data.Wtxid, &data.WitHash, sizePtr, vsizePtr, weightPtr, versionPtr, locktimePtr)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	sequencePtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sequence)))
	ret := CfdGetConfidentialTxIn(cfdErrHandle, txHex, indexPtr, &txid, voutPtr, sequencePtr, &scriptSig)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	stackIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&stackIndex)))
	ret := CfdGetConfidentialTxInWitness(cfdErrHandle, txHex, txinIndexPtr, stackIndexPtr, &stackData)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	assetAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetAmount)))
	tokenAmountPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenAmount)))
	ret := CfdGetTxInIssuanceInfo(cfdErrHandle, txHex, indexPtr, &entropy, &nonce, assetAmountPtr, &assetValue, tokenAmountPtr, &tokenValue, &assetRangeproof, &tokenRangeproof)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdGetConfidentialTxOut(cfdErrHandle, txHex, indexPtr, &asset, satoshiPtr, &valueCommitment, &nonce, &lockingScript, &surjectionProof, &rangeproof)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxInCount(cfdErrHandle, txHex, countPtr)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	txinIndexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&txinIndex)))
	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxInWitnessCount(cfdErrHandle, txHex, txinIndexPtr, countPtr)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	countPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&count)))
	ret := CfdGetConfidentialTxOutCount(cfdErrHandle, txHex, countPtr)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetSatoshiAmount)))
	ret := CfdSetRawReissueAsset(cfdErrHandle, txHex, txid, voutPtr, satoshiPtr, blindingNonce, entropy, address, directLockingScript, &asset, &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdGetIssuanceBlindingKey(cfdErrHandle, masterBlindingKey, txid, voutPtr, &blindingKey)
	err = convertCfdError(ret, cfdErrHandle)
	return blindingKey, err
}

/**
 * Get blind transaction handle.
 * param: handle               cfd handle
 * return: blindHandle         blindTx handle. release: CfdGoFreeBlindHandle
 * return: err                 error
 */
func CfdGoInitializeBlindTx(handle uintptr) (blindHandle uintptr, err error) {
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdInitializeBlindTx(cfdErrHandle, &blindHandle)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdAddBlindTxInData(cfdErrHandle, blindHandle, txid, voutPtr, asset, assetBlindFactor, valueBlindFactor, satoshiPtr, assetKey, tokenKey)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	ret := CfdAddBlindTxOutData(cfdErrHandle, blindHandle, indexPtr, confidentialKey)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdFinalizeBlindTx(cfdErrHandle, blindHandle, txHex, &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
	return outputTxHex, err
}

/**
 * Free blind handle.
 * param: handle               cfd handle
 * param: blindHandle          blindTx handle
 * return: err                 error
 */
func CfdGoFreeBlindHandle(handle uintptr, blindHandle uintptr) (err error) {
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdFreeBlindHandle(cfdErrHandle, blindHandle)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddConfidentialTxSign(cfdErrHandle, txHex, txid, voutPtr, isWitness, signDataHex, clearStack, &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdAddConfidentialTxDerSign(cfdErrHandle, txHex, txid, voutPtr, isWitness, signDataHex, sighashType, sighashAnyoneCanPay, clearStack, &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
	return outputTxHex, err
}

/**
 * Add unlocking script to confidential transaction input by index.
 *   (prototype interface)
 * param: handle               cfd handle
 * param: txHex                transaction hex
 * param: index                input index
 * param: isWitness            insert sign data to witness stack
 * param: unlockingScript      unlocking script hex
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxUnlockingScriptByIndex(handle uintptr, txHex string, index uint32, isWitness bool, unlockingScript string, clearStack bool) (outputTxHex string, err error) {
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	txid, vout, _, _, err := CfdGoGetConfidentialTxIn(cfdErrHandle, txHex, index)
	if err != nil {
		return
	}
	txHexWork, err := CfdGoAddConfidentialTxUnlockingScript(cfdErrHandle, txHex, txid, vout, isWitness, unlockingScript, clearStack)
	if err != nil {
		return 
	}

	outputTxHex = txHexWork
	return
}

/**
 * Add unlocking script to confidential transaction input.
 * param: handle               cfd handle
 * param: txHex                transaction hex
 * param: txid                 txin txid
 * param: vout                 txin vout
 * param: isWitness            insert sign data to witness stack
 * param: unlockingScript      unlocking script hex
 * param: clearStack           cleanup stack
 * return: outputTxHex         output transaction hex
 * return: err                 error
 */
func CfdGoAddConfidentialTxUnlockingScript(handle uintptr, txHex, txid string, vout uint32, isWitness bool, unlockingScript string, clearStack bool) (outputTxHex string, err error) {
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	scriptItems, err := CfdGoParseScript(cfdErrHandle, unlockingScript)
	if err != nil {
		return
	}

	txHexWork := txHex
	clearFlag := clearStack
	for _, scriptItem := range scriptItems {
		txHexWork, err = CfdGoAddConfidentialTxSign(cfdErrHandle, txHexWork, txid, vout, isWitness, scriptItem, clearFlag)
		if err != nil {
			return
		}

		if clearFlag {
			clearFlag = false
		}
	}

	outputTxHex = txHexWork
	return
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	ret := CfdFinalizeElementsMultisigSign(cfdErrHandle, multiSignHandle, txHex, txid, voutPtr, hashType, witnessScript, redeemScript, clearStack, &outputTxHex)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	voutPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&vout)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdCreateConfidentialSighash(cfdErrHandle, txHex, txid, voutPtr, hashType, pubkey, redeemScript, satoshiPtr, valueCommitment, sighashType, sighashAnyoneCanPay, &sighash)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	satoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&satoshiAmount)))
	ret := CfdUnblindTxOut(cfdErrHandle, txHex, indexPtr, blindingKey, &asset, satoshiPtr, &assetBlindFactor, &valueBlindFactor)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	indexPtr := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	assetSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&assetAmount)))
	tokenSatoshiPtr := SwigcptrInt64_t(uintptr(unsafe.Pointer(&tokenAmount)))
	ret := CfdUnblindIssuance(cfdErrHandle, txHex, indexPtr, assetBlindingKey, tokenBlindingKey, &asset, assetSatoshiPtr, &assetBlindFactor, &assetValueBlindFactor, &token, tokenSatoshiPtr, &tokenBlindFactor, &tokenValueBlindFactor)
	err = convertCfdError(ret, cfdErrHandle)
	return asset, assetAmount, assetBlindFactor, assetValueBlindFactor, token, tokenAmount, tokenBlindFactor, tokenValueBlindFactor, err
}

/**
 * Generate multisig sign handle.
 * param: handle               cfd handle
 * return: multisigSignHandle  multisig sign handle. release: CfdGoFreeMultisigSignHandle
 * return: err                 error
 */
func CfdGoInitializeMultisigSign(handle uintptr) (multisigSignHandle uintptr, err error) {
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdInitializeMultisigSign(cfdErrHandle, &multisigSignHandle)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdAddMultisigSignData(cfdErrHandle, multisigSignHandle, signature, relatedPubkey)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdAddMultisigSignDataToDer(cfdErrHandle, multisigSignHandle, signature, sighashType, sighashAnyoneCanPay, relatedPubkey)
	err = convertCfdError(ret, cfdErrHandle)
	return
}

/**
 * Free multisig sign handle.
 * param: handle               cfd handle
 * param: multisigSignHandle   multisig sign handle
 * return: err                 error
 */
func CfdGoFreeMultisigSignHandle(handle uintptr, multisigSignHandle uintptr) (err error) {
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdFreeMultisigSignHandle(cfdErrHandle, multisigSignHandle)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdCreateConfidentialAddress(cfdErrHandle, address, confidentialKey, &confidentialAddress)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdParseConfidentialAddress(cfdErrHandle, confidentialAddress,
			&address, &confidentialKey, &networkType)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdCalculateEcSignature(cfdErrHandle, sighash, privkeyHex, privkeyWif, wifNetworkType, hasGrindR, &signature)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdEncodeSignatureByDer(cfdErrHandle, signature, sighashType, sighash_anyone_can_pay, &derSignature)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdCreateKeyPair(cfdErrHandle, isCompress, networkType, &pubkey, &privkeyHex, &privkeyWif)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdGetPrivkeyFromWif(cfdErrHandle, privkeyWif, networkType, &privkeyHex)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdGetPubkeyFromPrivkey(cfdErrHandle, privkeyHex, privkeyWif, isCompress, &pubkey)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdCreateExtkeyFromSeed(cfdErrHandle, seed, networkType, keyType, &extkey)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdCreateExtkeyFromParentPath(cfdErrHandle, extkey, path, networkType, keyType, &childExtkey)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdCreateExtPubkey(cfdErrHandle, extkey, networkType, &extPubkey)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdGetPrivkeyFromExtkey(cfdErrHandle, extkey, networkType, &privkeyHex, &privkeyWif)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	ret := CfdGetPubkeyFromExtkey(cfdErrHandle, extkey, networkType, &pubkey)
	err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	if ret := CfdConvertScriptAsmToHex(cfdErrHandle, scriptAsm, &script); ret != (int)(KCfdSuccess) {
		err = convertCfdError(ret, cfdErrHandle)
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

	scriptAsm := strings.Join(scriptItems, " ");
	script, err = CfdGoConvertScriptAsmToHex(cfdErrHandle, scriptAsm);

	return
}

/**
 * Multisig sign data struct.
 */
type CfdMultisigSignData struct {
	// signature
	Signature string
	// use der encode
	IsDerEncode bool
	// sighash type. (CfdSighashType)
	SighashType int
	// sighash anyone can pay.
	SighashAnyoneCanPay bool
	// related pubkey.
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
	cfdErrHandle, err := CfdGoCloneHandle(handle)
	if err != nil {
		return
	}
	defer CfdGoCopyAndFreeHandle(handle, cfdErrHandle)

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
