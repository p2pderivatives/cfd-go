package cfdgo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCfdCreateRawTransaction(t *testing.T) {
	txHex, err := CfdGoInitializeConfidentialTx(uint32(2), uint32(0))
	assert.NoError(t, err)
	assert.Equal(t, "0200000000000000000000", txHex)

	sequence := (uint32)(KCfdSequenceLockTimeDisable)
	if err == nil {
		txHex, err = CfdGoAddConfidentialTxIn(
			txHex,
			"7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", 0,
			sequence)
		assert.NoError(t, err)
		assert.Equal(t, "020000000001bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffff0000000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddConfidentialTxIn(
			txHex,
			"1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1", 1,
			sequence)
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0000000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddConfidentialTxOut(
			txHex,
			"ef47c42d34de1b06a02212e8061323f50d5f02ceed202f1cb375932aa299f751",
			int64(100000000), "",
			"CTEw7oSCUWDfmfhCEdsB3gsG7D9b4xLCZEq71H8JxRFeBu7yQN3CbSF6qT6J4F7qji4bq1jVSdVcqvRJ",
			"", "")
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff010151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac00000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddConfidentialTxOut(
			txHex,
			"6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
			int64(1900500000), "",
			"2dxZw5iVZ6Pmqoc5Vn8gkUWDGB5dXuMBCmM", "", "")
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff020151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac00000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddConfidentialTxOut(
			txHex,
			"6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
			int64(500000), "", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddDestroyConfidentialTxOut(
			txHex,
			"ef47c42d34de1b06a02212e8061323f50d5f02ceed202f1cb375932aa299f751",
			int64(50000000))
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff040151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a12000000151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000002faf08000016a00000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoUpdateConfidentialTxOut(txHex, uint32(2), "6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3", int64(1000000), "", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff040151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000000f424000000151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000002faf08000016a00000000", txHex)
	}

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdCreateRawTransaction2(t *testing.T) {
	handle, err := CfdGoInitializeConfidentialTransaction(uint32(2), uint32(0))
	assert.NoError(t, err)
	defer CfdGoFreeTransactionHandle(handle)

	sequence := uint32(0xffffffff)
	if err == nil {
		err = CfdGoAddTxInput(
			handle,
			"7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", 0,
			sequence)
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddTxInput(
			handle,
			"1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1", 1,
			sequence)
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddConfidentialTxOutput(
			handle,
			"ef47c42d34de1b06a02212e8061323f50d5f02ceed202f1cb375932aa299f751",
			int64(100000000),
			"CTEw7oSCUWDfmfhCEdsB3gsG7D9b4xLCZEq71H8JxRFeBu7yQN3CbSF6qT6J4F7qji4bq1jVSdVcqvRJ")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddConfidentialTxOutput(
			handle,
			"6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
			int64(1900500000),
			"2dxZw5iVZ6Pmqoc5Vn8gkUWDGB5dXuMBCmM")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddConfidentialTxOutputFee(
			handle,
			"6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
			int64(500000))
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddConfidentialTxOutputDestroyAmount(
			handle,
			"ef47c42d34de1b06a02212e8061323f50d5f02ceed202f1cb375932aa299f751",
			int64(50000000))
		assert.NoError(t, err)
	}

	if err == nil {
		txHex, err := CfdGoFinalizeTransaction(handle)
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff040151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a12000000151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000002faf08000016a00000000", txHex)
	}

	if err == nil {
		handle2, err := CfdGoInitializeConfidentialTransactionByHex("020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff040151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a12000000151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000002faf08000016a00000000")
		assert.NoError(t, err)
		defer CfdGoFreeTransactionHandle(handle2)

		if err == nil {
			err = CfdGoAddConfidentialTxOutputByScript(
				handle2,
				"6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
				int64(10000),
				"0014eb3c0d55b7098a4aef4a18ee1eebcb1ed924a82b")
			assert.NoError(t, err)
		}
		if err == nil {
			txHex, err := CfdGoFinalizeTransaction(handle2)
			assert.NoError(t, err)
			assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff050151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a12000000151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000002faf08000016a01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000000271000160014eb3c0d55b7098a4aef4a18ee1eebcb1ed924a82b00000000", txHex)
		}
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGetTransaction(t *testing.T) {
	txHex := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	count, err := CfdGoGetConfidentialTxInCount(txHex)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), count)

	count, err = CfdGoGetConfidentialTxOutCount(txHex)
	assert.NoError(t, err)
	assert.Equal(t, uint32(4), count)

	if err == nil {
		txData, err := CfdGoGetConfidentialTxData(txHex)
		assert.NoError(t, err)
		assert.Equal(t, "cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992", txData.Txid)
		assert.Equal(t, "cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992", txData.Wtxid)
		assert.Equal(t, "938e3a9b5bac410e812d08db74c4ef2bc58d1ed99d94b637cab0ac2e9eb59df8", txData.WitHash)
		assert.Equal(t, uint32(512), txData.Size)
		assert.Equal(t, uint32(512), txData.Vsize)
		assert.Equal(t, uint32(2048), txData.Weight)
		assert.Equal(t, uint32(2), txData.Version)
		assert.Equal(t, uint32(0), txData.LockTime)
	}

	if err == nil {
		txid, vout, sequence, scriptSig, err := CfdGoGetConfidentialTxIn(txHex, uint32(1))
		assert.NoError(t, err)
		assert.Equal(t, "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", txid)
		assert.Equal(t, uint32(1), vout)
		assert.Equal(t, uint32(4294967295), sequence)
		assert.Equal(t, "", scriptSig)

		if err == nil {
			txinIndex, err := CfdGoGetConfidentialTxInIndex(txHex, txid, vout)
			assert.NoError(t, err)
			assert.Equal(t, uint32(1), txinIndex)
		}
	}

	if err == nil {
		entropy, nonce, assetAmount, assetValue, tokenAmount, tokenValue, assetRangeproof, tokenRangeproof, err := CfdGoGetTxInIssuanceInfo(txHex, uint32(1))
		assert.NoError(t, err)
		assert.Equal(t, "6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306", entropy)
		assert.Equal(t, "0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8", nonce)
		assert.Equal(t, "010000000023c34600", assetValue)
		assert.Equal(t, "", tokenValue)
		assert.Equal(t, int64(600000000), assetAmount)
		assert.Equal(t, int64(0), tokenAmount)
		assert.Equal(t, "", assetRangeproof)
		assert.Equal(t, "", tokenRangeproof)
	}

	if err == nil {
		asset, satoshiValue, valueCommitment, nonce, lockingScript, surjectionProof, rangeproof, err := CfdGoGetConfidentialTxOut(txHex, uint32(3))
		assert.NoError(t, err)
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
		assert.Equal(t, int64(600000000), satoshiValue)
		assert.Equal(t, "010000000023c34600", valueCommitment)
		assert.Equal(t, "03ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed879", nonce)
		assert.Equal(t, "76a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac", lockingScript)
		assert.Equal(t, "", surjectionProof)
		assert.Equal(t, "", rangeproof)

		if err == nil {
			txoutIndex, err := CfdGoGetConfidentialTxOutIndex(txHex, "2dodsWJgP3pTWWidK5hDxuYHqC1U4CEnT3n", "")
			assert.NoError(t, err)
			assert.Equal(t, uint32(3), txoutIndex)
		}
		if err == nil {
			txoutIndex, err := CfdGoGetConfidentialTxOutIndex(txHex, "", lockingScript)
			assert.NoError(t, err)
			assert.Equal(t, uint32(3), txoutIndex)
		}
	}

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGetTransactionByHandle(t *testing.T) {
	txHex := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txData, txinList, txoutList, err := GetConfidentialTxData(txHex, true)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(txinList))
	assert.Equal(t, 4, len(txoutList))

	if err == nil {
		assert.Equal(t, "cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992", txData.Txid)
		assert.Equal(t, "cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992", txData.Wtxid)
		assert.Equal(t, "938e3a9b5bac410e812d08db74c4ef2bc58d1ed99d94b637cab0ac2e9eb59df8", txData.WitHash)
		assert.Equal(t, uint32(512), txData.Size)
		assert.Equal(t, uint32(512), txData.Vsize)
		assert.Equal(t, uint32(2048), txData.Weight)
		assert.Equal(t, uint32(2), txData.Version)
		assert.Equal(t, uint32(0), txData.LockTime)

		// txid, vout, sequence, scriptSig, err := CfdGoGetConfidentialTxIn(txHex, uint32(1))
		assert.NoError(t, err)
		assert.Equal(t, "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", txinList[1].OutPoint.Txid)
		assert.Equal(t, uint32(1), txinList[1].OutPoint.Vout)
		assert.Equal(t, uint32(4294967295), txinList[1].Sequence)
		assert.Equal(t, "", txinList[1].ScriptSig)

		// entropy, nonce, assetAmount, assetValue, tokenAmount, tokenValue, assetRangeproof, tokenRangeproof, err := CfdGoGetTxInIssuanceInfo(txHex, uint32(1))
		assert.Equal(t, "6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306", txinList[1].Issuance.Entropy)
		assert.Equal(t, "0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8", txinList[1].Issuance.Nonce)
		assert.Equal(t, "010000000023c34600", txinList[1].Issuance.AssetValue)
		assert.Equal(t, "", txinList[1].Issuance.TokenValue)
		assert.Equal(t, int64(600000000), txinList[1].Issuance.AssetAmount)
		assert.Equal(t, int64(0), txinList[1].Issuance.TokenAmount)
		assert.Equal(t, "", txinList[1].IssuanceAmountRangeproof)
		assert.Equal(t, "", txinList[1].InflationKeysRangeproof)

		// asset, satoshiValue, valueCommitment, nonce, lockingScript, surjectionProof, rangeproof, err := CfdGoGetConfidentialTxOut(txHex, uint32(3))
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", txoutList[3].Asset)
		assert.Equal(t, int64(600000000), txoutList[3].Amount)
		assert.Equal(t, "010000000023c34600", txoutList[3].CommitmentValue)
		assert.Equal(t, "03ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed879", txoutList[3].CommitmentNonce)
		assert.Equal(t, "76a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac", txoutList[3].LockingScript)
		assert.Equal(t, "", txoutList[3].Surjectionproof)
		assert.Equal(t, "", txoutList[3].Rangeproof)
	}

	txHandle, err := CfdGoInitializeTxDataHandle(int(KCfdNetworkLiquidv1), txHex)
	assert.NoError(t, err)
	if err == nil {
		txinIndex, err := CfdGoGetTxInIndexByHandle(txHandle, txinList[1].OutPoint.Txid, txinList[1].OutPoint.Vout)
		assert.NoError(t, err)
		assert.Equal(t, uint32(1), txinIndex)

		if err == nil {
			txinIndex, err = CfdGoGetTxInIndexByHandle(txHandle, txinList[0].OutPoint.Txid, txinList[0].OutPoint.Vout)
			assert.NoError(t, err)
			assert.Equal(t, uint32(0), txinIndex)
		}
		if err == nil {
			txoutIndex, err := CfdGoGetTxOutIndexByHandle(txHandle, "2dodsWJgP3pTWWidK5hDxuYHqC1U4CEnT3n", "")
			assert.NoError(t, err)
			assert.Equal(t, uint32(3), txoutIndex)
		}
		if err == nil {
			txoutIndex, err := CfdGoGetTxOutIndexByHandle(txHandle, "", txoutList[3].LockingScript)
			assert.NoError(t, err)
			assert.Equal(t, uint32(3), txoutIndex)
		}
		if err == nil {
			txoutIndex, err := CfdGoGetTxOutIndexByHandle(txHandle, "", txoutList[2].LockingScript)
			assert.NoError(t, err)
			assert.Equal(t, uint32(2), txoutIndex)
		}

		freeErr := CfdGoFreeTxDataHandle(txHandle)
		assert.NoError(t, freeErr)
	}

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdSetRawReissueAsset(t *testing.T) {
	txHex := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100000000ffffffff03017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000000000000"

	asset, outTxHex, err := CfdGoSetRawReissueAsset(
		txHex, "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f",
		uint32(1),
		int64(600000000), "0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8",
		"6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306",
		"CTExCoUri8VzkxbbhqzgsruWJ5zYtmoFXxCWtjiSLAzcMbpEWhHmDrZ66bAb41VsmSKnvJWrq2cfjUw9",
		"")
	assert.NoError(t, err)
	assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
	assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", outTxHex)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGetIssuanceBlindingKey(t *testing.T) {
	blindingKey, err := CfdGoGetIssuanceBlindingKey(
		"ac2c1e4cce122139bb25abc50599e09738143cc4bc96e55f399a5e1e45d916a9",
		"57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", uint32(1))
	assert.NoError(t, err)
	assert.Equal(t, "7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f", blindingKey)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGetDefaultBlindingKey(t *testing.T) {
	masterBlindingKey := "ac2c1e4cce122139bb25abc50599e09738143cc4bc96e55f399a5e1e45d916a9"
	address := "ex1qav7q64dhpx9y4m62rrhpa67trmvjf2ptum84qh"
	lockingScript := "0014eb3c0d55b7098a4aef4a18ee1eebcb1ed924a82b"

	blindingKey, err := CfdGoGetDefaultBlindingKey(masterBlindingKey, lockingScript)
	assert.NoError(t, err)
	assert.Equal(t, "24ff3843a00c29fadee220b7d4943915cc5f65fddf1c20363495568bf406fc71", blindingKey)

	blindingKey, err = CfdGoGetDefaultBlindingKeyByAddress(masterBlindingKey, address)
	assert.NoError(t, err)
	assert.Equal(t, "24ff3843a00c29fadee220b7d4943915cc5f65fddf1c20363495568bf406fc71", blindingKey)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdBlindTransaction(t *testing.T) {
	txHex := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	blindHandle, err := CfdGoInitializeBlindTx()
	assert.NoError(t, err)

	if err == nil {
		option := NewCfdBlindTxOption()
		option.MinimumBits = 36
		err = CfdGoSetBlindTxOption(blindHandle, option)
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxInData(
			blindHandle,
			"57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", uint32(0),
			"186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179",
			"a10ecbe1be7a5f883d5d45d966e30dbc1beff5f21c55cec76cc21a2229116a9f",
			"ae0f46d1940f297c2dc3bbd82bf8ef6931a2431fbb05b3d3bc5df41af86ae808",
			int64(999637680), "", "")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxInData(
			blindHandle,
			"57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", uint32(1),
			"ed6927df918c89b5e3d8b5062acab2c749a3291bb7451d4267c7daaf1b52ad0b",
			"0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8",
			"62e36e1f0fa4916b031648a6b6903083069fa587572a88b729250cde528cfd3b",
			int64(700000000),
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f",
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxOutData(
			blindHandle, uint32(0),
			"02200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxOutData(
			blindHandle, uint32(1),
			"02cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxOutData(
			blindHandle, uint32(3),
			"03ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed879")
		assert.NoError(t, err)
	}

	if err == nil {
		txHex, err = CfdGoFinalizeBlindTx(blindHandle, txHex)
		assert.NoError(t, err)
	}

	err2 := CfdGoFreeBlindHandle(blindHandle) // release
	assert.NoError(t, err2)

	if err == nil {
		txData, err := CfdGoGetConfidentialTxData(txHex)
		assert.NoError(t, err)
		assert.Equal(t, 64, len(txData.Txid))
		assert.Equal(t, 64, len(txData.Wtxid))
		assert.Equal(t, 64, len(txData.WitHash))
		assert.Equal(t, uint32(12589), txData.Size)
		assert.Equal(t, uint32(3604), txData.Vsize)
		assert.Equal(t, uint32(14413), txData.Weight)
		assert.Equal(t, uint32(2), txData.Version)
		assert.Equal(t, uint32(0), txData.LockTime)
	}

	// unblind test
	if err == nil {
		asset, assetValue, aabf, avbf, token, tokenValue, tabf, tvbf, err := CfdGoUnblindIssuance(
			txHex, uint32(1),
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f",
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f")
		assert.NoError(t, err)
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
		assert.Equal(t, int64(600000000), assetValue)
		assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", aabf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", avbf)
		assert.Equal(t, "", token)
		assert.Equal(t, int64(0), tokenValue)
		assert.Equal(t, "", tabf)
		assert.Equal(t, "", tvbf)
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			txHex, uint32(0),
			"6a64f506be6e60b948987aa4d180d2ab05034a6a214146e06e28d4efe101d006")
		assert.NoError(t, err)
		assert.Equal(t, "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179", asset)
		assert.Equal(t, int64(999587680), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			txHex, uint32(1),
			"94c85164605f589c4c572874f36b8301989c7fabfd44131297e95824d473681f")
		assert.NoError(t, err)
		assert.Equal(t, "ed6927df918c89b5e3d8b5062acab2c749a3291bb7451d4267c7daaf1b52ad0b", asset)
		assert.Equal(t, int64(700000000), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			txHex, uint32(3),
			"0473d39aa6542e0c1bb6a2343b2319c3e92063dd019af4d47dbf50c460204f32")
		assert.NoError(t, err)
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
		assert.Equal(t, int64(600000000), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
	}

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdBlindTransaction2(t *testing.T) {
	baseTxHex := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	// option := NewCfdBlindTxOption()
	// option.MinimumBits = 36

	txinList := []CfdBlindInputData{
		{
			Txid:             "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f",
			Vout:             uint32(0),
			Asset:            "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179",
			AssetBlindFactor: "a10ecbe1be7a5f883d5d45d966e30dbc1beff5f21c55cec76cc21a2229116a9f",
			Amount:           int64(999637680),
			ValueBlindFactor: "ae0f46d1940f297c2dc3bbd82bf8ef6931a2431fbb05b3d3bc5df41af86ae808",
			AssetBlindingKey: "",
			TokenBlindingKey: "",
		},
		{
			Txid:             "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f",
			Vout:             uint32(1),
			Asset:            "ed6927df918c89b5e3d8b5062acab2c749a3291bb7451d4267c7daaf1b52ad0b",
			AssetBlindFactor: "0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8",
			Amount:           int64(700000000),
			ValueBlindFactor: "62e36e1f0fa4916b031648a6b6903083069fa587572a88b729250cde528cfd3b",
			AssetBlindingKey: "7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f",
			TokenBlindingKey: "7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f",
		},
	}
	// already set confidentialNonce in baseTxHex
	txoutList := []CfdBlindOutputData{}

	txHex, blinderList, err := CfdGoBlindRawTransactionAndGetBlinder(baseTxHex, txinList, txoutList, nil)
	// txHex, err := CfdGoBlindRawTransaction(baseTxHex, txinList, txoutList, &option)
	assert.NoError(t, err)
	if err == nil {
		txData, err := CfdGoGetConfidentialTxData(txHex)
		assert.NoError(t, err)
		assert.Equal(t, 64, len(txData.Txid))
		assert.Equal(t, 64, len(txData.Wtxid))
		assert.Equal(t, 64, len(txData.WitHash))
		assert.Equal(t, uint32(12589), txData.Size)
		assert.Equal(t, uint32(3604), txData.Vsize)
		assert.Equal(t, uint32(14413), txData.Weight)
		assert.Equal(t, uint32(2), txData.Version)
		assert.Equal(t, uint32(0), txData.LockTime)
		assert.Equal(t, 4, len(blinderList))
	}

	// unblind test
	if err == nil {
		asset, assetValue, aabf, avbf, token, tokenValue, tabf, tvbf, err := CfdGoUnblindIssuance(
			txHex, uint32(1),
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f",
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f")
		assert.NoError(t, err)
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
		assert.Equal(t, int64(600000000), assetValue)
		assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", aabf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", avbf)
		assert.Equal(t, "", token)
		assert.Equal(t, int64(0), tokenValue)
		assert.Equal(t, "", tabf)
		assert.Equal(t, "", tvbf)
		if len(blinderList) == 4 {
			assert.Equal(t, avbf, blinderList[0].ValueBlindFactor)
		}
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			txHex, uint32(0),
			"6a64f506be6e60b948987aa4d180d2ab05034a6a214146e06e28d4efe101d006")
		assert.NoError(t, err)
		assert.Equal(t, "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179", asset)
		assert.Equal(t, int64(999587680), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
		if len(blinderList) == 4 {
			assert.Equal(t, abf, blinderList[1].AssetBlindFactor)
			assert.Equal(t, vbf, blinderList[1].ValueBlindFactor)
		}
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			txHex, uint32(1),
			"94c85164605f589c4c572874f36b8301989c7fabfd44131297e95824d473681f")
		assert.NoError(t, err)
		assert.Equal(t, "ed6927df918c89b5e3d8b5062acab2c749a3291bb7451d4267c7daaf1b52ad0b", asset)
		assert.Equal(t, int64(700000000), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
		if len(blinderList) == 4 {
			assert.Equal(t, abf, blinderList[2].AssetBlindFactor)
			assert.Equal(t, vbf, blinderList[2].ValueBlindFactor)
		}
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			txHex, uint32(3),
			"0473d39aa6542e0c1bb6a2343b2319c3e92063dd019af4d47dbf50c460204f32")
		assert.NoError(t, err)
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
		assert.Equal(t, int64(600000000), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
		if len(blinderList) == 4 {
			assert.Equal(t, abf, blinderList[3].AssetBlindFactor)
			assert.Equal(t, vbf, blinderList[3].ValueBlindFactor)
		}
	}

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdBlindTransaction3(t *testing.T) {
	baseTxHex := "02000000000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100036a2e218bb512a3e65c80b59fec57aee428b7512276bcfa366c154dd7262994c817a914363273e2f851bda01e24cda41ba748b8d1f54cfe870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000002b29c3d0985a680ed6918d62a918d2df5fed13f9f72d4eb09003fe802a3b5954f016a0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000000c8000000000000"
	baseTxHex2 := "02000000000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100036a2e218bb512a3e65c80b59fec57aee428b7512276bcfa366c154dd7262994c817a914363273e2f851bda01e24cda41ba748b8d1f54cfe870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000002b29c3d0985a680ed6918d62a918d2df5fed13f9f72d4eb09003fe802a3b5954f17a91436e5e2e8732fe013bbec71c9d4866f882071f7e7870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000000c8000000000000"

	// option := NewCfdBlindTxOption()
	// option.MinimumRangeValue = int64(0)

	txinList := []CfdBlindInputData{
		{
			Txid:             "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Vout:             uint32(0),
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			AssetBlindFactor: "ebfecaae1665f32a3843ce65c42fb6e3f51136fa9d37274b810887923ae89339",
			Amount:           int64(100000200),
			ValueBlindFactor: "80af7bd339db43ad22c1fa9109eea6d617c8b87b91c4bde2b5fafcbb1902211a",
			AssetBlindingKey: "",
			TokenBlindingKey: "",
		},
	}
	// already set confidentialNonce in baseTxHex
	txoutList := []CfdBlindOutputData{}

	_, err := CfdGoBlindRawTransaction(baseTxHex2, txinList, txoutList, nil)
	assert.Error(t, err)
	if err != nil {
		assert.Equal(t, "CFD Error: message=[Amount is 0. Cannot specify 0 for amount if there is a valid confidential address.], code=[1]", err.Error())
	}

	txHex, err := CfdGoBlindRawTransaction(baseTxHex, txinList, txoutList, nil)
	// txHex, err := CfdGoBlindRawTransaction(baseTxHex, txinList, txoutList, &option)
	assert.NoError(t, err)
	if err == nil {
		txData, err := CfdGoGetConfidentialTxData(txHex)
		assert.NoError(t, err)
		assert.Equal(t, 64, len(txData.Txid))
		assert.Equal(t, 64, len(txData.Wtxid))
		assert.Equal(t, 64, len(txData.WitHash))
		assert.Equal(t, uint32(6246), txData.Size)
		assert.Equal(t, uint32(1802), txData.Vsize)
		assert.Equal(t, uint32(7206), txData.Weight)
		assert.Equal(t, uint32(2), txData.Version)
		assert.Equal(t, uint32(0), txData.LockTime)
		// assert.Equal(t, "", txHex)
	}

	baseTxHex3 := "02000000000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0000000000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100036a2e218bb512a3e65c80b59fec57aee428b7512276bcfa366c154dd7262994c817a914363273e2f851bda01e24cda41ba748b8d1f54cfe870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000000c8000000000000"
	txHex, err = CfdGoBlindRawTransaction(baseTxHex3, txinList, txoutList, nil)
	// txHex, err := CfdGoBlindRawTransaction(baseTxHex, txinList, txoutList, &option)
	assert.NoError(t, err)
	if err == nil {
		txData, err := CfdGoGetConfidentialTxData(txHex)
		assert.NoError(t, err)
		assert.Equal(t, 64, len(txData.Txid))
		assert.Equal(t, 64, len(txData.Wtxid))
		assert.Equal(t, 64, len(txData.WitHash))
		assert.Equal(t, uint32(3189), txData.Size)
		assert.Equal(t, uint32(962), txData.Vsize)
		assert.Equal(t, uint32(3846), txData.Weight)
		assert.Equal(t, uint32(2), txData.Version)
		assert.Equal(t, uint32(0), txData.LockTime)
		// assert.Equal(t, "", txHex)
	}

	pubkey := "03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6"
	privkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	txid := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
	vout := uint32(0)
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2wpkh)
	txHex2, err := CfdGoAddConfidentialTxSignWithPrivkey(txHex, txid, vout, hashType, pubkey, privkey, int64(0), "085e6338f9da8a7f754b8e2726894e04bee997c8ada526f3215de8bc151aa063d3", sigHashType, false, true)
	assert.NoError(t, err)
	// assert.Equal(t, "", txHex2)

	inputs := []CfdUtxo{
		{
			Txid:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Vout:            uint32(0),
			Amount:          int64(100000000),
			Asset:           "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:      "wpkh(030000000000000000000000000000000000000000000000000000000000000a01)",
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
		},
	}
	feeOption := NewCfdEstimateFeeOption()
	feeOption.EffectiveFeeRate = float64(0.1)
	feeOption.UseElements = true
	feeOption.FeeAsset = "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
	feeOption.RequireBlind = true
	feeOption.MinimumBits = 36
	totalFee, txFee, inputFee, err := CfdGoEstimateFeeUsingUtxo(baseTxHex3, inputs, feeOption)
	assert.NoError(t, err)
	assert.Equal(t, int64(99), totalFee)
	assert.Equal(t, int64(92), txFee)
	assert.Equal(t, int64(7), inputFee)
	totalFee, txFee, inputFee, err = CfdGoEstimateFeeUsingUtxo(txHex2, inputs, feeOption)
	assert.NoError(t, err)
	assert.Equal(t, int64(99), totalFee)
	assert.Equal(t, int64(92), txFee)
	assert.Equal(t, int64(7), inputFee)
	// feeOption.MinimumBits = 52
	//assert.Equal(t, int64(129), totalFee)
	//assert.Equal(t, int64(123), txFee)
	//assert.Equal(t, int64(6), inputFee)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdAddSignConfidentialTx(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	pubkey := "03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6"
	privkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	privkeyWifNetworkType := (int)(KCfdNetworkRegtest)
	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)
	txHex := ""
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2wpkh)
	isWitness := true
	if (hashType == (int)(KCfdP2pkh)) || (hashType == (int)(KCfdP2sh)) {
		isWitness = false
	}

	sighash, err := CfdGoCreateConfidentialSighash(
		kTxData, txid, vout, hashType,
		pubkey, "", int64(13000000000000), "", sigHashType, false)
	assert.NoError(t, err)
	assert.Equal(t, "c90939ef311f105806b401bcfa494921b8df297195fc125ebbd91a018c4066b9", sighash)

	signature, err := CfdGoCalculateEcSignature(
		sighash, "", privkey, privkeyWifNetworkType, true)
	assert.NoError(t, err)
	assert.Equal(t, "0268633a57723c6612ef217c49bdf804c632a14be2967c76afec4fd5781ad4c2131f358b2381a039c8c502959c64fbfeccf287be7dae710b4446968553aefbea", signature)

	isVerify, err := CfdGoVerifyEcSignature(sighash, pubkey, signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add signature
	txHex, err = CfdGoAddConfidentialTxDerSign(
		kTxData, txid, vout, isWitness, signature, sigHashType, false, true)
	assert.NoError(t, err)

	// add pubkey
	txHex, err = CfdGoAddConfidentialTxSign(
		txHex, txid, vout, isWitness, pubkey, false)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac0000000000000247304402200268633a57723c6612ef217c49bdf804c632a14be2967c76afec4fd5781ad4c20220131f358b2381a039c8c502959c64fbfeccf287be7dae710b4446968553aefbea012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d600000000000000000000000000", txHex)

	count, err := CfdGoGetConfidentialTxInWitnessCount(txHex, 0)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), count)

	stackData, err := CfdGoGetConfidentialTxInWitness(txHex, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, stackData)

	isVerify, err = CfdGoVerifySignature(int(KCfdNetworkLiquidv1), txHex, signature, hashType, pubkey, "", txid, vout, sigHashType, false, int64(13000000000000), "")
	assert.NoError(t, err)
	assert.True(t, isVerify)

	isVerify, err = CfdGoVerifyTxSign(int(KCfdNetworkLiquidv1), txHex, txid, vout, "ert1qav7q64dhpx9y4m62rrhpa67trmvjf2ptxfddld", int(KCfdP2wpkhAddress), "", int64(13000000000000), "")
	assert.NoError(t, err)
	assert.True(t, isVerify)

	isVerify, reason, err := CfdGoVerifyTxSignReason(int(KCfdNetworkLiquidv1), txHex, txid, vout, "ert1qs58jzsgjsteydejyhy32p2v2vm8llh9uns6d93", int(KCfdP2wpkhAddress), "", int64(13000000000000), "")
	assert.NoError(t, err)
	assert.False(t, isVerify)
	assert.Equal(t, "Unmatch locking script.", reason)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdAddSignConfidentialTxPkh(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	pubkey := "03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6"
	privkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	privkeyWifNetworkType := (int)(KCfdNetworkRegtest)
	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)
	txHex := ""
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2pkh)
	isWitness := true
	if (hashType == (int)(KCfdP2pkh)) || (hashType == (int)(KCfdP2sh)) {
		isWitness = false
	}

	sighash, err := CfdGoCreateConfidentialSighash(
		kTxData, txid, vout, hashType,
		pubkey, "", int64(13000000000000), "", sigHashType, false)
	assert.NoError(t, err)
	assert.Equal(t, "e955c2f4fa5077cd0ac724e2f626914c8286896eca30fcde405e051ea3443527", sighash)

	signature, err := CfdGoCalculateEcSignature(
		sighash, "", privkey, privkeyWifNetworkType, true)
	assert.NoError(t, err)
	assert.Equal(t, "4c5f91208f79fe7c74a2b5d88573b6150ac1d4f18cef8051dff1260a37c272d81b97ecd5f83d16cfc3cb39d9bdd21d1f77665135c4230a3157d2045450528ff5", signature)

	// add signature
	txHex, err = CfdGoAddConfidentialTxDerSign(
		kTxData, txid, vout, isWitness, signature, sigHashType, false, true)
	assert.NoError(t, err)

	// add pubkey
	txHex, err = CfdGoAddConfidentialTxSign(
		txHex, txid, vout, isWitness, pubkey, false)
	assert.NoError(t, err)
	assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a157000000006a47304402204c5f91208f79fe7c74a2b5d88573b6150ac1d4f18cef8051dff1260a37c272d802201b97ecd5f83d16cfc3cb39d9bdd21d1f77665135c4230a3157d2045450528ff5012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", txHex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoAddConfidentialTxUnlockingScript_P2PKH(t *testing.T) {
	// txHex comes from TestCfdCreateRawTransaction result data
	const txHex string = "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000"
	// unlockingScript comes from TestCfdParseScript PKH UnlockingScript source data
	const unlockingScript string = "47304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d0121038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301"
	txHexByInput, err := CfdGoAddConfidentialTxUnlockingScript(txHex, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", (uint32)(0), false, unlockingScript, false)
	assert.NoError(t, err)
	assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b06174000000006a47304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d0121038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000", txHexByInput)
	// check adding script sig by index func
	txHexByIndex, err := CfdGoAddConfidentialTxUnlockingScriptByIndex(txHex, (uint32)(0), false, unlockingScript, false)
	assert.NoError(t, err)
	assert.Equal(t, txHexByInput, txHexByIndex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoAddConfidentialTxUnlockingScript_P2MS(t *testing.T) {
	// txHex comes from TestCfdCreateRawTransaction result data
	const txHex string = "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000"
	// unlockingScript comes from TestCfdCreateMultisigScriptSig
	const unlockingScript string = "00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae"
	txHexByInput, err := CfdGoAddConfidentialTxUnlockingScript(txHex, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", (uint32)(0), false, unlockingScript, false)
	assert.NoError(t, err)
	assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b0617400000000d900473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000", txHexByInput)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoAddConfidentialTxUnlockingScript_P2SHP2WPKH(t *testing.T) {
	// txHex comes from TestCfdGoAddConfidentialTxUnlockingScript/Add_P2MS_UnlockingScript result data
	const txHex string = "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b0617400000000d900473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000"

	// unlockingScript comes from TestCfdCreateMultisigScriptSig
	const scriptSig string = "0020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f"
	// Append ScriptSig
	txHexResult, err := CfdGoAddConfidentialTxUnlockingScript(txHex, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", (uint32)(0), false, scriptSig, true)
	assert.NoError(t, err)
	assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b0617400000000220020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482fffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000", txHexResult)

	// dummy witness signatrues
	const witnessStackScript string = "00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae"
	// Append txinwitness
	txHexResult, err = CfdGoAddConfidentialTxUnlockingScript(txHexResult, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", (uint32)(0), true, witnessStackScript, true)
	assert.NoError(t, err)
	assert.Equal(t, "020000000102bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b0617400000000220020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482fffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a1200000000000000000040100473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae0000000000000000000000", txHexResult)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdAddMultisigSignConfidentialTx(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	privkey1 := "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	privkey2 := "cQUTZ8VbWNYBEtrB7xwe41kqiKMQPRZshTvBHmkoJGaUfmS5pxzR"
	networkType := (int)(KCfdNetworkRegtest)
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2sh)

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, multisigScript, _, err := CfdGoCreateMultisigScript(
		networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "2MtG4TZaMXCNdEyUYAyJDraQRFwYC5j4S9U", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)

	// sign multisig
	multiSignHandle, err := CfdGoInitializeMultisigSign()
	assert.NoError(t, err)
	if err == nil {
		satoshi := int64(13000000000000)
		sighash, err := CfdGoCreateConfidentialSighash(kTxData, txid, vout,
			hashType, "", multisigScript, satoshi, "", sigHashType, false)
		assert.NoError(t, err)
		assert.Equal(t, "64878cbcd5c1805659d0747097cbf4b9ec5c187ebd80afa996c8fc95bd650b70", sighash)

		// user1
		signature1, err := CfdGoCalculateEcSignature(
			sighash, "", privkey1, networkType, true)
		assert.NoError(t, err)

		err = CfdGoAddMultisigSignDataToDer(
			multiSignHandle, signature1, sigHashType, false, pubkey1)
		assert.NoError(t, err)

		// user2
		signature2, err := CfdGoCalculateEcSignature(
			sighash, "", privkey2, networkType, true)
		assert.NoError(t, err)

		derSignature2, err := CfdGoEncodeSignatureByDer(signature2, sigHashType, false)
		assert.NoError(t, err)

		err = CfdGoAddMultisigSignData(multiSignHandle, derSignature2, pubkey2)
		assert.NoError(t, err)

		// generate
		txHex, err := CfdGoFinalizeElementsMultisigSign(
			multiSignHandle, kTxData, txid, vout, hashType, "", multisigScript, true)
		assert.NoError(t, err)
		assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a15700000000d90047304402206fc4cc7e489208a2f4d24f5d35466debab2ce7aa34b5d00e0a9426c9d63529cf02202ec744939ef0b4b629c7d87bc2d017714b52bb86dccb0fd0f10148f62b7a09ba01473044022073ea24720b24c736bcb305a5de2fd8117ca2f0a85d7da378fae5b90dc361d227022004c0088bf1b73a56ae5ec407cf9c330d7206ffbcd0c9bb1c72661726fd4990390147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", txHex)

		err = CfdGoFreeMultisigSignHandle(multiSignHandle)
		assert.NoError(t, err)

		// verify der encoded signature
		isVerify, err := CfdGoVerifySignature(int(KCfdNetworkLiquidv1), kTxData, derSignature2, hashType, pubkey2, multisigScript, txid, vout, sigHashType, false, satoshi, "")
		assert.NoError(t, err)
		assert.True(t, isVerify)
	}

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdAddMultisigSignConfidentialTxWitness(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	privkey1 := "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	privkey2 := "cQUTZ8VbWNYBEtrB7xwe41kqiKMQPRZshTvBHmkoJGaUfmS5pxzR"
	networkType := (int)(KCfdNetworkRegtest)
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2wsh)

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, scriptsig, multisigScript, err := CfdGoCreateMultisigScript(
		networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "bcrt1qdenhgyqf6yzkwjshlph8xsesxrh2qcpuqg8myh4q33h6m4kz7cksgwt0dh", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)
	assert.Equal(t, "", scriptsig)

	// sign multisig
	multiSignHandle, err := CfdGoInitializeMultisigSign()
	assert.NoError(t, err)
	if err == nil {
		satoshi := int64(13000000000000)
		sighash, err := CfdGoCreateConfidentialSighash(kTxData, txid, vout,
			hashType, "", multisigScript, satoshi, "", sigHashType, false)
		assert.NoError(t, err)
		assert.Equal(t, "d17f091203341a0d1f0101c6d010a40ce0f3cef8a09b2b605b77bb6cfc23359f", sighash)

		// user1
		signature1, err := CfdGoCalculateEcSignature(
			sighash, "", privkey1, networkType, true)
		assert.NoError(t, err)

		err = CfdGoAddMultisigSignDataToDer(
			multiSignHandle, signature1, sigHashType, false, pubkey1)
		assert.NoError(t, err)

		// user2
		signature2, err := CfdGoCalculateEcSignature(
			sighash, "", privkey2, networkType, true)
		assert.NoError(t, err)

		err = CfdGoAddMultisigSignDataToDer(
			multiSignHandle, signature2, sigHashType, false, pubkey2)
		assert.NoError(t, err)

		// generate
		txHex, err := CfdGoFinalizeElementsMultisigSign(
			multiSignHandle, kTxData, txid, vout, hashType, multisigScript, "", true)
		assert.NoError(t, err)
		assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000000004004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae00000000000000000000000000", txHex)

		err = CfdGoFreeMultisigSignHandle(multiSignHandle)
		assert.NoError(t, err)
	}

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdAddMultisigSignConfidentialTxManual(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	privkey1 := "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	privkey2 := "cQUTZ8VbWNYBEtrB7xwe41kqiKMQPRZshTvBHmkoJGaUfmS5pxzR"
	networkType := (int)(KCfdNetworkRegtest)
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2wsh)

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, scriptsig, multisigScript, err := CfdGoCreateMultisigScript(
		networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "bcrt1qdenhgyqf6yzkwjshlph8xsesxrh2qcpuqg8myh4q33h6m4kz7cksgwt0dh", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)
	assert.Equal(t, "", scriptsig)

	satoshi := int64(13000000000000)
	sighash, err := CfdGoCreateConfidentialSighash(kTxData, txid, vout,
		hashType, "", multisigScript, satoshi, "", sigHashType, false)
	assert.NoError(t, err)
	assert.Equal(t, "d17f091203341a0d1f0101c6d010a40ce0f3cef8a09b2b605b77bb6cfc23359f", sighash)

	// user1
	signature1, err := CfdGoCalculateEcSignature(
		sighash, "", privkey1, networkType, true)
	assert.NoError(t, err)

	// user2
	signature2, err := CfdGoCalculateEcSignature(
		sighash, "", privkey2, networkType, true)
	assert.NoError(t, err)

	derSignature2, err := CfdGoEncodeSignatureByDer(signature2, sigHashType, false)
	assert.NoError(t, err)
	assert.Equal(t, "30440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a7901", derSignature2)

	signDataList := []CfdSignParameter{
		{
			Data:                "",
			IsDerEncode:         false,
			SighashType:         sigHashType,
			SighashAnyoneCanPay: false,
		},
		{
			Data:                derSignature2,
			IsDerEncode:         false,
			SighashType:         sigHashType,
			SighashAnyoneCanPay: false,
		},
		{
			Data:                signature1,
			IsDerEncode:         true,
			SighashType:         sigHashType,
			SighashAnyoneCanPay: false,
		},
	}
	txHex, err := CfdGoAddConfidentialTxScriptHashSign(kTxData, txid, vout, hashType, signDataList, multisigScript)

	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000000004004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae00000000000000000000000000", txHex)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdSetElementsMultisigScriptSig(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	// privkey1 := "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	// privkey2 := "cQUTZ8VbWNYBEtrB7xwe41kqiKMQPRZshTvBHmkoJGaUfmS5pxzR"
	networkType := (int)(KCfdNetworkRegtest)
	hashType := (int)(KCfdP2wsh)

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, scriptsig, multisigScript, err := CfdGoCreateMultisigScript(
		networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "bcrt1qdenhgyqf6yzkwjshlph8xsesxrh2qcpuqg8myh4q33h6m4kz7cksgwt0dh", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)
	assert.Equal(t, "", scriptsig)

	scriptsigs := "004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae"

	// sign multisig
	txHex, err := CfdGoSetElementsMultisigScriptSig(kTxData, txid, vout, scriptsigs, hashType)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000000004004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae00000000000000000000000000", txHex)

	// p2sh-p2wsh
	txHex, err = CfdGoSetElementsMultisigScriptSig(kTxData, txid, vout, scriptsigs, (int)(KCfdP2shP2wsh))
	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a15700000000232200206e67741009d105674a17f86e73433030eea0603c020fb25ea08c6fadd6c2f62dffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000000004004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae00000000000000000000000000", txHex)

	// p2sh
	txHex, err = CfdGoSetElementsMultisigScriptSig(kTxData, txid, vout, scriptsigs, (int)(KCfdP2sh))
	assert.NoError(t, err)
	assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a15700000000d9004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", txHex)

	// error check
	_, err = CfdGoSetElementsMultisigScriptSig(kTxData, txid, vout, "", hashType)
	assert.Error(t, err)
	if err != nil {
		assert.Equal(t, "CFD Error: message=[Invalid scriptsig array length.], code=[1]", err.Error())
	}
	_, err = CfdGoSetElementsMultisigScriptSig(kTxData, txid, vout, "0047522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", hashType)
	assert.Error(t, err)
	if err != nil {
		assert.Equal(t, "CFD Error: message=[Invalid scriptsig array length.], code=[1]", err.Error())
	}
	_, err = CfdGoSetElementsMultisigScriptSig(kTxData, txid, vout, scriptsigs, (int)(KCfdP2wpkh))
	assert.Error(t, err)
	if err != nil {
		assert.Equal(t, "CFD Error: message=[Unsupported hashType.], code=[1]", err.Error())
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdAddSignConfidentialTxOpCode(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	networkType := (int)(KCfdNetworkRegtest)
	hashType := (int)(KCfdP2sh)
	isWitness := true
	if (hashType == (int)(KCfdP2pkh)) || (hashType == (int)(KCfdP2sh)) {
		isWitness = false
	}

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, multisigScript, _, err := CfdGoCreateMultisigScript(
		networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "2MtG4TZaMXCNdEyUYAyJDraQRFwYC5j4S9U", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)

	// add multisig sign (manual)
	txHex := kTxData
	txHex, err = CfdGoAddConfidentialTxSign(
		txHex, txid, vout, isWitness, "OP_0", true)
	assert.NoError(t, err)

	txHex, err = CfdGoAddConfidentialTxSign(
		txHex, txid, vout, isWitness, "304402206fc4cc7e489208a2f4d24f5d35466debab2ce7aa34b5d00e0a9426c9d63529cf02202ec744939ef0b4b629c7d87bc2d017714b52bb86dccb0fd0f10148f62b7a09ba01", false)
	assert.NoError(t, err)

	txHex, err = CfdGoAddConfidentialTxSign(
		txHex, txid, vout, isWitness, "3044022073ea24720b24c736bcb305a5de2fd8117ca2f0a85d7da378fae5b90dc361d227022004c0088bf1b73a56ae5ec407cf9c330d7206ffbcd0c9bb1c72661726fd49903901", false)
	assert.NoError(t, err)

	txHex, err = CfdGoAddConfidentialTxSign(
		txHex, txid, vout, isWitness, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", false)
	assert.NoError(t, err)

	assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a15700000000d90047304402206fc4cc7e489208a2f4d24f5d35466debab2ce7aa34b5d00e0a9426c9d63529cf02202ec744939ef0b4b629c7d87bc2d017714b52bb86dccb0fd0f10148f62b7a09ba01473044022073ea24720b24c736bcb305a5de2fd8117ca2f0a85d7da378fae5b90dc361d227022004c0088bf1b73a56ae5ec407cf9c330d7206ffbcd0c9bb1c72661726fd4990390147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", txHex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdConfidentialAddress(t *testing.T) {
	kAddress := "Q7wegLt2qMGhm28vch6VTzvpzs8KXvs4X7"
	kConfidentialKey := "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
	kConfidentialAddr := "VTpvKKc1SNmLG4H8CnR1fGJdHdyWGEQEvdP9gfeneJR7n81S5kiwNtgF7vrZjC8mp63HvwxM81nEbTxU"
	kNetworkType := (int)(KCfdNetworkLiquidv1)

	confidentialAddr, err := CfdGoCreateConfidentialAddress(kAddress, kConfidentialKey)
	assert.NoError(t, err)
	assert.Equal(t, kConfidentialAddr, confidentialAddr)

	addr, key, netType, err := CfdGoParseConfidentialAddress(confidentialAddr)
	assert.NoError(t, err)
	assert.Equal(t, kAddress, addr)
	assert.Equal(t, kConfidentialKey, key)
	assert.Equal(t, kNetworkType, netType)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdCoinSelection(t *testing.T) {
	assets, utxos := GetCoinSelectionTestData()
	targets := []CfdTargetAmount{
		{
			Amount: int64(115800000),
			Asset:  assets[0],
		},
		{
			Amount: int64(347180040),
			Asset:  assets[1],
		},
		{
			Amount: int64(37654100),
			Asset:  assets[2],
		},
	}

	option := NewCfdCoinSelectionOption()
	option.TxFeeAmount = int64(2000)
	option.FeeAsset = assets[0]

	selectUtxos, totalAmounts, utxoFee, err := CfdGoCoinSelection(utxos, targets, option)
	assert.NoError(t, err)
	assert.Equal(t, int64(9200), utxoFee)
	assert.Equal(t, 5, len(selectUtxos))
	assert.Equal(t, 3, len(totalAmounts))

	if len(selectUtxos) == 5 {
		assert.Equal(t, utxos[8].Amount, selectUtxos[0].Amount)
		assert.Equal(t, utxos[7].Amount, selectUtxos[1].Amount)
		assert.Equal(t, utxos[10].Amount, selectUtxos[2].Amount)
		assert.Equal(t, utxos[1].Amount, selectUtxos[3].Amount)
		assert.Equal(t, utxos[3].Amount, selectUtxos[4].Amount)
	}
	if len(totalAmounts) == 3 {
		assert.Equal(t, int64(117187500), totalAmounts[0].Amount)
		assert.Equal(t, targets[0].Asset, totalAmounts[0].Asset)
		assert.Equal(t, int64(347180050), totalAmounts[1].Amount)
		assert.Equal(t, targets[1].Asset, totalAmounts[1].Asset)
		assert.Equal(t, int64(37654200), totalAmounts[2].Amount)
		assert.Equal(t, targets[2].Asset, totalAmounts[2].Asset)
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdCoinSelectionUnuseFee(t *testing.T) {
	assets, utxos := GetCoinSelectionTestData()
	targets := []CfdTargetAmount{
		{
			Amount: int64(115800000),
			Asset:  assets[0],
		},
		{
			Amount: int64(347180040),
			Asset:  assets[1],
		},
		{
			Amount: int64(37654100),
			Asset:  assets[2],
		},
	}

	option := NewCfdCoinSelectionOption()
	option.EffectiveFeeRate = 0
	option.LongTermFeeRate = 0
	option.DustFeeRate = 0
	option.KnapsackMinChange = 0
	option.FeeAsset = assets[0]

	selectUtxos, totalAmounts, utxoFee, err := CfdGoCoinSelection(utxos, targets, option)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), utxoFee)
	assert.Equal(t, 5, len(selectUtxos))
	assert.Equal(t, 3, len(totalAmounts))

	if len(selectUtxos) == 5 {
		assert.Equal(t, utxos[1].Amount, selectUtxos[0].Amount)
		assert.Equal(t, utxos[3].Amount, selectUtxos[1].Amount)
		assert.Equal(t, utxos[8].Amount, selectUtxos[2].Amount)
		assert.Equal(t, utxos[7].Amount, selectUtxos[3].Amount)
		assert.Equal(t, utxos[10].Amount, selectUtxos[4].Amount)
	}
	if len(totalAmounts) == 3 {
		assert.Equal(t, int64(117187500), totalAmounts[0].Amount)
		assert.Equal(t, targets[0].Asset, totalAmounts[0].Asset)
		assert.Equal(t, int64(347180050), totalAmounts[1].Amount)
		assert.Equal(t, targets[1].Asset, totalAmounts[1].Asset)
		assert.Equal(t, int64(37654200), totalAmounts[2].Amount)
		assert.Equal(t, targets[2].Asset, totalAmounts[2].Asset)
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func GetCoinSelectionTestData() (assets []string, utxos []CfdUtxo) {
	// mnemonic: token hair neglect leader furnace obtain sadness tool you father paddle skate remain carry impact dinosaur correct essay rent illness predict mercy exist ring
	// xpriv: xprv9s21ZrQH143K4QXrTfC9L43GKCuLcDiBCWjyVqfZUTzoPJWUstD4HTJKGz1U5jAGZzKshcX6cCyZ1ZdxSUQLz92pEZWEGwxa39ks2vhTsfA
	// derive: 44h/0h/0h/0/*
	assets = []string{
		"aa00000000000000000000000000000000000000000000000000000000000000",
		"bb00000000000000000000000000000000000000000000000000000000000000",
		"cc00000000000000000000000000000000000000000000000000000000000000",
	}
	utxos = []CfdUtxo{
		{
			Txid:       "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
			Vout:       uint32(0),
			Amount:     int64(312500000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(0329165ca5832de80305c92d4b1415f10340d267ba05cbffcfe02d386dc5020e4d))",
		},
		{
			Txid:       "30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a",
			Vout:       uint32(0),
			Amount:     int64(78125000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(022db3cb17d98db6cd8d513f88b095dbe80ef9e57acd5b1d9e8bd7f24618079451))",
		},
		{
			Txid:       "9e1ead91c432889cb478237da974dd1e9009c9e22694fd1e3999c40a1ef59b0a",
			Vout:       uint32(0),
			Amount:     int64(1250000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(032d04e0b1474a82ad68c0ef37e1a7cf6c75ef01b22c00882e8e4e127a942823a1))",
		},
		{
			Txid:       "8f4af7ee42e62a3d32f25ca56f618fb2f5df3d4c3a9c59e2c3646c5535a3d40a",
			Vout:       uint32(0),
			Amount:     int64(39062500),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(03a7fb569db921abf70f1b6b9ad9ac863196deecd99d606b139bba7d740d1cc5bf))",
		},
		{
			Txid:       "4d97d0119b90421818bff4ec9033e5199199b53358f56390cb20f8148e76f40a",
			Vout:       uint32(0),
			Amount:     int64(156250000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(02df74fc8124ff6f3982e90afb318f3e955b10f58c4c6014b3a767e16160f811d9))",
		},
		{
			Txid:       "b9720ed2265a4ced42425bffdb4ef90a473b4106811a802fce53f7c57487fa0b",
			Vout:       uint32(0),
			Amount:     int64(2500000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(029222484db385d268a2a4604ea40fd2228401061f741ad9da8c907ba9df29c2d3))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000b01",
			Vout:       uint32(0),
			Amount:     int64(26918400),
			Asset:      assets[1],
			Descriptor: "sh(wpkh(038f9011753b74fa0134d4b64a1491f99e0c4c0e16da616627c1f6a93c5e7555c0))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000b02",
			Vout:       uint32(0),
			Amount:     int64(750000),
			Asset:      assets[1],
			Descriptor: "sh(wpkh(0302f567f9671b570dbcf179f3ba5f2fb381ea7e8db6ab9e0968c07d40325c3fcd))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000b03",
			Vout:       uint32(0),
			Amount:     int64(346430050),
			Asset:      assets[1],
			Descriptor: "sh(wpkh(034ff60d8fb18ae88019f6f905cfaa0e1841f75edfa1f3c0a5bfaf77b796243901))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000b04",
			Vout:       uint32(0),
			Amount:     int64(18476350),
			Asset:      assets[1],
			Descriptor: "sh(wpkh(029f2126cd8b55af7cc3cee8154c44de7cb7cb214809f81144d6b323d9c7a3993e))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000c01",
			Vout:       uint32(0),
			Amount:     int64(37654200),
			Asset:      assets[2],
			Descriptor: "sh(wpkh(02f1d2c28388e3fd609ff383f022b615f1cd8a1931632706f63bfb6e253875ca03))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000c02",
			Vout:       uint32(0),
			Amount:     int64(127030000),
			Asset:      assets[2],
			Descriptor: "sh(wpkh(02cca4482dc1e7d54c879c0d9069e3d66c3bf91b2bf46eddc74f18d76c659dfd10))",
		},
	}

	return
}

func GetEstimateFeeTestData() (assets []string, inputs []CfdEstimateFeeInput) {
	// mnemonic: token hair neglect leader furnace obtain sadness tool you father paddle skate remain carry impact dinosaur correct essay rent illness predict mercy exist ring
	// xpriv: xprv9s21ZrQH143K4QXrTfC9L43GKCuLcDiBCWjyVqfZUTzoPJWUstD4HTJKGz1U5jAGZzKshcX6cCyZ1ZdxSUQLz92pEZWEGwxa39ks2vhTsfA
	// derive: 44h/0h/0h/0/*
	assets = []string{
		"aa00000000000000000000000000000000000000000000000000000000000000",
		"bb00000000000000000000000000000000000000000000000000000000000000",
	}
	inputs = []CfdEstimateFeeInput{
		{
			Utxo: CfdUtxo{
				Txid:       "aa00000000000000000000000000000000000000000000000000000000000001",
				Vout:       uint32(0),
				Amount:     int64(100000000),
				Asset:      assets[0],
				Descriptor: "pkh(0329165ca5832de80305c92d4b1415f10340d267ba05cbffcfe02d386dc5020e4d)",
			},
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
		},
		{
			Utxo: CfdUtxo{
				Txid:       "aa00000000000000000000000000000000000000000000000000000000000002",
				Vout:       uint32(0),
				Amount:     int64(200000000),
				Asset:      assets[0],
				Descriptor: "sh(multi(1,022db3cb17d98db6cd8d513f88b095dbe80ef9e57acd5b1d9e8bd7f24618079451,032d04e0b1474a82ad68c0ef37e1a7cf6c75ef01b22c00882e8e4e127a942823a1))",
			},
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
		},
		{
			Utxo: CfdUtxo{
				Txid:       "bb00000000000000000000000000000000000000000000000000000000000001",
				Vout:       uint32(1),
				Amount:     int64(30000000),
				Asset:      assets[1],
				Descriptor: "wpkh(03a7fb569db921abf70f1b6b9ad9ac863196deecd99d606b139bba7d740d1cc5bf)",
			},
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
		},
		{
			Utxo: CfdUtxo{
				Txid:       "bb00000000000000000000000000000000000000000000000000000000000002",
				Vout:       uint32(2),
				Amount:     int64(40000000),
				Asset:      assets[1],
				Descriptor: "wsh(multi(1,02df74fc8124ff6f3982e90afb318f3e955b10f58c4c6014b3a767e16160f811d9,029222484db385d268a2a4604ea40fd2228401061f741ad9da8c907ba9df29c2d3))",
			},
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
		},
	}

	return
}

func TestCfdGoVerifyConfidentialTxSignature(t *testing.T) {

	t.Run("PKHSignature", func(t *testing.T) {
		txHex := "02000000000117c10bbfcd4e89f6c33864ed627aa113f249343f4b2bbe6e86dcc725e0d06cfc010000006a473044022038527c96efaaa29b862c8fe8aa4e96602b03035505ebe1f166dd8b9f3731b7b502207e75d937ca1bb2e2f4208618051eb8aad02ad88a71477d7a6e7ec257f72cb6500121036b70f6598ee5c00ad068c9b86c7a1d5c433767a46db3bc3f9d53417171db1782fdffffff0301bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000001dcd6500001976a91479975e7d3775b748cbcd5500804518280a2ebbae88ac01bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000001dcccde80017a9141cd92b989652fbc4c2a92eb1d56456d0ef17d4158701bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000000000971800000a000000"
		txid := "fc6cd0e025c7dc866ebe2b4b3f3449f213a17a62ed6438c3f6894ecdbf0bc117"
		vout := uint32(1)

		// prepare pkh signature
		pubkey, _, wif, err := CfdGoCreateKeyPair(true, (int)(KCfdNetworkRegtest))
		assert.NoError(t, err)
		sighashType := (int)(KCfdSigHashAll)
		satoshiValue := int64(1000000000)
		sighash, err := CfdGoCreateConfidentialSighash(txHex, txid, vout,
			(int)(KCfdP2pkh), pubkey, "", satoshiValue, "", sighashType, false)
		assert.NoError(t, err)
		signature, err := CfdGoCalculateEcSignature(sighash, "", wif, (int)(KCfdNetworkRegtest), true)
		assert.NoError(t, err)

		// check signature
		result, err := CfdGoVerifyConfidentialTxSignature(txHex, signature, pubkey, "", txid, vout, sighashType, false, satoshiValue, "", (int)(KCfdWitnessVersionNone))
		assert.NoError(t, err)
		assert.True(t, result)
		// check signature
		result, err = CfdGoVerifyConfidentialTxSignatureByIndex(txHex, signature, pubkey, "", 0, sighashType, false, satoshiValue, "", (int)(KCfdWitnessVersionNone))
		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("PKHSignatureFail", func(t *testing.T) {
		txHex := "02000000000117c10bbfcd4e89f6c33864ed627aa113f249343f4b2bbe6e86dcc725e0d06cfc010000006a473044022038527c96efaaa29b862c8fe8aa4e96602b03035505ebe1f166dd8b9f3731b7b502207e75d937ca1bb2e2f4208618051eb8aad02ad88a71477d7a6e7ec257f72cb6500121036b70f6598ee5c00ad068c9b86c7a1d5c433767a46db3bc3f9d53417171db1782fdffffff0301bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000001dcd6500001976a91479975e7d3775b748cbcd5500804518280a2ebbae88ac01bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000001dcccde80017a9141cd92b989652fbc4c2a92eb1d56456d0ef17d4158701bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000000000971800000a000000"
		txid := "fc6cd0e025c7dc866ebe2b4b3f3449f213a17a62ed6438c3f6894ecdbf0bc117"
		vout := uint32(1)

		// prepare pkh signature
		pubkey, _, wif, err := CfdGoCreateKeyPair(true, (int)(KCfdNetworkRegtest))
		assert.NoError(t, err)
		sighashType := (int)(KCfdSigHashAll)
		satoshiValue := int64(1000000000)
		sighash, err := CfdGoCreateConfidentialSighash(txHex, txid, vout,
			(int)(KCfdP2pkh), pubkey, "", satoshiValue, "", sighashType, false)
		assert.NoError(t, err)
		signature, err := CfdGoCalculateEcSignature(sighash, "", wif, (int)(KCfdNetworkRegtest), true)
		assert.NoError(t, err)

		// check signature
		invalidSighashType := (int)(KCfdSigHashSingle)
		result, err := CfdGoVerifyConfidentialTxSignature(txHex, signature, pubkey, "", txid, vout, invalidSighashType, false, satoshiValue, "", (int)(KCfdWitnessVersionNone))
		assert.NoError(t, err)
		assert.False(t, result)
		// check signature
		result, err = CfdGoVerifyConfidentialTxSignatureByIndex(txHex, signature, pubkey, "", 0, invalidSighashType, false, satoshiValue, "", (int)(KCfdWitnessVersionNone))
		assert.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("WSHSignature", func(t *testing.T) {
		txHex := "02000000010117c10bbfcd4e89f6c33864ed627aa113f249343f4b2bbe6e86dcc725e0d06cfc010000006a473044022038527c96efaaa29b862c8fe8aa4e96602b03035505ebe1f166dd8b9f3731b7b502207e75d937ca1bb2e2f4208618051eb8aad02ad88a71477d7a6e7ec257f72cb6500121036b70f6598ee5c00ad068c9b86c7a1d5c433767a46db3bc3f9d53417171db1782fdffffff030bc7b2b8da0c30f37b12580e0bd092bfbe16e28494fe30feab1769ab4135d30a7609c8e4c3012d90840dbed48eeebc253399645119c01125488640f415285e6e7663031651fe4267cf54e606a83e4c741a01df124d4eb915ae37ad9d5191661d74310b1976a91479975e7d3775b748cbcd5500804518280a2ebbae88ac0b8f78a97d70ad5799c1ef2ca5f7f553ec30fdc87392eb2b5a9acc42d72f5900250978d7a93a301c65b0759c8e7f4b4424ff2a4c124ee2467b08e266423faa3afef30249a8537d641e728c2192f66433e125041341b36fa3e3cde5578ad1acb9a3944b17a9141cd92b989652fbc4c2a92eb1d56456d0ef17d4158701bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000000000971800000a0000000000000043010001cd72e3aa85cc53ce42edd91e03a6b4d3cd6b08d2125f019639f0ae6ee29e7f8539232c60e68020ab948d95e5c70da679309e8a511a1a0ef65c7b5e5f4dfb83c7fd4d0b60230000000000000001c39d00a796090bd9872e87a9d5f06b5c73c4fe64104a59c25536f90813b311c90de520f63a57875a2e9b6111f41f5fb7b4a253c76027af35fbcf7ddb9e5688ebefb04948f349e48e2ef4cd73b17f1d5786822222f2a1e5367bd1d39b139283800bfc4b7d50ce927469541151be53b3518b0fa1e9acb8089072976b1d659e8136c666f0b57cec51775ccd40998ee57ace137e25ee7e066d9d434c0e54304913019db87855de47f7f1e974578dfedb95a92048fafe0dca541bd917ea22d9c02fd58fafc8ee35f016b4b1ebf0051a314038201163b3fc6fa09b7ac0bf45474b216f8e152433433193b6e5db6da465ddd5c0e7d23b6a2e153998e0e936539aa3ce4f1ed448157dff1f420c404c019ec5e86ab18a9b859cc3165a7f104f3a7a9abb6835a62834750f110730e7d16de16cbb7f6607fc4ae04de5baec980e3137766c23568f8bb03473d3e043d3a8d8da0a2613bf27d0ce388ed44b8e1a217b2ef5193d19fb6b943c1b8a1bebfb02b9cea87fec0edbe03ee63a3a1168c53456af1fed9fe7707b2fb58159922cb84e1e28a29d26e036c12c91666096d556eefada060c530a28837f37a456847a26fcee92092837c14144ac3e1f3a84763e40cced0d77dcfe76f537825e08d2441d612d5e80eef617ffa6b96e30825d8905bef96dd4da8457f8d43e3f3c0294443c0b5a5a2a1b2f32f6402873c7de17276ec66b0fddf246fcb305e88a09c45e1c1322d5e152216d09a02654e83b503454dfeacd52129b4956ad300a9d52ca9f955f1babb56a1a676f243ce7ef69cacbfb23cb71907a6b8ff1a42c4769c5298d5fd5027e1c352a582231a5323b02da24ba5c2df5e125554ed0ee1cb5e9e65eda5c683469d264c9f0adbfc5fcbb3459da30ef31dd7cb32a9d5d6d2b412db81df3345f09065151b0190ec07ff0c5573d4c783be1f8aeb27d8042387352d62e808b24b834fef27d1c986da5207e5c9645026bff40577fc167b321fa17b31872bc0f796dc834f66f9302a4ce505f3f1e865a0ba9be615efe25dbdb2c3b61bc03206e6891469ce11c4065a2fcf03cb436d9182d66ce452038ac5f4fd8dc61e20f4a4f8cb7ad81e9a66c8b12d592c445ffe905495bf1e277de55a10da8c48dfdb0db1c2d2be9077c47326d0611dff08131063680fd858ad72e53d3eafe0a85f436eb3e03100a0f98057ddf1c47372ff318bad1b3cae928aeaf98608e397e4d8aa0c2fa594eaa9386e6fc8642077cc6c2f81a3e59704269a556eeb90161ef0f7271b798a5ac6430e0986d6c6c5b0ddeb2ef22c873a338824ba46bd3b634cd30143d66237eed3d89041e38e178f1dee6a5c0da039804face0a90c6c8b58a5b86b402e964678029a71c8c4c82ffba9fdef3c055493eef3e61b5e3aef9cc73816eb3360d2c719b198428f5a904ee1f241b20712aa67f4737fe56ba3884bc0aaaee8faa2d39ccf125f92c35877bb0ecccf0d95376a30464873475f62faadb18013e3cc879c4e42b166d20042980b84aa9be48ef7578664464956caabcbf3ab2cec3f87b0ae1c7d3ebe2234489491ceb0f4b3445308dc4c41f68ada861c95e9f0b0ed2da0b9bdc882923a4ec7118fe6eb1af554aa018c7df6f6987c353ef63017add74324b46c5a6910f8d929ff3d2ec271207fa7220ddaec2c3746fb8a12d49b2b0e8896a08f44e49c58ebe7eae582982e7bd5abd9289da25cddeb8e14c56faf1443be3a51516ac8eb463b643b10bec77052b48397bdae8a3948b19a58a98c2ded30b54abad2d930fcbb4ac74e6557b8764bafc566988071e74e1f516b367fcb6cbc23ce4171dbe8bbdfd8347f121e509052bc1870dd22bdfcbfca952ccd751005dd11649a3ee9db35a65d1975166a29a1186381f4055db5940ffc4034c68360f1c3ef6a20a7aece3e084d8c67eb48dddb3ec4c964c11826172edf44bae8676b2cfcf81cdf2f16e642081944a46bd2ddfffcb0b1862d83ef5592e57409c8f7b6d359a2d0cb1d1fd0d2f55428144764f0127ad78d202c0fdbc6ee5139d33fc78183199115dc21a4a7a006559deda04f01a21d32a41950d324f1b728583daaadd4c355c04a9496e485393803099ce10627f214bf872f1dd3848afe1e884e21db791a596cd7e9eb5cb1ed24ddaee49b90baf83425f48067c367b7038db82ba50ecc5363cc9ef954c583e3eaaaa9579e34a8f28acdc51f857154bfa3db2cbff5b0513f5d91de7195922e4f092602b0c4e2efae95f00030cb8f9a9f717917e279d5c4139f54866e765b3db872b7a6085452bb9a548c3613b458bb41aa80b56e6b47bcc1af86ea391ad446a5d1f3552255645ac224653a52e0ac112c84455979a58bac88eccd346ed99a6ab7fccb98daa062e387fe31501be23406cbd48e44f11801b75dfe93efadc49564ce57afd4cfd39cd1616f8e50b16e8e06311c04e4c98ba4fed7496666e6526cfbc5a9d3121fb25e9744914bfad8c3de1a18b942f7f0dccd89d0ed3a3e4d84d2664acf781e365bb3c2b3e9340db66b8b2a5850535898113f0e9e1e215c70c5241e82c005b2e45e1d73f51b6cc8adf2a0f5e6a931005fd6bd5e572937f79f75b0bc09e6e606e3769b23ee96ddeb3058d7f7fc9c9c0dfce5486032be1478fa5452d9ed019025760543179b002e68f1e9483e35d50bbab770b2639ad95f6667a59451de23f45cc7e50f1ec55374426e16a9ab3d6f8d16da2c7ff020e7972a66bb05bd707ac78c51c2238442eb24cad8db44439388e979714d5a5146c5c1609dbdcce2f5d8040f50dd2b83f57577c6e4795b6e753a58075939429cc4afce88e212e0fb09fe462b81c2b53cf0e7f8c483e5bebc3ed9dd29302d527a8994bf1564d80c5f93e724256f5462eceddfb42643c0f9626c16f04f438ce1838037620a5cb25347603955a29c6ca4a9cc9ca7a6f4b0f70c31bce11a30ddb456284df75774f1e7a43fcece176d91681ecaaaf03163d214a0164ce8408346e32548b04c050ad536e030bd5937a889faf49e58a7541c4a851f7d7e3033cb67736922bd501c9e3f9874ccb15d83814b2289e5b189e465b8e2bf2e2c7fd3809acbb3006c6cc52794efe490c81a9aa47e70041fe83d665501755fdb58aec42b0868bacccc64cdc93718357292a1194bae59dd878d0652a8f3617ac27d70bad6a13ed603dd5cbaa3bad81be71080d5d83b17e17268ab2886305dd1255f71513bfec828b09d8fec5747cdbb04fbac230328554f5c5a1447767be43e3478e6656470df605b8f8f6da8e1180d27ba691e81544c70ee865be596a9189474a4ecd5d747c1dce7b13d6d87548f365e261e9614fa0f23092eadc4736c507735cda4de06d0d26cc1b56e5f73ee90fe5b98bdb13da7deaa2b69ef45ebff11fb996f05bf20da22bf8b0ad42c709a66a96826330468621c11aec2037653676fdff88b8608620c6b66fd6dfe32d9a26e78ddc30af791353018d8ac8932c02750c4c65b7521b5b06ac67c6cfb7208c566e936a22c975542f898bd21c323633dd88de7e2cce6fcac321427616fd0251a4021bba684ec211d086d77c260b34f90e7e5fb6e8fc5d13093d206e968f90bc1ba4d81be9ce628240f45d6b2304d4325e584ff26ffce6c750a8ed717023314394d85522536ecad24329a5accbc07f729b420e51ae2376b91332372ca31340978f92efb651519a5c1b1a51bbe36937cbcc03d275f0b47b24268367116e3e10abd1c3309aa7ce34948cf71e28532a5461e677178b8b502a872a9fd2ce9dcc32ade49e6eacc2fd0d45b5eed217d5dc4eaee1285f7b84273722c11b31e6e5883a2cfafe1ddd932416dd370154dad23cf2cbf19fc457127ac0f798dc4c897baab75e5bdd9b716cc75960b63c046be1ac5899491715399e02e764b5843470cbeecb09593c3fcc219174af4ae3676e42474086de66af619367f2f2d8c35debf4c05e30d977b927c859106e93881eabd412cdb1e9fe57a888a887baa68f1430eb8b024a2cff4e1261862564c41c691fb2a6f23698ac59b337049a9fa7f181aa0e3097da72004ad10cf102e94399b59230e8144be80b3c615a3181e8c5d3a04301000180a7ad67c40d615de0cd11824b672a8de6c641f3838ffff23d44b5bacc7c4c388d2a7f424b83ca04c468823634b0efc5f267a281d2e13bc9d30604a6688062aefd4d0b60230000000000000001199a003a0c07eb5fc7ff995a228aacd2ec3719819a9dec0aa26d10adc9c1a58d836093180ca76a3f8f67ac72668e909264852a2d1427ec85a02544219dc00181ec605ec8cbaa7af879501cd3a4e7398d78af3aaba9d5d6ea0504404ea1312b90c3628bea1d458c296594d773e3fa86b0ae1bd70845a8ac82e8c9386ff2da6d2739f74b221bcd68e3412a20d16bcc951869942da413f7a2cedb06c4fbcf3a89e5898314c35e6ddf3dc657f24f4c828f2c73604d14b312b2962e1b50494d294751f861c9343fcc2e3734545f25219cc48a099881d3bde6cfc64f54a21c934388a1c93f0a396b4cfd356a86e36e63dd9ea10196a10cdac69fc7f38a36fcf91521af60918d3083e57ee9413edec7f660af704e966b45a84cc14e0c56831ca27ef5082c291852f60a31305a36238daee77bb447e988319135e4fc2be7fa0db7b145874164f90589bff507f32f8c4ef27b4697283c955e84925552e8d61419ad08b2b40b55fb729b76034610f5606c930b6d4eb5578b27547554200e9185c27ec84169f2db8341783bbbaffc76b80e557974ae40de2acac657b8d1f03e49ed4ddf298083bcfdea14d01f7a31ea731dd2cfaf2a5a229847ac227d7c14ec1a68e2d748b63182515571c4e41dc69b95c6467316b0be33da252a32b27cf35e0d0a9a759cf9c7ee84489ed1254214c586d8ddb6a228e6498dc7379c49b344b160447c7e01cbfcbe92eab3eba4da9664b5db003486ddfca31864d16fe51851bb043f62723d3ef03452a263e4dd11da93ce9f7dc2db5ae16b64a2ce07d81d4a2bd35d62abbe05ec7b2af6327c99a04c0b9316942fa74878bd91b96bc1304e6f2be7e50ccf7bc866ad37fb34effe83700d3ea93e220d5251dfad1af156b84f4fa9d97dcc62f140c26f8369716d9ceaa5ffc69a9ee647fbdc648da9eabbd6e36a271a00840ce75e9addee57074b866429b98547c3c380b9defef2b65742ed5fa4b4acaa59324ed8cc491e51f4c15a34a3b712c91acb9c5cad43be2e481206f5e8be006eb6d632a31df1bc2bce4e267ae48c75c10d7ad7d54b4a3579bdc8c27cee6f7067a63acba681a34eeaeebee359d82ba0bea46baecdc40c641f9995ca3f7daa9c5679ed160fad6b3755466cd463d3e7a117ba3c311ba7aba451b288a02c3b0c462f21dbc0dfd1cd805d40bcf85d78bfa7a1a689edb599f5d54956d3a11d5f3f2b0b0cb72851605cb7e90f9401e9be9f6f1014a43502dec2291f3b583c99ad4192ee5c3bb01024aebed7d3276cf61bf5bbc495174c6bd8a9ab37a166e9b48da9216d7f476199566827a329ec3ed48892a4b19d7c2be4aa7f0bd1843aea86869615df5ad8cb327874ab9d297270140cf519994c425c4d08700360dd3427e7be91521cfd671f844e28d3e1298c1b81be596e2aafc42e727697b30c981eb70a104d8277cdedf55dccd4ceb95657ddf30d9990ba1d2c67b6ae863c7dbb7d1898cf90181f3375bc7c7ca42fbd6a51d30ea19331fd9fd93a0b68d985505296c89e0d2f38871546c9d6805459f9c26e8f503673823d34a03ba63090c499ad21a1629197f772dea62f4989e8ebde6e18cedfcba7ab3956df479d59a2e19d86b1a3c0ed8fc298871b270a720b6853f6609bc33d095ce2d506b7b32c4f63ea30b4b484c29c616ff6a800aaa080f1374c5f72cb6e186e56b6ecd9de8bbdc79a4282182867eaf41e1e789caadb4a01dd9eafadab1035396434112db932e3d4a9a7c2d5ab635e2917c1ee3242bc98e6b36499a588b90abd7224619e9421c53f710f3bad74db88305c1af4d4bb97438d49a8d46257d7adc3290e96bb05029f78f1cc54cabc21da94c768400a0a7ddcb147df8dc2b6353d261b48a47eccca5ffaff80e9fb5ecea1efa940806777c16c0ccebf5d5c9c8d3d64afc1ceb72aad306390ee4e1ce418317d229547cf7d96fa6c3e72624d138438ac3df68b6cdf4bb54812cd31dac2e5ab2d4090ca8a01de888199b205ab31933227646c8b6e8faddf08dd94438cc0fdf5b4c8ef7c48123b8c9d16a09162895c75469447ee4630a5c52f716ceb3fc73653f56fc90753dcde00c7e1b4e46a9a1f40674fd130dea42f935d9e811261057871e4367ec42b9b6127f3687e10e6777b3e4d537695d01a5053c14a70b6435c624cdcc93c4b9fc68726590d64d8ed3ac9b74609851f868e03568ced113968babeef5d4eb95b33d0c0d196d55f58bb394ed9109c89f3f8317cfdbac738aaeed72afcf146dd5e3f2555e77f0d959263961c55989b01dc47172103c1a27050ffd5272ef700aa1cf24ef2e2c1c640251b64567a55ba813389e5b851764ab6966fcd08f2e33ef77eadaf83d7c734dd849e5ff0e9a18b5739d7322600b0d8b459cefb9eb424a481043e0bd67af17fe15de1269f3f96173925ef0dfef6b39fccf35d9a961f682dd9d976e735c6fc7139e7c398e0af4488a0760766e5dca6d1a3d8641d872ee1614d55d9a31929207adc0e813594f2571eac8160f882ee9ccefdeeb3cb98a2b885871ce17a4262b4c0bc53b21491d86866e5bcce058aa978bd84b0a21ff4e03a6547054e8f41b5b24926ee808c50f6f857bf09e070612b9816cd79eb18cc7ce58f84404d031fd7f8d9433880ec5a40090625e6580337ff84b10de7331a9cf93aa81768fccda2efaa8a9617c788540726662194d17be8cbb7e5799a7766294fa11fcfa34955f5ffefeca4356a58b255104b5a84822789dbab7f99393410eb356dd2694b5c5068566c572c11ca4aac9820461560488691bb11ee2dffbe5b87118ed017d3e4a1fe9c4f1c9bd18b70ccac6691ca104b90d376d6763537ba767caef629d3c940b5f96857d7bd3e1927193e4daba0b6c0c99ed89e2a177e3cc80cd37bfb9613ca9a4aea47eb311353aae84e5fd231531428635178a05e7c59251305c8a0c9ea66d8ad73ea7288379e49ce1f6afd59c13163f00720105810681fe57ca8980f0945c4d8d490e2fd70141485ade4b2f1c9434b7d2593490810b5018c06cdf8729c17cbc17f44a2bbe242e4e6a905e53910139375dfe05f48baa0d5f13ea1830c85c5188206ff68c3578b860fd201b8aa8ef87cbbfc2784d2f0db470bcfe9b693cf2286d7c1834746159e7710e00878ba814ace639765b08fc36a0862b80a06445a05b85e71fa5132e8697a73085afc1ea11a91d8373be39ea60b0e7d6a7cd66872eb91a3dd24aeedaac82f9f3c459f0020dc636b42b55f5b379b50bbca6a6fe80aaa7c8cd629cd735675787f82905eb5139e79337ab0da46a0f56ad6abcf7af9cb0b7f5a9675aae6e9bb11918fbb2f5a9c7efefb8b610ba55b748b4e5b5f58b67a188fbee42e3ddd57a34bf696e9720081e4f510c6b4e928984ac75525bf3c7b22c2dd21e4a2a292e1497b69aa7843fd23f00aee321abfd59a821126e2df88e1bda8a4d6d2dfca3702cb24933b0692a3430e5839663da12b4223ec334fa7be72640c1e7554ad58b08962059cd29270021daef264b0269a24b79b18f041fb8ffc78bf491c9f2665fae997f2373bc4616cf269cdadedd061ed983c076130897e4a43b0db1214a83c18e5be77642fad84e66cc0dfcff4cbc22d025c9c23ad1472a32b77f0b7c3fb9bc85e23ec498baf3cafb14b341699ae65e257835e1b8ceffed3f958077e0678d959e03c4cffdf5baef730b5697f042d1e7d869e3b34c318c2928f56a78bbdb5fcf9ec0db2ad0ebab630a0b010114bea72c5017667021a311fab8a7ac1fee3587624b2561e447ef9f0bdac31e2e923fd5b2affb3d2efc9ce16bd2930682caaeea2b3197b142cab7767c1a043fc3e39ddfcdff3f520d89efd43d06bfbd95055df25bb55a0138bd187ba99cdc4c469f1e4d8da05f68117cbe6c0f56be0b3b2605c4185adf48df8b113210e2752070a1c2409eeda7764c4c0bb66b6c3ef6e1e02de7c13f19ff730edd70fdca25d76c77c839d19665156b6c8a3dee400f68abe17a270fee5207ae82137719936ce29e9351f7cedf02b14a6033d228b2edb522104eca5c27a7567bba3b8ca80b3f1aa8cb9e9e5464a7a73bf09606ecc6d2c9390cdb20000"
		txid := "fc6cd0e025c7dc866ebe2b4b3f3449f213a17a62ed6438c3f6894ecdbf0bc117"
		vout := uint32(1)

		// prepare signature
		pubkey, privkey, _, err := CfdGoCreateKeyPair(
			true, (int)(KCfdNetworkRegtest))
		assert.NoError(t, err)
		dummyPubkey := "0229ebd1cac7855ca60b0846bd179ff3d411f807f3f3a43abf498e0a415c94d622"
		redeemScript, err := CfdGoCreateScript(
			[]string{"OP_1", pubkey, dummyPubkey, "OP_2", "OP_CHECKMULTISIG"})
		assert.NoError(t, err)
		sighashType := (int)(KCfdSigHashAll)
		valueCommitment := "0993c069270bf8d090ce8695b82e52fb2959a9765d987d4ffd7a767b0c5b1c4cbc"
		sighash, err := CfdGoCreateConfidentialSighash(txHex, txid, vout,
			(int)(KCfdP2wsh), "", redeemScript, int64(0), valueCommitment, sighashType, false)
		assert.NoError(t, err)
		signature, err := CfdGoCalculateEcSignature(sighash, privkey, "", 0, true)
		assert.NoError(t, err)

		// check signature
		result, err := CfdGoVerifyConfidentialTxSignature(txHex, signature, pubkey, redeemScript, txid, vout, sighashType, false, int64(0), valueCommitment, (int)(KCfdWitnessVersion0))
		assert.NoError(t, err)
		assert.True(t, result)
		// check signature
		result, err = CfdGoVerifyConfidentialTxSignatureByIndex(txHex, signature, pubkey, redeemScript, 0, sighashType, false, 0, valueCommitment, (int)(KCfdWitnessVersion0))
		assert.NoError(t, err)
		assert.True(t, result)
	})

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoSerializeTxForLedger(t *testing.T) {
	txHex := "020000000101e46aa5d11fb7f2243e75bbd90ad94e5ae0d1992c4a5c0d6ba71a77e73df8e23b00000000171600142851f8219e77b0f3ae8421a8274168c743e574d2ffffffff02016d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f0100000000000005dc00000b547995d08f8fa9e87e122548afc2ea80f552aee8e45a44df4cb81292fed26530086bd721b7048f58fc925f56b0642e107a492c9509b475186f7fd573e47a500437020129d9733769531b80adf2a6ab2f8e212beb26f94ebc2afdb43d5b04cac794b41976a914af991f5a938a1767f93adac12bdf8f42156a4ecc88ac00000000000002483045022100917ccdbe993dbc4c0bfe0839bf7df16eb481a175c60a7badbb676145e75f924a022012a868a2286420a3d0793e241c4f767a95c985db7c44a0c8a0e872843fc230c8012102bff933ba22e896a0cc0a0834f11c6afb63995605d4def392776a26535cea8e9b00000043010001bd2e6fb69a23e881376f7c692de1aebfd700a905c8a30b493a855685e939f870adf7d6deae5197ddac0e685b0030e76488ec549d4467a4fe1d8e814b3a453878fd4d0b60230000000000000001ea10015893fbe5cadd09e8a2944bb85a3ac04a65a345fbfc5598d5590624603335faec0351b03a46b5a9cc763ee1769badde123ec6aa62c9c0f9f62a868f8c38b4e20a2abd02e74ec5076b38d7893d8a7eb6677b1fa4e7b26716672e059d4b2d4bb965eadc0b1f2670ac51e8e97d9d5c1774c07ea5555ccbb27f7ebc3d7aa0a8eaf2229780587d2289724cc9721d9b0db71f799d59422f95dda24aa357253fb1b411f0538646120a92227e13897dcc8627a6a915f568e9a4ad56b165002c4e9f8db6d2f5c3b6fa5f81851a7c0d70360e4a6504eab5761d79a992f1a9f94360b20027c6fe190deb6bd1b15014f33d6c958b3d8b33b2a7f8385674a4c043fbdffbecba492c5fc8e0bbf2f6d5221a6aae302454b902e679f7e28805a7c351a4e0ce238857ff53c27dc390f3d5ee56d288e92e88da4f51a38e509886fdfba9c957eed31d1549af668bcac6e62886416e4a0ac99c873d03779c5a19ee154ba8c4b12e689e095ea606c024d7beec052e451113dfe1cbcedc182f5434c490d867c3d1aa0d56845b098c87372131e898f74068c4ee43ace49029fd2903b69e0c7fe01a19fae0436880077818cca0c2a8f01975eb3580ce89ae8ffae76bf01ee77a576736eed52849b9584a87eef8b05446d34a33e77ccf117a6aaf3acb0e290e8a3cd5020a6ffe32879d81dd473d0c960052d67825341b1de30b8cea5fe94b9f024bcd6ac2f5963d0ee69137b08714b168d4121837e490bab2815e384d0d15c6d98d990ca61bf648e6fbe89c4b5b22eb7ad68e1688f17fbccadc1ea232f7c4cc10348b9f32ac1ac966c85a7c30e7d2f5582d2d327f106197f19994b23c76026fe034f2e90cb0c9c85ae5693d3f1f9adf9391f70a3d50e0b2ff0e5fe6062e2e62689e5eebb3cb1728b0f553bc5bf288f178240ec4c2028387be30cbfc7d95219e6aa14df11e850c1eed06c3b4e6af58619f4ee93e826f548f6d4841e345215b97b90356d641c367fb478a7207e170fba9d9cb1eb75bab69ccff6f83c28d48132432571074503da5123f09f406a0b632b03d18d2a6320da8b51d46b13daedf69054f352a29bb7e5b95e14f0fc8f2f53478a61d2e754aacaeb7d1287eee4d74b0892263d09bd0423c50940527d404bbe1135c683465553d558f79c00e6cd88ba833fe72732cb624e7c432433236e2f80c5d29665d909059ad1b1dd17b8a5e1cef0bb6a3ff10908435956c82b8347e0871b36d0f1d7b46c12ac2454af4412ac5675621b6feca07730fd14cc0f3d50d6485e0b59ae6abaa064e0514b24c57abf5bb20740b15ef6d64f249bbda993c8f90a5235a7170572cc5e213fea65cb9617ade120349cefaf10e0a945e3ac039021a2dc3652070cc4bdfcd5e2d451bd6bf28f25e4e68f5832b21566829fd37500ac1ae6429132e97278a2bf82074500f5676dcff3adfdefc88daf1a81ab23db5fe7089154219a258518fb204b3fe9ad572bc47fd4c5a200a14593cc7efe24b7d98144ae35d4e6328c76c1807168a6d799ed3aad5f4586bc1437d7cdf38b026b9e131f39d0bba348b6598b7fbc9f2c9ec0bcc03c28329b416bffa285644031d489e86d43ef12b3f42e76c36e5ae9df1f3ac0f1d9cdd5d4d7c446b19d1d8d9a58c93ae27ff8daab5e49104b991b38ef4dd848d9898d1814ebf391bf57a9314f298268c5fa884c114e83a87210aa8b483be9c3f5a4eb345af951bfde6157bfbbfc7fae28297a534f2651d5c4f11314b29859510d8fa99127435c30c2e99a308a68e6b699967fe5b5ab35146b758e876450c1a03b9b90fcb7cc05929680ed282d93e53c1d56590928b547e10222db9ba6f2d8d0afaa93af871e4a8f9d9e69f07fede10ec6f088fd5195349e566fa420583822371ab2778327019548de0ed9cd4e412b14fed14f768a6b5f11ac26637779dac567a2372ad033fbc9a3ada97b10d6bde95fbe665215068a6a9f29872d102a14c7edcd0ccd19f47c09ddef7aae4d1a2bd6050806c662e4669391996c869bf94d3863589f96b02be28d045ed7eaa92c399289de5b193fd4db5da347fee11eb9b1ac901a2ad542496b8c869e0c55ef27d8b7b4905fd24d652789dcc89a59368f0ca0f0ea8c99b4d12c14c35e77a96d4a0f0f38044fa51125991d655c85988e150f7bc3b8f9c69e6b1df46feafdd74aef1e91b7075f45dfaab28adac7a0cb3bfb5b11bc21e3db880448ff78f6f32335d218e2d9ee5a99b64a2649c66d7b7385bc9a7ae3fa44f937128e589f4fe99ea601e40c1b61c53c06657ea9097be13d546453d5bd2864db7f26ed5167d9268584165798aef967260cf8f96dfb9054c07013e1fbf59f550c43017f753ff4ee7afcd47e0e7f682376cff563778e062362dca0c7b1a7ffcce268f42832d75a42b9358720ef827a218221810fc8c28f10d5fab56fd5cce327b1c8d5f6b94225a97855a85783cd9e0b15dc05317d4d70cce6c010205319985ae0e6cd9d24e71c7904d3e8aece8b90aa81eca459c4f2627556dbffa0126b37bd07307e7bb8b01d53cd5f68900ed066392f376806b56790afc249766cd98f9bcc3aaa69c22fb5acdbd320e550131ce16654ede5077043db69a541b8568c715bfda43ea72673a46d1657318629dd83843c60fd5f296f5e26f5aede395d4f46812d977b1cc8a0f1396319a196268f1904e7c9b10e4c191b5f233074dc047c8a1d4733802789a22c54b8776d877dd8995b6d1e8d22f2efd4260a50eb4fc86b9c144242630217f1f2ea75981f4cc02025332c1683a60228eb73d10ceb179a59d11c00b55976fe4ae48e4a5b2a6ac4718923c511d241c63574065959620653cfde157ae5494ff4d2eca43ee70741f13eb8e19875fdc265e52087973e51d374ff7f1ae8eb386347749d39c886f670fd580ce2f24c1092433d76c7cc030a6c5495665dbe0909eccf8e0f77b268fc4b87fcac541599ae1ceace33f50b02d952a7c60a1dbfb75dfcba104f41c85a7133b2d97617874d8ba8f10ed5b5d1d5798d495384088a6d6a6a4af3c3bb755c5806bac3ad273af1dd58a6ce1bd5f5a9f9d2e2b24e2ab75ea9fd8b631ea29f07d1e90517f1690a110530aac7b29c8fe468afc2be93d953d5b172e7c8668a2658f0c95c96043ce03e5f57857e80011117ecbb6f10dd0e0c3deb269b24cf46f5d4ac875e8bb461151cfc66b69ad8d15d2a4ebbc247a20983d94b6f92701ab25bcdd2b768ea44b3c009c150d8aa71fc4440ac0ab6622e29fcc15629a82f3e07bca6eb6900f2670b219ef2ba12edc1a76b6892efb025e38a7a7b1f0a6ac36caa6abf4851ca811e795ba710709d788532026bd134f7ae9c5f3972a9fbec5991f9bb1747eb4064c66eb2e4161c901befab36a9bac48d9b77516a36a722dd705d0da3db493f72bd7195ee8ff99b4626b857e9e34fd6f29f077eb2add160266f7364db4f2b6c39331352f95e7377e10629f9478b5ee57165ff0cbeff7c6481c7be82cd245c462d0ec9c79e35fbc6dd44c427c2a85ce5b79543ea50dd909d59f7de80467aa0e88c8dfeabe74961db74ed4fe9f04454d21f4aad89c26da4a6f5299565edcb1991f9c9f28271604b6540d0556241e67a4d613f4fb0c52ef437c8da0c5e3bbe4798c8659cd393bfc7d10a13edc9c18ab6809cde93ae805c6ee2b3af72ac570678bb1dc0268ad034b18092b8bd9c6f97af6ef0b9d958099b5fe4ba0dd08f004e7d36aee2eedea403a004486eeb22ed71cebdb3413106c7bbd826a7c6c4efe4cc0deb1861212d2bb535c3adefba28ebf3623bf2782bd4600fbcc6a9df20002a47c54cc660a6b27211a8d3dd0444e1a2298260ea6ffa6088ace1590ae7ee9951f7f620e55b49beb0ec8ad1262c98b1ec1b4fa75fd1ff4931b71388e07b31d699246ef6fe59bba6f69b7111ea73f51e685fea3798d2d74fedb900c9ff6ba2cabd150fdf936eca041eb27c38c529767ab14f9b1f9b694c3f2d103779fa3c5d2c75fd287be2fe4169dc05951895b884247e65e8a88ac6628e1abada705287ecb1b3441402dbd6bd0550042e5ae6502d771b844ff46eaae6c61bee5f0ecbd3c61df"
	expectedSerializeHash := "1ded6067d70f670ab35a00c18ceea5924cbf9d5af73a555b75b0aaa0e9269a44"

	serializeData, err := CfdGoSerializeTxForLedger(txHex, true, false)
	assert.NoError(t, err)
	assert.Equal(t, expectedSerializeHash, serializeData)

	privkeyHex := "4ba30e5d071da978486caf229a63d82a81169fbfc49b7b4418ebc6e93ebb11c5"
	isGrindR := false
	signature, err := CfdGoCalculateEcSignature(
		serializeData, privkeyHex, "", (int)(KCfdNetworkMainnet), isGrindR)
	assert.NoError(t, err)
	assert.Equal(t, "f5f7818496d20de9666b5614f5a900a1024171de5cea10523c6966d4f6eac4230099c96123c6453ec8c04671926789859ef12df2bae274936ce5b2023882234c", signature)

	derSignature, err := CfdGoEncodeSignatureByDer(signature, (int)(KCfdSigHashAll), false)
	assert.NoError(t, err)
	assert.Equal(t, "3045022100f5f7818496d20de9666b5614f5a900a1024171de5cea10523c6966d4f6eac42302200099c96123c6453ec8c04671926789859ef12df2bae274936ce5b2023882234c01", derSignature)

	derEncodedSignature := string([]rune(derSignature)[:len(derSignature)-2])
	assert.Equal(t, "3045022100f5f7818496d20de9666b5614f5a900a1024171de5cea10523c6966d4f6eac42302200099c96123c6453ec8c04671926789859ef12df2bae274936ce5b2023882234c", derEncodedSignature)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoAddConfidentialTxSignWithPrivkey(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	pubkey := "03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6"
	privkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2wpkh)

	txHex, err := CfdGoAddConfidentialTxSignWithPrivkey(kTxData, txid, vout, hashType, pubkey, privkey, int64(13000000000000), "", sigHashType, false, true)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac0000000000000247304402200268633a57723c6612ef217c49bdf804c632a14be2967c76afec4fd5781ad4c20220131f358b2381a039c8c502959c64fbfeccf287be7dae710b4446968553aefbea012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d600000000000000000000000000", txHex)

	count, err := CfdGoGetConfidentialTxInWitnessCount(txHex, 0)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), count)

	stackData, err := CfdGoGetConfidentialTxInWitness(txHex, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, stackData)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoAddConfidentialTxPubkeyHashSign(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	pubkey := "03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6"
	privkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	privkeyWifNetworkType := (int)(KCfdNetworkRegtest)
	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)
	txHex := ""
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2wpkh)
	addressType := (int)(KCfdP2wpkhAddress)
	satoshi := int64(13000000000000)
	valueCommitment := ""

	networkType := (int)(KCfdNetworkLiquidv1)
	address, lockingScript, segwitLockingScript, err := CfdGoCreateAddress(hashType, pubkey, "", networkType)
	assert.NoError(t, err)
	assert.Equal(t, "ex1qav7q64dhpx9y4m62rrhpa67trmvjf2ptum84qh", address)
	assert.Equal(t, "0014eb3c0d55b7098a4aef4a18ee1eebcb1ed924a82b", lockingScript)
	assert.Equal(t, "", segwitLockingScript)

	sighash, err := CfdGoCreateConfidentialSighash(
		kTxData, txid, vout, hashType,
		pubkey, "", satoshi, valueCommitment, sigHashType, false)
	assert.NoError(t, err)
	assert.Equal(t, "c90939ef311f105806b401bcfa494921b8df297195fc125ebbd91a018c4066b9", sighash)

	signature, err := CfdGoCalculateEcSignature(
		sighash, "", privkey, privkeyWifNetworkType, true)
	assert.NoError(t, err)
	assert.Equal(t, "0268633a57723c6612ef217c49bdf804c632a14be2967c76afec4fd5781ad4c2131f358b2381a039c8c502959c64fbfeccf287be7dae710b4446968553aefbea", signature)

	signatureData := CfdSignParameter{signature, true, sigHashType, false}
	txHex, err = CfdGoAddConfidentialTxPubkeyHashSign(kTxData, txid, vout, hashType, pubkey, signatureData)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac0000000000000247304402200268633a57723c6612ef217c49bdf804c632a14be2967c76afec4fd5781ad4c20220131f358b2381a039c8c502959c64fbfeccf287be7dae710b4446968553aefbea012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d600000000000000000000000000", txHex)

	if err == nil {
		isVerify, err := CfdGoVerifyConfidentialTxSign(txHex, txid, vout, address, addressType, "", satoshi, valueCommitment)
		assert.NoError(t, err)
		assert.Equal(t, true, isVerify)
	}

	count, err := CfdGoGetConfidentialTxInWitnessCount(txHex, 0)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), count)

	stackData, err := CfdGoGetConfidentialTxInWitness(txHex, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, stackData)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoAddConfidentialTxMultisigSign(t *testing.T) {
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	privkey1 := "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	privkey2 := "cQUTZ8VbWNYBEtrB7xwe41kqiKMQPRZshTvBHmkoJGaUfmS5pxzR"
	networkType := (int)(KCfdNetworkLiquidv1)
	networkKeyType := (int)(KCfdNetworkTestnet)
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2wsh)
	addressType := (int)(KCfdP2wshAddress)
	txHex := ""

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, _, multisigScript, err := CfdGoCreateMultisigScript(
		networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "ex1qdenhgyqf6yzkwjshlph8xsesxrh2qcpuqg8myh4q33h6m4kz7ckswsunzy", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)

	satoshi := int64(13000000000000)
	sighash, err := CfdGoCreateConfidentialSighash(kTxData, txid, vout,
		hashType, "", multisigScript, satoshi, "", sigHashType, false)
	assert.NoError(t, err)
	assert.Equal(t, "d17f091203341a0d1f0101c6d010a40ce0f3cef8a09b2b605b77bb6cfc23359f", sighash)

	if err == nil {
		isVerify, err := CfdGoVerifyConfidentialTxSign(kTxData, txid, vout, addr, addressType, "", satoshi, "")
		assert.NoError(t, err)
		assert.Equal(t, false, isVerify)
	}

	if err == nil {
		isVerify, reason, err := CfdGoVerifyConfidentialTxSignReason(kTxData, txid, vout, addr, addressType, "", satoshi, "")
		assert.NoError(t, err)
		assert.Equal(t, false, isVerify)
		assert.Equal(t, "NotFound witness stack. segwit need scriptsig.", reason)
	}

	if err == nil {
		// user1
		signature1, err := CfdGoCalculateEcSignature(
			sighash, "", privkey1, networkKeyType, true)
		assert.NoError(t, err)

		// user2
		signature2, err := CfdGoCalculateEcSignature(
			sighash, "", privkey2, networkKeyType, true)
		assert.NoError(t, err)

		signDataList := []CfdMultisigSignData{
			{
				Signature:           signature1,
				IsDerEncode:         true,
				SighashType:         sigHashType,
				SighashAnyoneCanPay: false,
				RelatedPubkey:       pubkey1,
			},
			{
				Signature:           signature2,
				IsDerEncode:         true,
				SighashType:         sigHashType,
				SighashAnyoneCanPay: false,
				RelatedPubkey:       pubkey2,
			},
		}

		txHex, err = CfdGoAddConfidentialTxMultisigSign(kTxData, txid, vout, hashType, signDataList, multisigScript)
		assert.NoError(t, err)
		assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000000004004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae00000000000000000000000000", txHex)
	}

	if err == nil {
		isVerify, err := CfdGoVerifyConfidentialTxSign(txHex, txid, vout, addr, addressType, "", satoshi, "")
		assert.NoError(t, err)
		assert.Equal(t, true, isVerify)
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoDecodeRawTransaction(t *testing.T) {
	txHex := "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000000004004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae00000000000000000000000000"
	expJSONStr := "{\"txid\":\"cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992\",\"hash\":\"d6a850f43637361ad8501cb47e4d0725af4ad50657ceb8a6e0d7c975effae805\",\"wtxid\":\"d6a850f43637361ad8501cb47e4d0725af4ad50657ceb8a6e0d7c975effae805\",\"withash\":\"a9357382302ed93ab51083f451e2d7872db11ef07948198b30166af1576fe678\",\"version\":2,\"size\":745,\"vsize\":571,\"weight\":2281,\"locktime\":0,\"vin\":[{\"txid\":\"57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"is_pegin\":false,\"sequence\":4294967295,\"txinwitness\":[\"\",\"30440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a7901\",\"304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b01\",\"522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae\"]},{\"txid\":\"57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"is_pegin\":false,\"sequence\":4294967295,\"issuance\":{\"assetBlindingNonce\":\"0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8\",\"assetEntropy\":\"6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306\",\"isreissuance\":true,\"asset\":\"accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd\",\"assetamount\":600000000}}],\"vout\":[{\"value\":999587680,\"asset\":\"186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179\",\"commitmentnonce\":\"02200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d\",\"commitmentnonce_fully_valid\":true,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_HASH160 ef3e40882e17d6e477082fcafeb0f09dc32d377b OP_EQUAL\",\"hex\":\"a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"H4zXUS6DJhgaQz4VD6qeq9n5mHhM9rsSMP\"]}},{\"value\":700000000,\"asset\":\"ed6927df918c89b5e3d8b5062acab2c749a3291bb7451d4267c7daaf1b52ad0b\",\"commitmentnonce\":\"02cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a\",\"commitmentnonce_fully_valid\":true,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 6c22e209d36612e0d9d2a20b814d7d8648cc7a77 OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac\",\"reqSigs\":1,\"type\":\"pubkeyhash\",\"addresses\":[\"Q789tcqaWXVKMzoEVLcNfreWoGaWauD7XG\"]}},{\"value\":50000,\"asset\":\"186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":2,\"scriptPubKey\":{\"asm\":\"\",\"hex\":\"\",\"type\":\"fee\"}},{\"value\":600000000,\"asset\":\"accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd\",\"commitmentnonce\":\"03ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed879\",\"commitmentnonce_fully_valid\":true,\"n\":3,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 9bdcb18911fa9faad6632ca43b81739082b0a195 OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac\",\"reqSigs\":1,\"type\":\"pubkeyhash\",\"addresses\":[\"QBUWEyd6fhyYwZotj1wEbDqoADc9dPEVeo\"]}}]}"

	jsonStr, err := CfdGoDecodeRawTransactionJson(txHex, "mainnet", true)
	assert.NoError(t, err)
	assert.Equal(t, jsonStr, expJSONStr)
	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestPeginTx(t *testing.T) {
	peginTx := "0200000001017926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000002540ba97c0017a91414b71442e11941fd7807a82eabee13d6ec171ed9870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000003a84000000000000000000060800e40b54020000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f16001412dcdeef890f60967896391c95b0e02c9258dfe5fdda060200000000010a945efd42ce42de413aa7398a95c35facc14ec5d35bb23e5f980014e94ab96a620000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffffe50b46ecadb5cc52a7ef149a23323464353415f02d7b4a943963b26a9beb2a030000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff67173609ca4c13662356a2507c71e5d497baeff56a3c42af989f3b270bc870560000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff784a9fd151fe2808949fae18afcf52244a77702b9a83950bc7ec52a8239104850000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff259618278cecbae1bed8b7806133d14987c3c6118d2744707f509c58ea2c0e870000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff5c30c2fdcb6ce0b666120777ec18ce5211dd4741f40f033648432694b0919da50000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffffbb0f857d4b143c74c7fdb678bf41b65e7e3f2e7644b3613ae6370d21c0882ad60000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffffbce488c283e07bf364edb5057e020aa3d137d8d6130711dc12f03f35564945680000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff258cb927989780ac92a3952ffd1f54e9b65e59fb07219eb106840b5d76b547fb0000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffffe98ec686efbca9bdd18ae85a3a8235a607e1cfb6138bac1461d400cbbabbe00f0000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffff0100e40b540200000017a91472c44f957fc011d97e3406667dca5b1c930c4026870247304402206b4de54956e864dfe3ff3a4957e329cf171e919498bb8f98c242bef7b0d5e3350220505355401a500aabf193b93492d6bceb93c3b183034f252d65a139245c7486a601210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f40247304402200fc48c7b5bd6de74c951250c60e8e6c9d3a605dc557bdc93ce86e85d2f27834a02205d2a8768adad669683416d1126c8537ab1eb36b0e83d5d9e6a583297b7f9d2cb01210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f40247304402207ad97500fbe6049d559a1e10586cd0b1f02baeb98dc641a971a506a57288aa0002202a6646bc4262904f6d1a9288c12ff586b5a674f5a351dfaba2698c8b8265366f01210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f4024730440220271e41a1e8f953b6817333e43d6a5e2924b291d52120011a5f7f1fb8049ae41b02200f1a25ed9da813122caadf8edf8d01da190f9407c2b61c27d4b671e07136bce701210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022050291184dcd4733de6e6a43d9efb1e21e7d2c563e9138481f04010f3acbb139f02206c01c3bfe4e5b71c4aac524a18f35e25ae7306ca110b3c3b079ae6da2b0a0a5701210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022045a188c10aec4f1a3a6c8a3a3c9f7d4dc63b9eacc011839c907d1c5da206a1390220399ca60516204efd9d220eaa0c804867137133c4d70780223fdde699288af3790121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d7802473044022053621a5c74b313c648d179041c154152372060941d9c9080340eb913358b705602201ac178f639360356ca7d75656d92bd7801d976e74bd5d2e30d6310a94940d0bc0121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d780247304402207b4a7a271a8fc03e8045ca367cb64046fa06e5b13a105e67efe7dd6571503fcb022072852e1c3f87eeac039601a0df855fb5d65bbdcd3ad95ff96bfc7b534fd89f7601210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022037e9f0943a79e155a57526e251cfd39e004552b76c0de892448eb939d2d12fdf02203a02f0045e8f90739eddc06c026c95b4a653aeb89528d851ab75952fd7db07b801210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022057a9953ba83d5e710fc64e1c533d81b0913f434b3e1c865cebd6cb106e09fa77022012930afe63ae7f1115a2f3b13039e71387fc2d4ed0e36eaa7be55a754c8c84830121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d78130e00009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f3010500000000"

	stackData, err := CfdGoGetConfidentialTxInPeginWitness(peginTx, uint32(0), uint32(1))
	assert.NoError(t, err)
	assert.Equal(t, "25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a", stackData)

	count, err := CfdGoGetConfidentialTxInPeginWitnessCount(peginTx, uint32(0))
	assert.NoError(t, err)
	assert.Equal(t, uint32(6), count)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestFundRawTransaction(t *testing.T) {
	assets, utxos := GetCoinSelectionTestData()
	netType := int(KCfdNetworkLiquidv1)
	option := NewCfdFundRawTxOption(netType)
	option.EffectiveFeeRate = float64(0.15)
	option.LongTermFeeRate = float64(0.15)
	option.MinimumBits = 36
	option.FeeAsset = assets[0]

	targets := []CfdFundRawTxTargetAmount{
		{
			Amount:          int64(115800000),
			Asset:           assets[0],
			ReservedAddress: "ex1qdnf34k9c255nfa9anjx0sj5ne0t6f80p5rne4e",
		},
		{
			Amount:          int64(347180040),
			Asset:           assets[1],
			ReservedAddress: "ex1q3tlca6nma70vvrf46up5ktjguxqwj0zamt7ktn",
		},
		{
			Amount:          int64(37654100),
			Asset:           assets[2],
			ReservedAddress: "ex1q0xdg60c3y5dk5m05hg2k52xavjkedx53t3k40m",
		},
	}
	txinList := []CfdUtxo{
		{
			Txid:            "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff",
			Vout:            uint32(0),
			Amount:          int64(112340000),
			Asset:           assets[0],
			Descriptor:      "sh(wpkh([ef735203/0'/0'/7']022c2409fbf657ba25d97bb3dab5426d20677b774d4fc7bd3bfac27ff96ada3dd1))#4z2vy08x",
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
		},
	}
	txHex := "010000000001fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000feffffff010100000000000000000000000000000000000000000000000000000000000000aa010000000006b22c2000160014c6598809d09edaacb8f4f4d5b9b81e4413a5724311000000"

	expTxHex := "010000000006fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000feffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000feffffff0ad4a335556c64c3e2599c3a4c3ddff5b28f616fa55cf2323d2ae642eef74a8f0000000000feffffff030b0000000000000000000000000000000000000000000000000000000000000000000000feffffff020b0000000000000000000000000000000000000000000000000000000000000000000000feffffff010c0000000000000000000000000000000000000000000000000000000000000000000000feffffff050100000000000000000000000000000000000000000000000000000000000000aa010000000006b22c2000160014c6598809d09edaacb8f4f4d5b9b81e4413a572430100000000000000000000000000000000000000000000000000000000000000aa01000000000000026a00000100000000000000000000000000000000000000000000000000000000000000bb010000000014b18c12001600148aff8eea7bef9ec60d35d7034b2e48e180e93c5d0100000000000000000000000000000000000000000000000000000000000000cc0100000000023e8eb800160014799a8d3f11251b6a6df4ba156a28dd64ad969a910100000000000000000000000000000000000000000000000000000000000000aa010000000006fc2142001600146cd31ad8b8552934f4bd9c8cf84a93cbd7a49de111000000"
	expFee := int64(618)

	outputTx, fee, usedAddressList, err := CfdGoFundRawTransaction(netType, txHex, txinList, utxos, targets, &option)
	assert.NoError(t, err)
	assert.Equal(t, expTxHex, outputTx)
	assert.Equal(t, expFee, fee)
	assert.Equal(t, 3, len(usedAddressList))
	if len(usedAddressList) == 3 {
		assert.Equal(t, "ex1q3tlca6nma70vvrf46up5ktjguxqwj0zamt7ktn", usedAddressList[0])
		assert.Equal(t, "ex1q0xdg60c3y5dk5m05hg2k52xavjkedx53t3k40m", usedAddressList[1])
		assert.Equal(t, "ex1qdnf34k9c255nfa9anjx0sj5ne0t6f80p5rne4e", usedAddressList[2])
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestFundRawTransaction2(t *testing.T) {
	assets := []string{
		"aa00000000000000000000000000000000000000000000000000000000000000",
		"bb00000000000000000000000000000000000000000000000000000000000000",
		"cc00000000000000000000000000000000000000000000000000000000000000",
	}
	utxos := []CfdUtxo{
		{
			Txid:       "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
			Vout:       uint32(0),
			Amount:     int64(5000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(037ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a))",
		},
		{
			Txid:       "30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a",
			Vout:       uint32(0),
			Amount:     int64(100000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(0330f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a))",
		},
		{
			Txid:       "9e1ead91c432889cb478237da974dd1e9009c9e22694fd1e3999c40a1ef59b0a",
			Vout:       uint32(0),
			Amount:     int64(95000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(032d04e0b1474a82ad68c0ef37e1a7cf6c75ef01b22c00882e8e4e127a942823a1))",
		},
		{
			Txid:       "8f4af7ee42e62a3d32f25ca56f618fb2f5df3d4c3a9c59e2c3646c5535a3d40a",
			Vout:       uint32(0),
			Amount:     int64(100000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(03a7fb569db921abf70f1b6b9ad9ac863196deecd99d606b139bba7d740d1cc5bf))",
		},
		{
			Txid:       "4d97d0119b90421818bff4ec9033e5199199b53358f56390cb20f8148e76f40a",
			Vout:       uint32(0),
			Amount:     int64(99992500),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(02df74fc8124ff6f3982e90afb318f3e955b10f58c4c6014b3a767e16160f811d9))",
		},
		{
			Txid:       "4d97d0119b90421818bff4ec9033e5199199b53358f56390cb20f8148e76f40a",
			Vout:       uint32(1),
			Amount:     int64(94992500),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(029222484db385d268a2a4604ea40fd2228401061f741ad9da8c907ba9df29c2d3))",
		},
		{
			Txid:       "4d97d0119b90421818bff4ec9033e5199199b53358f56390cb20f8148e76f40a",
			Vout:       uint32(2),
			Amount:     int64(5000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(038f9011753b74fa0134d4b64a1491f99e0c4c0e16da616627c1f6a93c5e7555c0))",
		},
	}
	netType := int(KCfdNetworkLiquidv1)
	option := NewCfdFundRawTxOption(netType)
	option.EffectiveFeeRate = float64(0.15)
	option.FeeAsset = assets[0]

	targets := []CfdFundRawTxTargetAmount{
		{
			Amount:          int64(0),
			Asset:           assets[0],
			ReservedAddress: "ex1qdnf34k9c255nfa9anjx0sj5ne0t6f80p5rne4e",
		},
	}
	txinList := []CfdUtxo{}
	txHex := "010000000000010100000000000000000000000000000000000000000000000000000000000000aa010000000002faf08000160014c6598809d09edaacb8f4f4d5b9b81e4413a5724311000000"

	outputTx, fee, usedAddressList, err := CfdGoFundRawTransaction(netType, txHex, txinList, utxos, targets, &option)
	assert.NoError(t, err)
	assert.Equal(t, "0100000000010af4768e14f820cb9063f55833b5999119e53390ecf4bf181842909b11d0974d0100000000feffffff030100000000000000000000000000000000000000000000000000000000000000aa010000000002faf08000160014c6598809d09edaacb8f4f4d5b9b81e4413a572430100000000000000000000000000000000000000000000000000000000000000aa01000000000000011900000100000000000000000000000000000000000000000000000000000000000000aa010000000002ae86db001600146cd31ad8b8552934f4bd9c8cf84a93cbd7a49de111000000", outputTx)
	assert.Equal(t, int64(281), fee)
	assert.Equal(t, 1, len(usedAddressList))
	if len(usedAddressList) == 1 {
		assert.Equal(t, "ex1qdnf34k9c255nfa9anjx0sj5ne0t6f80p5rne4e", usedAddressList[0])
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestFundRawTransaction3(t *testing.T) {
	assets := []string{
		"6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
		"f59c5f3e8141f322276daa63ed5f307085808aea6d4ef9ba61e28154533fdec7",
	}
	utxos := []CfdUtxo{
		{
			Txid:       "cd4433fd3d014187050aefe878f76ab76aa8b1eef3ba965cb8dc76b0d271d002",
			Vout:       uint32(2),
			Amount:     int64(999799),
			Asset:      assets[0],
			Descriptor: "wpkh(02db28ad892aa1e500d1e88ffa24200088bc82a8a87807cd13a1d1a1c7799c41e5)",
		},
		{
			Txid:       "62ac8a5272b67aab0ca60db859bed64729463de72ee1743fd7eb9c72f4437b06",
			Vout:       uint32(0),
			Amount:     int64(19999),
			Asset:      assets[1],
			Descriptor: "wpkh(023004f49c61a63e339fa554e218774d6b4752bbfcfca61fe1c567b96af196b524)",
		},
		{
			Txid:       "376906dfec46e2abc2c98cc4a51d725cb8bbc5ece38ae1127c90802823202988",
			Vout:       uint32(2),
			Amount:     int64(1),
			Asset:      assets[1],
			Descriptor: "wpkh(02272bcdbec1c0a2170e72f2d8cf42188d59ea7eae9296d60d435af3fe465d9bb5)",
		},
	}

	netType := int(KCfdNetworkLiquidv1)
	option := NewCfdFundRawTxOption(netType)
	option.EffectiveFeeRate = float64(0.15)
	option.FeeAsset = assets[0]
	option.KnapsackMinChange = int64(0)
	targets := []CfdFundRawTxTargetAmount{
		{
			Amount:          int64(0),
			Asset:           assets[1],
			ReservedAddress: "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8",
		},
		{
			Amount:          int64(0),
			Asset:           assets[0],
			ReservedAddress: "lq1qqgv5wwfp4h0pfnyy2kkxl0kg3qnahcpfq7emrxu9xusz879axq0spg9cxu8wf72ktsft5r8vxnkfd8s5kmg32fvy8texp5p6s",
		},
	}
	txinList := []CfdUtxo{}

	txHex, err := CfdGoAddConfidentialTxOut(
		"0200000000000000000000",
		"f59c5f3e8141f322276daa63ed5f307085808aea6d4ef9ba61e28154533fdec7",
		int64(20000), "",
		"lq1qqg0hpf63fs29e7cpep63hy4vtv6334v947e9dkhfh397ge9l234vv2d2jzk547809pvaq4e7d884v72hagesq35ggggjtedtw", "", "")
	assert.NoError(t, err)
	assert.Equal(t, "0200000000000101c7de3f535481e261baf94e6dea8a808570305fed63aa6d2722f341813e5f9cf5010000000000004e20021f70a7514c145cfb01c8751b92ac5b3518d585afb256dae9bc4be464bf546ac616001429aa90ad4af8ef2859d0573e69cf567957ea330000000000", txHex)

	outputTx, fee, usedAddressList, err := CfdGoFundRawTransaction(netType, txHex, txinList, utxos, targets, &option)
	assert.NoError(t, err)
	assert.Equal(t, "02000000000302d071d2b076dcb85c96baf3eeb1a86ab76af778e8ef0a058741013dfd3344cd0200000000ffffffff067b43f4729cebd73f74e12ee73d462947d6be59b80da60cab7ab672528aac620000000000ffffffff882920232880907c12e18ae3ecc5bbb85c721da5c48cc9c2abe246ecdf0669370200000000ffffffff0301c7de3f535481e261baf94e6dea8a808570305fed63aa6d2722f341813e5f9cf5010000000000004e20021f70a7514c145cfb01c8751b92ac5b3518d585afb256dae9bc4be464bf546ac616001429aa90ad4af8ef2859d0573e69cf567957ea3300016d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f01000000000000012f0000016d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f0100000000000f40480219473921adde14cc8455ac6fbec88827dbe02907b3b19b85372023f8bd301f00160014a0b8370ee4f9565c12ba0cec34ec969e14b6d11500000000", outputTx)
	assert.Equal(t, int64(303), fee)
	assert.Equal(t, 1, len(usedAddressList))
	if len(usedAddressList) == 1 {
		assert.Equal(t, "lq1qqgv5wwfp4h0pfnyy2kkxl0kg3qnahcpfq7emrxu9xusz879axq0spg9cxu8wf72ktsft5r8vxnkfd8s5kmg32fvy8texp5p6s", usedAddressList[0])
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestGetCommitment(t *testing.T) {
	assetCommitment, err := CfdGoGetAssetCommitment(
		"6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
		"346dbdba35c19f6e3958a2c00881024503f6611d23d98d270b98ef9de3edc7a3")
	assert.NoError(t, err)
	assert.Equal(t, "0a533b742a568c0b5285bf5bdfe9623a78082d19fac9be1678f7c3adbb48b34d29",
		assetCommitment)

	amount := int64(13000000000000)
	amountCommitment, err := CfdGoGetAmountCommitment(
		amount, assetCommitment,
		"fe3357df1f35df75412d9ad86ebd99e622e26019722f316027787a685e2cd71a")
	assert.NoError(t, err)
	assert.Equal(t, "08672d4e2e60f2e8d742552a8bc4ca6335ed214982c7728b4483284169aaae7f49",
		amountCommitment)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestSplitTxOutByElements(t *testing.T) {
	txHex, err := CfdGoSplitConfidentialTxOut(
		"02000000000109c4149d4e59119f2b11b3e160b02694bc4ecbf56f6de4ab587128f86bf4e7d30000000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000005ee3fe00374eb131b54a7b528e5449b3827bcaa5069c259346810f20cf9079bd17b32fe481976a914d753351535a2a55f33ab39bbd6c70a55d46904e788ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000",
		0,
		[]CfdConfidentialTxOut{
			{
				Amount:  9000000,
				Address: "ert1qz33wef9ehrvd7c64p27jf5xtvn50946xeekx50",
			},
			{
				Amount:  500000,
				Address: "XWMioJVK77vhKHgnSpaCcSBDgf93LFHzYg",
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "02000000000109c4149d4e59119f2b11b3e160b02694bc4ecbf56f6de4ab587128f86bf4e7d30000000000ffffffff0401f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f0100000000055d4a800374eb131b54a7b528e5449b3827bcaa5069c259346810f20cf9079bd17b32fe481976a914d753351535a2a55f33ab39bbd6c70a55d46904e788ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000001f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000000895440001600141462eca4b9b8d8df63550abd24d0cb64e8f2d74601f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a1200017a914d081b8e259b744aa903e1831cfce8956941273ce8700000000", txHex)

	txHex, err = CfdGoSplitConfidentialTxOut(
		"020000000002a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000ffffffffa38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0200000000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001c8400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000befe33cc397c03f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef3116871976a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac00000000",
		1,
		[]CfdConfidentialTxOut{
			{
				Amount:  9997999992700,
				Address: "lq1qqf6e92446smp3hdp87a8rcue8nt4z7n39576f9nycphwr0farac2laprx8zp3m69z7axgjkka87fj6q66sunwxxytxeqzrd9w",
			},
			{
				Amount:  1000000000,
				Address: "Azpn9vbC1Sjvwc2evnjaZjEHPdQxvdr4sTew6psnwxoomvdDBfpfDJNXU4Zthvhy1TkUgX4USjTZpjSL",
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "020000000002a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000ffffffffa38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0200000000ffffffff040125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001c8400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000b5e620f4800003f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef3116871976a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000917d73cef7c027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af160014f42331c418ef4517ba644ad6e9fc99681ad439370125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000003b9aca00027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af17a9149ec42b6cfa1b0bc3f55f07af29867057cb0b8a2e8700000000", txHex)

	txHex, err = CfdGoSplitConfidentialTxOut(
		"020000000002a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000ffffffffa38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0200000000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001c8400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000befe33cc397c03f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef3116871976a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac00000000",
		1,
		[]CfdConfidentialTxOut{
			{
				Amount:          9997999992700,
				LockingScript:   "0014f42331c418ef4517ba644ad6e9fc99681ad43937",
				CommitmentNonce: "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
			},
			{
				Amount:          1000000000,
				LockingScript:   "a9149ec42b6cfa1b0bc3f55f07af29867057cb0b8a2e87",
				CommitmentNonce: "027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af",
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "020000000002a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000ffffffffa38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0200000000ffffffff040125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001c8400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000b5e620f4800003f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef3116871976a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000917d73cef7c027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af160014f42331c418ef4517ba644ad6e9fc99681ad439370125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000003b9aca00027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af17a9149ec42b6cfa1b0bc3f55f07af29867057cb0b8a2e8700000000", txHex)

	indexes, err := CfdGoGetTxOutIndexes(
		int(KCfdNetworkLiquidv1),
		"020000000002a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000ffffffffa38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0200000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001c8400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000befe33cc397c03f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef3116871976a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000befe33cc397c03f234757d0e00e6a7a7a3b4b2b31fb0328d7b9f755cd1093d9f61892fef3116871976a91435ef6d4b59f26089dfe2abca21408e15fee42a3388ac00000000",
		"2deLw2MsbXTr44ZXKBS91midF2WzJPfQ8cz",
		"")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(indexes))
	if len(indexes) == 2 {
		assert.Equal(t, uint32(1), indexes[0])
		assert.Equal(t, uint32(2), indexes[1])
	}

	txHex, err = CfdGoUpdateWitnessStack(
		int(KCfdNetworkLiquidv1),
		"0200000001010e3c60901da7ffc518253e5736b9b73fd8aa5f79f249fa75bfe662c0f6ee42c301000000171600140c2eade9f3c984d0b2cedc79075a5793b0f5ce05ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000005f5e100001976a914b3c03c18599d13a481d1eb8a0ac2cc156564b4c688ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a1200000000000000000024730440220437d443d290dcbd21b9dfdc612ac6cc5134f5acca19aa3c90b870ec41480839d02205662e29994c06cbeba70640aa74c7a4aafa50dba52ff45117800a1680240af6b0104111111110000000000",
		"c342eef6c062e6bf75fa49f2795faad83fb7b936573e2518c5ffa71d90603c0e",
		1,
		1,
		"02d8595abf5033d37a8a04947a537e8b28e2cb863e1ccd742012334c47e2c87a09")
	assert.NoError(t, err)
	assert.Equal(t, "0200000001010e3c60901da7ffc518253e5736b9b73fd8aa5f79f249fa75bfe662c0f6ee42c301000000171600140c2eade9f3c984d0b2cedc79075a5793b0f5ce05ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000005f5e100001976a914b3c03c18599d13a481d1eb8a0ac2cc156564b4c688ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a1200000000000000000024730440220437d443d290dcbd21b9dfdc612ac6cc5134f5acca19aa3c90b870ec41480839d02205662e29994c06cbeba70640aa74c7a4aafa50dba52ff45117800a1680240af6b012102d8595abf5033d37a8a04947a537e8b28e2cb863e1ccd742012334c47e2c87a090000000000", txHex)

	txHex, err = CfdGoUpdatePeginWitnessStack(
		"0200000001017926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000002540ba97c0017a91414b71442e11941fd7807a82eabee13d6ec171ed9870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000003a84000000000000000000060800e40b54020000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f16001412dcdeef890f60967896391c95b0e02c9258dfe5fdda060200000000010a945efd42ce42de413aa7398a95c35facc14ec5d35bb23e5f980014e94ab96a620000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffffe50b46ecadb5cc52a7ef149a23323464353415f02d7b4a943963b26a9beb2a030000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff67173609ca4c13662356a2507c71e5d497baeff56a3c42af989f3b270bc870560000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff784a9fd151fe2808949fae18afcf52244a77702b9a83950bc7ec52a8239104850000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff259618278cecbae1bed8b7806133d14987c3c6118d2744707f509c58ea2c0e870000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff5c30c2fdcb6ce0b666120777ec18ce5211dd4741f40f033648432694b0919da50000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffffbb0f857d4b143c74c7fdb678bf41b65e7e3f2e7644b3613ae6370d21c0882ad60000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffffbce488c283e07bf364edb5057e020aa3d137d8d6130711dc12f03f35564945680000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff258cb927989780ac92a3952ffd1f54e9b65e59fb07219eb106840b5d76b547fb0000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffffe98ec686efbca9bdd18ae85a3a8235a607e1cfb6138bac1461d400cbbabbe00f0000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffff0100e40b540200000017a91472c44f957fc011d97e3406667dca5b1c930c4026870247304402206b4de54956e864dfe3ff3a4957e329cf171e919498bb8f98c242bef7b0d5e3350220505355401a500aabf193b93492d6bceb93c3b183034f252d65a139245c7486a601210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f40247304402200fc48c7b5bd6de74c951250c60e8e6c9d3a605dc557bdc93ce86e85d2f27834a02205d2a8768adad669683416d1126c8537ab1eb36b0e83d5d9e6a583297b7f9d2cb01210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f40247304402207ad97500fbe6049d559a1e10586cd0b1f02baeb98dc641a971a506a57288aa0002202a6646bc4262904f6d1a9288c12ff586b5a674f5a351dfaba2698c8b8265366f01210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f4024730440220271e41a1e8f953b6817333e43d6a5e2924b291d52120011a5f7f1fb8049ae41b02200f1a25ed9da813122caadf8edf8d01da190f9407c2b61c27d4b671e07136bce701210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022050291184dcd4733de6e6a43d9efb1e21e7d2c563e9138481f04010f3acbb139f02206c01c3bfe4e5b71c4aac524a18f35e25ae7306ca110b3c3b079ae6da2b0a0a5701210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022045a188c10aec4f1a3a6c8a3a3c9f7d4dc63b9eacc011839c907d1c5da206a1390220399ca60516204efd9d220eaa0c804867137133c4d70780223fdde699288af3790121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d7802473044022053621a5c74b313c648d179041c154152372060941d9c9080340eb913358b705602201ac178f639360356ca7d75656d92bd7801d976e74bd5d2e30d6310a94940d0bc0121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d780247304402207b4a7a271a8fc03e8045ca367cb64046fa06e5b13a105e67efe7dd6571503fcb022072852e1c3f87eeac039601a0df855fb5d65bbdcd3ad95ff96bfc7b534fd89f7601210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022037e9f0943a79e155a57526e251cfd39e004552b76c0de892448eb939d2d12fdf02203a02f0045e8f90739eddc06c026c95b4a653aeb89528d851ab75952fd7db07b801210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022057a9953ba83d5e710fc64e1c533d81b0913f434b3e1c865cebd6cb106e09fa77022012930afe63ae7f1115a2f3b13039e71387fc2d4ed0e36eaa7be55a754c8c84830121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d78130e00009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f3010500000000",
		"f393f3eb0c3c4642ae586301dcf9299d78d3bb0f4f1ddad0f4c2fd5093292679",
		0,
		5,
		"000000204e28f541a3b2400720e1b7034c037e98e4806deb13f93927bf325eea3bcd5436a701767035de031ba3471b589ea214b54f0baa26d1118d2fb13a679f7b4b472e71128b5dffff7f2000000000020000000237f9a1552febc7194d5fac93e52a10dde4009ff485fbcc172b22d621b58c2d69109d857925ebfb477c6e6e70069814f279e4a6d871af9165631df4e5982e22710105")
	assert.NoError(t, err)
	assert.Equal(t, "0200000001017926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000002540ba97c0017a91414b71442e11941fd7807a82eabee13d6ec171ed9870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000003a84000000000000000000060800e40b54020000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f16001412dcdeef890f60967896391c95b0e02c9258dfe5fdda060200000000010a945efd42ce42de413aa7398a95c35facc14ec5d35bb23e5f980014e94ab96a620000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffffe50b46ecadb5cc52a7ef149a23323464353415f02d7b4a943963b26a9beb2a030000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff67173609ca4c13662356a2507c71e5d497baeff56a3c42af989f3b270bc870560000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff784a9fd151fe2808949fae18afcf52244a77702b9a83950bc7ec52a8239104850000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff259618278cecbae1bed8b7806133d14987c3c6118d2744707f509c58ea2c0e870000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff5c30c2fdcb6ce0b666120777ec18ce5211dd4741f40f033648432694b0919da50000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffffbb0f857d4b143c74c7fdb678bf41b65e7e3f2e7644b3613ae6370d21c0882ad60000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffffbce488c283e07bf364edb5057e020aa3d137d8d6130711dc12f03f35564945680000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffff258cb927989780ac92a3952ffd1f54e9b65e59fb07219eb106840b5d76b547fb0000000017160014ca2041536307bbe086e8c7fe8563e1c9b9b6eb84feffffffe98ec686efbca9bdd18ae85a3a8235a607e1cfb6138bac1461d400cbbabbe00f0000000017160014a8a7c0032d1d283e39889861b3f05156e379cfb6feffffff0100e40b540200000017a91472c44f957fc011d97e3406667dca5b1c930c4026870247304402206b4de54956e864dfe3ff3a4957e329cf171e919498bb8f98c242bef7b0d5e3350220505355401a500aabf193b93492d6bceb93c3b183034f252d65a139245c7486a601210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f40247304402200fc48c7b5bd6de74c951250c60e8e6c9d3a605dc557bdc93ce86e85d2f27834a02205d2a8768adad669683416d1126c8537ab1eb36b0e83d5d9e6a583297b7f9d2cb01210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f40247304402207ad97500fbe6049d559a1e10586cd0b1f02baeb98dc641a971a506a57288aa0002202a6646bc4262904f6d1a9288c12ff586b5a674f5a351dfaba2698c8b8265366f01210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f4024730440220271e41a1e8f953b6817333e43d6a5e2924b291d52120011a5f7f1fb8049ae41b02200f1a25ed9da813122caadf8edf8d01da190f9407c2b61c27d4b671e07136bce701210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022050291184dcd4733de6e6a43d9efb1e21e7d2c563e9138481f04010f3acbb139f02206c01c3bfe4e5b71c4aac524a18f35e25ae7306ca110b3c3b079ae6da2b0a0a5701210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022045a188c10aec4f1a3a6c8a3a3c9f7d4dc63b9eacc011839c907d1c5da206a1390220399ca60516204efd9d220eaa0c804867137133c4d70780223fdde699288af3790121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d7802473044022053621a5c74b313c648d179041c154152372060941d9c9080340eb913358b705602201ac178f639360356ca7d75656d92bd7801d976e74bd5d2e30d6310a94940d0bc0121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d780247304402207b4a7a271a8fc03e8045ca367cb64046fa06e5b13a105e67efe7dd6571503fcb022072852e1c3f87eeac039601a0df855fb5d65bbdcd3ad95ff96bfc7b534fd89f7601210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022037e9f0943a79e155a57526e251cfd39e004552b76c0de892448eb939d2d12fdf02203a02f0045e8f90739eddc06c026c95b4a653aeb89528d851ab75952fd7db07b801210281465587e09d80f5a7b8ce94bab4a4571dc8cff4483cc9eb89e76ecfa650b6f402473044022057a9953ba83d5e710fc64e1c533d81b0913f434b3e1c865cebd6cb106e09fa77022012930afe63ae7f1115a2f3b13039e71387fc2d4ed0e36eaa7be55a754c8c84830121031c01fd031bc09b385d138b3b2f44ec04c03934b66f6485f37a17b4899f1b8d78130e000097000000204e28f541a3b2400720e1b7034c037e98e4806deb13f93927bf325eea3bcd5436a701767035de031ba3471b589ea214b54f0baa26d1118d2fb13a679f7b4b472e71128b5dffff7f2000000000020000000237f9a1552febc7194d5fac93e52a10dde4009ff485fbcc172b22d621b58c2d69109d857925ebfb477c6e6e70069814f279e4a6d871af9165631df4e5982e2271010500000000", txHex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestIssuance(t *testing.T) {
	blindingKey := "1c9c3636830860edfe1cc70649417f33b0799959ea7197a4e75a5ba2a326ddd3"
	confidentialAddress := "CTErYaEfjCbu7recW9N2PoJq4Qt6XAqSoEAq31vfjGjJvvLV3hRGnfGgFuyJw9AqYGgZh57nYLjzHGcM"
	tokenAmount := int64(1000000000)

	entropy, asset, token, txHex, err := CfdGoSetRawIssueAsset(
		"020000000001db3e7442a3a033e04def374fe6e3ce4351122655705e55e9fb02c7135508775e0000000000ffffffff02017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b9328e00017a9149d4a252d04e5072497ef2ac59574b1b14a7831b187017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000007a120000000000000",
		"5e77085513c702fbe9555e705526125143cee3e64f37ef4de033a0a342743edb",
		0,
		"0000000000000000000000000000000000000000000000000000000000000000",
		500000000,
		"CTEmp5tY22tBaWCEUiEUReuRcQV95geubpwi1By249nnCbFU94iv75V1Y1ESRET7gU8JqbxrBTSjkaUx",
		"",
		tokenAmount,
		confidentialAddress,
		"",
		false)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001db3e7442a3a033e04def374fe6e3ce4351122655705e55e9fb02c7135508775e0000008000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000001dcd650001000000003b9aca0004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b9328e00017a9149d4a252d04e5072497ef2ac59574b1b14a7831b187017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000007a12000000154d634b51f6463ef827c1aca10ebf9758ca38ed0b969d6be1f5e28afe021406e01000000001dcd6500024e93dfae62a90ff7ebf8813fd9ffcf1d22115b88c9020ac3a144eccef98e8b981976a9148bba9241b14f785130e7ff186901997a5a1cc65688ac019f8e8c650b600dd566a087727cf24c01a02095c0e4329c82f27bceb31cc880c901000000003b9aca0002fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad81976a914e55f5b7134f05f779d0913413b6e0cb7d208780488ac00000000", txHex)
	assert.Equal(t, "6e4021e0af285e1fbed669b9d08ea38c75f9eb10ca1a7c82ef63641fb534d654", asset)
	assert.Equal(t, "c980c81cb3ce7bf2829c32e4c09520a0014cf27c7287a066d50d600b658c8e9f", token)

	// blind
	baseAsset := "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179"
	txinList := []CfdBlindInputData{
		{
			Txid:             "5e77085513c702fbe9555e705526125143cee3e64f37ef4de033a0a342743edb",
			Vout:             0,
			Asset:            baseAsset,
			Amount:           1000000000,
			AssetBlindFactor: "28093061ab2e407c6015f8cb33f337ffb118eaf3beb2d254de64203aa27ecbf7",
			ValueBlindFactor: "f87734c279533d8beba96c5369e169e6caf5f307a34d72d4a0f9c9a7b8f8f269",
		},
	}
	txHex, err = CfdGoBlindRawTransaction(txHex, txinList, []CfdBlindOutputData{}, nil)
	assert.NoError(t, err)
	txHex, err = CfdGoAddTxSignWithPrivkey(
		int(KCfdNetworkLiquidv1), txHex,
		"5e77085513c702fbe9555e705526125143cee3e64f37ef4de033a0a342743edb", 0,
		int(KCfdP2wpkh),
		"03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6",
		"cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1",
		int64(1000000000), int(KCfdSigHashAll), false, true)
	assert.NoError(t, err)
	assert.Equal(t, "6e4021e0af285e1fbed669b9d08ea38c75f9eb10ca1a7c82ef63641fb534d654", asset)

	data, err := CfdGoGetConfidentialTxData(txHex)
	assert.NoError(t, err)

	feeUtxoIndex := uint32(0)
	tokenIndex := uint32(3)
	tokenAsset, tokenAmount2, assetBlinder, blinder, err := CfdGoUnblindTxOut(txHex, tokenIndex, blindingKey)
	assert.NoError(t, err)
	assert.Equal(t, token, tokenAsset)
	assert.Equal(t, tokenAmount, tokenAmount2)
	assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", assetBlinder)
	assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", blinder)

	_, _, vouts, err := GetConfidentialTxDataAll(txHex, true, false, int(KCfdNetworkLiquidv1))
	assert.NoError(t, err)
	amount3, asset3, assetBlinder2, blinder2, err := CfdGoUnblindData(
		blindingKey,
		vouts[tokenIndex].LockingScript,
		vouts[tokenIndex].Asset,
		vouts[tokenIndex].CommitmentValue,
		vouts[tokenIndex].CommitmentNonce,
		vouts[tokenIndex].Rangeproof)
	assert.NoError(t, err)
	assert.Equal(t, tokenAmount, amount3)
	assert.Equal(t, token, asset3)
	assert.Equal(t, assetBlinder, assetBlinder2)
	assert.Equal(t, blinder, blinder2)

	// create reissue base tx
	txHandle, err := InitializeTransaction(int(KCfdNetworkLiquidv1), uint32(2), uint32(0))
	assert.NoError(t, err)
	if err == nil {
		defer FreeTransactionHandle(txHandle)
		err = AddTransactionInput(txHandle, data.Txid, feeUtxoIndex, uint32(KCfdSequenceLockTimeFinal))
		assert.NoError(t, err)

		err = AddTransactionInput(txHandle, data.Txid, tokenIndex, uint32(KCfdSequenceLockTimeFinal))
		assert.NoError(t, err)

		// [0](change)=999000000
		err = AddTransactionOutput(txHandle, int64(999000000), "el1qqf4026u44983693n58xhxd9ej6l0q4seka289pluyqr4seext7v5jl9xs3ya8x54m2guds5rsu04s7m5k3wpv3dr07xgxdla8kdvflhxv603xs3tm3wz", "", baseAsset)
		assert.NoError(t, err)
		// [1](fee)=500000
		err = AddTransactionOutput(txHandle, int64(500000), "", "", baseAsset)
		assert.NoError(t, err)
		// [2](token)=1000000000
		err = AddTransactionOutput(txHandle, tokenAmount, "AzpotonWHeKeBs4mZfXbnVvNCR23oKZ5UzpccaAZeP3igcWZLT2anN1QdrTYPMcFBMRD5411hS7pmATo", "", token)
		assert.NoError(t, err)

		// set reissuance
		asset, err = SetReissueAsset(
			txHandle, data.Txid, tokenIndex, int64(300000000),
			assetBlinder, entropy, "AzpkYfJkupsG2p8Px1BafsjzaxKEoMUFKypr2x7jd6kZQHcRyx6zYtZHCUEEzzSayr8Kj9JPNnWceL7W", "")
		assert.NoError(t, err)
		assert.Equal(t, "6e4021e0af285e1fbed669b9d08ea38c75f9eb10ca1a7c82ef63641fb534d654", asset)

		asset2, assetAmount, _, _, lockingScript, _, _, err := CfdGoGetConfidentialTxOutByHandle(txHandle, 3)
		assert.NoError(t, err)
		assert.Equal(t, asset, asset2)
		assert.Equal(t, int64(300000000), assetAmount)
		assert.Equal(t, "a914f70fa95299789b76e11b35164ad9ff94b24954f587", lockingScript)
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestPegin(t *testing.T) {
	// fedpeg script
	fedpegScript := "522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae"
	privkey := "cUfipPioYnHU61pfYTH9uuNoswRXx8rtzXhJZrsPeVV1LRFdTxvp"
	pubkey, err := CfdGoGetPubkeyFromPrivkey("", privkey, true)
	assert.NoError(t, err)

	// create pegin address
	peginAddress, claimScript, _, err := CfdGoGetPeginAddress(int(KCfdNetworkRegtest), fedpegScript, int(KCfdP2shP2wsh), pubkey, "")
	assert.NoError(t, err)
	assert.Equal(t, "2MvmzAFKZ5xh44vyb7qY7NB2AoDuS55rVFW", peginAddress)
	assert.Equal(t, "0014e794713e386d83f32baa0e9d03e47c0839dc57a8", claimScript)

	// create bitcoin tx
	var btcTx string
	var btcTxData CfdTxData
	amount := int64(100000000)
	peginAmount := amount - int64(500)
	txHandle, err := InitializeTransaction(int(KCfdNetworkRegtest), uint32(2), uint32(0))
	assert.NoError(t, err)
	if err == nil {
		defer FreeTransactionHandle(txHandle)
		err = AddTransactionInput(txHandle, "ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c", 0, uint32(KCfdSequenceLockTimeFinal))
		assert.NoError(t, err)

		err = AddTransactionOutput(txHandle, peginAmount, peginAddress, "", "")
		assert.NoError(t, err)
		// add sign
		utxos := []CfdUtxo{
			{
				Txid:       "ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c",
				Vout:       uint32(0),
				Amount:     amount,
				Descriptor: "wpkh(cNYKHjNc33ZyNMcDck59yWm1CYohgPhr2DYyCtmWNkL6sqb5L1rH)",
			},
		}
		err = SetUtxoListByHandle(txHandle, utxos)
		assert.NoError(t, err)
		sighashType := NewSigHashType(int(KCfdSigHashAll))
		err = SignWithPrivkeyByHandle(txHandle,
			"ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c", 0,
			"cNYKHjNc33ZyNMcDck59yWm1CYohgPhr2DYyCtmWNkL6sqb5L1rH",
			sighashType, true, nil, nil)
		assert.NoError(t, err)

		btcTx, err = GetTransactionHex(txHandle)
		assert.NoError(t, err)
		assert.Equal(t, "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad800000000", btcTx)

		btcTxData, err = CfdGoGetTxInfoByHandle(txHandle)
		assert.NoError(t, err)
		assert.Equal(t, "12708508f0baf8691a3d7e22fd19afbf9bd8bf0d358e3310838bcc7916539c7b", btcTxData.Txid)
	}
	peginIndex := uint32(0)

	txoutProof := "00000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105"

	// create pegin tx
	var txHex string
	genesisBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	asset := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
	peginTxHandle, err := InitializeTransaction(int(KCfdNetworkElementsRegtest), uint32(2), uint32(0))
	assert.NoError(t, err)
	if err == nil {
		defer FreeTransactionHandle(peginTxHandle)
		err = AddPeginInput(peginTxHandle, btcTxData.Txid, peginIndex, peginAmount,
			asset, genesisBlockHash, claimScript, btcTx, txoutProof)
		assert.NoError(t, err)

		// amount: 99999500
		// [0]=99998500
		err = AddTransactionOutput(peginTxHandle, int64(99998500),
			"el1qqtl9a3n6878ex25u0wv8u5qlzpfkycc0cftk65t52pkauk55jqka0fajk8d80lafn4t9kqxe77cu9ez2dyr6sq54lwy009uex", "", asset)
		assert.NoError(t, err)
		// [1](fee)=1000
		err = AddTransactionOutput(peginTxHandle, int64(1000), "", "", asset)
		assert.NoError(t, err)

		txHex, err = GetTransactionHex(peginTxHandle)
		assert.NoError(t, err)

		// add dummy output (for blind)
		txHex, err = CfdGoAddConfidentialTxOut(txHex, asset, 0, "", "", "6a", "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9")
		assert.NoError(t, err)
		assert.Equal(t, "0200000001017b9c531679cc8b8310338e350dbfd89bbfaf19fd227e3d1a69f8baf0088570120000004000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5db2402fe5ec67a3f8f932a9c7b987e501f105362630fc2576d5174506dde5a94902dd7160014a7b2b1da77ffa99d565b00d9f7b1c2e44a6907a80125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000003e800000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000003662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9016a0000000000000006080cdff505000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014e794713e386d83f32baa0e9d03e47c0839dc57a8c0020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad8000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105000000000000", txHex)
	}

	// blind
	txinList := []CfdBlindInputData{
		{
			Txid:   btcTxData.Txid,
			Vout:   peginIndex,
			Asset:  asset,
			Amount: peginAmount,
		},
	}
	txHex, err = CfdGoBlindRawTransaction(txHex, txinList, []CfdBlindOutputData{}, nil)
	assert.NoError(t, err)
	// add sign
	_, err = CfdGoAddConfidentialTxSignWithPrivkey(
		txHex, btcTxData.Txid, peginIndex, int(KCfdP2wpkh), pubkey, privkey,
		peginAmount, "", int(KCfdSigHashAll), false, true)
	assert.NoError(t, err)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestPegout(t *testing.T) {
	// mainchain address descriptor
	mainchainXpubkey := "xpub6A53gzNdDBQYCtFFpZT7kUpoBGpzWigaukrdF9xoUZt7cYMD2qCAHVLsstNoQEDMFJWdX78KvT6yxpC76aGCN5mENVdWtFGcWZoKdtLq5jW"
	mainchainPubkey, err := CfdGoGetPubkeyFromExtkey(mainchainXpubkey, int(KCfdNetworkMainnet))
	assert.NoError(t, err)
	negateMainchainPubkey, err := CfdGoNegatePubkey(mainchainPubkey)
	assert.NoError(t, err)
	mainchainOutputDescriptor := "pkh(" + mainchainXpubkey + "/0/*)"
	bip32Counter := uint32(0)

	onlinePrivkey := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePubkey, err := CfdGoGetPubkeyFromPrivkey("", onlinePrivkey, true)
	assert.NoError(t, err)
	// whitelist
	pakEntry := negateMainchainPubkey + onlinePubkey
	whitelist := pakEntry
	mainchainNetwork := int(KCfdNetworkMainnet)
	elementsNetwork := int(KCfdNetworkLiquidv1)

	// pegout address
	pegoutAddress, baseDescriptor, err := CfdGoGetPegoutAddress(mainchainNetwork, elementsNetwork, mainchainOutputDescriptor, bip32Counter, int(KCfdP2pkhAddress))
	assert.NoError(t, err)
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddress)
	assert.Equal(t, "pkh("+mainchainXpubkey+")", baseDescriptor)

	// create pegout tx
	genesisBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	asset := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
	pegoutTxHandle, err := InitializeTransaction(int(KCfdNetworkElementsRegtest), uint32(2), uint32(0))
	assert.NoError(t, err)
	if err == nil {
		defer FreeTransactionHandle(pegoutTxHandle)
		err = AddTransactionInput(pegoutTxHandle, "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3", 0, 4294967293)
		assert.NoError(t, err)

		err = AddTransactionOutput(pegoutTxHandle, int64(209998999992700),
			"XBMr6srTXmWuHifFd8gs54xYfiCBsvrksA", "", asset)
		assert.NoError(t, err)
		address, err := AddPegoutOutput(pegoutTxHandle, asset, int64(1000000000),
			mainchainNetwork, elementsNetwork, genesisBlockHash, onlinePubkey, onlinePrivkey, mainchainOutputDescriptor, bip32Counter, whitelist)
		assert.NoError(t, err)
		assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", address)

		err = AddTransactionOutput(pegoutTxHandle, int64(7300), "", "", asset)
		assert.NoError(t, err)

		txHex, err := GetTransactionHex(pegoutTxHandle)
		assert.NoError(t, err)
		assert.Equal(t, "020000000001a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000befe33cc397c0017a914001d6db698e75a5a8af771730c4ab258af30546b870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000003b9aca0000a06a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a914efbced4774546c03a8554ce2da27c0300c9dd43b88ac2103700dcb030588ed828d85f645b48971de0d31e8c0244da46710d18681627f5a4a4101044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d00660125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001c84000000000000", txHex)

		pegoutAddress, hasPegout, err := CfdGoGetPegoutAddressFromTransaction(elementsNetwork, txHex, uint32(1), mainchainNetwork)
		assert.NoError(t, err)
		assert.True(t, hasPegout)
		assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddress)

		_, hasPegout, err = CfdGoGetPegoutAddressFromTransaction(elementsNetwork, txHex, uint32(0), mainchainNetwork)
		assert.NoError(t, err)
		assert.False(t, hasPegout)
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestSighashRangeproof(t *testing.T) {
	txHex := "020000000101b7fc3ad65a21649fdf9a225a6165a2f945e895f2eac6b2bbc1d2f3681080f8030000000000ffffffff030b3584c0a40110d0a208aad09ca9be67dbe5fc7343b6287a8abb122439def1cc8c094d982039de127c6ffb3a012d7a54cb790baf1e923f48307eefd189aaa830dd4f03536ffcfc5365ae010225b8011f8b94e495574b4d0527350fef11fdbd93dbe21b17a914a3949e9a8b0b813db67c8fc5ad14194a297979cd870bcf3a513f93f3098858ba760efdcea670e9675930b210b9b7e5c33a87ebe3823d08e6b041a5120606213de33e800d38636a5a18277badf9f9393db822b15f3973aa03eaa4f0b5baacb04a6d8b37b5e70584550be4962178e20a9c0aec5faef855ccc617a914a3949e9a8b0b813db67c8fc5ad14194a297979cd870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000027100000000000000000000043010001033a6e5463aeaf8460ef48520746c9a162f4b715eb6d4f00cb975e3b7a01e57092012829e2e1e87787fe5e04512e0b68500f97ae8771a44c05a87d3646e9215bfd4d0b602300000000000000014d3500fbe175b8e442af9d8322a0c892e2bca2c25561799c01c07f66cbb936e9c90404338f40bcf348912cc25855cbd38621076efd088b36b1933baf9513aea1bbd522551c82a478a7fa34e1dcda8ef648761031332ad5388ccbc171f9475c9fde056908bdec0b0c408c41691c4bed297da4b1740bbf0f81eb2ccf0f112ba6ca2c6f1d6bf3c1cecc613aaac01153bfaf7906df82402dcc8d0867eecd212fee82827e1ab5fb7ab448b36bed57bc9edb153544a961ee5e22a33385336e77f2b67dd6274c4d0232635c3112f7cb9dbb758beeac7db0ca1945c3497d1187aee1106181b2b2bd8c5602b1460085d2ac1319d0df500169a9344528feed3304ad212678e79946ebcf915cbbb9be47b0e850e0022c058e95e6e18d73227d354910b6d2ef7435c8a5f6e1355c2e35173e7bef86924a14a0f3e747562af1898a8c65ac52ba31bd860e81090f3cc1da296557685c4529681b25066d4db6febed3cbc3252e87df247a96a6f8c44550ebaf0610b3ebfdc80c744d41b4cb80b17d3ffa95024fac8ec40cbad4a2e442479e334021ee50218dabfec1d68bfda180d7d509e0d2da389f589ee6024791c2557b4175aae469e7e11b2779d1a8433ffe99ac7db6cbc7a4296c1eba50636839b1a378ad27c9fca08859689d5f08103c45f8de0eedabe7987afa9dd3aeb970cb8276c22fd329f182b8200b1d1a4baa88f2a82e54b40ae07cb10bd7c9bad09e59b461ea0f955791ace19af8dd90cb7b55cd09d319abc75686d15606b88356cf1f6838f59d61d473d4d128821d7628ac3c9b9068e65acfbab69fcbe498ee115fcb1cb3133d51d66e4727a4c37a56b66b940d40f4aaa16be4fc7a8c58d1df13614905472354a996f463c0102503a5191c4677a9666f3190555022a1f447d0cc45f65a845dd8a0a9fd9835948fe4aee490ead426df02327ce189458c85d08aad605810e5b9372023992040213e0df83c1d775c248edd7095271f88d065c073a15b37c3455b23ae946fa4cb7e40a14dc8810614deacf8ccab5634bce2f6475c35867c0c71add1d2af013269bc0973d8a54a78b2f6234c9520ea490f188aa493d612f5bef278cfb9f48e525f7eb202f3603bfe5d978b1233447872dff46a21b1d19ec8a8f6a9c4dc1c4ee3ebb4124b4c2a9d7d28705eecb04b9c592cee292155c7204a5a3f781cbc970d9549f5afba68d2e1ddc4b08ee3af6085716c7af487c92a1abe79d7c9f5027cb03190c9f47e05db5896cd94b119c53de617533dd7bdce57e9f3ce69cf8f25b6bcfce6d8abdcf14e098551d8f72256c2c04a5fb835f5b9f5ba1c7a5989a1c93e181240cb175e34ecedb9f2ef23614054f44cbaacb732e5529f02a7622c2ffaf811d205ed2be83f723ff8ba4ff23dbca65aabad5196c44c37982bbd5a54f9b38e776b52b8e817ca2f2c246dcd7b68922f9b2b4e8792c4a00c02a81de950afa532ce77ded61182f8fb65a49d416ffd697a8bab26feff05c9e0e7bcf028fd4775566f5864c4cdd51e425756369d9d4478ca027907511cedab3dcd098f9c9a019714a6ce3b40f54fcfaa6e035c4c8e566bb050ef9b9f4ac995155f2fcda379f94a3cf2819e5d57221ebe63af2dbcf319942728ada876379a0d98991d25125168307e089bd2bc24843d0b58f958d75b37f097dced7d7579d94346127d7a2029c1966ccf7e80ede17511da539ed2e4cb7b65f644e906f9c57c5a17ec9375ab5b9b867d1ab68a00371cbb5fa209d6badae3728723e0dff89cd5f9bd38dec57321b43b32c747b0f645e02df0ce9d946a723243d53a85232c4f26853b2d788c7f5c6e9974da549af5cf23813eaf88a409198729f12f5b83cccff34b6153e0d3adb79a3ce11dde701807519db5df63939d4ed44abd34971bc14a477ed35a7596907753477aabdfc15265f2625787d8a152f9b5deabc5371682657b0c9bd4dc20ca95e388de3454ec80ded9b9b268ec55e2f0816be7e9b979a81685e2885bce1f0c873d6f268fda1a8d4fe8f736e95842fc9b05f84ed1d14a67566dfe931fa13ffff2672d9f9d30b13e62ecca4ff20f462be0626c0b93493446ff90d7ff1bddd867c8c6d9ccee603ab0fb0896544a20f2f9a5f5928e026bfd0ea93cc4c26abcf6159fa2c15245f2f3190cfc201316985a17b666e16230598a84e4bc31a6ae90491ea1f4550f96360778342c84c494c9faa073624396d8ca2e1ced3b545959040be0a5cb9d8bedd9584ba2db6f3bbf2dca734806076cb406432793f7b3ba7bc4ac35325e97d1f48d219c9e0e5a1555cb49cd97fdbfda3034ef08073a490624e2e1b76450e091d878c3caf9fe066680b96af0db14d9939c489dfd387b2e86b89ecd4bf1e6cc4c7a7f0e4533c6dcb510bec483faac1a9bc73cf2e1e595e8ffad98c7c400601b56840766f4d7934b2cbd6aa70bf6ebd18436d23f963b1a7711b3966415e50a0b0c67cb6de142e1a1ba5d7dfa77542c44bbbaa0e95ed0e702a506fdab23ee7aaa7843083266693dfb6c31be76e0bc3b33fa18b11e95888a18cdc4793ae7bc1a4686c546a52c9843fa19739522cdbbf874ec59d0c38b6a4b3aedbfbe72d82b8efba6deac3cbdb2f18ac25de8c8f095f1c921431e6a7c342fb17e8d3a5cb809521765de4adb001ae63d92e109317d090425dcdc197dfdbe7440b857824ef6128397653e20c33f995b4c782db036b420945b4c2c3d953ead32378939e9b74537e2dd26cd360bac1dbf752f66f1ddbb03eede3c76efc619bb06ebac2a0cfbb6c40f9a2762995e0911950c07eb7b5ca642234e0c0df99db32dfe99253003c052db72d4f744e423cc28620e1742363e5745ba759d15b62f77bb9c6534bcc13ee8ef1381219ac07219f8a75caa256ab7c3fffd0c40f93556541c929a1754c289235c4f80b68f0cd0043c9e0c2922e512a0730a80c2b4bf038ee9d5ece4e5dbc1f84258a81da43e4921278f1e4aeffa6cbfb8b2f83e9dc756811a00a44a48498b7f0f1b8ab9b1808914cb66b3fd41e6d4ff6579747b2174b4651c66382fd6000b6db2dec4763f61667115113469b73de1d911af384a36f7e4c960e10102e015b8d1250af9ea7981e79d84b49f714aa3210fb6e7f9b2a860d9df18c981f69b479bfd744a6c054df476919407bd227c58c76f244c8b8ea4265912e95b4285da68be013e3888b92d57b8689ad1ef5c6f0d3c0bed3cf25e86931e7c4bf14042d8ca9b7c323b2875b981eb9b5883c4e3bd75233cd9ae19568a3adede390bcfa787067596ab704c9b057d6a91b77c514de5c034a96cb31db3393ead266aab3eaebf2fbeffa63c4202c5febaa3f2b848878a5c2235619071c10f6146868e735971c8a53f59d3235b0e3b4a460473e7173f29d42982f69cef40207d43e2fd308a7ff6421044c8960c991f33a9d3334a8d63109251f672fd89f75ae1d9b32559b73c5a22e019f46a503f9dfb5bc82deb5103dde9e91f145c7507ad55b21e0ff8f96b5dcb6222dc8c5e428ddd9e9c7658a8ba8d318aa6180e75c260bb83e16898a68711be33c0ba8906e3233c8c1f31c9fc75857655ef26ba7b53952dab096a48ccf9258490a0b6e05304da43a43878eb0740fe1f952b9028d450b904ebca2d00d036bd38a435ffcf73d795397a84ec18f72a93cdddd4b8dfdac4c6c7877e16b480e819857c8e18920beb0ee09e6c3b2b6baadcffeac776591744394eb512d5814c1f68ff0c73e2bb3e2f4e0186282cd8da6b8e96e1d5bca47c98329608edaebe36c01895638a7c728cf871d2f19d5833234d2277d3acfd60ebd6c4add790eee3758bd840bc22962f1fa2227ae2853813cc36b5be46e37b246f6a9b0a21b6159a82b5f92800941e33df02188761bc730c2b284aa15dd4545ae0f4c4229a4d8c9b415a691a355e1858a26c7433195a42e55c020cbc0efcb51b560d561715c546091d655dd5cac04b4ce0986941229591f33f7c96e9acef7e878043c49a4a420de859ff20695196c37660511276e43705f73751d68f7ef1929b3ab8e32faabc3c83ac13466c543650220aa2669a3ed7fe34d6f6e6ddb44e390b7338a8a3056a8643010001ff410fe519866271fcc3d47b83120429858ebaa008dce79ae35b4455d7ec3f3045ffab1a938bbf628ff8c14f87f08943acca6bdeebfb06c18b58ec8f4d1d9c51fd4d0b60230000000000000001e20700490755f44beb25382ec7d71b25290f105ca685a456ebd1a7c560386ec9d03fbcb13ae429d8a04902b5daf4ef10010551a2848a31c42a43dc4037705a3ccd2e329f4ae6b02bebe80e58062b374e35d099147cdb36dcbf174ced965c6697a4187f68eb482706f30b24c4312a93a576f07398cd3c5a001645885aa6fdd659a1aeebfd51fe2fe0fc8f26ca9071ee7480de50a9c0637a9c551fedb0215045a888c40d4629109d8c93be540df83c991ac8c1ac9c3e2bb798fcea1c4a4791925c01d349e4ee5832b6e3d53a6d2dc2193b78d97b3b0dd951a846d48d83ceb067518e558214fa17837b747285b80aa92200c5340bdfb727e55d72c26dbc7816073a3654b084022e2d951463a0838f4683ec74184f18af1c0fddbebe292b6615c3c12b7bc381943f2a0968df482be55dd45ce19491349f2cb982935c092cd281f24e3ccffea71f3c776dc79cd4338fc93e393d92de1456166bc1019c1252932f43408338c3a84716dc842cea2a069b057a968d73892429ffd02225550bef7faa19e580cda00ec18d1d60d8e338a9cab95aaa857c579904eea03873c96b23bdd7b2d7aa39d402d5e81cf3585d390c990ba6d786ff2e8183c15e8ca4faeebefd7630b54179a6edea020f6de31ba0b8f36173ba0caf6eace25d9aaaf2ec1ec3cf6a87caef74787447017a2f661598ca5252baccedcf3b7cab0d1bf3d13d69651d92c0dda2baed6f979b5bf5b1f9e4b60592da53cad89bdc53111aafa7a9d8874e7d9f145e128162b709db2557456a1f06789ff8508bce78b47fcd6d63914753e3c5002b1a3a31cf5ac6e42ab6638499c0b964681e854e7284a9fad3a96e5c53ead3ea652e9d0af6e6b86fd920edb6187fe22a03f47fb617ab4232155fd249922d4893d2c786abb074bd399b210e4461c75169f13b0ddedc25c4def03f9a7e6e58e1a9575fe59556cefab31114c3b59fcfe80883920aede6ca6db4db539367894bf9c0a465a0448c6b2f370a3c41e1a9790dcad74918f41dcc7f568559401bc4a471102e43489a731328aad4cb8f9cb459298569a724048b2e879964143837eee75e8a4906fc3bfa22581589f3ca9f6b9958c46a30747e54b5c7fe66f510c77d658458f2311140287b9fc421a48e17073707087f37c1098e9d60b67bac01f1b5b2feef6c1902bbe5581a1b13836f555e63f6fefcc715f4b818acb499ac17e9a3633bf97e975ac49cbf76aaa1ef85411a3fb9062195e202d03a6aed9b652bcb380424032cbaadc3a8b808414836fe68f29b62d27a22abdb5a618191707b442e9dba525fb13698c1af1d00db5927e8178eb7e69ecd21b3199b3eb10ce7d9619428070fa17664b0b8134b45c6c532c74fb32b581a63f3af2d675a74ab467703f4dfede85c7f570fe65c21f71c709db4ae94e4b6fb92314aafb88f953dc8ed3b28da983910413fc9bdc78627c98b519bcaec8de7cf21abbe44deea9c3bd4ead89433bbffaf7a00f1712c09601df224c9635612f97df35812b64fe88a6055d7a971611b358ff7c65320a4eec533a007824fbfb1f0640f5634a0875189321a692fda6e4b39c2e339e3072e181dd228603c82d232f3e7370d344512ea0c0ae8428835974600bbb5870bb922de9f47be0c4fc2f3632f4ae44c7029589f3463ea4418e51c4038788942306cf7715ff8a09bd27413211db78d165fd0a698968f1f1b1023feccb850c99596933da86be7cea9590ec25d487739a25f1552a7f06f8265111dbd65b20241557234a6ddff88a42222e3622c2bb8c0020ed5e21cbce129b734df3cccb008386f78eab530f9625117a0d6d29a396e849564a0c74ec2198da0200dd80a5071fb23f282d0ef2c9bb0290bbad54f91fb3175d38b66cd7b729e370f64948fccdd69703c99196afef66b2187f7a8b9ad13a012cd344e43dc16b3cfc28a680a9764c150c93bf1db12ccb98414aaefa426ef91360acdad7cc13be34660751a8af8f11975ebfb646e8fe5293b51553dfe22d8be3c7d1ab1c4850a362ce11d12b2048a64e8b6398eb5e2078a14eebd532542917b337033b6e82b35a8630cccf170bd73f7e6868634409f1c3351fc83ad399afb3847fbaa7beb4c534bbdbd87df1cb49c9462901f46f00d9e4a1c02c8d817ed31a8e77cdc271ca8f05498951dba32abc0153637790377917ce9d872a4853c67ea639befdc9873ebeb66c30b803d9866c8118e5c7ced668fab3a80b2d4b68f8a387dd0efe3b493888cd02479c7186eea9b58f6b4b8dca92dea056ba78a81d35b29e2586a25385e3574ba4e28ce2702fe1d781b38aae3dd7ab7375014e631421fedfef38b00bc2e622422c3e5cfaf92180c20903e1ab4e983ef8fa20201f47674ce3f85f37691c611155367075ed9e131606105973b428d2e2f7badd32bb4d460735aa5d5774835d5b25369a3959bc71e60a53696c7473101c76a36fcf84192dd3f8ed934c7485033519d1704c78aecda9c8abf0dc118879779dbf4ca888dfd4dad2a6e4bb832e0283563a6057237122f325c72eef7dc89adc842b6f305ed9b2e7b24723754a1d3a26e149b90ba51cb0207d46ccd0a69bd63ad1e95f641069f69639bdccea03428601606bc85a5f2b747a3476e3449ff2aeed12214468353a5326e322354fb56c3f1dac4fa61584ddc38c5a54c5fb8ec332085f50ebfffde12c46e0283656fd954d121191dea53d19fe287e8aee935011fa7b3a240afdb24db95f3ae77c86462028f5b054ef8af36d3f7b4453ad50f470fec39f95901a57d3b3bb01e952269983475f1d13c5a5921a8709332fa9586a0fd8f82f87d06e66e9ec2272fd67a9cfcc1f48b7a1da9a3af716216b811f03fcf4a12c8e832c4e36bcb83f7cae5dd17a385cb9a679d9cc64be8d9f972ea022cd9625664180e98c3f292e62b56b5bea3b9845ce720482f5fb6931dfbd35aa3fc816a776a4553360ec18888b1d9d9acb07edeb5908955373fe6984abc8dbc6724cfec5a908fd606169d0c5ff914e0db3f1a566602dba4265c67f3233b1623b016306d8d3bb0d8c2f47e101fb626c42849c9cd83b5dd7d148ff4a488b6929e52048cf0a61d8e2d506e5d6e70c8beac188de2c14bf8f7c385461257886baf4bf3ad78e16c657e3de62e5cb42015a2cce88516887e1995018a51fa5a2a6688613dde7edf213266e5520b73336cc775ea542908f3f76e67d2792e73afb3429aeae188e39aceb3d17652740ae37fb3639c16888336bc9f1cfea546d3443214d153405e03216ae0ebb79b949ead937daf5587409cf53b6be2428c289dedd6194c2a42719660bc3ca3706f8ba4141734b6e2734ec0e90bb267fc59b92e91a38f554097193494073fb7559b6571994dc5381b5b4ca4443665cf4da2f41dbc737b554a4266c5a40bccc36f94585788eaceddbcc6a082cc1265811c7546f562743264fd8c6926b4f28a7136583057701b8386ba7821ffb12ba742d8a475765c58c1ab68d44adf9a45127a9d0a456152f2ec1317c3c7dda48944fa8595d0e86662c311e6970bb6e51589105def2032e775d5025553d3f44c89044272f870aa7b19a7f71ae0e5d184b6cb7d9e697ae8a56ac1d5619e0d9f1673072928e201975ec84417c83c0fd611cde590995d7d44ad1dbc09c98e178e48bc861b37e46c5257c8a66f6323a1a33958b14eb811ab6c8827dbf16955d01b5ce46bd1e1b19afd48a70310dfbc54d8bb6ed68ec4612c71145bff3a1833e1bb8c52962ec51219abbb58de0ba4c6ca3105fc2c181809102df98ba0e6c22ed21c6d5b30fa2432e8065d5b2b98b95800d6e5600aef541990321bf28be3cff705457c9c00d2a727352e92d102b15a9f7105457b27f93111bf4552ae1588e69e7656e2f1cb723c969c6e8a886564bee122eab57b145fbb2781dea3c099633a80141dfddefa16d93ed7becedff15f196dbd8adff8c47affc10d75aec5e9e03828e371787276193cae56253fc54eb9d1bf925152ad5f3b671f3944f9f61ab35f52b3790c655dc6f0f30ce33169b563f85057b1235fbd62c1d0f9ae9642c639c951bde2baf544117687ab8a3682206ab35b010000"
	expTxHex := "020000000101b7fc3ad65a21649fdf9a225a6165a2f945e895f2eac6b2bbc1d2f3681080f8030000000000ffffffff030b3584c0a40110d0a208aad09ca9be67dbe5fc7343b6287a8abb122439def1cc8c094d982039de127c6ffb3a012d7a54cb790baf1e923f48307eefd189aaa830dd4f03536ffcfc5365ae010225b8011f8b94e495574b4d0527350fef11fdbd93dbe21b17a914a3949e9a8b0b813db67c8fc5ad14194a297979cd870bcf3a513f93f3098858ba760efdcea670e9675930b210b9b7e5c33a87ebe3823d08e6b041a5120606213de33e800d38636a5a18277badf9f9393db822b15f3973aa03eaa4f0b5baacb04a6d8b37b5e70584550be4962178e20a9c0aec5faef855ccc617a914a3949e9a8b0b813db67c8fc5ad14194a297979cd870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000027100000000000000000024730440220750ed6df0b947abbe4ed7addfa7160a9bd628e1b6e01305562e518c8e683f278022044badfa55477a26acc5f4a160fe7f1f4c7f9e8d6bfd535711802800e814a9ba3412103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d60043010001033a6e5463aeaf8460ef48520746c9a162f4b715eb6d4f00cb975e3b7a01e57092012829e2e1e87787fe5e04512e0b68500f97ae8771a44c05a87d3646e9215bfd4d0b602300000000000000014d3500fbe175b8e442af9d8322a0c892e2bca2c25561799c01c07f66cbb936e9c90404338f40bcf348912cc25855cbd38621076efd088b36b1933baf9513aea1bbd522551c82a478a7fa34e1dcda8ef648761031332ad5388ccbc171f9475c9fde056908bdec0b0c408c41691c4bed297da4b1740bbf0f81eb2ccf0f112ba6ca2c6f1d6bf3c1cecc613aaac01153bfaf7906df82402dcc8d0867eecd212fee82827e1ab5fb7ab448b36bed57bc9edb153544a961ee5e22a33385336e77f2b67dd6274c4d0232635c3112f7cb9dbb758beeac7db0ca1945c3497d1187aee1106181b2b2bd8c5602b1460085d2ac1319d0df500169a9344528feed3304ad212678e79946ebcf915cbbb9be47b0e850e0022c058e95e6e18d73227d354910b6d2ef7435c8a5f6e1355c2e35173e7bef86924a14a0f3e747562af1898a8c65ac52ba31bd860e81090f3cc1da296557685c4529681b25066d4db6febed3cbc3252e87df247a96a6f8c44550ebaf0610b3ebfdc80c744d41b4cb80b17d3ffa95024fac8ec40cbad4a2e442479e334021ee50218dabfec1d68bfda180d7d509e0d2da389f589ee6024791c2557b4175aae469e7e11b2779d1a8433ffe99ac7db6cbc7a4296c1eba50636839b1a378ad27c9fca08859689d5f08103c45f8de0eedabe7987afa9dd3aeb970cb8276c22fd329f182b8200b1d1a4baa88f2a82e54b40ae07cb10bd7c9bad09e59b461ea0f955791ace19af8dd90cb7b55cd09d319abc75686d15606b88356cf1f6838f59d61d473d4d128821d7628ac3c9b9068e65acfbab69fcbe498ee115fcb1cb3133d51d66e4727a4c37a56b66b940d40f4aaa16be4fc7a8c58d1df13614905472354a996f463c0102503a5191c4677a9666f3190555022a1f447d0cc45f65a845dd8a0a9fd9835948fe4aee490ead426df02327ce189458c85d08aad605810e5b9372023992040213e0df83c1d775c248edd7095271f88d065c073a15b37c3455b23ae946fa4cb7e40a14dc8810614deacf8ccab5634bce2f6475c35867c0c71add1d2af013269bc0973d8a54a78b2f6234c9520ea490f188aa493d612f5bef278cfb9f48e525f7eb202f3603bfe5d978b1233447872dff46a21b1d19ec8a8f6a9c4dc1c4ee3ebb4124b4c2a9d7d28705eecb04b9c592cee292155c7204a5a3f781cbc970d9549f5afba68d2e1ddc4b08ee3af6085716c7af487c92a1abe79d7c9f5027cb03190c9f47e05db5896cd94b119c53de617533dd7bdce57e9f3ce69cf8f25b6bcfce6d8abdcf14e098551d8f72256c2c04a5fb835f5b9f5ba1c7a5989a1c93e181240cb175e34ecedb9f2ef23614054f44cbaacb732e5529f02a7622c2ffaf811d205ed2be83f723ff8ba4ff23dbca65aabad5196c44c37982bbd5a54f9b38e776b52b8e817ca2f2c246dcd7b68922f9b2b4e8792c4a00c02a81de950afa532ce77ded61182f8fb65a49d416ffd697a8bab26feff05c9e0e7bcf028fd4775566f5864c4cdd51e425756369d9d4478ca027907511cedab3dcd098f9c9a019714a6ce3b40f54fcfaa6e035c4c8e566bb050ef9b9f4ac995155f2fcda379f94a3cf2819e5d57221ebe63af2dbcf319942728ada876379a0d98991d25125168307e089bd2bc24843d0b58f958d75b37f097dced7d7579d94346127d7a2029c1966ccf7e80ede17511da539ed2e4cb7b65f644e906f9c57c5a17ec9375ab5b9b867d1ab68a00371cbb5fa209d6badae3728723e0dff89cd5f9bd38dec57321b43b32c747b0f645e02df0ce9d946a723243d53a85232c4f26853b2d788c7f5c6e9974da549af5cf23813eaf88a409198729f12f5b83cccff34b6153e0d3adb79a3ce11dde701807519db5df63939d4ed44abd34971bc14a477ed35a7596907753477aabdfc15265f2625787d8a152f9b5deabc5371682657b0c9bd4dc20ca95e388de3454ec80ded9b9b268ec55e2f0816be7e9b979a81685e2885bce1f0c873d6f268fda1a8d4fe8f736e95842fc9b05f84ed1d14a67566dfe931fa13ffff2672d9f9d30b13e62ecca4ff20f462be0626c0b93493446ff90d7ff1bddd867c8c6d9ccee603ab0fb0896544a20f2f9a5f5928e026bfd0ea93cc4c26abcf6159fa2c15245f2f3190cfc201316985a17b666e16230598a84e4bc31a6ae90491ea1f4550f96360778342c84c494c9faa073624396d8ca2e1ced3b545959040be0a5cb9d8bedd9584ba2db6f3bbf2dca734806076cb406432793f7b3ba7bc4ac35325e97d1f48d219c9e0e5a1555cb49cd97fdbfda3034ef08073a490624e2e1b76450e091d878c3caf9fe066680b96af0db14d9939c489dfd387b2e86b89ecd4bf1e6cc4c7a7f0e4533c6dcb510bec483faac1a9bc73cf2e1e595e8ffad98c7c400601b56840766f4d7934b2cbd6aa70bf6ebd18436d23f963b1a7711b3966415e50a0b0c67cb6de142e1a1ba5d7dfa77542c44bbbaa0e95ed0e702a506fdab23ee7aaa7843083266693dfb6c31be76e0bc3b33fa18b11e95888a18cdc4793ae7bc1a4686c546a52c9843fa19739522cdbbf874ec59d0c38b6a4b3aedbfbe72d82b8efba6deac3cbdb2f18ac25de8c8f095f1c921431e6a7c342fb17e8d3a5cb809521765de4adb001ae63d92e109317d090425dcdc197dfdbe7440b857824ef6128397653e20c33f995b4c782db036b420945b4c2c3d953ead32378939e9b74537e2dd26cd360bac1dbf752f66f1ddbb03eede3c76efc619bb06ebac2a0cfbb6c40f9a2762995e0911950c07eb7b5ca642234e0c0df99db32dfe99253003c052db72d4f744e423cc28620e1742363e5745ba759d15b62f77bb9c6534bcc13ee8ef1381219ac07219f8a75caa256ab7c3fffd0c40f93556541c929a1754c289235c4f80b68f0cd0043c9e0c2922e512a0730a80c2b4bf038ee9d5ece4e5dbc1f84258a81da43e4921278f1e4aeffa6cbfb8b2f83e9dc756811a00a44a48498b7f0f1b8ab9b1808914cb66b3fd41e6d4ff6579747b2174b4651c66382fd6000b6db2dec4763f61667115113469b73de1d911af384a36f7e4c960e10102e015b8d1250af9ea7981e79d84b49f714aa3210fb6e7f9b2a860d9df18c981f69b479bfd744a6c054df476919407bd227c58c76f244c8b8ea4265912e95b4285da68be013e3888b92d57b8689ad1ef5c6f0d3c0bed3cf25e86931e7c4bf14042d8ca9b7c323b2875b981eb9b5883c4e3bd75233cd9ae19568a3adede390bcfa787067596ab704c9b057d6a91b77c514de5c034a96cb31db3393ead266aab3eaebf2fbeffa63c4202c5febaa3f2b848878a5c2235619071c10f6146868e735971c8a53f59d3235b0e3b4a460473e7173f29d42982f69cef40207d43e2fd308a7ff6421044c8960c991f33a9d3334a8d63109251f672fd89f75ae1d9b32559b73c5a22e019f46a503f9dfb5bc82deb5103dde9e91f145c7507ad55b21e0ff8f96b5dcb6222dc8c5e428ddd9e9c7658a8ba8d318aa6180e75c260bb83e16898a68711be33c0ba8906e3233c8c1f31c9fc75857655ef26ba7b53952dab096a48ccf9258490a0b6e05304da43a43878eb0740fe1f952b9028d450b904ebca2d00d036bd38a435ffcf73d795397a84ec18f72a93cdddd4b8dfdac4c6c7877e16b480e819857c8e18920beb0ee09e6c3b2b6baadcffeac776591744394eb512d5814c1f68ff0c73e2bb3e2f4e0186282cd8da6b8e96e1d5bca47c98329608edaebe36c01895638a7c728cf871d2f19d5833234d2277d3acfd60ebd6c4add790eee3758bd840bc22962f1fa2227ae2853813cc36b5be46e37b246f6a9b0a21b6159a82b5f92800941e33df02188761bc730c2b284aa15dd4545ae0f4c4229a4d8c9b415a691a355e1858a26c7433195a42e55c020cbc0efcb51b560d561715c546091d655dd5cac04b4ce0986941229591f33f7c96e9acef7e878043c49a4a420de859ff20695196c37660511276e43705f73751d68f7ef1929b3ab8e32faabc3c83ac13466c543650220aa2669a3ed7fe34d6f6e6ddb44e390b7338a8a3056a8643010001ff410fe519866271fcc3d47b83120429858ebaa008dce79ae35b4455d7ec3f3045ffab1a938bbf628ff8c14f87f08943acca6bdeebfb06c18b58ec8f4d1d9c51fd4d0b60230000000000000001e20700490755f44beb25382ec7d71b25290f105ca685a456ebd1a7c560386ec9d03fbcb13ae429d8a04902b5daf4ef10010551a2848a31c42a43dc4037705a3ccd2e329f4ae6b02bebe80e58062b374e35d099147cdb36dcbf174ced965c6697a4187f68eb482706f30b24c4312a93a576f07398cd3c5a001645885aa6fdd659a1aeebfd51fe2fe0fc8f26ca9071ee7480de50a9c0637a9c551fedb0215045a888c40d4629109d8c93be540df83c991ac8c1ac9c3e2bb798fcea1c4a4791925c01d349e4ee5832b6e3d53a6d2dc2193b78d97b3b0dd951a846d48d83ceb067518e558214fa17837b747285b80aa92200c5340bdfb727e55d72c26dbc7816073a3654b084022e2d951463a0838f4683ec74184f18af1c0fddbebe292b6615c3c12b7bc381943f2a0968df482be55dd45ce19491349f2cb982935c092cd281f24e3ccffea71f3c776dc79cd4338fc93e393d92de1456166bc1019c1252932f43408338c3a84716dc842cea2a069b057a968d73892429ffd02225550bef7faa19e580cda00ec18d1d60d8e338a9cab95aaa857c579904eea03873c96b23bdd7b2d7aa39d402d5e81cf3585d390c990ba6d786ff2e8183c15e8ca4faeebefd7630b54179a6edea020f6de31ba0b8f36173ba0caf6eace25d9aaaf2ec1ec3cf6a87caef74787447017a2f661598ca5252baccedcf3b7cab0d1bf3d13d69651d92c0dda2baed6f979b5bf5b1f9e4b60592da53cad89bdc53111aafa7a9d8874e7d9f145e128162b709db2557456a1f06789ff8508bce78b47fcd6d63914753e3c5002b1a3a31cf5ac6e42ab6638499c0b964681e854e7284a9fad3a96e5c53ead3ea652e9d0af6e6b86fd920edb6187fe22a03f47fb617ab4232155fd249922d4893d2c786abb074bd399b210e4461c75169f13b0ddedc25c4def03f9a7e6e58e1a9575fe59556cefab31114c3b59fcfe80883920aede6ca6db4db539367894bf9c0a465a0448c6b2f370a3c41e1a9790dcad74918f41dcc7f568559401bc4a471102e43489a731328aad4cb8f9cb459298569a724048b2e879964143837eee75e8a4906fc3bfa22581589f3ca9f6b9958c46a30747e54b5c7fe66f510c77d658458f2311140287b9fc421a48e17073707087f37c1098e9d60b67bac01f1b5b2feef6c1902bbe5581a1b13836f555e63f6fefcc715f4b818acb499ac17e9a3633bf97e975ac49cbf76aaa1ef85411a3fb9062195e202d03a6aed9b652bcb380424032cbaadc3a8b808414836fe68f29b62d27a22abdb5a618191707b442e9dba525fb13698c1af1d00db5927e8178eb7e69ecd21b3199b3eb10ce7d9619428070fa17664b0b8134b45c6c532c74fb32b581a63f3af2d675a74ab467703f4dfede85c7f570fe65c21f71c709db4ae94e4b6fb92314aafb88f953dc8ed3b28da983910413fc9bdc78627c98b519bcaec8de7cf21abbe44deea9c3bd4ead89433bbffaf7a00f1712c09601df224c9635612f97df35812b64fe88a6055d7a971611b358ff7c65320a4eec533a007824fbfb1f0640f5634a0875189321a692fda6e4b39c2e339e3072e181dd228603c82d232f3e7370d344512ea0c0ae8428835974600bbb5870bb922de9f47be0c4fc2f3632f4ae44c7029589f3463ea4418e51c4038788942306cf7715ff8a09bd27413211db78d165fd0a698968f1f1b1023feccb850c99596933da86be7cea9590ec25d487739a25f1552a7f06f8265111dbd65b20241557234a6ddff88a42222e3622c2bb8c0020ed5e21cbce129b734df3cccb008386f78eab530f9625117a0d6d29a396e849564a0c74ec2198da0200dd80a5071fb23f282d0ef2c9bb0290bbad54f91fb3175d38b66cd7b729e370f64948fccdd69703c99196afef66b2187f7a8b9ad13a012cd344e43dc16b3cfc28a680a9764c150c93bf1db12ccb98414aaefa426ef91360acdad7cc13be34660751a8af8f11975ebfb646e8fe5293b51553dfe22d8be3c7d1ab1c4850a362ce11d12b2048a64e8b6398eb5e2078a14eebd532542917b337033b6e82b35a8630cccf170bd73f7e6868634409f1c3351fc83ad399afb3847fbaa7beb4c534bbdbd87df1cb49c9462901f46f00d9e4a1c02c8d817ed31a8e77cdc271ca8f05498951dba32abc0153637790377917ce9d872a4853c67ea639befdc9873ebeb66c30b803d9866c8118e5c7ced668fab3a80b2d4b68f8a387dd0efe3b493888cd02479c7186eea9b58f6b4b8dca92dea056ba78a81d35b29e2586a25385e3574ba4e28ce2702fe1d781b38aae3dd7ab7375014e631421fedfef38b00bc2e622422c3e5cfaf92180c20903e1ab4e983ef8fa20201f47674ce3f85f37691c611155367075ed9e131606105973b428d2e2f7badd32bb4d460735aa5d5774835d5b25369a3959bc71e60a53696c7473101c76a36fcf84192dd3f8ed934c7485033519d1704c78aecda9c8abf0dc118879779dbf4ca888dfd4dad2a6e4bb832e0283563a6057237122f325c72eef7dc89adc842b6f305ed9b2e7b24723754a1d3a26e149b90ba51cb0207d46ccd0a69bd63ad1e95f641069f69639bdccea03428601606bc85a5f2b747a3476e3449ff2aeed12214468353a5326e322354fb56c3f1dac4fa61584ddc38c5a54c5fb8ec332085f50ebfffde12c46e0283656fd954d121191dea53d19fe287e8aee935011fa7b3a240afdb24db95f3ae77c86462028f5b054ef8af36d3f7b4453ad50f470fec39f95901a57d3b3bb01e952269983475f1d13c5a5921a8709332fa9586a0fd8f82f87d06e66e9ec2272fd67a9cfcc1f48b7a1da9a3af716216b811f03fcf4a12c8e832c4e36bcb83f7cae5dd17a385cb9a679d9cc64be8d9f972ea022cd9625664180e98c3f292e62b56b5bea3b9845ce720482f5fb6931dfbd35aa3fc816a776a4553360ec18888b1d9d9acb07edeb5908955373fe6984abc8dbc6724cfec5a908fd606169d0c5ff914e0db3f1a566602dba4265c67f3233b1623b016306d8d3bb0d8c2f47e101fb626c42849c9cd83b5dd7d148ff4a488b6929e52048cf0a61d8e2d506e5d6e70c8beac188de2c14bf8f7c385461257886baf4bf3ad78e16c657e3de62e5cb42015a2cce88516887e1995018a51fa5a2a6688613dde7edf213266e5520b73336cc775ea542908f3f76e67d2792e73afb3429aeae188e39aceb3d17652740ae37fb3639c16888336bc9f1cfea546d3443214d153405e03216ae0ebb79b949ead937daf5587409cf53b6be2428c289dedd6194c2a42719660bc3ca3706f8ba4141734b6e2734ec0e90bb267fc59b92e91a38f554097193494073fb7559b6571994dc5381b5b4ca4443665cf4da2f41dbc737b554a4266c5a40bccc36f94585788eaceddbcc6a082cc1265811c7546f562743264fd8c6926b4f28a7136583057701b8386ba7821ffb12ba742d8a475765c58c1ab68d44adf9a45127a9d0a456152f2ec1317c3c7dda48944fa8595d0e86662c311e6970bb6e51589105def2032e775d5025553d3f44c89044272f870aa7b19a7f71ae0e5d184b6cb7d9e697ae8a56ac1d5619e0d9f1673072928e201975ec84417c83c0fd611cde590995d7d44ad1dbc09c98e178e48bc861b37e46c5257c8a66f6323a1a33958b14eb811ab6c8827dbf16955d01b5ce46bd1e1b19afd48a70310dfbc54d8bb6ed68ec4612c71145bff3a1833e1bb8c52962ec51219abbb58de0ba4c6ca3105fc2c181809102df98ba0e6c22ed21c6d5b30fa2432e8065d5b2b98b95800d6e5600aef541990321bf28be3cff705457c9c00d2a727352e92d102b15a9f7105457b27f93111bf4552ae1588e69e7656e2f1cb723c969c6e8a886564bee122eab57b145fbb2781dea3c099633a80141dfddefa16d93ed7becedff15f196dbd8adff8c47affc10d75aec5e9e03828e371787276193cae56253fc54eb9d1bf925152ad5f3b671f3944f9f61ab35f52b3790c655dc6f0f30ce33169b563f85057b1235fbd62c1d0f9ae9642c639c951bde2baf544117687ab8a3682206ab35b010000"

	pubkey := "03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6"
	privkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	txid := "03f8801068f3d2c1bbb2c6eaf295e845f9a265615a229adf9f64215ad63afcb7"
	vout := uint32(0)
	sigHashType := (int)(KCfdSigHashAllPlusRangeproof)
	hashType := (int)(KCfdP2wpkh)
	txHex2, err := CfdGoAddConfidentialTxSignWithPrivkey(txHex, txid, vout, hashType, pubkey, privkey, int64(0), "09b6e7605917e27f35690dcae922f664c8a3b057e2c6249db6cd304096aa87a226", sigHashType, false, true)
	assert.NoError(t, err)
	assert.Equal(t, expTxHex, txHex2)

	// add sighashtype
	util := NewSchnorrUtil()
	bytes, err := NewByteDataFromHex("61f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f20872")
	assert.NoError(t, err)

	sighashType := NewSigHashType(int(KCfdSigHashAll))
	sighashType.Rangeproof = true
	_, err = util.AddSighashTypeInSignature(&bytes, sighashType)
	// Confirm that an error occurs because elements do not support it yet.
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid sighash type for schnorr signature.")
	// assert.Equal(t, "61f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f2087241", sig.ToHex())

	fmt.Printf("%s test done.\n", GetFuncName())
}
