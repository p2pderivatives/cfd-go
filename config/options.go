package config

import (
	types "github.com/cryptogarageinc/cfd-go/types"
)

type CfdConfigOption func(*CfdConfig)

// NetworkOption returns configuration option function.
func NetworkOption(networkType types.NetworkType) CfdConfigOption {
	return func(conf *CfdConfig) {
		if conf != nil {
			conf.Network = networkType
		}
	}
}

// BitcoinGenesisBlockHashOption returns configuration option function.
func BitcoinGenesisBlockHashOption(genesisBlockHash string) CfdConfigOption {
	return func(conf *CfdConfig) {
		if conf != nil {
			conf.BitcoinGenesisBlockHash = genesisBlockHash
		}
	}
}

// BitcoinAssetIdOption returns configuration option function.
func BitcoinAssetIdOption(bitcoinAssetId string) CfdConfigOption {
	return func(conf *CfdConfig) {
		if conf != nil {
			conf.BitcoinAssetId = bitcoinAssetId
		}
	}
}
