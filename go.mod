module github.com/dylanpoe/test

go 1.22.2

require (
	github.com/blocto/solana-go-sdk v1.30.0
	github.com/btcsuite/btcd v0.23.5-0.20231215221805-96c9fd8078fd
	github.com/btcsuite/btcd/btcec/v2 v2.2.0
	github.com/btcsuite/btcd/btcutil v1.1.0
	github.com/miguelmota/go-ethereum-hdwallet v0.1.2
	github.com/mr-tron/base58 v1.2.0
	github.com/tyler-smith/go-bip32 v1.0.0
	github.com/tyler-smith/go-bip39 v1.1.0
)

replace github.com/btcsuite/btcutil => github.com/btcsuite/btcd/btcutil v1.1.5

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/FactomProject/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/FactomProject/btcutilecc v0.0.0-20130527213604-d3a63a5752ec // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/ethereum/go-ethereum v1.10.17 // indirect
	golang.org/x/crypto v0.0.0-20220518034528-6f7dac969898 // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
)
