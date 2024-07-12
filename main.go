package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"

	"fmt"
	"sync"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/mr-tron/base58"

	"github.com/blocto/solana-go-sdk/types"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

type KeyManager struct {
	Mnemonic   string
	Passphrase string
	keys       map[string]*bip32.Key
	mux        sync.Mutex
}

// NewKeyManager return new key manager
// Mnemonic Should be provided
func NewKeyManager(mnemonic, passphrase string) (*KeyManager, error) {
	if mnemonic == "" {
		entropy, err := bip39.NewEntropy(128)
		if err != nil {
			return nil, err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
	}

	km := &KeyManager{
		Mnemonic:   mnemonic,
		Passphrase: passphrase,
		keys:       make(map[string]*bip32.Key, 0),
	}
	return km, nil
}

func (km *KeyManager) GetSeed() []byte {
	return bip39.NewSeed(km.Mnemonic, km.Passphrase)
}

func (km *KeyManager) getKey(path string) (*bip32.Key, bool) {
	km.mux.Lock()
	defer km.mux.Unlock()

	key, ok := km.keys[path]
	return key, ok
}

func (km *KeyManager) setKey(path string, key *bip32.Key) {
	km.mux.Lock()
	defer km.mux.Unlock()

	km.keys[path] = key
}

func (km *KeyManager) GetMasterKey() (*bip32.Key, error) {
	path := "m"

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	key, err := bip32.NewMasterKey(km.GetSeed())
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

type Key struct {
	Path     string
	bip32Key *bip32.Key
}

func CalculateFromPrivateKey(prvKey *btcec.PrivateKey, compress bool) (wif, address, segwitBech32, segwitNested, taproot string, err error) {
	// generate the wif(wallet import format) string
	btcwif, err := btcutil.NewWIF(prvKey, &chaincfg.MainNetParams, compress)
	if err != nil {
		return "", "", "", "", "", err
	}
	wif = btcwif.String()

	// generate a normal p2pkh address
	serializedPubKey := btcwif.SerializePubKey()
	addressPubKey, err := btcutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", "", "", err
	}
	address = addressPubKey.EncodeAddress()

	// generate a normal p2wkh address from the pubkey hash
	witnessProg := btcutil.Hash160(serializedPubKey)
	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", "", "", err
	}
	segwitBech32 = addressWitnessPubKeyHash.EncodeAddress()

	// generate an address which is
	// backwards compatible to Bitcoin nodes running 0.6.0 onwards, but
	// allows us to take advantage of segwit's scripting improvments,
	// and malleability fixes.
	serializedScript, err := txscript.PayToAddrScript(addressWitnessPubKeyHash)
	if err != nil {
		return "", "", "", "", "", err
	}
	addressScriptHash, err := btcutil.NewAddressScriptHash(serializedScript, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", "", "", err
	}
	segwitNested = addressScriptHash.EncodeAddress()

	// generate a taproot address
	tapKey := txscript.ComputeTaprootKeyNoScript(prvKey.PubKey())
	addressTaproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", "", "", err
	}
	taproot = addressTaproot.EncodeAddress()

	return wif, address, segwitBech32, segwitNested, taproot, nil
}
func (k *Key) Calculate(compress bool) (wif, address, segwitBech32, segwitNested, taproot string, err error) {
	prvKey, _ := btcec.PrivKeyFromBytes(k.bip32Key.Key)
	return CalculateFromPrivateKey(prvKey, compress)
}
func (km *KeyManager) GetKey(purpose, coinType, account, change, index uint32) (*Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d/%d`, 1, 2, account, change, index)

	key, ok := km.getKey(path)
	if ok {
		return &Key{Path: path, bip32Key: key}, nil
	}

	parent, err := km.GetChangeKey(purpose, coinType, account, change)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(index)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return &Key{Path: path, bip32Key: key}, nil
}

func (km *KeyManager) GetPurposeKey(purpose uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'`, 1)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetMasterKey()
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(purpose)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetCoinTypeKey(purpose, coinType uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'`, 1, 2)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetPurposeKey(purpose)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(coinType)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}
func (km *KeyManager) GetAccountKey(purpose, coinType, account uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'`, 1, 2, account)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetCoinTypeKey(purpose, coinType)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(account + 0x80000000)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetChangeKey(purpose, coinType, account, change uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d`, 1, 2, account, change)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetAccountKey(purpose, coinType, account)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(change)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func BTCADDRESS(mnemonic string) (address, wif string) {

	km, err := NewKeyManager(mnemonic, "")
	if err != nil {
		fmt.Printf("\n NewKeyManager:%v \n", err)
	}

	key, err := km.GetKey(0x8000002C, 0x80000000, 0, 0, uint32(0))
	if err != nil {
		log.Fatal(err)
	}
	wif, address, _, _, _, err = key.Calculate(true)
	if err != nil {
		log.Fatal(err)
	}

	return wif, address

}

func main() {
	i := 0
	for i = 0; i < 1; i++ {
		entropy, err := bip39.NewEntropy(128)
		if err != nil {
			fmt.Printf("\n generateKey:%v \n", err)

		}

		mnemonic, _ := bip39.NewMnemonic(entropy)

		// BTC ADDRESS
		addressbtc, addresswif := BTCADDRESS(mnemonic)
		seed := bip39.NewSeed(mnemonic, "") //这里可以选择传入指定密码或者空字符串，不同密码生成的助记词不同,建议传入空字符

		wallet, err := hdwallet.NewFromSeed(seed)
		if err != nil {
			fmt.Printf("\n NewFromSeed:%v \n", err)
		}

		path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0") //从0开始，相同助记词可以生产无限个地址
		account, err := wallet.Derive(path, false)
		if err != nil {
			fmt.Printf("\n Derive:%v \n", err)
		}

		// ETH address
		address := account.Address.Hex()
		address_ETH := address
		privateKeyHex, _ := wallet.PrivateKeyHex(account)

		// SOLANA address
		accountSolana, err := types.AccountFromSeed(seed[:32])
		if err != nil {
			fmt.Println("SOLANA FromBip39 err is ", err)
			return
		}

		// tron address
		address = "41" + address[2:]
		addb, _ := hex.DecodeString(address)
		hash1 := s256(s256(addb))
		secret := hash1[:4]
		for _, v := range secret {
			addb = append(addb, v)
		}
		fmt.Printf(`
		mnemonic:%v 
		BTC address: %v
		BTC WIF address: %v
		Privatekey OF ETH And Tron:%v  
		Privatekey OF SOLANA :%v
		SOLANA address: %v
		TRON address:%v 
		ETH address: %v`, mnemonic,
			addressbtc,
			addresswif,
			privateKeyHex,
			base58.Encode(accountSolana.PrivateKey),
			accountSolana.PublicKey.ToBase58(),
			base58.Encode(addb), address_ETH)
	}
}

func s256(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	bs := h.Sum(nil)
	return bs
}

