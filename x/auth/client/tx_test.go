package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto/ed25519"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

var (
	priv = ed25519.GenPrivKey()
	addr = sdk.AccAddress(priv.PubKey().Address())
)

func TestParseQueryResponse(t *testing.T) {
	simRes := &sdk.SimulationResponse{
		GasInfo: sdk.GasInfo{GasUsed: 10, GasWanted: 20},
		Result:  &sdk.Result{Data: []byte("tx data"), Log: "log"},
	}

	bz, err := codec.ProtoMarshalJSON(simRes)
	require.NoError(t, err)

	res, err := parseQueryResponse(bz)
	require.NoError(t, err)
	require.Equal(t, 10, int(res.GasInfo.GasUsed))
	require.NotNil(t, res.Result)

	res, err = parseQueryResponse([]byte("fuzzy"))
	require.Error(t, err)
}

func TestCalculateGas(t *testing.T) {
	cdc := makeCodec()
	makeQueryFunc := func(gasUsed uint64, wantErr bool) func(string, []byte) ([]byte, int64, error) {
		return func(string, []byte) ([]byte, int64, error) {
			if wantErr {
				return nil, 0, errors.New("query failed")
			}
			simRes := &sdk.SimulationResponse{
				GasInfo: sdk.GasInfo{GasUsed: gasUsed, GasWanted: gasUsed},
				Result:  &sdk.Result{Data: []byte("tx data"), Log: "log"},
			}

			bz, _ := codec.ProtoMarshalJSON(simRes)
			return bz, 0, nil
		}
	}

	type args struct {
		queryFuncGasUsed uint64
		queryFuncWantErr bool
		adjustment       float64
	}

	tests := []struct {
		name         string
		args         args
		wantEstimate uint64
		wantAdjusted uint64
		expPass      bool
	}{
		{"error", args{0, true, 1.2}, 0, 0, false},
		{"adjusted gas", args{10, false, 1.2}, 10, 12, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			queryFunc := makeQueryFunc(tt.args.queryFuncGasUsed, tt.args.queryFuncWantErr)
			simRes, gotAdjusted, err := CalculateGas(queryFunc, cdc, []byte(""), tt.args.adjustment)
			if tt.expPass {
				require.NoError(t, err)
				require.Equal(t, simRes.GasInfo.GasUsed, tt.wantEstimate)
				require.Equal(t, gotAdjusted, tt.wantAdjusted)
				require.NotNil(t, simRes.Result)
			} else {
				require.Error(t, err)
				require.Nil(t, simRes.Result)
			}
		})
	}
}

func TestDefaultTxEncoder(t *testing.T) {
	cdc := makeCodec()

	defaultEncoder := authtypes.DefaultTxEncoder(cdc)
	encoder := GetTxEncoder(cdc)

	compareEncoders(t, defaultEncoder, encoder)
}

func TestConfiguredTxEncoder(t *testing.T) {
	cdc := makeCodec()

	customEncoder := func(tx sdk.Tx) ([]byte, error) {
		return json.Marshal(tx)
	}

	config := sdk.GetConfig()
	config.SetTxEncoder(customEncoder)

	encoder := GetTxEncoder(cdc)

	compareEncoders(t, customEncoder, encoder)
}

func TestReadStdTxFromFile(t *testing.T) {
	cdc := codec.New()
	sdk.RegisterCodec(cdc)

	// Build a test transaction
	fee := authtypes.NewStdFee(50000, sdk.Coins{sdk.NewInt64Coin("atom", 150)})
	stdTx := authtypes.NewStdTx([]sdk.Msg{}, fee, []authtypes.StdSignature{}, "foomemo")

	// Write it to the file
	encodedTx, _ := cdc.MarshalJSON(stdTx)
	jsonTxFile := writeToNewTempFile(t, string(encodedTx))
	defer os.Remove(jsonTxFile.Name())

	// Read it back
	decodedTx, err := ReadStdTxFromFile(cdc, jsonTxFile.Name())
	require.NoError(t, err)
	require.Equal(t, decodedTx.Memo, "foomemo")
}

func TestBatchScanner_Scan(t *testing.T) {
	cdc := codec.New()
	sdk.RegisterCodec(cdc)

	// Build a test transaction
	fee := authtypes.NewStdFee(50000, sdk.Coins{sdk.NewInt64Coin("atom", 150)})
	stdTx := authtypes.NewStdTx([]sdk.Msg{}, fee, []authtypes.StdSignature{}, "foomemo")

	// Write it twice to the scanner

	buffer := strings.Builder{}
	encodedTx, err := cdc.MarshalJSON(stdTx)
	require.NoError(t, err)
	buffer.WriteString(fmt.Sprintf("%s\n", encodedTx))
	buffer.WriteString(fmt.Sprintf("%s\n", encodedTx))

	// Write malformed line
	buffer.WriteString("malformed\n")

	// write another stdtx
	buffer.WriteString(fmt.Sprintf("%s\n", encodedTx))

	i := 0
	scanner := NewBatchScanner(cdc, strings.NewReader(buffer.String()))

	for scanner.Scan() {
		stdTx := scanner.StdTx()
		require.Equal(t, "atom", stdTx.Fee.Amount[0].Denom)
		require.Equal(t, int64(150), stdTx.Fee.Amount[0].Amount.Int64())
		i++
	}

	// no error return from bufio.Scanner
	require.NoError(t, scanner.Err())
	// unmarshalling error was returned
	require.EqualError(t, scanner.UnmarshalErr(), "invalid character 'm' looking for beginning of value")
	// once an error occurs, the remaining transactions are ignored
	require.Equal(t, 2, i)
}

func compareEncoders(t *testing.T, expected sdk.TxEncoder, actual sdk.TxEncoder) {
	msgs := []sdk.Msg{sdk.NewTestMsg(addr)}
	tx := authtypes.NewStdTx(msgs, authtypes.StdFee{}, []authtypes.StdSignature{}, "")

	defaultEncoderBytes, err := expected(tx)
	require.NoError(t, err)
	encoderBytes, err := actual(tx)
	require.NoError(t, err)
	require.Equal(t, defaultEncoderBytes, encoderBytes)
}

func writeToNewTempFile(t *testing.T, data string) *os.File {
	fp, err := ioutil.TempFile(os.TempDir(), "client_tx_test")
	require.NoError(t, err)

	_, err = fp.WriteString(data)
	require.NoError(t, err)

	return fp
}

func makeCodec() *codec.Codec {
	var cdc = codec.New()
	sdk.RegisterCodec(cdc)
	cryptocodec.RegisterCrypto(cdc)
	authtypes.RegisterCodec(cdc)
	cdc.RegisterConcrete(sdk.TestMsg{}, "cosmos-sdk/Test", nil)
	return cdc
}
