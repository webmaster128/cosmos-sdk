package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
)

// SubModuleCdc defines the IBC solo machine client codec.
var SubModuleCdc *codec.Codec

// RegisterCodec registers the Solo Machine types.
func RegisterCodec(cdc *codec.Codec) {
	cdc.RegisterConcrete(ClientState{}, "ibc/client/solomachine/ClientState", nil)
	cdc.RegisterConcrete(ConsensusState{}, "ibc/client/solomachine/ConsensusState", nil)
	cdc.RegisterConcrete(Header{}, "ibc/client/solomachine/Header", nil)
	cdc.RegisterConcrete(Evidence{}, "ibc/client/solomachine/Evidence", nil)
	cdc.RegisterConcrete(MsgCreateClient{}, "ibc/client/solomachine/MsgCreateClient", nil)
	cdc.RegisterConcrete(MsgUpdateClient{}, "ibc/client/solomachine/MsgUpdateClient", nil)
	cdc.RegisterConcrete(MsgSubmitClientMisbehaviour{}, "ibc/client/solomachine/MsgSubmitClientMisbehaviour", nil)

	SetSubModuleCodec(cdc)
}

// SetSubModuleCodec sets the ibc solo machine client codec.
func SetSubModuleCodec(cdc *codec.Codec) {
	SubModuleCdc = cdc
}