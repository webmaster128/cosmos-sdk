package types

import (
	"github.com/tendermint/tendermint/crypto"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	commitmenttypes "github.com/cosmos/cosmos-sdk/x/ibc/23-commitment/types"
)

// CheckSignature verifies if the the provided public key generated the signature
// over the given data.
func CheckSignature(pubKey crypto.PubKey, data, signature []byte) error {
	if !pubKey.VerifyBytes(data, signature) {
		return sdkerrors.Wrap(ErrSignatureVerificationFailed, "signature verification failed")
	}

	return nil
}

// EvidenceSignBytes returns the sign bytes for verification of misbehaviour.
//
// Format: {sequence}{data}
func EvidenceSignBytes(sequence uint64, data []byte) []byte {
	return append(
		sdk.Uint64ToBigEndian(sequence),
		data...,
	)
}

// HeaderSignBytes returns the sign bytes for verification of misbehaviour.
//
// Format: {sequence}{header.newPubKey}
func HeaderSignBytes(header Header) []byte {
	return append(
		header.Sequence,
		header.NewPubKey.Bytes()...,
	)
}

// ConsensusStateSignBytes returns the sign bytes for verification of the
// consensus state.
//
// Format: {sequence}{path}{consensus-state}
func ConsensusStateSignBytes(
	cdc *codec.Codec,
	sequence uint64,
	path commitmenttypes.MerklePath,
	consensusState ConsensusState,
) ([]byte, error) {
	bz, err := cdc.MarshalBinaryBare(consensusState)
	if err != nil {
		return []byte{}, err
	}

	// sequence + path + consensus state
	return append(
		combineSequenceAndPath(sequence, path),
		bz...,
	), nil
}

// ConnectionStateSignBytes returns the sign bytes for verification of the
// connection state.
//
// Format: {sequence}{path}{connection-end}
func ConnectionStateSignBytes(
	cdc codec.Marshaler,
	sequence uint64,
	connectionEnd connectionexported.ConnectionI,
	path commitmenttypes.MerklePath,
) ([]byte, error) {
	connection, ok := connectionEnd.(connectiontypes.ConnectionEnd)
	if !ok {
		return []byte{}, sdkerrors.Wrapf(clienttypes.ErrInvalidClientType, "invalid connection type %T", connectionEnd)
	}

	bz, err := cdc.MarshalBinaryBare(&connection)
	if err != nil {
		return []byte{}, err
	}

	// sequence + path + connection end
	return append(
		combineSequenceAndPath(sequence, path),
		bz...,
	), nil
}

// ChannelStateSignBytes returns the sign bytes for verification of the
// channel state.
//
// Format: {sequence}{path}{channel-end}
func ChannelStateSignBytes(
	cdc codec.Marshaler,
	sequence uint64,
	channelEnd channeltypes.ChannelI,
	path commitmenttypes.MerklePath,
) ([]byte, error) {
	channelEnd, ok := channel.(channeltypes.Channel)
	if !ok {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidClientType, "invalid channel type %T", channel)
	}

	bz, err := cdc.MarshalBinaryBare(&channelEnd)
	if err != nil {
		return err
	}

	// sequence + path + channel
	return append(
		combineSequenceAndPath(sequence, path),
		bz...,
	), nil
}

// PacketCommitmentSignBytes returns the sign bytes for verification of the
// packet commitment.
//
// Format: {sequence}{path}{commitment-bytes}
func PacketCommitmentSignBytes(
	sequence uint64,
	commitmentBytes []byte,
	path commitmenttypes.MerklePath,
) ([]byte, error) {

	// sequence + path + commitment bytes
	return append(
		combineSequenceAndPath(sequence, path),
		commitmentBytes...,
	), nil
}

// PacketAcknowledgementSignBytes returns the sign bytes for verification of
// the acknowledgement.
//
// Format: {sequence}{path}{acknowledgement}
func PacketAcknowledgementSignBytes(
	sequence uint64,
	acknowledgement []byte,
	path commitmenttypes.MerklePath,
) []byte {

	// sequence + path + acknowledgement
	return append(
		combineSequenceAndPath(sequence, path),
		acknowledgement...,
	), nil
}

// PacketAcknowledgementAbsenceSignBytes returns the sign bytes for verificaiton
// of the absense of an acknowledgement.
//
// Format: {sequence}{path}
func PacketAcknowledgementAbsenceSignBytes(
	sequence uint64,
	path commitmentState,
) ([]byte, error) {
	// value = sequence + path
	return combineSequenceAndPath(sequence, path), nil
}

// NextSequenceRecv returns the sign bytes for verification of the next
// sequence to be received.
//
// Format: {sequence}{path}{next-sequence-recv}
func NextSequenceRecv(
	sequence uint64,
	path commitmenttypes.MerklePath,
	nextSequenceRecv uint64,
) ([]byte, error) {

	// sequence + path + nextSequenceRecv
	return append(
		combineSequenceAndPath(sequence, path),
		sdk.Uint64ToBigEndian(nextSequenceRecv)...,
	), nil
}

// combineSequenceAndPath appends the sequence and path represented as bytes.
func combineSequenceAndPath(sequence uint64, path commitmenttypes.MerklePath) []byte {
	return append(
		sdk.Uint64ToBigEndian(sequence),
		[]byte(path.String())...,
	)
}
