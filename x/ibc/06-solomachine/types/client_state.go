package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clientexported "github.com/cosmos/cosmos-sdk/x/ibc/02-client/exported"
	clienttypes "github.com/cosmos/cosmos-sdk/x/ibc/02-client/types"
	connectionexported "github.com/cosmos/cosmos-sdk/x/ibc/03-connection/exported"
	connectiontypes "github.com/cosmos/cosmos-sdk/x/ibc/03-connection/types"
	channelexported "github.com/cosmos/cosmos-sdk/x/ibc/04-channel/exported"
	channeltypes "github.com/cosmos/cosmos-sdk/x/ibc/04-channel/types"
	commitmentexported "github.com/cosmos/cosmos-sdk/x/ibc/23-commitment/exported"
	commitmenttypes "github.com/cosmos/cosmos-sdk/x/ibc/23-commitment/types"
	host "github.com/cosmos/cosmos-sdk/x/ibc/24-host"
)

var _ clientexported.ClientState = ClientState{}

// ClientState of a Solo Machine represents whether or not the client is frozen.
type ClientState struct {
	// Client ID
	ID string `json:"id" yaml:"id"`

	// Frozen status of the client
	FrozenSequence uint64 `json:"frozen_sequence" yaml:"frozen_sequence"`

	// Latest sequence of the client
	LatestSequence uint64 `json:"latest_sequence" yaml:"latest_sequence"`
}

// InitializeFromMsg creates a solo machine client from a MsgCreateClient.
func InitializeFromMsg(msg MsgCreateClient) (ClientState, error) {
	return NewClientState(msg.GetClientID(), msg.LatestSequence), nil
}

// NewClientState creates a new ClientState instance.
func NewClientState(id string, latestSequence uint64) ClientState {
	return ClientState{
		ID:             id,
		Frozen:         false,
		LatestSequence: latestSequence,
	}
}

// GetID returns the solo machine client state identifier.
func (cs ClientState) GetID() string {
	return cs.ID
}

// GetChainID returns an empty string.
func (cs ClientState) GetChainID() string {
	return ""
}

// ClientType is Solo Machine.
func (cs ClientState) ClientType() clientexported.ClientType {
	return clientexported.SoloMachine
}

// GetLatestHeight returns the latest sequence number.
func (cs ClientState) GetLatestHeight() uint64 {
	return cs.LatestSequence
}

// IsFrozen returns true if the client is frozen
func (cs ClientState) IsFrozen() bool {
	return cs.FrozenSequence != 0
}

// Validate performs basic validation of the client state fields.
func (cs ClientState) Validate() error {
	if err := host.ClientIdentifierValidator(cs.ID); err != nil {
		return err
	}
	return cs.ConsensusState.ValidateBasic()
}

// VerifyClientConsensusState verifies a proof of the consensus state of the
// Solo Machine client stored on the target machine.
func (cs ClientState) VerifyClientConsensusState(
	store sdk.KVStore,
	cdc *codec.Codec,
	root commitmentexported.Root,
	sequence uint64,
	counterpartyClientIdentifier string,
	consensusHeight uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	consensusState clientexported.ConsensusState,
) error {
	if err := validateVerificationArgs(cs, sequence, prefix, proof, prefix, consensusState); err != nil {
		return err
	}

	clientPrefixedPath := "clients/" + counterpartyClientIdentifier + "/" + host.ConsensusStatePath(consensusHeight)
	path, err := commitmenttypes.ApplyPrefix(prefix, clientPrefixedPath)
	if err != nil {
		return err
	}

	// casted type already verified
	signatureProof, _ := proof.(commitmenttypes.SignatureProof)

	data, err := ConsensusStateSignBytes(cdc, sequence, path, consensusState)
	if err != nil {
		return err
	}

	if err := CheckSignature(consensusState.PubKey, value, signature); err != nil {
		return sdkerrors.Wrap(clienttypes.ErrFailedClientConsensusStateVerification, err.Error())
	}

	clientState.LatestSequence++
	setClientState(store, clientState)
	setConsensusState(store, clientState.LatestSequence, consensusState)
	return nil
}

// VerifyConnectionState verifies a proof of the connection state of the
// specified connection end stored on the target machine.
func (cs ClientState) VerifyConnectionState(
	store sdk.KVStore,
	cdc codec.Marshaler,
	sequence uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	connectionID string,
	connectionEnd connectionexported.ConnectionI,
	consensusState clientexported.ConsensusState,
) error {
	if err := validateVerificationArgs(cs, sequence, prefix, proof, prefix, consensusState); err != nil {
		return err
	}

	path, err := commitmenttypes.ApplyPrefix(prefix, host.ConnectionPath(connectionID))
	if err != nil {
		return err
	}

	// casted type already verified
	signatureProof, _ := proof.(commitmenttypes.SignatureProof)

	data, err := ConnectionStateSignBytes(cdc, sequence, connectionEnd, path)
	if err != nil {
		return err
	}

	if err := CheckSignature(consensusState.PubKey, data, signatureProof.Signature); err != nil {
		return sdkerrors.Wrap(clienttypes.ErrFailedConnectionStateVerification, err.Error())
	}

	clientState.LatestSequence++
	setClientState(store, clientState)
	setConsensusState(store, clientState.LatestSequence, consensusState)
	return nil
}

// VerifyChannelState verifies a proof of the channel state of the specified
// channel end, under the specified port, stored on the target machine.
func (cs ClientState) VerifyChannelState(
	store sdk.KVStore,
	cdc codec.Marshaler,
	sequence uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	channel channelexported.ChannelI,
	consensusState clientexported.ConsensusState,
) error {
	if err := validateVerificationArgs(cs, sequence, prefix, proof, prefix, consensusState); err != nil {
		return err
	}

	path, err := commitmenttypes.ApplyPrefix(prefix, host.ChannelPath(portID, channelID))
	if err != nil {
		return err
	}

	// casted type already verified
	signatureProof, _ := proof.(commitmenttypes.SignatureProof)

	data, err := ChannelStateSignBytes(cdc, sequence, path, channel)
	if err != nil {
		return err
	}

	if err := CheckSignature(consensusState.PubKey, data, signatureProof.Signature); err != nil {
		return sdkerrors.Wrap(clienttypes.ErrFailedChannelStateVerification, err.Error())
	}

	clientState.LatestSequence++
	setClientState(store, clientState)
	setConsensusState(store, clientState.LatestSequence, consensusState)
	return nil
}

// VerifyPacketCommitment verifies a proof of an outgoing packet commitment at
// the specified port, specified channel, and specified sequence.
func (cs ClientState) VerifyPacketCommitment(
	store sdk.KVStore,
	sequence uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	sequence uint64,
	commitmentBytes []byte,
	consensusState clientexported.ConsensusState,
) error {
	if err := validateVerificationArgs(cs, sequence, prefix, proof, prefix, cs.ConsensusState); err != nil {
		return err
	}

	path, err := commitmenttypes.ApplyPrefix(prefix, host.PacketCommitmentPath(portID, channelID, sequence))
	if err != nil {
		return err
	}

	// casted type already verified
	signatureProof, _ := proof.(commitmenttypes.SignatureProof)

	data, err := PacketCommitmentSignBytes(sequence, path, commitmentBytes)
	if err != nil {
		return err
	}

	if err := CheckSignature(consensusState.PubKey, data, signatureProof.Signature); err != nil {
		return sdkerrors.Wrap(clienttypes.ErrFailedPacketCommitmentVerification, err.Error())
	}

	clientState.LatestSequence++
	setClientState(store, clientState)
	setConsensusState(store, clientState.LatestSequence, consensusState)
	return nil
}

// VerifyPacketAcknowledgement verifies a proof of an incoming packet
// acknowledgement at the specified port, specified channel, and specified sequence.
func (cs ClientState) VerifyPacketAcknowledgement(
	store sdk.KVStore,
	sequence uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	sequence uint64,
	acknowledgement []byte,
	consensusState clientexported.ConsensusState,
) error {
	if err := validateVerificationArgs(cs, sequence, prefix, proof, prefix, cs.ConsensusState); err != nil {
		return err
	}

	path, err := commitmenttypes.ApplyPrefix(prefix, host.PacketAcknowledgementPath(portID, channelID, sequence))
	if err != nil {
		return err
	}

	// casted type already verified
	signatureProof, _ := proof.(commitmenttypes.SignatureProof)

	data, err := PacketAcknowledgementSignBytes(sequence, path, acknowledgement)
	if err != nil {
		return err
	}

	if err := CheckSignature(consensusState.PubKey, data, signatureProof.Signature); err != nil {
		return sdkerrors.Wrap(clienttypes.ErrFailedPacketAckVerification, err.Error())
	}

	clientState.LatestSequence++
	setClientState(store, clientState)
	setConsensusState(store, clientState.LatestSequence, consensusState)
	return nil

}

// VerifyPacketAcknowledgementAbsence verifies a proof of the absence of an
// incoming packet acknowledgement at the specified port, specified channel, and
// specified sequence.
func (cs ClientState) VerifyPacketAcknowledgementAbsence(
	store sdk.KVStore,
	sequence uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	packetSequence uint64,
	consensusState clientexported.ConsensusState,
) error {
	if err := validateVerificationArgs(cs, sequence, prefix, proof, prefix, cs.ConsensusState); err != nil {
		return err
	}

	path, err := commitmenttypes.ApplyPrefix(prefix, host.PacketAcknowledgementPath(portID, channelID, packetSequence))
	if err != nil {
		return err
	}

	// casted type already verified
	signatureProof, _ := proof.(commitmenttypes.SignatureProof)

	data, err := PacketAcknowledgementAbsenceSignBytes(sequence, path)
	if err != nil {
		return err
	}

	if err := CheckSignature(consensusState.PubKey, data, signatureProof.Signature); err != nil {
		return sdkerrors.Wrap(clienttypes.ErrFailedPacketAckAbsenceVerification, err.Error())
	}

	clientState.LatestSequence++
	setClientState(store, clientState)
	setConsensusState(store, clientState.LatestSequence, consensusState)
	return nil

}

// VerifyNextSequenceRecv verifies a proof of the next sequence number to be
// received of the specified channel at the specified port.
func (cs ClientState) VerifyNextSequenceRecv(
	store sdk.KVStore,
	sequence uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	nextSequenceRecv uint64,
	consensusState clientexported.ConsensusState,
) error {
	if err := validateVerificationArgs(cs, sequence, prefix, proof, prefix, cs.ConsensusState); err != nil {
		return err
	}

	path, err := commitmenttypes.ApplyPrefix(prefix, host.NextSequenceRecvPath(portID, channelID))
	if err != nil {
		return err
	}

	// casted type already verified
	signatureProof, _ := proof.(commitmenttypes.SignatureProof)

	data, err := NextSequenceRecvSignBytes(sequence, path, nextSequenceRecv)
	if err != nil {
		return err
	}

	if err := CheckSignature(consensusState.PubKey, data, signatureProof.Signature); err != nil {
		return sdkerrors.Wrapf(clienttypes.ErrFailedNextSeqRecvVerification, err.Error())
	}

	clientState.LatestSequence++
	setClientState(store, clientState)
	setConsensusState(store, clientState.LatestSequence, consensusState)
	return nil
}

// validateVerificationArgs perfoms the basic checks on the arguments that are
// shared between the verification functions.
func validateVerificationArgs(
	cs ClientState,
	sequence uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	consensusState clientexported.ConsensusState,
) error {
	if cs.GetLatestHeight() < sequence {
		return sdkerrors.Wrapf(
			sdkerrors.ErrInvalidHeight,
			"client state (%s) sequence < proof sequence (%d < %d)", cs.ID, cs.GetLatestHeight(), sequence,
		)
	}

	if cs.IsFrozen() && cs.FrozenSequence <= sequence {
		return clienttypes.ErrClientFrozen
	}

	if prefix == nil {
		return sdkerrors.Wrap(commitmenttypes.ErrInvalidPrefix, "prefix cannot be empty")
	}

	_, ok := prefix.(commitmenttypes.SignaturePrefix)
	if !ok {
		return sdkerrors.Wrapf(commitmenttypes.ErrInvalidPrefix, "invalid prefix type %T, expected SignaturePrefix", prefix)
	}

	if proof == nil {
		return sdkerrors.Wrap(commitmenttypes.ErrInvalidProof, "proof cannot be empty")
	}

	_, ok := proof.(commitmenttypes.SignatureProof)
	if !ok {
		return sdkerrors.Wrapf(commitmenttypes.ErrInvalidProof, "invalid proof type %T, expected SignatureProof", proof)
	}

	if consensusState == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidConsensus, "consensus state cannot be empty")
	}

	_, ok := consensusState.(ConsensusState)
	if !ok {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidConsensus, "invalid consensus type %T, expected %T", consensusState, ConsensusState{})
	}

	return nil
}

// sets the client state in the store
func setClientState(store sdk.KVStore, clientState clientexported.ClientState) {
	bz := SubModuleCdc.MustMarshalBinaryBare(clientState)
	store.Set(host.KeyClientState(), bz)
}

// sets the consensus state in the store.
func setConsensusState(store sdk.KVStore, sequence uint64, consensusState clientexported.ConsensusState) {
	bz := k.cdc.MustMarshalBinaryBare(consensusState)
	store.Set(host.KeyConsensusState(sequence), bz)
}
