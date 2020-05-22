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
	if err := validateVerificationArgs(cs, sequence, proof, consensusState); err != nil {
		return err
	}

	clientPrefixedPath := "clients/" + counterpartyClientIdentifier + "/" + host.ConsensusStatePath(consensusHeight)
	path, err := commitmenttypes.ApplyPrefix(prefix, clientPrefixedPath)
	if err != nil {
		return err
	}

	data, err := ConsensusStateSignBytes(cdc, sequence, path, consensusState)

	if err := CheckSignature(consensusState.PubKey, value, signature); err != nil {
		return sdkerrors.Wrap(clienttypes.ErrFailedClientConsensusStateVerification, "failed to verify proof against current public key, sequence, and consensus state")
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
	_ uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	connectionID string,
	connectionEnd connectionexported.ConnectionI,
	consensusState clientexported.ConsensusState,
) error {
	path, err := commitmenttypes.ApplyPrefix(prefix, host.ConnectionPath(connectionID))
	if err != nil {
		return err
	}

	signature, err := validateVerificationArgs(cs, sequence, consensusState)
	if err != nil {
		return err
	}

	data := ConnectionStateSignBytes(cs, cdc, connectionEnd, path)

	if !cs.ConsensusState.PubKey.VerifyBytes(value, signatureProof.Signature) {
		return sdkerrors.Wrap(
			clienttypes.ErrFailedConnectionStateVerification,
			"failed to verify proof against current public key, sequence, and connection state",
		)
	}

	cs.ConsensusState.Sequence++
	setClientState(store, cs)
	return nil
}

// VerifyChannelState verifies a proof of the channel state of the specified
// channel end, under the specified port, stored on the target machine.
func (cs ClientState) VerifyChannelState(
	store sdk.KVStore,
	cdc codec.Marshaler,
	_ uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	channel channelexported.ChannelI,
	consensusState clientexported.ConsensusState,
) error {
	path, err := commitmenttypes.ApplyPrefix(prefix, host.ChannelPath(portID, channelID))
	if err != nil {
		return err
	}

	if cs.IsFrozen() {
		return clienttypes.ErrClientFrozen
	}

	// cast the proof to a signature proof
	signatureProof, ok := proof.(commitmenttypes.SignatureProof)
	if !ok {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidClientType, "proof type %T is not type SignatureProof", proof)
	}

	if !cs.ConsensusState.PubKey.VerifyBytes(value, signatureProof.Signature) {
		return sdkerrors.Wrap(
			clienttypes.ErrFailedChannelStateVerification,
			"failed to verify proof against current public key, sequence, and channel state",
		)
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
	_ uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	sequence uint64,
	commitmentBytes []byte,
	consensusState clientexported.ConsensusState,
) error {
	path, err := commitmenttypes.ApplyPrefix(prefix, host.PacketCommitmentPath(portID, channelID, sequence))
	if err != nil {
		return err
	}

	if cs.IsFrozen() {
		return clienttypes.ErrClientFrozen
	}

	// cast the proof to a signature proof
	signatureProof, ok := proof.(commitmenttypes.SignatureProof)
	if !ok {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidClientType, "proof type %T is not type SignatureProof", proof)
	}

	if !cs.ConsensusState.PubKey.VerifyBytes(value, signatureProof.Signature) {
		return sdkerrors.Wrap(
			clienttypes.ErrFailedPacketCommitmentVerification,
			"failed to verify proof against current public key, sequence, and packet commitment",
		)
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
	_ uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	sequence uint64,
	acknowledgement []byte,
	consensusState clientexported.ConsensusState,
) error {
	path, err := commitmenttypes.ApplyPrefix(prefix, host.PacketAcknowledgementPath(portID, channelID, sequence))
	if err != nil {
		return err
	}

	if cs.IsFrozen() {
		return clienttypes.ErrClientFrozen
	}

	// cast the proof to a signature proof
	signatureProof, ok := proof.(commitmenttypes.SignatureProof)
	if !ok {
		return sdkerrors.Wrap(clienttypes.ErrInvalidClientType, "proof type %T is not type SignatureProof")
	}

	if !cs.ConsensusState.PubKey.VerifyBytes(value, signatureProof.Signature) {
		return sdkerrors.Wrap(
			clienttypes.ErrFailedPacketAckVerification,
			"failed to verify proof against current public key, sequence, and acknowledgement",
		)
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
	_ uint64,
	prefix commitmentexported.Prefix,
	proof commitmentexported.Proof,
	portID,
	channelID string,
	sequence uint64,
	consensusState clientexported.ConsensusState,
) error {
	path, err := commitmenttypes.ApplyPrefix(prefix, host.PacketAcknowledgementPath(portID, channelID, sequence))
	if err != nil {
		return err
	}

	if cs.IsFrozen() {
		return clienttypes.ErrClientFrozen
	}

	// cast the proof to a signature proof
	signatureProof, ok := proof.(commitmenttypes.SignatureProof)
	if !ok {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidClientType, "proof type %T is not type SignatureProof", proof)
	}

	if !cs.ConsensusState.PubKey.VerifyBytes(value, signatureProof.Signature) {
		return sdkerrors.Wrap(
			clienttypes.ErrFailedPacketAckAbsenceVerification,
			"failed to verify proof against current public key, sequence, and an absent acknowledgement",
		)
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
	path, err := commitmenttypes.ApplyPrefix(prefix, host.NextSequenceRecvPath(portID, channelID))
	if err != nil {
		return err
	}

	clientState, signature, err := sanitizeVerificationArgs(cs, sequence, proof, consensusState)
	if err != nil {
		return err
	}

	data, err := NextSequenceRecvSignBytes(sequence, path, nextSequenceRecv)
	if err != nil {
		return err
	}

	if err := CheckSignature(consensusState.PubKey, data, signature); err != nil {
		return sdkerrors.Wrapf(clienttypes.ErrFailedNextSeqRecvVerification, err.Error())
	}

	clientState.LatestSequence++
	setClientState(store, clientState)
	setConsensusState(store, clientState.LatestSequence, consensusState)
	return nil
}

func sanitizeVerificationArgsAndGetSignature(
	cs ClientState,
	sequence uint64,
	proof commitmentexported.Proof,
	consensusState clientexported.ConsensusState,
) ([]byte, error) {
	if cs.GetLatestHeight() < sequence {
		return nil, sdkerrors.Wrapf(
			ErrInvalidSequence,
			"client state (%s) sequence < proof height (%d < %d)", cs.ID, cs.GetLatestHeight(), sequence,
		)
	}

	if cs.IsFrozen() && cs.FrozenSequence <= sequence {
		return nil, clienttypes.ErrClientFrozen
	}

	if proof == nil {
		return nil, sdkerrors.Wrap(commitmenttypes.ErrInvalidProof, "proof cannot be empty")
	}

	// cast the proof to a signature proof
	signatureProof, ok := proof.(commitmenttypes.SignatureProof)
	if !ok {
		return nil, sdkerrors.Wrapf(clienttypes.ErrInvalidClientType, "invalid proof type %T, expected %T", proof, commitmenttypes.SignatureProof{})
	}

	if consensusState == nil {
		return nil, sdkerrors.Wrap(clienttypes.ErrInvalidConsensus, "consensus state cannot be empty")
	}

	_, ok = consensusState.(ConsensusState)
	if !ok {
		return nil, sdkerrors.Wrapf(clienttypes.ErrInvalidConsensus, "invalid consensus type %T, expected %T", consensusState, ConsensusState{})
	}

	return signatureProof.Signature, nil
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
