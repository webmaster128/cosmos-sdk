package keeper_test

import (
	"fmt"

	connection "github.com/cosmos/cosmos-sdk/x/ibc/03-connection"
	"github.com/cosmos/cosmos-sdk/x/ibc/03-connection/types"
	commitmenttypes "github.com/cosmos/cosmos-sdk/x/ibc/23-commitment/types"
	host "github.com/cosmos/cosmos-sdk/x/ibc/24-host"
)

// TestConnOpenInit - Chain A (ID #1) initializes (INIT state) a connection with
// Chain B (ID #2) which is yet UNINITIALIZED
func (suite *KeeperTestSuite) TestConnOpenInit() {
	testCases := []struct {
		msg      string
		malleate func()
		expPass  bool
	}{
		{"success", func() {
			suite.chainA.CreateClient(suite.chainB)
		}, true},
		{"connection already exists", func() {
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDA, testClientIDB, types.INIT)
		}, false},
		{"couldn't add connection to client", func() {}, false},
	}

	counterparty := connection.NewCounterparty(testClientIDB, testConnectionIDB, commitmenttypes.NewMerklePrefix(suite.chainA.App.IBCKeeper.ConnectionKeeper.GetCommitmentPrefix().Bytes()))

	for i, tc := range testCases {
		tc := tc
		i := i
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			tc.malleate()
			err := suite.chainA.App.IBCKeeper.ConnectionKeeper.ConnOpenInit(suite.chainA.GetContext(), testConnectionIDA, testClientIDB, counterparty)

			if tc.expPass {
				suite.Require().NoError(err, "valid test case %d failed: %s", i, tc.msg)
			} else {
				suite.Require().Error(err, "invalid test case %d passed: %s", i, tc.msg)
			}
		})
	}
}

// TestConnOpenTry - Chain B (ID #2) calls ConnOpenTry to verify the state of
// connection on Chain A (ID #1) is INIT
func (suite *KeeperTestSuite) TestConnOpenTry() {
	// counterparty for A on B
	counterparty := connection.NewCounterparty(
		testClientIDB, testConnectionIDA, commitmenttypes.NewMerklePrefix(suite.chainB.App.IBCKeeper.ConnectionKeeper.GetCommitmentPrefix().Bytes()),
	)

	testCases := []struct {
		msg      string
		malleate func() uint64
		expPass  bool
	}{
		{"success", func() uint64 {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.INIT)
			suite.chainB.UpdateClient(suite.chainA)
			suite.chainA.UpdateClient(suite.chainB)
			suite.chainB.UpdateClient(suite.chainA)
			suite.chainA.UpdateClient(suite.chainB)
			suite.chainB.UpdateClient(suite.chainA)
			return suite.chainA.Header.GetHeight() - 1
		}, true},
		{"consensus height > latest height", func() uint64 {
			return 0
		}, false},
		{"self consensus state not found", func() uint64 {
			//suite.ctx = suite.ctx.WithBlockHeight(100)
			return 100
		}, false},
		{"connection state verification invalid", func() uint64 {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.UNINITIALIZED)
			suite.chainB.UpdateClient(suite.chainA)
			return 0
		}, false},
		{"consensus state verification invalid", func() uint64 {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.INIT)
			suite.chainB.UpdateClient(suite.chainA)
			suite.chainA.UpdateClient(suite.chainB)
			return suite.chainB.Header.GetHeight() - 1
		}, false},
		{"invalid previous connection", func() uint64 {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDA, testClientIDB, types.UNINITIALIZED)
			suite.chainB.UpdateClient(suite.chainA)
			suite.chainA.UpdateClient(suite.chainB)
			return 0
		}, false},
		{"couldn't add connection to client", func() uint64 {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDB, testClientIDA, types.UNINITIALIZED)
			suite.chainB.UpdateClient(suite.chainA)
			return 0
		}, false},
	}

	for i, tc := range testCases {
		tc := tc
		i := i
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			consensusHeight := tc.malleate()

			connectionKey := host.KeyConnection(testConnectionIDA)
			proofInit, proofHeight := suite.chainA.QueryProof(connectionKey)

			consensusKey := prefixedClientKey(testClientIDB, host.KeyConsensusState(consensusHeight))
			proofConsensus, _ := suite.chainA.QueryProof(consensusKey)

			err := suite.chainB.App.IBCKeeper.ConnectionKeeper.ConnOpenTry(
				suite.chainB.GetContext(), testConnectionIDB, counterparty, testClientIDA,
				connection.GetCompatibleVersions(), proofInit, proofConsensus,
				proofHeight, consensusHeight,
			)

			if tc.expPass {
				suite.Require().NoError(err, "valid test case %d failed with consensus height %d and proof height %d: %s", i, consensusHeight, proofHeight, tc.msg)
			} else {
				suite.Require().Error(err, "invalid test case %d passed with consensus height %d and proof height %d: %s", i, consensusHeight, proofHeight, tc.msg)
			}
		})
	}
}

// TestConnOpenAck - Chain A (ID #1) calls TestConnOpenAck to acknowledge (ACK state)
// the initialization (TRYINIT) of the connection on  Chain B (ID #2).
func (suite *KeeperTestSuite) TestConnOpenAck() {
	version := connection.GetCompatibleVersions()[0]

	testCases := []struct {
		msg      string
		version  string
		malleate func() uint64
		expPass  bool
	}{
		{"success", version, func() uint64 {
			suite.chainA.CreateClient(suite.chainB)
			suite.chainB.CreateClient(suite.chainA)
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDA, testClientIDB, types.TRYOPEN)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.INIT)
			suite.chainB.UpdateClient(suite.chainA)
			suite.chainA.UpdateClient(suite.chainB)
			return suite.chainB.Header.GetHeight() - 1
		}, true},
		{"success from tryopen", version, func() uint64 {
			suite.chainA.CreateClient(suite.chainB)
			suite.chainB.CreateClient(suite.chainA)
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDA, testClientIDB, types.TRYOPEN)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.TRYOPEN)
			suite.chainB.UpdateClient(suite.chainA)
			suite.chainA.UpdateClient(suite.chainB)
			return suite.chainB.Header.GetHeight() - 1
		}, true},
		{"consensus height > latest height", version, func() uint64 {
			return 10
		}, false},
		{"connection not found", version, func() uint64 {
			return 2
		}, false},
		{"connection state is not INIT", version, func() uint64 {
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDA, testClientIDB, types.UNINITIALIZED)
			return suite.chainB.Header.GetHeight()
		}, false},
		{"incompatible IBC versions", "2.0", func() uint64 {
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDA, testClientIDB, types.INIT)
			return suite.chainB.Header.GetHeight()
		}, false},
		{"self consensus state not found", version, func() uint64 {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.INIT)
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDA, testClientIDB, types.TRYOPEN)
			suite.chainB.UpdateClient(suite.chainA)
			return suite.chainB.Header.GetHeight() - 1
		}, false},
		{"connection state verification failed", version, func() uint64 {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.INIT)
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDA, testClientIDB, types.UNINITIALIZED)
			suite.chainB.UpdateClient(suite.chainA)
			return suite.chainB.Header.GetHeight() - 1
		}, false},
		{"consensus state verification failed", version, func() uint64 {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.INIT)
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDA, testClientIDB, types.UNINITIALIZED)
			suite.chainB.UpdateClient(suite.chainA)
			return suite.chainB.Header.GetHeight() - 1
		}, false},
	}

	for i, tc := range testCases {
		tc := tc
		i := i
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			consensusHeight := tc.malleate()

			connectionKey := host.KeyConnection(testConnectionIDB)
			proofTry, proofHeight := suite.chainB.QueryProof(connectionKey)

			consensusKey := prefixedClientKey(testClientIDA, host.KeyConsensusState(consensusHeight))
			proofConsensus, _ := suite.chainB.QueryProof(consensusKey)

			err := suite.chainA.App.IBCKeeper.ConnectionKeeper.ConnOpenAck(
				suite.chainA.GetContext(), testConnectionIDA, tc.version, proofTry, proofConsensus,
				proofHeight, consensusHeight,
			)

			if tc.expPass {
				suite.Require().NoError(err, "valid test case %d failed with consensus height %d and proof height %d: %s", i, consensusHeight, proofHeight, tc.msg)
			} else {
				suite.Require().Error(err, "invalid test case %d passed with consensus height %d and proof height %d: %s", i, consensusHeight, proofHeight, tc.msg)
			}
		})
	}
}

// TestConnOpenConfirm - Chain B (ID #2) calls ConnOpenConfirm to confirm that
// Chain A (ID #1) state is now OPEN.
func (suite *KeeperTestSuite) TestConnOpenConfirm() {
	testCases := []testCase{
		{"success", func() {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDB, testClientIDA, types.OPEN)
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDA, testClientIDB, types.TRYOPEN)
			suite.chainB.UpdateClient(suite.chainA)
		}, true},
		{"connection not found", func() {}, false},
		{"chain B's connection state is not TRYOPEN", func() {
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDA, testClientIDB, types.UNINITIALIZED)
			suite.chainA.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDB, testClientIDA, types.OPEN)
		}, false},
		{"connection state verification failed", func() {
			suite.chainB.CreateClient(suite.chainA)
			suite.chainA.CreateClient(suite.chainB)
			suite.chainB.UpdateClient(suite.chainA)
			suite.chainA.CreateConnection(testConnectionIDA, testConnectionIDB, testClientIDA, testClientIDB, types.INIT)
			suite.chainB.CreateConnection(testConnectionIDB, testConnectionIDA, testClientIDB, testClientIDA, types.TRYOPEN)
			suite.chainA.UpdateClient(suite.chainB)
		}, false},
	}

	for i, tc := range testCases {
		tc := tc
		i := i
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			tc.malleate()

			connectionKey := host.KeyConnection(testConnectionIDA)
			proofAck, proofHeight := suite.chainA.QueryProof(connectionKey)

			if tc.expPass {
				err := suite.chainB.App.IBCKeeper.ConnectionKeeper.ConnOpenConfirm(
					suite.chainB.GetContext(), testConnectionIDB, proofAck, proofHeight,
				)
				suite.Require().NoError(err, "valid test case %d failed: %s", i, tc.msg)
			} else {
				err := suite.chainB.App.IBCKeeper.ConnectionKeeper.ConnOpenConfirm(
					suite.chainB.GetContext(), testConnectionIDB, proofAck, proofHeight,
				)
				suite.Require().Error(err, "invalid test case %d passed: %s", i, tc.msg)
			}
		})
	}
}

type testCase = struct {
	msg      string
	malleate func()
	expPass  bool
}
