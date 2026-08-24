// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

import "utils/Test.sol";

contract FrameTxTest is Test {
    address internal constant READER = address(0xF8141);
    address internal constant SENDER = address(0x1001);
    address internal constant CHANGED_ACCOUNT = address(0x2002);
    address internal constant DEPLOYED_ACCOUNT = address(0x3003);
    address internal constant EMITTER = address(0x4004);
    address internal constant GAS_PAYER = address(0x5005);

    bytes32 internal constant SIG_HASH = bytes32(uint256(0xA002));
    bytes32 internal constant SOURCE_ID = bytes32(uint256(0xA003));
    bytes32 internal constant RECENT_ROOT = bytes32(uint256(0xA004));
    bytes32 internal constant DEPLOYED_CODE_HASH = bytes32(uint256(0xA005));
    bytes32 internal constant CODE_HASH_BEFORE = bytes32(uint256(0xA006));
    bytes32 internal constant CODE_HASH_AFTER = bytes32(uint256(0xA007));
    bytes32 internal constant TOPIC_0 = bytes32(uint256(0xA008));
    bytes32 internal constant TOPIC_1 = bytes32(uint256(0xA009));

    function testSetFrameTxMapsHegotaContext() public {
        vm.setFrameTx(_frameTx());

        assertEq(uint256(_txparam(0x01)), 17);
        assertEq(address(uint160(uint256(_txparam(0x02)))), SENDER);
        assertEq(uint256(_txparam(0x03)), 21);
        assertEq(uint256(_txparam(0x04)), 22);
        assertEq(uint256(_txparam(0x05)), 23);
        assertEq(uint256(_txparam(0x06)), 24);
        assertEq(uint256(_txparam(0x07)), 2);
        assertEq(_txparam(0x08), SIG_HASH);
        assertEq(uint256(_txparam(0x09)), 1);
        assertEq(uint256(_txparam(0x0A)), 0);
        assertEq(uint256(_txparam(0x0B)), 2);
        assertEq(uint256(_txparam(0x0C)), 41);

        assertEq(_signatureData(1, 1, 4), hex"bbcc0000");

        assertEq(_recentRootReference(0, 0), SOURCE_ID);
        assertEq(uint256(_recentRootReference(0, 1)), 37);
        assertEq(_recentRootReference(0, 2), RECENT_ROOT);

        assertEq(uint256(_txtrace(0x00, 0)), 1);
        assertEq(address(uint160(uint256(_txtrace(0x03, 0)))), CHANGED_ACCOUNT);
        assertEq(uint256(_txtrace(0x04, 0)), 41);
        assertEq(uint256(_txtrace(0x05, 0)), 42);

        assertEq(uint256(_txtrace(0x01, 0)), 1);
        assertEq(address(uint160(uint256(_txtrace(0x06, 0)))), CHANGED_ACCOUNT);
        assertEq(uint256(_txtrace(0x07, 0)), 43);
        assertEq(uint256(_txtrace(0x08, 0)), 44);
        assertEq(uint256(_txtrace(0x09, 0)), 45);

        assertEq(uint256(_txtrace(0x02, 0)), 1);
        assertEq(address(uint160(uint256(_txtrace(0x0A, 0)))), DEPLOYED_ACCOUNT);
        assertEq(_txtrace(0x0B, 0), DEPLOYED_CODE_HASH);

        assertEq(uint256(_txtrace(0x0C, 0)), 1);
        assertEq(address(uint160(uint256(_txtrace(0x0D, 0)))), EMITTER);
        assertEq(uint256(_txtrace(0x0E, 0)), 2);
        assertEq(_txtrace(0x0F, 0), TOPIC_0);
        assertEq(_txtrace(0x10, 0), TOPIC_1);
        assertEq(uint256(_txtrace(0x13, 0)), 4);
        assertEq(uint256(_txtrace(0x14, 0)), 46);
        assertEq(address(uint160(uint256(_txtrace(0x15, 0)))), GAS_PAYER);
        assertEq(_eventData(0, 1, 2), hex"bbcc");

        assertEq(_txdiff(0x04, CHANGED_ACCOUNT, 0), CODE_HASH_BEFORE);
        assertEq(_txdiff(0x05, CHANGED_ACCOUNT, 0), CODE_HASH_AFTER);
        assertEq(uint256(_txdiff(0x0A, CHANGED_ACCOUNT, 0)), 0x0F);

        vm.clearFrameTx();
        vm.etch(READER, abi.encodePacked(hex"60", bytes1(0x01), hex"b05f5260205ff3"));
        (bool success,) = READER.staticcall("");
        assertTrue(!success);
    }

    function _frameTx() internal pure returns (Vm.FrameTx memory frameTx) {
        frameTx.sender = SENDER;
        frameTx.nonce = 17;
        frameTx.stateGasLeft = 41;
        frameTx.sigHash = SIG_HASH;
        frameTx.maxCost = 24;
        frameTx.maxPriorityFeePerGas = 21;
        frameTx.maxFeePerGas = 22;
        frameTx.maxFeePerBlobGas = 23;
        frameTx.blobCount = 2;
        frameTx.frameIndex = 0;
        frameTx.approvableScopes = 3;

        frameTx.frames = new Vm.FrameTxFrame[](1);
        frameTx.frames[0].mode = 3;
        frameTx.frames[0].target = address(0x6006);
        frameTx.frames[0].gasLimit = 100_000;

        frameTx.signatures = new Vm.FrameTxSignature[](2);
        frameTx.signatures[0].scheme = 1;
        frameTx.signatures[0].signer = address(0x7007);
        frameTx.signatures[1].scheme = 0;
        frameTx.signatures[1].signature = hex"aabbcc";

        frameTx.recentRootReferences = new Vm.FrameTxRecentRootReference[](1);
        frameTx.recentRootReferences[0] =
            Vm.FrameTxRecentRootReference({sourceId: SOURCE_ID, slot: 37, root: RECENT_ROOT});

        frameTx.trace.balanceDiffs = new Vm.FrameTxBalanceDiff[](1);
        frameTx.trace.balanceDiffs[0] =
            Vm.FrameTxBalanceDiff({account: CHANGED_ACCOUNT, balanceBefore: 41, balanceAfter: 42});
        frameTx.trace.storageDiffs = new Vm.FrameTxStorageDiff[](1);
        frameTx.trace.storageDiffs[0] =
            Vm.FrameTxStorageDiff({account: CHANGED_ACCOUNT, key: 43, valueBefore: 44, valueAfter: 45});
        frameTx.trace.deployedContracts = new Vm.FrameTxDeployedContract[](1);
        frameTx.trace.deployedContracts[0] =
            Vm.FrameTxDeployedContract({account: DEPLOYED_ACCOUNT, codeHash: DEPLOYED_CODE_HASH});
        frameTx.trace.accountDiffs = new Vm.FrameTxAccountDiff[](1);
        frameTx.trace.accountDiffs[0] = Vm.FrameTxAccountDiff({
            account: CHANGED_ACCOUNT,
            nonceChanged: true,
            codeHashBefore: CODE_HASH_BEFORE,
            codeHashAfter: CODE_HASH_AFTER
        });
        frameTx.trace.events = new Vm.FrameTxEvent[](1);
        frameTx.trace.events[0].emitter = EMITTER;
        frameTx.trace.events[0].topics = new bytes32[](2);
        frameTx.trace.events[0].topics[0] = TOPIC_0;
        frameTx.trace.events[0].topics[1] = TOPIC_1;
        frameTx.trace.events[0].data = hex"aabbccdd";
        frameTx.trace.gasPreCharge = 46;
        frameTx.trace.gasPayer = GAS_PAYER;
    }

    function _txparam(uint8 param) internal returns (bytes32) {
        return _runWord(abi.encodePacked(hex"60", bytes1(param), hex"b05f5260205ff3"));
    }

    function _recentRootReference(uint8 index, uint8 field) internal returns (bytes32) {
        return _runWord(abi.encodePacked(hex"60", bytes1(index), hex"60", bytes1(field), hex"b65f5260205ff3"));
    }

    function _signatureData(uint8 index, uint8 offset, uint8 length) internal returns (bytes memory) {
        bytes memory code = abi.encodePacked(
            hex"60",
            bytes1(index),
            hex"60",
            bytes1(length),
            hex"60",
            bytes1(offset),
            hex"6000b560",
            bytes1(length),
            hex"6000f3"
        );
        return _run(code);
    }

    function _txtrace(uint8 param, uint8 index) internal returns (bytes32) {
        return _runWord(abi.encodePacked(hex"60", bytes1(param), hex"60", bytes1(index), hex"b75f5260205ff3"));
    }

    function _txdiff(uint8 param, address account, uint256 input) internal returns (bytes32) {
        return _runWord(
            abi.encodePacked(hex"7f", bytes32(input), hex"73", account, hex"60", bytes1(param), hex"b85f5260205ff3")
        );
    }

    function _eventData(uint8 index, uint8 offset, uint8 length) internal returns (bytes memory) {
        bytes memory code = abi.encodePacked(
            hex"60",
            bytes1(length),
            hex"60",
            bytes1(offset),
            hex"600060",
            bytes1(index),
            hex"b960",
            bytes1(length),
            hex"6000f3"
        );
        return _run(code);
    }

    function _runWord(bytes memory code) internal returns (bytes32) {
        return abi.decode(_run(code), (bytes32));
    }

    function _run(bytes memory code) internal returns (bytes memory result) {
        vm.etch(READER, code);
        bool success;
        (success, result) = READER.staticcall("");
        assertTrue(success);
    }
}
