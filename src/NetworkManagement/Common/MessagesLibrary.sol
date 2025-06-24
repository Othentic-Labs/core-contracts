// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.25;

/*______     __      __                              __      __ 
 /      \   /  |    /  |                            /  |    /  |
/$$$$$$  | _$$ |_   $$ |____    ______   _______   _$$ |_   $$/   _______ 
$$ |  $$ |/ $$   |  $$      \  /      \ /       \ / $$   |  /  | /       |
$$ |  $$ |$$$$$$/   $$$$$$$  |/$$$$$$  |$$$$$$$  |$$$$$$/   $$ |/$$$$$$$/ 
$$ |  $$ |  $$ | __ $$ |  $$ |$$    $$ |$$ |  $$ |  $$ | __ $$ |$$ |
$$ \__$$ |  $$ |/  |$$ |  $$ |$$$$$$$$/ $$ |  $$ |  $$ |/  |$$ |$$ \_____ 
$$    $$/   $$  $$/ $$ |  $$ |$$       |$$ |  $$ |  $$  $$/ $$ |$$       |
 $$$$$$/     $$$$/  $$/   $$/  $$$$$$$/ $$/   $$/    $$$$/  $$/  $$$$$$$/
*/

library MessagesLibrary {
    bytes4 internal constant BATCH_CLEAR_SIG = bytes4(keccak256("BATCH_CLEAR"));
    bytes4 internal constant BATCH_PAYMENT_SIG = bytes4(keccak256("BATCH_PAYMENT"));
    bytes4 internal constant EIGEN_REWARDS_SIG = bytes4(keccak256("EIGEN_REWARDS"));
    bytes4 internal constant REGISTER_SIG = bytes4(keccak256("REGISTER"));
    bytes4 internal constant UNREGISTER_SIG = bytes4(keccak256("UNREGISTER"));
    bytes4 internal constant OPERATOR_EJECTION_SIG = bytes4(keccak256("OPERATOR_EJECTION"));

    //////////////////////////////////////////////////////////////////
    //      Message Builders
    //////////////////////////////////////////////////////////////////
    //
    //      Tasks Manager to Network Manager messages
    //
    /////////////////////////////////////////////////////////////////

    function BuildOperatorEjectionMessage(address _operator) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(MessagesLibrary.OPERATOR_EJECTION_SIG, _operator);
    }

    function BuildBatchPaymentRequestMessage(bytes memory _operators, uint256 _taskNumber)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(MessagesLibrary.BATCH_PAYMENT_SIG, _operators, _taskNumber);
    }

    function BuildEigenRewardsRequestMessage(bytes memory _operators, uint256 _taskNumber, bytes memory _rewardsData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(MessagesLibrary.EIGEN_REWARDS_SIG, _operators, _taskNumber, _rewardsData);
    }

    //////////////////////////////////////////////////////////////////
    //
    //       AvsGovernance to AttestationCenter messages
    //
    /////////////////////////////////////////////////////////////////
    function BuildRegisterOperatorMessage(
        address _operator,
        uint256 _votingPower,
        uint256[4] calldata _blsKey,
        address _rewardsReceiver
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(MessagesLibrary.REGISTER_SIG, _operator, _votingPower, _blsKey, _rewardsReceiver);
    }

    function BuildUnregisterRequestMessage(address _operator) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(MessagesLibrary.UNREGISTER_SIG, _operator);
    }

    function BuildBatchClearRequestMessage(bytes memory _operators, uint256 _lastPaidTaskNumber)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(MessagesLibrary.BATCH_CLEAR_SIG, _operators, _lastPaidTaskNumber);
    }

    //////////////////////////////////////////////////////////////////
    //
    //       L1MessageHandler
    //
    /////////////////////////////////////////////////////////////////

    function ParseOperatorEjectionMessage(bytes memory _message) internal pure returns (address _operator) {
        return abi.decode(_message, (address));
    }

    function ParseBatchPaymentRequestMessage(bytes memory _message)
        internal
        pure
        returns (bytes memory _operators, uint256 _lastPayedTask)
    {
        return abi.decode(_message, (bytes, uint256));
    }

    function ParseEigenRewardsRequestMessage(bytes memory _message)
        internal
        pure
        returns (bytes memory _operators, uint256 _lastPayedTask, bytes memory _data)
    {
        return abi.decode(_message, (bytes, uint256, bytes));
    }

    //////////////////////////////////////////////////////////////////
    //
    //       L2MessageHandler
    //
    /////////////////////////////////////////////////////////////////

    function ParseRegisterToAvsMessage(bytes memory _message)
        internal
        pure
        returns (address _operator, uint256 _votingPower, uint256[4] memory _blsKey, address _rewardsReceiver)
    {
        return abi.decode(_message, (address, uint256, uint256[4], address));
    }

    function ParseBatchClearMessage(bytes memory _message)
        internal
        pure
        returns (bytes memory _operators, uint256 _lastPaidTaskNumber)
    {
        return abi.decode(_message, (bytes, uint256));
    }

    function ParseUnregisterOperatorMessage(bytes memory _message) internal pure returns (address operator) {
        return abi.decode(_message, (address));
    }

    function PayloadToSig(bytes calldata _payload) internal pure returns (bytes4 _sig, bytes memory _body) {
        _sig = bytes4(_payload[0:4]);
        _body = _payload[4:];
    }
}
