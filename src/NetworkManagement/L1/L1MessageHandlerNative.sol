// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.19;
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

import "@othentic/NetworkManagement/Common/MessageHandlerNative.sol";
import "@othentic/NetworkManagement/L1/interfaces/IAvsGovernance.sol";
import "@othentic/NetworkManagement/L1/interfaces/IL1MessageHandler.sol";
import "@othentic/NetworkManagement/L1/L1MessageHandlerStorage.sol";
import {MessagesLibrary} from "@othentic/NetworkManagement/Common/MessagesLibrary.sol";
import "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import "@othentic/NetworkManagement/Common/interfaces/NativeBridge/IL2StateReceiver.sol";
import "@othentic/NetworkManagement/L1/L1MessageHandlerNativeStorage.sol";

contract L1MessageHandlerNative is IL2StateReceiver, IL1MessageHandler, MessageHandlerNative {
    function initialize(
        address _avsGovernanceMultisigOwner,
        address _operationsMultisig,
        address _communityMultisig,
        address _stateSenderAddress,
        address _localStateReceiverAddress
    ) public initializer {
        _initialize(
            _avsGovernanceMultisigOwner,
            _operationsMultisig,
            _communityMultisig,
            _stateSenderAddress,
            _localStateReceiverAddress
        );
        _grantRole(RolesLibrary.STATE_RECEIVER, _localStateReceiverAddress);
    }

    function setAvsGovernance(address _avsGovernanceAddress) external onlyRole(RolesLibrary.AVS_FACTORY_ROLE) {
        _getL1MessageHandlerStorage().avsGovernance = IAvsGovernance(_avsGovernanceAddress);
        _grantRole(RolesLibrary.AVS_GOVERNANCE, _avsGovernanceAddress);

        emit SetAvsGovernance(_avsGovernanceAddress);
    }

    function getAvsGovernance() external view returns (address) {
        return address(_getL1MessageHandlerStorage().avsGovernance);
    }

    function transferAvsGovernance(address _newAvsGovernanceAddress)
        external
        onlyRole(RolesLibrary.OPERATIONS_MULTISIG)
    {
        L1MessageHandlerNativeStorageData storage _sd = _getL1MessageHandlerStorage();
        _revokeRole(RolesLibrary.AVS_GOVERNANCE, address(_sd.avsGovernance));
        _grantRole(RolesLibrary.AVS_GOVERNANCE, _newAvsGovernanceAddress);
        _sd.avsGovernance = IAvsGovernance(_newAvsGovernanceAddress);
        emit SetAvsGovernance(_newAvsGovernanceAddress);
    }

    function onL2StateReceive(address _sender, bytes calldata data)
        external
        override
        onlyRole(RolesLibrary.STATE_RECEIVER)
    {
        (bytes4 _sig, bytes memory _body) = MessagesLibrary.PayloadToSig(data);
        if (_sig == MessagesLibrary.BATCH_PAYMENT_SIG && _sender != address(0)) {
            _handleBatchPaymentRequestMessage(_body);
        } else {
            revert("L1MessageHandlerNative: Unknown message signature");
        }
    }

    function _handleBatchPaymentRequestMessage(bytes memory _message) internal {
        (bytes memory _operatorsBytes, uint256 _lastPayedTask) =
            MessagesLibrary.ParseBatchPaymentRequestMessage(_message);

        IAvsGovernanceExtension.PaymentRequestMessage[] memory _operators =
            abi.decode(_operatorsBytes, (IAvsGovernanceExtension.PaymentRequestMessage[]));
        (bool _success,) = address(_getL1MessageHandlerStorage().avsGovernance).call(
            abi.encodeCall(IAvsGovernanceExtension.withdrawBatchRewards, (_operators, _lastPayedTask, 1))
        ); // 1 This is a placeHolder for the remote chain ID
        require(_success, "L1MessageHandlerNative: Failed to call avsGovernance.withdrawBatchRewards");
        emit PaymentsRequested(_operators, _lastPayedTask);
    }

    function sendMessage(bytes memory message) external onlyRole(RolesLibrary.AVS_GOVERNANCE) {
        _sendMessage(message);
    }

    function _getL1MessageHandlerStorage() internal pure returns (L1MessageHandlerNativeStorageData storage sd) {
        return L1MessageHandlerNativeStorage.load();
    }
}
