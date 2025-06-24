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

import "@othentic/NetworkManagement/Common/interfaces/IMessageHandler.sol";
import "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import "@othentic/NetworkManagement/Common/OthenticAccessControl.sol";
import "@othentic/NetworkManagement/Common/interfaces/NativeBridge/IStateSender.sol";
import "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import "@othentic/NetworkManagement/Common/MessageHandlerNativeStorage.sol";

abstract contract MessageHandlerNative is IMessageHandler, OthenticAccessControl {
    event MessageSent(address recipient, bytes message);
    event RemoteStateReceiverAddressSet(address remoteStateReceiverAddress);

    function setRemoteStateReceiverAddress(address _remoteStateReceiverAddress)
        external
        onlyRole(RolesLibrary.AVS_FACTORY_ROLE)
    {
        MessageHandlerNativeStorageData storage _sd = _getStorage();
        _revokeRole(RolesLibrary.STATE_RECEIVER, _sd.remoteStateReceiverAddress);
        _grantRole(RolesLibrary.STATE_RECEIVER, _remoteStateReceiverAddress);
        _sd.remoteStateReceiverAddress = _remoteStateReceiverAddress;
        emit RemoteStateReceiverAddressSet(_remoteStateReceiverAddress);
    }

    function _initialize(
        address _avsGovernanceMultisigOwner,
        address _operationsMultisig,
        address _communityMultisig,
        address _stateSenderAddress,
        address _localStateReceiverAddress
    ) internal virtual onlyInitializing {
        __OthenticAccessControl_init(_avsGovernanceMultisigOwner, _operationsMultisig, _communityMultisig);
        MessageHandlerNativeStorageData storage _sd = _getStorage();
        _sd.stateSender = IStateSender(_stateSenderAddress);
        _sd.localStateReceiverAddress = _localStateReceiverAddress;
        _grantRole(RolesLibrary.AVS_FACTORY_ROLE, msg.sender);
        _grantRole(RolesLibrary.STATE_RECEIVER, _localStateReceiverAddress);
    }

    function _sendMessage(bytes memory _message) internal {
        MessageHandlerNativeStorageData storage _sd = _getStorage();
        _sd.stateSender.syncState(_sd.remoteStateReceiverAddress, _message);
        emit MessageSent(_sd.remoteStateReceiverAddress, _message);
    }

    function _getStorage() internal pure virtual returns (MessageHandlerNativeStorageData storage) {
        return MessageHandlerNativeStorage.load();
    }
}
