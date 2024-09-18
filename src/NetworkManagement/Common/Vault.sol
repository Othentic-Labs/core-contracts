// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.20;
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

import "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {IVault} from "@othentic/NetworkManagement/Common/interfaces/IVault.sol";
import {IVaultDepositCallback} from "@othentic/NetworkManagement/L1/interfaces/IVaultDepositCallback.sol";
import "@othentic/NetworkManagement/Common/VaultStorage.sol";
import "@othentic/NetworkManagement/Common/RolesLibrary.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */

abstract contract Vault is IVault, Initializable, AccessControlUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    uint256 constant MILLION_DENOMINATOR = 1000000;
    address constant ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    
    modifier onlyERC20() {
        if (address(_getStorge().token) == ETH_ADDRESS) revert NativeETHNotSupported();
        _;
    }

    modifier onlyETH() {
        if (address(_getStorge().token) != ETH_ADDRESS) revert ERC20NotSupported();
        _;
    }

    modifier onlyNonZeroAmounts() {
        if(msg.value == 0) revert ZeroValueNotAllowed();
        _;
    }

    function initialize(address _token, address _operationsMultisig, address _otTreasury, uint256 _protocolFee) public initializer {
        _initialize(_token, _operationsMultisig, _otTreasury, _protocolFee);
    }
    
    function _initialize(address _token, address _operationsMultisig, address _otTreasury, uint256 _protocolFee) internal onlyInitializing {
        VaultStorageData storage _sd = _getStorge();
        _sd.token = IERC20(_token);
        _sd.otTreasury = _otTreasury;
        _sd.protocolFee = _protocolFee;
        __AccessControl_init();
        _grantRole(RolesLibrary.OPERATIONS_MULTISIG, _operationsMultisig);
        _grantRole(RolesLibrary.AVS_FACTORY_ROLE, msg.sender);
    }

    function getToken() external view returns (address rewardsToken) {
        return address(_getStorge().token);
    }
    
    function setProtocolFee(uint256 _protocolFee) external onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        _getStorge().protocolFee = _protocolFee;
    }
    
    function setOtTreasury(address _otTreasury) external onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        _getStorge().otTreasury = _otTreasury;
    }

    function depositNative() external onlyETH onlyNonZeroAmounts payable {
        VaultStorageData storage _sd = _getStorge();
        uint256 _protocolFee = _sd.protocolFee;
        _validateProtocolFee(msg.value, _protocolFee);
        uint256 _fee = (msg.value * _protocolFee) / MILLION_DENOMINATOR;
        (bool _success,) = address(_sd.otTreasury).call{ value: _fee }("");
        _sd.balance += (msg.value - _fee);
        if (!_success) revert TransferToOtTreasuryFailed();
        emit RewardsDeposited(_sd.ownerVault, msg.value);
    }

    function depositERC20(address _from, uint256 _amount) external onlyERC20 {
        VaultStorageData storage _sd = _getStorge();
        _sd.token.safeTransferFrom(_from, address(this), _amount);
        _depositERC20Rewards(_amount, _sd);
    }

    function depositERC20WithCallback(address _from, uint256 _amount, bytes calldata _data) external onlyERC20 {
        VaultStorageData storage _sd = _getStorge();
        uint256 _balanceBefore = _sd.token.balanceOf(address(this));
        IVaultDepositCallback(_from).vaultDepositCallback(_amount, _data);
        if (_balanceBefore + _amount > _sd.token.balanceOf(address(this))) revert TransferFailed();
        _depositERC20Rewards(_amount, _sd);
    }

    function _withdrawRewards(address _operator, uint256 _lastPayedTask, uint256 _feeToClaim) internal returns (bool _success) {
        VaultStorageData storage _sd = _getStorge();
        IERC20 _token = _sd.token;
        if (_sd.balance < _feeToClaim) {
                _success = false;
         }
        else if(address(_token)!= ETH_ADDRESS) {     
            (_success, ) = address(_token).call(abi.encodeWithSignature("transfer(address,uint256)", _operator, _feeToClaim));
        }
        else {
            (_success,) = _operator.call{value: _feeToClaim}("");
        }

        if (_success) {
            _sd.balance -= _feeToClaim; 
            emit RewardWithdrawn(_operator, _lastPayedTask, _feeToClaim);
        } 
        else {
            emit RewardWithdrawalFailed(_operator, _lastPayedTask, _feeToClaim);
        }
    }

    function _depositERC20Rewards(uint256 _amount, VaultStorageData storage _sd) internal {
        if (_amount == 0) revert ZeroValueNotAllowed();
        _transferERC20ProtocolFee(_amount, _sd);
        emit RewardsDeposited(_sd.ownerVault, _amount);
    }

    function _transferERC20ProtocolFee(uint256 _amount, VaultStorageData storage _sd) internal {
        uint256 _protocolFee = _sd.protocolFee;
        _validateProtocolFee(_amount, _protocolFee);
        uint256 _fee = (_amount * _protocolFee) / MILLION_DENOMINATOR;
        _sd.token.safeTransfer(_sd.otTreasury, _fee);
        _sd.balance += (_amount - _fee);
    }

    function _validateProtocolFee(uint256 _amount, uint256 _protocolFee) internal pure {
        if (((_amount * _protocolFee) / MILLION_DENOMINATOR) == 0) revert InvalidProtocolFee();
    }

    function _getStorge() internal pure returns (VaultStorageData storage sd) {
        return VaultStorage.load();
    }
}
