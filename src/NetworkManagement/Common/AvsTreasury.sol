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

import "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {IAvsTreasury} from "@othentic/NetworkManagement/Common/interfaces/IAvsTreasury.sol";
import {IAvsTreasuryDepositCallback} from "@othentic/NetworkManagement/L1/interfaces/IAvsTreasuryDepositCallback.sol";
import "@othentic/NetworkManagement/Common/AvsTreasuryStorage.sol";
import "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {SafeERC20NoRevert} from "@othentic/NetworkManagement/Common/SafeERC20NoRevert.sol";
import {VennFirewallConsumer} from "@ironblocks/firewall-consumer/contracts/consumers/VennFirewallConsumer.sol";
import {ContextUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/ContextUpgradeable.sol";
import {Context} from "openzeppelin-contracts/contracts/utils/Context.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
abstract contract AvsTreasury is
    IAvsTreasury,
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    VennFirewallConsumer
{
    using SafeERC20 for IERC20;
    using SafeERC20NoRevert for IERC20;

    uint256 constant MILLION_DENOMINATOR = 1_000_000;
    address public constant ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    modifier onlyERC20() {
        if (address(_getStorage().token) == ETH_ADDRESS) revert NativeETHNotSupported();
        _;
    }

    modifier onlyETH() {
        if (address(_getStorage().token) != ETH_ADDRESS) revert ERC20NotSupported();
        _;
    }

    modifier onlyNonZeroAmounts() {
        if (_msgValue() == 0) revert ZeroValueNotAllowed();
        _;
    }

    modifier validateExecutionTime() {
        AvsTreasuryStorageData storage _sd = _getStorage();
        if (block.timestamp < _sd.tokenReplacementDetails.executionTime) revert TokenModificationDelayNotPassed();
        _;
    }

    modifier onlyEmptyAVSTreasury() {
        if (_getStorage().balance > 0) revert AvsTreasuryBalanceNotZero();
        _;
    }

    function initialize(InitializationParams calldata _initalizationParams) public initializer {
        _initialize(_initalizationParams);
    }

    function _initialize(InitializationParams calldata _initalizationParams) internal onlyInitializing {
        AvsTreasuryStorageData storage _sd = _getStorage();
        _sd.token = IERC20(_initalizationParams.token);
        _sd.otTreasury = _initalizationParams.otTreasury;
        _sd.protocolFee = _initalizationParams.protocolFee;
        _sd.tokenReplacementModificationDelay = 7 days;
        _sd.tokenReplacementDetails.executionTime = type(uint48).max;
        __AccessControl_init();
        __ReentrancyGuard_init();
        _grantRole(RolesLibrary.OPERATIONS_MULTISIG, _initalizationParams.operationsMultisig);
        _grantRole(RolesLibrary.AVS_FACTORY_ROLE, _msgSender());
        _grantRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG, _initalizationParams.avsGovernanceMultisigOwner);
        _grantRole(RolesLibrary.TOKEN_REPLACEMENT_MODIFICATION_DELAY, _initalizationParams.operationsMultisig);
        _grantRole(RolesLibrary.TOKEN_REPLACEMENT_MODIFICATION_DELAY, _initalizationParams.communityMultisig);
    }

    function getToken() external view returns (address rewardsToken) {
        return address(_getStorage().token);
    }

    function getTokenReplacementDetails() external view returns (TokenReplacementDetails memory) {
        return _getStorage().tokenReplacementDetails;
    }

    function getTokenReplacementModificationDelay() external view returns (uint32) {
        return _getStorage().tokenReplacementModificationDelay;
    }

    function setProtocolFee(uint256 _protocolFee)
        external
        firewallProtected
        onlyRole(RolesLibrary.OPERATIONS_MULTISIG)
    {
        _getStorage().protocolFee = _protocolFee;
    }

    function setOtTreasury(address _otTreasury) external firewallProtected onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        _getStorage().otTreasury = _otTreasury;
    }

    function setTokenReplacementModificationDelay(uint32 _tokenReplacementModificationDelay)
        external
        firewallProtected
        onlyRole(RolesLibrary.TOKEN_REPLACEMENT_MODIFICATION_DELAY)
    {
        _getStorage().tokenReplacementModificationDelay = _tokenReplacementModificationDelay;
        emit SetTokenReplacementModificationDelay(_tokenReplacementModificationDelay);
    }

    function queueTokenReplacement(address _newToken)
        external
        firewallProtected
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        AvsTreasuryStorageData storage _sd = _getStorage();
        _sd.tokenReplacementDetails =
            TokenReplacementDetails(IERC20(_newToken), uint48(block.timestamp + _sd.tokenReplacementModificationDelay));
        emit TokenReplacementQueued(_newToken, _sd.tokenReplacementDetails.executionTime);
    }

    function completeTokenReplacement()
        external
        firewallProtected
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        validateExecutionTime
        nonReentrant
    {
        _completeTokenReplacement();
    }

    //@obsolete to delete after migration
    function migrateTreasuryStorage(
        address _avsGovernanceMultisigOwner,
        address _operationsMultisig,
        address _communityMultisig
    ) external firewallProtected onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        AvsTreasuryStorageData storage _sd = _getStorage();
        _sd.tokenReplacementModificationDelay = 7 days;
        _sd.tokenReplacementDetails.executionTime = type(uint48).max;
        _grantRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG, _avsGovernanceMultisigOwner);
        _grantRole(RolesLibrary.TOKEN_REPLACEMENT_MODIFICATION_DELAY, _operationsMultisig);
        _grantRole(RolesLibrary.TOKEN_REPLACEMENT_MODIFICATION_DELAY, _communityMultisig);
    }

    function depositNative() external payable firewallProtected onlyETH onlyNonZeroAmounts {
        AvsTreasuryStorageData storage _sd = _getStorage();
        uint256 _protocolFee = _sd.protocolFee;
        _validateProtocolFee(_msgValue(), _protocolFee);
        uint256 _fee = (_msgValue() * _protocolFee) / MILLION_DENOMINATOR;
        (bool _success,) = address(_sd.otTreasury).call{value: _fee}("");
        uint256 _deposited = _msgValue() - _fee;
        _sd.balance += _deposited;
        if (!_success) revert TransferToOtTreasuryFailed();
        emit RewardsDeposited(_sd.avsTreasuryOwner, _deposited);
    }

    // @obselete - depositERC20(uint256 _amount) should be used instead

    function depositERC20(address, /*_from*/ uint256 _amount) external firewallProtected onlyERC20 nonReentrant {
        _depositERC20(_amount);
    }

    function depositERC20(uint256 _amount) external firewallProtected onlyERC20 nonReentrant {
        _depositERC20(_amount);
    }

    function depositERC20WithCallback(address _from, uint256 _amount, bytes calldata _data)
        external
        firewallProtected
        onlyERC20
        nonReentrant
    {
        AvsTreasuryStorageData storage _sd = _getStorage();
        uint256 _balanceBefore = _sd.token.balanceOf(address(this));
        IAvsTreasuryDepositCallback(_from).avsTreasuryDepositCallback(_amount, _data);
        if (_balanceBefore + _amount > _sd.token.balanceOf(address(this))) revert TransferFailed();
        _depositERC20Rewards(_amount, _sd);
    }

    function transferAvsGovernanceMultisig(address _newAvsGovernanceMultisig)
        external
        firewallProtected
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        _revokeRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG, _msgSender());
        _grantRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG, _newAvsGovernanceMultisig);
        emit SetAvsGovernanceMultisig(_newAvsGovernanceMultisig);
    }

    function _withdrawRewards(address _operator, uint256 _lastPayedTask, uint256 _feeToClaim)
        internal
        returns (bool _success)
    {
        AvsTreasuryStorageData storage _sd = _getStorage();
        IERC20 _token = _sd.token;
        if (_sd.balance < _feeToClaim) {
            _success = false;
        } else if (address(_token) != ETH_ADDRESS) {
            _success = _token.safeTransferNoRevert(_operator, _feeToClaim);
        } else {
            (_success,) = _operator.call{value: _feeToClaim}("");
        }

        if (_success) {
            _sd.balance -= _feeToClaim;
            emit RewardWithdrawn(_operator, _lastPayedTask, _feeToClaim);
        } else {
            emit RewardWithdrawalFailed(_operator, _lastPayedTask, _feeToClaim);
        }
    }

    function _depositERC20Rewards(uint256 _amount, AvsTreasuryStorageData storage _sd) internal {
        if (_amount == 0) revert ZeroValueNotAllowed();
        uint256 _deposited = _transferERC20ProtocolFee(_amount, _sd);
        emit RewardsDeposited(_sd.avsTreasuryOwner, _deposited);
    }

    function _depositERC20RewardsBack(uint256 _amount) internal returns (bool _success) {
        AvsTreasuryStorageData storage _sd = _getStorage();
        IERC20 _token = _sd.token;

        _success = _token.safeTransferFromNoRevert(msg.sender, address(this), _amount);
        if (_success) {
            _sd.balance += _amount;
            emit RewardsDepositedBack(msg.sender, _amount);
        }
    }

    function _transferERC20ProtocolFee(uint256 _amount, AvsTreasuryStorageData storage _sd)
        internal
        returns (uint256 _deposited)
    {
        uint256 _protocolFee = _sd.protocolFee;
        _validateProtocolFee(_amount, _protocolFee);
        uint256 _fee = (_amount * _protocolFee) / MILLION_DENOMINATOR;
        _sd.token.safeTransfer(_sd.otTreasury, _fee);
        _deposited = _amount - _fee;
        _sd.balance += _deposited;
    }

    function _validateProtocolFee(uint256 _amount, uint256 _protocolFee) internal pure {
        if (((_amount * _protocolFee) / MILLION_DENOMINATOR) == 0) revert InvalidProtocolFee();
    }

    function _getStorage() internal pure returns (AvsTreasuryStorageData storage sd) {
        return AvsTreasuryStorage.load();
    }

    function _completeTokenReplacement() private {
        AvsTreasuryStorageData storage _sd = _getStorage();
        IERC20 _token = _sd.token;
        if (address(_token) == ETH_ADDRESS) {
            // Native token
            uint256 _treasuryNativeTokenBalance = address(this).balance;
            if (_treasuryNativeTokenBalance > 0) {
                payable(_msgSender()).transfer(_treasuryNativeTokenBalance);
            }
        } else {
            // ERC20 token
            uint256 _treasuryETHTokenBalance = _token.balanceOf(address(this));
            if (_treasuryETHTokenBalance > 0) {
                _token.safeTransfer(_msgSender(), _treasuryETHTokenBalance);
            }
        }
        _sd.balance = 0;
        _sd.token = _sd.tokenReplacementDetails.queuedTokenReplacement;
        _sd.tokenReplacementDetails = TokenReplacementDetails(IERC20(address(0)), type(uint48).max);
        emit TokenReplaced(address(_sd.token));
    }

    function _depositERC20(uint256 _amount) private {
        AvsTreasuryStorageData storage _sd = _getStorage();
        _sd.token.safeTransferFrom(_msgSender(), address(this), _amount);
        _depositERC20Rewards(_amount, _sd);
    }

    function _contextSuffixLength() internal view virtual override(ContextUpgradeable, Context) returns (uint256) {
        return super._contextSuffixLength();
    }

    function _msgSender() internal view virtual override(ContextUpgradeable, Context) returns (address) {
        return super._msgSender();
    }

    function _msgData() internal view virtual override(ContextUpgradeable, Context) returns (bytes calldata) {
        return super._msgData();
    }
}
