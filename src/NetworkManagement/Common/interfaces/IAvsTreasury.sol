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
/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

interface IAvsTreasury {
    struct InitializationParams {
        address avsGovernanceMultisigOwner;
        address operationsMultisig;
        address communityMultisig;
        address token;
        address otTreasury;
        uint256 protocolFee;
    }

    struct TokenReplacementDetails {
        IERC20 queuedTokenReplacement;
        uint48 executionTime;
    }

    event RewardsDeposited(address avsTreasuryOwner, uint256 amount);
    event RewardsDepositedBack(address avsContract, uint256 amount);
    event RewardWithdrawn(address indexed operator, uint256 lastPayedTask, uint256 feeToClaim);
    event RewardWithdrawalFailed(address indexed operator, uint256 lastPayedTask, uint256 feeToClaim);
    event SetTokenReplacementModificationDelay(uint32 delay);
    event TokenReplacementQueued(address queuedTokenReplacement, uint256 modificationTimeTokenReplacement);
    event TokenReplaced(address newToken);
    event SetAvsGovernanceMultisig(address newAvsGovernanceMultisig);

    error NativeETHNotSupported();
    error ERC20NotSupported();
    error ZeroValueNotAllowed();
    error InvalidAmount();
    error TransferToOtTreasuryFailed();
    error InvalidProtocolFee();
    error TransferFailed();
    error TokenModificationDelayNotPassed();
    error AvsTreasuryBalanceNotZero();

    function depositNative() external payable;
    // @obsolete
    function depositERC20(address _from, uint256 _amount) external;
    function depositERC20(uint256 _amount) external;
    function depositERC20WithCallback(address _from, uint256 _amount, bytes calldata _data) external;
    function withdrawRewards(address _operator, uint256 _lastPayedTask, uint256 _feeToClaim)
        external
        returns (bool success);
    function setTokenReplacementModificationDelay(uint32 _delay) external;
    function queueTokenReplacement(address _newToken) external;
    function completeTokenReplacement() external;
    function getToken() external view returns (address rewardsToken);
    function getTokenReplacementDetails() external view returns (TokenReplacementDetails memory);
    function getTokenReplacementModificationDelay() external view returns (uint32);
    function ETH_ADDRESS() external view returns (address);
    function transferAvsGovernanceMultisig(address _newAvsGovernanceMultisig) external;
}
