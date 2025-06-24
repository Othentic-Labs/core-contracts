// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.25;

import "@othentic/NetworkManagement/L1/interfaces/IAvsGovernance.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {IOptInService} from "@symbiotic/src/interfaces/service/IOptInService.sol";
import {INetworkRegistry} from "@symbiotic/src/interfaces/INetworkRegistry.sol";
import {INetworkMiddlewareService} from "@symbiotic/src/contracts/service/NetworkMiddlewareService.sol";
import {IVaultFactory} from "@symbiotic/src/contracts/VaultFactory.sol";

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
interface IOthenticRegistry {
    struct InitializationParams {
        address slasher;
        address delegationManager;
        address strategyManager;
        address ownerMultiSig;
        address vaultFactory;
        address networkRegistry;
        address optInService;
        address networkMiddlewareService;
        address l1AvsFactory;
        address avsDirectory;
        address rewardsCoordinator;
    }

    event OperatorOptIn(address operator, uint256 shares, uint32 serveUntilBlock);
    event AvsOptIn(address avsGovernance, string avsName);

    error InvalidBlockId();

    // @obsolete
    function getVotingPower(address _operator, IAvsGovernance.VotingPowerMultiplier[] calldata _votingPowerMultipliers)
        external
        view
        returns (uint256);

    function getOperatorRestakedStrategies(address _operator, address[] memory _allStrategies, address _avsGovernance)
        external
        view
        returns (address[] memory);
    function registerAvs(string memory _avsName) external;
    function isValidStakeAmount(
        address _operator,
        IAvsGovernance.StakingContractDetails[] calldata _minStakePerStakingContract,
        address _avsGovernance
    ) external view returns (bool);
    function getDefaultStrategies(uint256 _chainid)
        external
        pure
        returns (IAvsGovernance.StakingContractInfo[] memory);
    function isValidStakingContract(address _stakingContract) external view returns (bool);
    function optInService() external view returns (IOptInService);
    function networkRegistry() external view returns (INetworkRegistry);
    function networkMiddlewareService() external view returns (INetworkMiddlewareService);
    function rewardsCoordinator() external view returns (IRewardsCoordinator);
    function vaultFactory() external view returns (IVaultFactory);
    function getVotingPower(
        address _operator,
        IAvsGovernance.VotingPowerMultiplier[] calldata _votingPowerMultipliers,
        address _avsGovernance
    ) external view returns (uint256);
}
