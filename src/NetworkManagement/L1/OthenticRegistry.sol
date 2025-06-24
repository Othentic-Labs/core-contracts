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

import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";

import {ISlasher} from "@eigenlayer/contracts/interfaces/ISlasher.sol";
import {IDelegationManager} from "@eigenlayer/contracts/interfaces/IDelegationManager.sol";
import {IStrategy} from "@eigenlayer/contracts/interfaces/IStrategy.sol";
import {IStrategyManager} from "@eigenlayer/contracts/interfaces/IStrategyManager.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {
    AvsGovernancesLibrary, AvsGovernances, InavlidAvsGovernance, NotActiveOperator
} from "./AvsGovernancesLibrary.sol";
import {IOthenticRegistry} from "./interfaces/IOthenticRegistry.sol";
import {IAvsGovernance} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernance.sol";
import {IVault} from "@symbiotic/src/interfaces/vault/IVault.sol";
import {IVaultFactory} from "@symbiotic/src/interfaces/IVaultFactory.sol";
import {IOptInService} from "@symbiotic/src/interfaces/service/IOptInService.sol";
import {INetworkRegistry} from "@symbiotic/src/interfaces/INetworkRegistry.sol";
import {IBaseDelegator} from "@symbiotic/src/interfaces/delegator/IBaseDelegator.sol";
import {Subnetwork} from "@symbiotic/src/contracts/libraries/Subnetwork.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {INetworkMiddlewareService} from "@symbiotic/src/contracts/service/NetworkMiddlewareService.sol";
import {IAVSDirectoryFull, IAVSDirectory} from "@othentic/NetworkManagement/L1/interfaces/IAVSDirectoryFull.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
contract OthenticRegistry is Initializable, OwnableUpgradeable, IOthenticRegistry {
    using AvsGovernancesLibrary for AvsGovernances;

    address private constant BEACON_CHAIN_ETH_STRATEGY = 0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0;

    ISlasher public slasher;
    IDelegationManager public delegationManager;
    IStrategyManager public strategyManager;
    AvsGovernances private avsGovernances; // obsolete
    IVaultFactory public vaultFactory;
    IOptInService public optInService;
    INetworkRegistry public networkRegistry;
    INetworkMiddlewareService public networkMiddlewareService;
    IL1AvsFactory public l1AvsFactory;
    IAVSDirectoryFull public avsDirectory;
    IRewardsCoordinator public rewardsCoordinator;

    modifier onlyAvsGovernance() {
        if (!l1AvsFactory.isVerifiedAvsGovernanceDeployment(msg.sender)) revert InavlidAvsGovernance();
        _;
    }

    function initialize(InitializationParams calldata _initializationParams) public initializer {
        _initialize(_initializationParams);
    }

    function _initialize(InitializationParams calldata _initializationParams) internal onlyInitializing {
        __Ownable_init(_initializationParams.ownerMultiSig);
        slasher = ISlasher(_initializationParams.slasher);
        delegationManager = IDelegationManager(_initializationParams.delegationManager);
        strategyManager = IStrategyManager(_initializationParams.strategyManager);
        vaultFactory = IVaultFactory(_initializationParams.vaultFactory);
        networkRegistry = INetworkRegistry(_initializationParams.networkRegistry);
        optInService = IOptInService(_initializationParams.optInService);
        networkMiddlewareService = INetworkMiddlewareService(_initializationParams.networkMiddlewareService);
        l1AvsFactory = IL1AvsFactory(_initializationParams.l1AvsFactory);
        avsDirectory = IAVSDirectoryFull(_initializationParams.avsDirectory);
        rewardsCoordinator = IRewardsCoordinator(_initializationParams.rewardsCoordinator);
    }

    function registerAvs(string memory _avsName) external {
        emit AvsOptIn(msg.sender, _avsName);
    }

    // @obsolete - remove in next release
    function getVotingPower(address _operator, IAvsGovernance.VotingPowerMultiplier[] calldata _votingPowerMultipliers)
        external
        view
        returns (uint256)
    {
        uint256 _votingPower = 0;
        address _avsGovernance = msg.sender;
        for (uint256 i = 0; i < _votingPowerMultipliers.length;) {
            _votingPower += _getVotingPower(_operator, _votingPowerMultipliers[i], _avsGovernance);
            unchecked {
                ++i;
            }
        }
        return _votingPower;
    }

    function getVotingPower(
        address _operator,
        IAvsGovernance.VotingPowerMultiplier[] calldata _votingPowerMultipliers,
        address _avsGovernance
    ) external view returns (uint256) {
        uint256 _votingPower = 0;
        for (uint256 i = 0; i < _votingPowerMultipliers.length;) {
            _votingPower += _getVotingPower(_operator, _votingPowerMultipliers[i], _avsGovernance);
            unchecked {
                ++i;
            }
        }
        return _votingPower;
    }

    function isValidStakeAmount(
        address _operator,
        IAvsGovernance.StakingContractDetails[] calldata _minStakePerStakingContracts,
        address _avsGovernance
    ) external view returns (bool) {
        bool _isValidStakeAmount = true;

        for (uint256 i = 0; i < _minStakePerStakingContracts.length;) {
            IAvsGovernance.StakingContractDetails calldata _stakingContractMinShares = _minStakePerStakingContracts[i];
            if (_stakingContractMinShares.sharedSecurityProvider == IAvsGovernance.SharedSecurityProvider.EigenLayer) {
                if (
                    _getEigenLayerStakeAmount(_operator, _stakingContractMinShares.stakingContract, _avsGovernance)
                        < _stakingContractMinShares.stakeAmount
                ) {
                    _isValidStakeAmount = false;
                    break;
                }
            } else if (
                _stakingContractMinShares.sharedSecurityProvider == IAvsGovernance.SharedSecurityProvider.Symbiotic
            ) {
                if (
                    _getSymbioticStakeAmount(_operator, _stakingContractMinShares.stakingContract, _avsGovernance)
                        < _stakingContractMinShares.stakeAmount
                ) {
                    _isValidStakeAmount = false;
                    break;
                }
            }
            unchecked {
                ++i;
            }
        }
        return _isValidStakeAmount;
    }

    function getOperatorRestakedStrategies(address _operator, address[] memory _allStrategies, address _avsGovernance)
        external
        view
        returns (address[] memory)
    {
        address[] memory _result = new address[](_allStrategies.length);
        uint256 _count = 0;
        for (uint256 i = 0; i < _allStrategies.length;) {
            if (_getEigenLayerStakeAmount(_operator, _allStrategies[i], _avsGovernance) > 0) {
                _result[_count] = _allStrategies[i];
                _count++;
            }
            unchecked {
                ++i;
            }
        }
        // Adjust the size of the result array to fit the number of valid strategies
        assembly {
            mstore(_result, _count)
        }
        return _result;
    }

    function getDefaultStrategies(uint256 _chainid)
        external
        pure
        returns (IAvsGovernance.StakingContractInfo[] memory)
    {
        if (_chainid == 1) {
            IAvsGovernance.StakingContractInfo[] memory _strategies = new IAvsGovernance.StakingContractInfo[](14);
            _strategies[0] = IAvsGovernance.StakingContractInfo(
                0x0Fe4F44beE93503346A3Ac9EE5A26b130a5796d6, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // swETH strategy
            _strategies[1] = IAvsGovernance.StakingContractInfo(
                0x13760F50a9d7377e4F20CB8CF9e4c26586c658ff, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // ankrETH strategy
            _strategies[2] = IAvsGovernance.StakingContractInfo(
                0x1BeE69b7dFFfA4E2d53C2a2Df135C388AD25dCD2, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // rETH strategy
            _strategies[3] = IAvsGovernance.StakingContractInfo(
                0x298aFB19A105D59E74658C4C334Ff360BadE6dd2, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // mETH strategy
            _strategies[4] = IAvsGovernance.StakingContractInfo(
                0x54945180dB7943c0ed0FEE7EdaB2Bd24620256bc, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // cbETH strategy
            _strategies[5] = IAvsGovernance.StakingContractInfo(
                0x57ba429517c3473B6d34CA9aCd56c0e735b94c02, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // osETH strategy
            _strategies[6] = IAvsGovernance.StakingContractInfo(
                0x7CA911E83dabf90C90dD3De5411a10F1A6112184, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // wBETH strategy
            _strategies[7] = IAvsGovernance.StakingContractInfo(
                0x8CA7A5d6f3acd3A7A8bC468a8CD0FB14B6BD28b6, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // sfrxETH strategy
            _strategies[8] = IAvsGovernance.StakingContractInfo(
                0x93c4b944D05dfe6df7645A86cd2206016c51564D, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // stETH strategy
            _strategies[9] = IAvsGovernance.StakingContractInfo(
                0x9d7eD45EE2E8FC5482fa2428f15C971e6369011d, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // ETHx strategy
            _strategies[10] = IAvsGovernance.StakingContractInfo(
                0xa4C637e0F704745D182e4D38cAb7E7485321d059, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // 0ETH strategy
            _strategies[11] = IAvsGovernance.StakingContractInfo(
                0xaCB55C530Acdb2849e6d4f36992Cd8c9D50ED8F7, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // EIGEN strategy
            _strategies[12] = IAvsGovernance.StakingContractInfo(
                0xAe60d8180437b5C34bB956822ac2710972584473, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // lsETH strategy
            _strategies[13] = IAvsGovernance.StakingContractInfo(
                BEACON_CHAIN_ETH_STRATEGY, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // Beacon Chain ETH strategy
            return _strategies;
        } else if (_chainid == 17_000) {
            IAvsGovernance.StakingContractInfo[] memory _strategies = new IAvsGovernance.StakingContractInfo[](12);
            _strategies[0] = IAvsGovernance.StakingContractInfo(
                0x05037A81BD7B4C9E0F7B430f1F2A22c31a2FD943, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // lsETH strategy
            _strategies[1] = IAvsGovernance.StakingContractInfo(
                0x31B6F59e1627cEfC9fA174aD03859fC337666af7, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // ETHx strategy
            _strategies[2] = IAvsGovernance.StakingContractInfo(
                0x3A8fBdf9e77DFc25d09741f51d3E181b25d0c4E0, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // rETH strategy
            _strategies[3] = IAvsGovernance.StakingContractInfo(
                0x43252609bff8a13dFe5e057097f2f45A24387a84, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // EIGEN strategy
            _strategies[4] = IAvsGovernance.StakingContractInfo(
                0x46281E3B7fDcACdBa44CADf069a94a588Fd4C6Ef, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // osETH strategy
            _strategies[5] = IAvsGovernance.StakingContractInfo(
                0x70EB4D3c164a6B4A5f908D4FBb5a9cAfFb66bAB6, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // cbETH strategy
            _strategies[6] = IAvsGovernance.StakingContractInfo(
                0x7673a47463F80c6a3553Db9E54c8cDcd5313d0ac, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // ankrETH strategy
            _strategies[7] = IAvsGovernance.StakingContractInfo(
                0x7D704507b76571a51d9caE8AdDAbBFd0ba0e63d3, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // stETH strategy
            _strategies[8] = IAvsGovernance.StakingContractInfo(
                0x80528D6e9A2BAbFc766965E0E26d5aB08D9CFaF9, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // WETH strategy
            _strategies[9] = IAvsGovernance.StakingContractInfo(
                0x9281ff96637710Cd9A5CAcce9c6FAD8C9F54631c, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // sfrxETH strategy
            _strategies[10] = IAvsGovernance.StakingContractInfo(
                0xaccc5A86732BE85b5012e8614AF237801636F8e5, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // mETH strategy
            _strategies[11] = IAvsGovernance.StakingContractInfo(
                BEACON_CHAIN_ETH_STRATEGY, IAvsGovernance.SharedSecurityProvider.EigenLayer
            ); // Beacon Chain ETH strategy
            return _strategies;
        } else if (_chainid == 31_337) {
            IAvsGovernance.StakingContractInfo[] memory _strategies = new IAvsGovernance.StakingContractInfo[](0);
            return _strategies;
        } else {
            revert InvalidBlockId();
        }
    }

    function isValidStakingContract(address _stakingContract) external view returns (bool) {
        return _isValidStakingContract(_stakingContract);
    }

    function getNetworkRegistry() external view returns (INetworkRegistry) {
        return networkRegistry;
    }

    // =============================== Migration function - Obsolete ===============================

    function symbioticMigration(
        address _vaultFactory,
        address _networkRegistry,
        address _optInService,
        address _networkMiddlewareService,
        address _l1AvsFactory,
        address _avsDirectory
    ) external onlyOwner {
        vaultFactory = IVaultFactory(_vaultFactory);
        networkRegistry = INetworkRegistry(_networkRegistry);
        optInService = IOptInService(_optInService);
        networkMiddlewareService = INetworkMiddlewareService(_networkMiddlewareService);
        l1AvsFactory = IL1AvsFactory(_l1AvsFactory);
        avsDirectory = IAVSDirectoryFull(_avsDirectory);
    }

    function setStrategyManager(address _strategyManager) external onlyOwner {
        strategyManager = IStrategyManager(_strategyManager);
    }

    function setDelegationManager(address _delegationManager) external onlyOwner {
        delegationManager = IDelegationManager(_delegationManager);
    }

    function setRewardsCoordinator(address _rewardsCoordinator) external onlyOwner {
        rewardsCoordinator = IRewardsCoordinator(_rewardsCoordinator);
    }

    // =============================== Internal functions ===============================

    function _getVotingPower(
        address _operator,
        IAvsGovernance.VotingPowerMultiplier calldata _votingPowerMultiplier,
        address _avsGovernance
    ) private view returns (uint256) {
        if (!_isValidStakingContract(_votingPowerMultiplier.stakingContract)) {
            return 0;
        }

        if (_votingPowerMultiplier.sharedSecurityProvider == IAvsGovernance.SharedSecurityProvider.EigenLayer) {
            return _getEigenLayerStakeAmount(_operator, _votingPowerMultiplier.stakingContract, _avsGovernance)
                * _votingPowerMultiplier.multiplier;
        } else if (_votingPowerMultiplier.sharedSecurityProvider == IAvsGovernance.SharedSecurityProvider.Symbiotic) {
            return _getSymbioticStakeAmount(_operator, _votingPowerMultiplier.stakingContract, _avsGovernance)
                * _votingPowerMultiplier.multiplier;
        } else {
            return 0;
        }
    }

    function _getEigenLayerStakeAmount(address _operator, address _stakingContract, address _avsGovernance)
        private
        view
        returns (uint256)
    {
        if (
            avsDirectory.avsOperatorStatus(_avsGovernance, _operator)
                == IAVSDirectory.OperatorAVSRegistrationStatus.UNREGISTERED
        ) {
            return 0;
        }
        IStrategy _strategy = IStrategy(_stakingContract);
        uint256 _shares = delegationManager.operatorShares(_operator, _strategy);
        if (_stakingContract == BEACON_CHAIN_ETH_STRATEGY) {
            return _shares;
        } else {
            return _strategy.sharesToUnderlyingView(_shares);
        }
    }

    function _getSymbioticStakeAmount(address _operator, address _stakingContract, address _avsGovernance)
        private
        view
        returns (uint256)
    {
        IVault _vault = IVault(_stakingContract);
        address _delegator = _vault.delegator();
        return IBaseDelegator(_delegator).stakeAt(
            Subnetwork.subnetwork(_avsGovernance, 0), _operator, Time.timestamp() - 1, hex""
        );
    }

    function _isValidStakingContract(address _stakingContract) private view returns (bool) {
        if (_stakingContract == BEACON_CHAIN_ETH_STRATEGY) {
            return true;
        } else {
            return strategyManager.strategyIsWhitelistedForDeposit(IStrategy(_stakingContract))
                || vaultFactory.isEntity(_stakingContract);
        }
    }

    // slither-disable-next-line unused-state,naming-convention
    uint256[39] private __gap;
}

interface IL1AvsFactory {
    function isVerifiedAvsGovernanceDeployment(address _avsGovernanceAddress) external view returns (bool);
}
