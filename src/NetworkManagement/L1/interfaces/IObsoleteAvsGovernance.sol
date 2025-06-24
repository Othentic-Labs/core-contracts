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

import {IAvsGovernance} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernance.sol";
import {ISignatureUtils} from "@eigenlayer/contracts/interfaces/ISignatureUtils.sol";
import {BLSAuthLibrary} from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";
import {IVetoSlasher} from "@symbiotic/src/interfaces/slasher/IVetoSlasher.sol";

interface IObsoleteAvsGovernance {
    event MinStakeForStakingContractSet(address stakingContract, uint256 minShares);
    event SetStakingContractMultiplier(address stakingContract, uint256 multiplier);
    event setNewSupportedStakingContracts(address[] stakingContracts);
    event OperatorUnregistered(address indexed operator);
    event SetRewardsReceiver(address indexed operator, address receiver);

    error ZeroAddress();
    error InvalidStakingContract();
    error OperatorNotRegistered();
    error OperatorAlreadyRegistered();
    error AllowlistDisabled();
    error InvalidAllowlistAuthToken();
    error NumOfOperatorsLimitReached(uint256 numOfOperatorsLimit);
    error InvalidRewardsReceiver();
    error NotEnoughVotingPower();

    event OperatorRegistered(address indexed operator, uint256[4] blsKey);

    error InvalidBlsRegistrationSignature();
    error AllowlistEnabled();
    error StakingContractsNotInAscendingOrder();

    // obsolete - only supports EigenLayer registration
    function registerAsAllowedOperator(
        uint256[4] calldata _blsKey,
        bytes calldata _authToken,
        address _rewardsReceiver,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata _operatorSignature,
        BLSAuthLibrary.Signature calldata _blsRegistrationSignature
    ) external;

    // obsolete - only supports EigenLayer registration
    function registerAsOperator(
        uint256[4] calldata _blsKey,
        address _rewardsReceiver,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata _operatorSignature,
        BLSAuthLibrary.Signature calldata _blsRegistrationSignature
    ) external;

    // @obsolete - Use avsTreasury()
    function vault() external view returns (address);

    // @obsolete - Use minStakeAmountPerStakingContract()
    function minSharesForStrategy(address _stakingContract) external view returns (uint256);

    // @obsolete - Use stakingContracts()
    function strategies() external view returns (address[] memory);

    // @obsolete - Use multiplier()
    function strategyMultiplier(address _stakingContract) external view returns (uint256);

    // @obsolete - Use setMinStakesForStakingContract
    function setMinSharesForStrategy(address _stakingContract, uint256 _minShares) external;

    // @obsolete - Use setStakingContractMultiplier
    function setStrategyMultiplier(IAvsGovernance.VotingPowerMultiplier calldata _votingPowerMultiplier) external;

    // @obsolete - Use setStakingContractMultiplierBatch
    function setStrategyMultiplierBatch(IAvsGovernance.VotingPowerMultiplier[] calldata _votingPowerMultipliers)
        external;

    // @obsolete - need to use registerAvsToEigenLayer
    function updateAVSMetadataURI(string calldata metadataURI) external;

    // obsolete - only supports EigenLayer, use setSupportedStakingContracts
    function setSupportedStrategies(address[] memory _strategies) external;

    // @obsolete - auth token required
    function registerOperatorToEigenLayer(ISignatureUtils.SignatureWithSaltAndExpiry memory /*_eigenSig*/ ) external;

    // @obsolete - auth token required
    function registerOperatorToSymbiotic(IAvsGovernance.SymbioticOptInSignature memory /*_symbioticSig*/ ) external;

    function setSymbioticResolver(IVetoSlasher _vetoSlasher, address _resolver, bytes calldata _hints) external;
}
