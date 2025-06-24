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

struct TaskDefinition {
    uint16 taskDefinitionId;
    string name;
    uint256 blockExpiry;
    uint256 baseRewardFeeForAttesters;
    uint256 baseRewardFeeForPerformer;
    uint256 baseRewardFeeForAggregator;
    uint256 disputePeriodBlocks;
    uint256 minimumVotingPower;
    uint256[] restrictedAttesterIds;
    uint256 maximumNumberOfAttesters;
}

// @obsolete - use TaskDefinitionParamsV2
struct TaskDefinitionParams {
    uint256 blockExpiry;
    uint256 baseRewardFeeForAttesters;
    uint256 baseRewardFeeForPerformer;
    uint256 baseRewardFeeForAggregator;
    uint256 disputePeriodBlocks;
    uint256 minimumVotingPower;
    uint256[] restrictedAttesterIds;
}

struct TaskDefinitionParamsV2 {
    uint256 blockExpiry;
    uint256 baseRewardFeeForAttesters;
    uint256 baseRewardFeeForPerformer;
    uint256 baseRewardFeeForAggregator;
    uint256 disputePeriodBlocks;
    uint256 minimumVotingPower;
    uint256[] restrictedAttesterIds;
    uint256 maximumNumberOfAttesters;
}

struct TaskDefinitions {
    uint16 counter;
    mapping(uint16 => TaskDefinition) taskDefinitions;
}

error InvalidBlockExpiry();

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
library TaskDefinitionLibrary {
    event TaskDefinitionCreated(
        uint16 taskDefinitionId,
        string name,
        uint256 blockExpiry,
        uint256 baseRewardFeeForAttesters,
        uint256 baseRewardFeeForPerformer,
        uint256 baseRewardFeeForAggregator,
        uint256 disputePeriodBlocks,
        uint256 minimumVotingPower,
        uint256[] restrictedAttesterIds,
        uint256 maximumNumberOfAttesters
    );

    uint16 constant MIN_INTERNAL_TASK_ID = 10_001; // 10001 or greater ids are reserved for internal tasks
    uint16 constant VOTING_POWER_SYNC_TASK_DEFINITION_ID = 10_001;
    uint16 constant TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID = 10_002;

    function createNewTaskDefinition(
        TaskDefinitions storage self,
        string memory _name,
        TaskDefinitionParamsV2 memory _params
    ) internal returns (uint16 _id) {
        if (_params.blockExpiry <= block.number) revert InvalidBlockExpiry();
        _id = ++self.counter;
        self.taskDefinitions[_id] = TaskDefinition(
            _id,
            _name,
            _params.blockExpiry,
            _params.baseRewardFeeForAttesters,
            _params.baseRewardFeeForPerformer,
            _params.baseRewardFeeForAggregator,
            _params.disputePeriodBlocks,
            _params.minimumVotingPower,
            _params.restrictedAttesterIds,
            _params.maximumNumberOfAttesters
        );
        emit TaskDefinitionCreated(
            _id,
            _name,
            _params.blockExpiry,
            _params.baseRewardFeeForAttesters,
            _params.baseRewardFeeForPerformer,
            _params.baseRewardFeeForAggregator,
            _params.disputePeriodBlocks,
            _params.minimumVotingPower,
            _params.restrictedAttesterIds,
            _params.maximumNumberOfAttesters
        );
    }

    function getTaskDefinition(TaskDefinitions storage self, uint16 _taskDefinitionId)
        internal
        view
        returns (TaskDefinition storage)
    {
        return self.taskDefinitions[_taskDefinitionId];
    }

    function getMinimumVotingPower(TaskDefinitions storage self, uint16 _taskDefinitionId)
        internal
        view
        returns (uint256)
    {
        return self.taskDefinitions[_taskDefinitionId].minimumVotingPower;
    }

    function getRestrictedAttesterIds(TaskDefinitions storage self, uint16 _taskDefinitionId)
        internal
        view
        returns (uint256[] storage)
    {
        return self.taskDefinitions[_taskDefinitionId].restrictedAttesterIds;
    }

    function getMaximumNumberOfAttesters(TaskDefinitions storage self, uint16 _taskDefinitionId)
        internal
        view
        returns (uint256)
    {
        return self.taskDefinitions[_taskDefinitionId].maximumNumberOfAttesters;
    }
}
