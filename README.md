# ZkSync-PreviousBugs
# Issue explanation: **paymaster will refund spentOnPubdata to user**
    
**Core problem**:
    
Before diving into the bug, let’s discover what paymaster is according to the ZkSync docs.
    
> Paymasters in the ZKsync ecosystem represent a groundbreaking approach to handling transaction fees. They are special accounts designed to subsidize transaction costs for other accounts, potentially making certain transactions free for end-users. This feature is particularly useful for dApp developers looking to improve their platform's accessibility and user experience by covering transaction fees on behalf of their users.
> 
    
So, basically the problem is that the Paymasters overcompensates the fee which are refunded to the user because they are not deduct(taking into the account) the gas spent on public data. It means that → `paymaster` will refund the `spentOnPubdata` already used by the user.
    
    ```solidity
    let spentOnPubdata := getErgsSpentForPubdata(
                        basePubdataSpent,
                        gasPerPubdata
                    )
    ```
    
    **How to find it next time**:
    
Next time, when i will deal with the gas stuff, be very cautious, since it is the topic that could deliver high. Be sure that nothing is manipulative, everything is correctly deducted / accounted.
    
# Issue explanation: **the devs made the mistake and during the unfreeze the chain, it is freezed**.
    
**Core problem**:
    
    ```solidity
    function unfreezeChain(uint256 _chainId) external onlyOwner {
            IZkSyncStateTransition(stateTransition[_chainId]).freezeDiamond();
        }
    ```
    
**How to find it next time**:
    
Seems it is simple mistake, but be very cautious in the future audit, since devs also could make a mistake somewhere which would lead to certain types of bugs.
    
# Issue explanation: **during the initialisation the L1LegacyBridge isn’t set, which results in the msg. failed to be delivered.**
    
**Core problem**:
    
The new L2ERC20Bridge will upgraded to become the L2SharedBridge, and it will be backwards compatible with all messages from the old L1ERC20Bridge, so we upgrade that first as L1->L2 messages are much faster, and in the meantime we can upgrade the L1ERC20Bridge. The new L2SharedBridge can receive deposits from both the old L1ERC20Bridge and the new L1SharedBridge.
    
Because firstly the L2SharedBridge will be updated, and only then the L1SharedBridge will be updated, we need to make that `L2SharedBridge` needs to be compatible with the old `L1ERC20Bridge` before `L1ERC20Bridge` is updated.
    
However, once we initialise new bridge contract on the same zkSyncEra chainId → the legacy bridge isn’t set , and during the future finialize deposits, the deposits will not be delivered
    
    ```solidity
    function initialize(
            address _l1Bridge,
            address _l1LegecyBridge,
            bytes32 _l2TokenProxyBytecodeHash,
            address _aliasedOwner
        ) external reinitializer(2) {
            require(_l1Bridge != address(0), "bf");
            require(_l2TokenProxyBytecodeHash != bytes32(0), "df");
            require(_aliasedOwner != address(0), "sf");
            require(_l2TokenProxyBytecodeHash != bytes32(0), "df");
    
            l1Bridge = _l1Bridge;
            l2TokenProxyBytecodeHash = _l2TokenProxyBytecodeHash;
    
            if (block.chainid != ERA_CHAIN_ID) {
                address l2StandardToken = address(new L2StandardERC20{salt: bytes32(0)}());
                l2TokenBeacon = new UpgradeableBeacon{salt: bytes32(0)}(l2StandardToken);
                l2TokenBeacon.transferOwnership(_aliasedOwner);
            } else {
                require(_l1LegecyBridge != address(0), "bf2");
                // l2StandardToken and l2TokenBeacon are already deployed on ERA, and stored in the proxy
            }
        }
    ```
    
**How to find it next time**:
    
Here is the clear logic error, but this could be catch if we would clearly understand the migration mechanism. I’ve seen many times that top auditors recommend the following → read the code carefully and only then compare it to the official docs, here where the discrepancy could be found.
    
      
    
# Issue explanation: **State transition manager is unable to force upgrade a deployed ST**
    
https://github.com/code-423n4/2024-03-zksync-findings/issues/53
    
**Core problem**:
    
The bug involves the **State Transition Manager (STM)** in the zkSync system being unable to perform a **force upgrade** of a deployed **State Transition (ST)** contract, which is intended to be a safeguard for urgent, high-risk situations. This safeguard is part of the design, but due to issues in the code implementation, the STM cannot carry out this force upgrade. Basically, there is an issue in the code implementation that doesn’t allow to make the updating.
    
    Here is the function
    
    ```solidity
    //code/contracts/ethereum/contracts/state-transition/chain-deps/facets/Admin.sol
        function upgradeChainFromVersion(
            uint256 _oldProtocolVersion,
            Diamond.DiamondCutData calldata _diamondCut
    |>    ) external onlyAdminOrStateTransitionManager {
    ...
    ```
    
    However, as we can see that `onlyAdminOrStateTransitionManager` can call it. But!
    
1. `StateTransitionManger.sol` has no method to invoke this function.
2. Admin has the `executeUpgrade` method, which can be called only by the `StateTransitionManager`. But, it is important to note that the `executeUpgrade` could only be invoked via `_setChainIdUpgrade()` method, but this method also can be invoked only in `createNewChain()`. So, we have `createNewChain()` → `_setChainIdUpgrade()` → `executeUpgrade` . Overall, as we can see that the method we want to call from the admin can be invoked only on the genesis block. This means, after a chain(ST)'s genesis, `executeUpgrade()` cannot be invoked by stateTransitionManger again to perform further upgrades.
    
As a result of (1)&(2), StateChainManager cannot force upgrade an ST `in case of urgent high risk situation`. This invalidates the safeguard of force upgrade as stated by doc.
    
**How to find it next time**:
    
There are 2 key points here for taking into the account for the future.
    
1. We could have some methods that potentially could be not callable. So, it is important to examine the flow of each function and clearly understand from where it could be called.
2. Secondly, pay overall attention on the function that play a crucial role but could be called only via the certain entities. 
    
Because in the first case, we think globally whether the calling flow is correct. In the second case we speak about the protected functions.
    
    ---
    
# Issue explanation: **User might be able to double withdraw during migration**
    
https://solodit.xyz/issues/m-04-user-might-be-able-to-double-withdraw-during-migration-code4rena-zksync-zksync-git
    
**Core problem**:
    
To understand this exploit we need to understand how the migration on the zkSync would work.
    
1. New contracts are enabled; Such as `Bridgehub`, `StateTransitionManager`, `L1SharedBridge`
2. Era upgrade and L2 system contracts upgrade(at this point old `L1ERC20Bridge` still works)
3. Upgrade L2 bridge and `L1ERC20Brdige.sol`. 
4. Then migrate funds to the new `L1sharedBridge`.
    
Since `L1ERC20Bridge.sol` is upgraded at the end. An edge condition can occur between Step_1 and Step_2, where a user can still withdraw ERC20 tokens to the old `L1ERC20Brdige.sol`.
    
    ```solidity
        function finalizeWithdrawal(
            uint256 _chainId,
            uint256 _l2BatchNumber,
            uint256 _l2MessageIndex,
            uint16 _l2TxNumberInBatch,
            bytes calldata _message,
            bytes32[] calldata _merkleProof
        ) external override {
           //@audit-info when _l2BatchNumber>= eraFirstPostUpgradeBatch, `_isEraLegacyWithdrawal()` return false, checking on withdrawal status on legacyERC20bridge will be bypassed.
    |>     if (_isEraLegacyWithdrawal(_chainId, _l2BatchNumber)) {
                require(
                    !legacyBridge.isWithdrawalFinalized(
                        _l2BatchNumber,
                        _l2MessageIndex
                    ),
                    "ShB: legacy withdrawal"
                );
            }
            _finalizeWithdrawal(
                _chainId,
                _l2BatchNumber,
                _l2MessageIndex,
                _l2TxNumberInBatch,
                _message,
                _merkleProof
            );
    ```
    
As we can see from there, that if the `_l2BatchNumber` would equal to the `eraFirstPostUpgradeBatch` the check related to the `_isEraLegacyWithdrawal` would be bypassed and the withdrawal will not be finalised! Why it will be bypassed? Because of it
    
    ```solidity
    function _isEraLegacyWithdrawal(
            uint256 _chainId,
            uint256 _l2BatchNumber
        ) internal view returns (bool) {
            return
                (_chainId == ERA_CHAIN_ID) &&
    |>          (_l2BatchNumber < eraFirstPostUpgradeBatch); //@audit-info note:when _l2BatchNumber>= eraFirstPostUpgradeBatch, `_isEraLegacyWithdrawal()` return false.
        }
    ```
    
So, if we `finalizeWithdrawal` exactly during the upgrade, it will not be finalised, and would allow the double spending.
    
**How to find it next time**:
    
We will deal with the blockchain. We have to pay attention on the `batchNumbers`, and whether we could skip some of them/or exploit if we have some special `batchNumbers`
    
# Issue explanation: **call the** **MsgValueSimulator and re-enter the state with messy data**
    
https://github.com/code-423n4/2023-03-zksync-findings/issues/153
    
**Core problem**:
    
There is a contract in the zkSync, which “simulates” the tx’s. It is called `MsgValueSimulator` , here is what it does
    
    ```solidity
     * @author Matter Labs
     * @notice The contract responsible for simulating transactions with `msg.value` inside zkEVM.
     * @dev It accepts value and whether the call should be system in the first extraAbi param and
     * the address to call in the second extraAbi param, transfers the funds and uses `mimicCall` to continue the
     * call with the same msg.sender.
    ```
    
The system could be exploited if the attacker sends the funds directly to this address. 
    
The `MsgValueSimulator` use the `mimicCall` to forward the original call.
    
    ```solidity
    return EfficientCall.mimicCall(gasleft(), to, _data, msg.sender, false, isSystemCall);
    ```
    
And if the `to` address is the `MsgValueSimulator` address, it will go back to the `MsgValueSimulator.fallback` function again.
    
There were a lot of disputes, so i will try to summarise all of it.
    
1. User call the `MsgValueSimulator` directly via `rawCall`.
2. Once the funds enter the contract/fallback, `MsgValueSimulator` use the `mimicCall` to forward the original call.
3. Once the funds, re-enter the function, `MsgValueSimulator` use the `fallback` to execute transfer.
    
The fallback would extract the value to send
    
    ```solidity
    (uint256 value, bool isSystemCall, address to) = _getAbiParams();
    ```
    
### First Call:
    
The **first call** refers to the initial transaction sent by an external account or contract (like a wallet or smart contract) to the `MsgValueSimulator` contract with a non-zero `msg.value`.
    
1. In this first call, the `EfficientCall.rawCall` function is used to execute the call to the `MsgValueSimulator` contract. This simulates the `system_call_byref` opcode, which is a low-level system call used to handle the interaction between contracts.
2. The `system_call_byref` opcode directly sets registers `r3`, `r4`, and `r5` (which represent `msg.value`, a flag, and the target `to` address, respectively) during this call.
3. The function `_getAbiParams` is used to read these registers (`r3`, `r4`, and `r5`) and correctly extract:
        - `r3` → `msg.value`: the amount of Ether being sent.
        - `r4` → a flag (e.g., `isSystemCall`).
        - `r5` → the `to` address (the intended recipient of the call).
    
In this **first call**, the system correctly populates the registers, and the `_getAbiParams` function retrieves valid values.
    
    ---
    
### Second Call:
    
The **second call** happens when the `MsgValueSimulator` forwards the original transaction using the `EfficientCall.mimicCall` function. This second call is crucial because it triggers the vulnerability.
    
1. **`EfficientCall.mimicCall`**:
        - The `mimicCall` function simulates the `MIMIC_CALL_BY_REF` opcode (not `SYSTEM_MIMIC_CALL_BY_REF` like in the first call). This is a key difference because `MIMIC_CALL_BY_REF` does **not** directly set the register values in the same structured way as `system_call_byref`.
2. **Register Scrambling**:
        - In this second call, the registers `r1r4` are used according to standard ABI conventions (used for function parameters in Solidity), while `r5` is used for the extra `who_to_mimic` argument. The `who_to_mimic` argument is the address to mimic in the call.
        - Since `MIMIC_CALL_BY_REF` doesn’t handle the registers the same way, the values in `r3`, `r4`, and `r5` get **scrambled** or **messed up**. These registers now hold unintended values, which makes the behavior unpredictable.
    3. In the **second call**, when `_getAbiParams` tries to read from registers `r3`, `r4`, and `r5`, it retrieves incorrect (or "messy") data:
        - `r3` (which is supposed to be `msg.value`) contains a large, unexpected value.
        - `r4` (which should be the `to` address) is incorrectly set to `msg.sender` (the calling contract or account itself).
        - `r5` contains a mask or flag, but this is also wrong and doesn’t represent the expected data.
    
**How to find it next time**:
    
Pay the attention on the opcodes, and what could happen if we could directly call the system contracts. Pay attention on the **MsgValueSimulator,** since last times couples of bug were there.
    
# Issue explanation: **user can call system contracts directly**
    
    https://github.com/code-423n4/2023-03-zksync-findings/issues/146
    
**Core problem**:
    
We reach the state where the bug is via `executeTransaction` → `_execute` where it would choose what to call to make (depends if the to is ContractDeployer), if not it would move into the `_rawCall`. In the `_rawCall` , if the msg.value is empty, make a regular call, if not, proceed via the MsgValueSimulator, where the `isSystemCall` flag is automatically set to `true` when the call is passed through `MsgValueSimulator`, effectively converting the transaction into a **system call**. 
    
The issue is → If a user sends a transaction with `msg.value` to any contract other than `ContractDeployer`, the transaction will still be treated as a **system call**.
    
**How to find it next time**:
    
Try to think in a way who to call the system contracts. Are there any ways to bypass the check and call it?
    
# Issue explanation: **diamondCut is not protected in case of governor's key leakage**
    
https://github.com/code-423n4/2022-10-zksync-findings/issues/46
    
**Core problem**:
    
The governor initiates an upgrade using the **diamondCut** function. This process includes making changes (called `facetCuts`) and possibly running some initialization code (`_calldata`) via an address (`_initAddress`). The upgrade doesn’t happen immediately. Instead, the governor must wait for a certain **notice period** to expire before executing the proposal, unless the **security council** members approve the proposal to skip the waiting period.
    
There are 2 conditions that allow to proceed:
    
1. The **upgradeNoticePeriod** has passed 
    
    Or
    
2. The upgrade has been **approved by security council** members
    
    ```solidity
       require(approvedBySecurityCouncil || upgradeNoticePeriodPassed, "a6"); // notice period should expire
       require(approvedBySecurityCouncil || !diamondStorage.isFrozen, "f3");
    ```
    
However, the problem could arise once the governer key will be compromised. The attacker could try to execute an existing upgrade with malicious `_calldata`, or try to create new/malicious proposal. 
    
However, the attacker still need to wait for the notice period, and since, there is a notice period (as zkSync noticed the key leakage, security council member will not approve the proposal, so bypassing the notice period is not possible), there is enough time for zkSync to apply security measures (pausing any deposit/withdraw, reporting in media to not execute any transaction in zkSync, and so on).
    
However, the attacker could act more strategically. Just before the governor is set to execute the proposal (either after the notice period has passed or with approval from the security council), the attacker could step in and execute the proposal first, using malicious `_calldata`. This is essentially the attacker **front-running** the governor.
    
Thus, if zkSync detects the governor's key compromise early, there would be enough time to implement protective measures. But if zkSync fails to notice the key leak in time, the attacker could modify the `_calldata` with malicious intent at the last moment, making it impossible to protect the project.
    
**How to find it next time**:
    
We will deal with the huge protocol, and attacker will target it, so we also need to think in a way, what would happen if the private key will be compromised, and if it will happen what the damage will be to the overall protocol.
    
# Issue explanation: **BLOCK_PERIOD is incorrect**
    
https://github.com/code-423n4/2022-10-zksync-findings/issues/259
    
**Core problem**:
    
On the zkSync, the block time is set to 13 sec., which is not correct, because after the merge the current block.timestamp on ethereum is 12 sec.
    
    ```solidity
    uint256 constant BLOCK_PERIOD = 13 seconds;
    ```
    
This results in incorrect calculation of `PRIORITY_EXPIRATION` which is used to determine when a transaction in the Priority Queue should be considered expired.
    
    ```solidity
    uint256 constant PRIORITY_EXPIRATION_PERIOD = 3 days;
    /// @dev Expiration delta for priority request to be satisfied (in ETH blocks)
    uint256 constant PRIORITY_EXPIRATION = PRIORITY_EXPIRATION_PERIOD/BLOCK_PERIOD;
    ```
    
    ![Screenshot 2024-10-20 at 10.04.42.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/780f7995-b8b4-47cd-a93c-00ca57cc9036/abbe29ac-58ac-416c-b981-21b2c10b3a29/Screenshot_2024-10-20_at_10.04.42.png)
    
**How to find it next time**:
    
Since it is L2, and it is based on the Mainnet we must carefully examine the parameters that is set by default, and prove that working with the Mainnet, it will not result in any problems.
    
# Issue explanation: **Attacker can forge arbitary read value from memory**
    
*Generated via ChatGPT since the bug is based in rust stuff.
    
This vulnerability concerns a **memory access issue** in a system where an attacker can manipulate how memory is read when accessing memory through a pointer. Specifically, the issue arises when an attacker is able to bypass proper bounds checking for memory reads, leading to the potential for arbitrary read results to be forged. Here's a detailed explanation:
    
### Overview of the Vulnerability
    
1. **Expected Behavior**:
        - When the system attempts to read memory that goes beyond the bounds of a valid pointer (i.e., the pointer plus the offset goes past the allowed memory region), it should return **zero bytes** (indicating an out-of-bounds read).
        - Additionally, if the offset exceeds the length of the memory slice, the system should **skip the read** entirely and return zeros without actually accessing the memory.
2. **Issue in the Current Implementation**:
        - The current code doesn’t properly handle this out-of-bounds case, leading to a situation where the system may proceed with memory access even when it shouldn’t. This opens up an avenue for an attacker to **fake memory reads** by inserting arbitrary data in place of valid memory content.
    
### Key Points in the Code Leading to the Vulnerability
    
1. **Offset Check**:
        
        ```rust
        let (_, offset_is_strictly_in_slice) = offset.overflowing_sub(cs, length);
        let offset_is_beyond_the_slice = offset_is_strictly_in_slice.negated(cs);
        let skip_if_legitimate_fat_ptr =
            Boolean::multi_and(cs, &[offset_is_beyond_the_slice, is_fat_ptr]);
        
        ```
        
        - The code attempts to check whether the offset is within the valid memory bounds. If the offset is outside the slice (i.e., `offset_is_beyond_the_slice`), it should skip the memory access.
        - However, this check isn't being handled correctly, allowing memory access even when the offset is beyond the allowed range.
2. **Skipping Memory Access**:
        
        ```rust
        let skip_memory_access = Boolean::multi_or(
            cs,
            &[
                already_panicked,
                skip_if_legitimate_fat_ptr,
                is_non_addressable,
            ],
        );
        
        ```
        
        - The system decides whether to skip memory access based on several conditions, including whether the pointer is legitimate or not. If any of these conditions are met, the memory read should be skipped.
        - However, the logic is flawed, and in certain cases, the memory access isn’t skipped even though it should be.
3. **Handling Out-of-Bounds Bytes**:
        
        ```rust
        bytes_out_of_bound = bytes_out_of_bound.mask_negated(cs, skip_memory_access);
        bytes_out_of_bound = bytes_out_of_bound.mask_negated(cs, uf);
        
        ```
        
        - This part of the code is responsible for handling bytes that are out of bounds. It should ensure that any out-of-bounds bytes are set to zero.
        - However, because the bounds check is skipped, these bytes are not being correctly zeroed out, allowing the attacker to inject arbitrary data into the memory read result.
    
### Exploitation Path
    
1. **Forging the Memory Read Result**:
        - The vulnerability allows an attacker to bypass the bounds checking and forge arbitrary memory read results. This means the attacker can control the value that the system thinks it has read from memory, even if it hasn’t actually read anything from valid memory.
        
        ```rust
        // Case where we should push zeros to the destination (dst0)
        diffs_accumulator
            .dst_0_values
            .push((can_write_into_memory, should_update_dst0, dst0_value));
        
        ```
        
        - In the final stage, the system pushes the memory read result (`dst0_value`) into the destination. Normally, if the memory read is out-of-bounds, this value should be zero.
        - However, because the system fails to properly handle this case, it pushes **arbitrary, potentially attacker-controlled values** into the destination instead.
2. **No Enforced Memory State**:
        - The vulnerability stems from the fact that the **memory state is not enforced**. If the memory is not accessed correctly (e.g., the bounds check fails), the memory should not be used. However, the system still proceeds as if the memory read was valid, which is a major security issue.
    
    ### Proof of Concept Walkthrough
    
    - **Memory Access Bypass**:
    The code first attempts to check whether the memory access should be skipped using a combination of conditions. However, the logic here is flawed, and in certain cases, the system does not skip the memory access even if it should. This allows the attacker to influence the memory read.
    - **Forging Memory Values**:
    After bypassing the bounds check, the attacker can inject arbitrary values into the destination register (`dst0_value`), as shown in the final part of the proof of concept:
        
        ```rust
        let dst0_value = VMRegister::conditionally_select(
            cs,
            is_write_access_and_increment,
            &incremented_src0_register,
            &read_value_as_register,
        );
        
        ```
        
        Here, the attacker can control what value gets written, which should have been a zero if the memory read had been correctly skipped.
        
    
### Key Exploitable Facts
    
1. **Improper Handling of Out-of-Bounds Memory Reads**:
        - The system doesn’t properly handle the case where memory is accessed beyond the valid pointer range, allowing the attacker to perform memory reads even when they shouldn’t be allowed.
2. **Forging Arbitrary Read Results**:
        - Due to the failure to properly zero out out-of-bounds bytes and the failure to skip memory access, the attacker can insert arbitrary values into the memory read result (`dst0_value`).
3. **No Memory State Enforcement**:
        - The system allows unvalidated memory reads to proceed, which violates the principle that if memory is not properly accessed, its values should not be used.
    
### Conclusion
    
This vulnerability arises from a failure in the bounds checking and memory access logic. An attacker can exploit the flaw to perform out-of-bounds memory reads and inject arbitrary data into the system. The lack of proper enforcement of memory state makes this a critical issue, as it allows an attacker to manipulate the results of memory reads, leading to potentially severe consequences for the system’s integrity and security.
    
# Issue explanation: **TransactionValidator checks intrinsic costs against wrong value**
    
    https://github.com/code-423n4/2023-10-zksync-findings/issues/975
    
**Core problem**:
    
    On the zkSync, the `totalGasLimit` is calculated in such way 
    
    ```solidity
    totalGasLimit = overhead + actualGasLimit = overhead + (intrinisicCosts + executionCosts)
    ```
    
    The function `TransactionValidator.getMinimalPriorityTransactionGasLimit` calculates the **intrinsic costs** that will be incurred for the processing of a transaction on L2
    
    ```solidity
    require(
        getMinimalPriorityTransactionGasLimit(
            _encoded.length,
            _transaction.factoryDeps.length,
            _transaction.gasPerPubdataByteLimit
        ) <= _transaction.gasLimit, 
        "up"
    );
    ```
    
The issue is that `_transaction.gasLimit` is the total `gasLimit` including the overhead for the operator. So, it must do the ≤ check not to the total `gasLimit` , but to the intrinsic value only, which is (totalGasLimit - overhead), so it could purely calculate whether the intrinsic cost is enough.
    
    Also, we have the similar check related to the intrinsic value in the bootloader, when processing the transaction, it subtracts the overhead from the total gas limit and then checks if the remaining gas is sufficient to cover the intrinsic costs:
    
    Because of this incorrect check, an attacker could send L1 to L2 transactions that cover either the overhead or the intrinsic costs but **not both**. These transactions would not have enough gas to be executed on L2 but would still incur overhead and intrinsic costs. This could lead to a **griefing attack**
    
# Issue explanation: **The incorrect overhead calculation in the transaction memory**
    
    https://github.com/code-423n4/2023-10-zksync-findings/issues/1105
    
**Core problem**:
    
    The overhead is calculated as the maximum of:
    
    1. overhead for slot
    2. overhead for memory occupation in the bootloader
    3. overhead for single instance circuits
    
    Overhead for memory occupation in the bootloader(2) is calculated like this:
    
    ```solidity
    MemoryOverhead = BatchOverhead ∗ EncodingLengthBootloaderMemory
    ```
    
    So, it is proportional to the bootloader memory the tx will occupy.
    
    The problem is exactly in this second component, let’s see.
    
     Here is the code of the gas overhead calculation in the Bootlader and TxValidator
    
    ```solidity
    //TxValidator
    uint256 overheadForLength = Math.ceilDiv(_encodingLength * batchOverheadGas, BOOTLOADER_TX_ENCODING_SPACE);
    ```
    
    ```solidity
    //Bootlader
    let overheadForLength := ceilDiv(
        safeMul(txEncodeLen, totalBatchOverhead, "ad"),
        BOOTLOADER_MEMORY_FOR_TXS()
    )
    ```
    
    In both cases the `_encodingLength` and `txEncodeLen` is the length of the transaction encoding, measured in bytes (derived from `abi.encode(transaction).length`)
    
**`BOOTLOADER_TX_ENCODING_SPACE`** and **`BOOTLOADER_MEMORY_FOR_TXS`()** have the value `273132` in the current config. The number **273132** is the actual value used for both **`BOOTLOADER_TX_ENCODING_SPACE`** and **`BOOTLOADER_MEMORY_FOR_TXS`**. This number represents the total number of **words** (where one word is equal to 32 bytes) available for encoding and storing transactions in the bootloader. It is relevant that it is not expressed in bytes, but in words (32 bytes each).
    
    <aside>
    💡
    
    The problem is: during the calculation of the overhead above, the encoded tx length which is denominated in bytes, is divided by the words(not bytes) → thus resulting in 32 times higher value.
    
    We need to multiply the amount of words * 32 to receive the actual bytes amount and then do the calculation.
    
    </aside>
    
**How to find it next time**:
    
    When i will dive into the memory and low level stuff, ensure that there is no any gaps. During the calculation check that bytes are correctly div/mul. by the respective bytes amount, not words. Ensure that nothing could be overwritten, there is no under/overflow.
    
# Issue explanation: **Loss of funds for the sender when L1->L2 TX fails in the bootloader on L2**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/979
    
**Core problem**:
    
Okay, the flow from the depositing L1-L2 finally reach the bootloader, where the complex ZkEvm stuff will happen. Here we concentrate on one thing, gas refund. Basically the bug is about if the user has 1_000 gas to execute the tx on the L2, but on the L2 it has consumed 500 gas and then revert, it should refund back to the user 500 gas remaining, but actually it doesn’t refund nothing.
    
This issue occurs due to the fact that `near` call opcode is used to execute the TX (to avoid 63/64 rule), and when the TX execution fails, near call panic is utilised to avoid reverting the bootloader and to revert minting ether to the user.
    
    ```solidity
    	let gasBeforeExecution := gas() 
    	success := ZKSYNC_NEAR_CALL_executeL1Tx(
    		callAbi,
    		txDataOffset
    	)
    ```
    
    ```solidity
    	// If the success is zero, we will revert in order
    	// to revert the minting of ether to the user
    	if iszero(success) {
    		nearCallPanic()
    	}
    ```
    
**How to find it next time**:
    
Pay close attention on the gas refund and how does it handled, ensure that all the gas is refunded, any peace of it isn’t left somewhere. But overall it is a good point to check whether if the tx is revert on the dst chain the gas is refunded. I guess we miss it on the zetaChain.
    
# Issue explanation: **Incorrect max precompile address**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/888
    
**Core problem**:
    
    The 2 new precompiles were added, however, they were failed to be “updated” by the system. The ZkSync has a var called `CURRENT_MAX_PRECOMPILE_ADDRESS` , which is pointed to the max precompile which is available in the system.
    
    ```solidity
    35: uint256 constant CURRENT_MAX_PRECOMPILE_ADDRESS = uint256(uint160(SHA256_SYSTEM_CONTRACT));
    ```
    
    So, currently it is pointed to the past precompile, and the system doesn’t see the new ones simply. Once we need to interact with the new precompiles we simply couldn’t do it, just simply looking by this peace of code.
    
    ```solidity
    89:     function getCodeHash(uint256 _input) external view override returns (bytes32) {
    90:         // We consider the account bytecode hash of the last 20 bytes of the input, because
    91:         // according to the spec "If EXTCODEHASH of A is X, then EXTCODEHASH of A + 2**160 is X".
    92:         address account = address(uint160(_input));
    93:         if (uint160(account) <= CURRENT_MAX_PRECOMPILE_ADDRESS) {
    94:             return EMPTY_STRING_KECCAK;
    95:         }
    ```
    
**How to find it next time**:
    
Check the code diff with the past implementation. Check what has been added. Check how does it fit into the system and whether they updated/integrated properly.
    
# Issue explanation: **EIP-155 is not enforced, allowing attackers/malicious operators to profit from replaying transactions**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/882
    
**Core problem**:
    
    As i got, it was very disputed issue. The core exploit that could happen is that if the tx is the legacy one, the `tx_type=0` , and respectively `tx.reserved[0] == 0` 
    
And once we have such stuff, we dive into the following trap
    
    ```solidity
            bytes memory encodedChainId;
            if (_transaction.reserved[0] != 0) {
                encodedChainId = bytes.concat(RLPEncoder.encodeUint256(block.chainid), hex"80_80");
            }
    ```
    
The code above happens in the `_encodeCodeLegacyTx`, and then this prepared payload move to the `_validateTransaction` , where it could be wrecked.
    
According to the auditor, the following impact could be
    
    > A malicious attacker can replay transactions from networks that don't have EIP-155 protection. Although most EVM networks now support EIP-155, attackers can still exploit older transactions from networks without this protection. For example, if an early Ethereum user (A) sent a transaction to another user (B) before EIP-155 was active, and user A later deposits ETH into the Zksync network, user B could replay the old transaction to steal funds from A on Zksync.
    > 
    > 
    > Additionally, operators could replay old user transactions from Ethereum or other EVM networks to collect gas fees or profit directly.
    > 
    
**How to find it next time**:
    
    Once we meet something related to the EIP155 take the close look, and brainstorm every potential thing what could happen. Even via the legacy/updating mechanism
    
# Issue explanation: **bootloader allows for calling any method of ContractDeployer with isSystem flag**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/512
    
**Core problem**:
    
    Interesting one, that had a lot of disputes. The core logic about is that we could initiate a cross-chain call from L1-L2 to arbitrary `updateAccountVersion` and `updateNonceOrdering`.
    
    DefaultAccount contract that controls the EOA accounts doesn't allow it, but the bootloader does.
    
    Since on the Mainnet the nonce-ordering is sequential, but on the zkSync it would lead to the account being “broken”. But the main point how it could be bypassed!
    
    There is `DefaultAccount.sol` which the system contract. There is an execute function.
    
    ```solidity
     function _execute(Transaction calldata _transaction) internal {
            address to = address(uint160(_transaction.to));
            uint128 value = Utils.safeCastToU128(_transaction.value);
            bytes calldata data = _transaction.data;
            uint32 gas = Utils.safeCastToU32(gasleft());
    
            // Note, that the deployment method from the deployer contract can only be called with a "systemCall" flag.
            bool isSystemCall;
            if (to == address(DEPLOYER_SYSTEM_CONTRACT) && data.length >= 4) {
                bytes4 selector = bytes4(data[:4]);
                // Check that called function is the deployment method,
                // the others deployer method is not supposed to be called from the default account.
                isSystemCall =
                    selector == DEPLOYER_SYSTEM_CONTRACT.create.selector ||
                    selector == DEPLOYER_SYSTEM_CONTRACT.create2.selector ||
                    selector == DEPLOYER_SYSTEM_CONTRACT.createAccount.selector ||
                    selector == DEPLOYER_SYSTEM_CONTRACT.create2Account.selector;
            }
            bool success = EfficientCall.rawCall({
                _gas: gas,
                _address: to,
                _value: value,
                _data: data,
                _isSystem: isSystemCall
            });
            if (!success) {
                EfficientCall.propagateRevert();
            }
        }
    ```
    
Here we need to understand: once the EOA make the cctx - call to the DEPLOYER_SYSTEM_CONTRACT, it would evaluate as `isSystemCall` only if following function selectors will be called (see above). In other variants, it will be not the systemCall.
    
But, we also have the bootloader, with the `msgValueSimulatorMimicCall`. And here the `isSystem` call would be the true only if make a call to the systemContract (no prerequisites for the fn() selectors above. 
    
    ```solidity
    function msgValueSimulatorMimicCall(to, from, value, dataPtr) -> success {
                    // Only calls to the deployer system contract are allowed to be system
                    let isSystem := shouldMsgValueMimicCallBeSystem(to, dataPtr)
    
                    success := mimicCallOnlyResult(
                        MSG_VALUE_SIMULATOR_ADDR(),
                        from,
                        dataPtr,
                        0,
                        1,
                        value,
                        to,
                        isSystem
                    )
                }
    ```
    
Overall, it is what allow us to bypass the `isSystemCall` and update this instances `updateAccountVersion` and `updateNonceOrdering` by simply executing the call via the bootloader.
    
**How to find it next time**:
    
    This bug is not fixed, so pay a close attention on it. If we have the new updating, check how we could abuse it by calling the function which are protected by the `isSystemCall`.
    
# Issue explanation: **Burning of the user gas in the `sendCompressedBytecode` function**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/805
    
**Core problem**:
    
    We have the `sendCompressedBytecode` which, as i understand upon the l2 tx, save/compress/deliver the state diff of the l2. This function , implement the internal logic called `nearCallPanic` , which is triggered if the publishing of the compressed code was not successful. In practice, such situation could happen because of invalid data provided by the operator (as we know that the operator could be malicious). Such possibility of forcing the overall flow to revert via `nearCallPanic` could lead to the following results.
    
    - When `nearCallPanic()` is invoked due to a failure, the entire gas allocated for the L2 transaction is consumed (burned).
    
    If there is at least one bytecode intended to be published at the beginning of the transaction, the operator can exploit this mechanism to intentionally consume all the gas, rendering the transaction unsuccessful without achieving its intended effects.
    
    
**How to find it next time**:
    
    Firstly, we need to remember that the operator is malicious one. Secondly we need to think in a way: how to prevent the data publishing being executed. What edges we can touch to achieve it? How we could DoS somehow the system?
    
# Issue explanation: **Lack of access to ETH on L2 through L1->L2 transactions**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/803
    
**Core problem**:
    
Firstly, it needs to note that everything happens via the Mailbox.sol
    
    > *L1->L2 communication is implemented as requesting an L2 transaction on L1 and executing it on L2. This means a user can call the function on the L1 contract to save the data about the transaction in some queue. Later on, a validator can process it on L2 and mark it as processed on the L1 priority queue. Currently, it is used for sending information from L1 to L2 or implementing multi-layer protocols. Users pays for the transaction execution in the native token when requests L1->L2 transaction.*
    > 
    
    Let’s clarify. The EOA on L2 has some msg.value on his account. However, when they attempt to move ETH from L1 to L2 using L1->L2 transactions, the logic currently implemented does not allow for these transactions to access the ETH already available on L2.
    
    There is a `function _requestL2Transaction` , is used to request execution of L2 transaction from L1. It enforces that the `msg.value` for an L1->L2 transaction is only derived from ETH that is sent from L1, not from the existing ETH balance on L2. This means that when users initiate an L1->L2 transaction, only the ETH being transferred from L1 is considered, effectively ignoring any ETH they may already have on L2 - it is the first prerequisite for the bug. Secondly, the function that handles the incoming requests for the EOA account has no implementation
    
    ```solidity
    /// @notice Method that should be used to initiate a transaction from this account by an external call.
        /// @dev The custom account is supposed to implement this method to initiate a transaction on behalf
        /// of the account via L1 -> L2 communication. However, the default account can initiate a transaction
        /// from L1, so we formally implement the interface method, but it doesn't execute any logic.
        /// @param _transaction The transaction to execute.
        function executeTransactionFromOutside(Transaction calldata _transaction) external payable override {
            // Behave the same as for fallback/receive, just execute nothing, returns nothing
        }
    ```
    
    What if we would have the “malicious operator”, which wouldn’t allow for the user’s l1-l2 tx’s to proceed? 
    
    The user will not be able to access his Eth on L2, if the malicious operator decides to not include user’s tx into the L1-L2.
    
**How to find it next time**:
    
Try to think in a way → what if we have the malicious operator, as hard as we can!
    
# Issue explanation: **Vulnerabilities in Deposit Limit Enforcement and the Impact on Failed Deposits**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/425
    
**Core problem**:
    
    We have a function that ‘verify’ the users limit which is imposed on the L2. This check is invoked when user tries to deposit the funds from l1. Also, this same mechanism is applied when a user seeks to reclaim their failed deposit on l1.
    
    ```solidity
    function _verifyDepositLimit(address _depositor, uint256 _amount) internal {
            IAllowList.Deposit memory limitData = IAllowList(s.allowList).getTokenDepositLimitData(address(0)); // address(0) denotes the ETH
            if (!limitData.depositLimitation) return; // no deposit limitation is placed for ETH
    
            require(s.totalDepositedAmountPerUser[_depositor] + _amount <= limitData.depositCap, "d2");
            s.totalDepositedAmountPerUser[_depositor] += _amount;
        }
    ```
    
    However, the problem could occur in the following situations.
    
    1. If we have no limit. The Alice deposits the 100 token but deposits fail. After the owner imposes the limit on this token. Then, Alice seeks to reclaim her failed deposit and once she will try to do it, amount 100 is going to be deducted from `totalDepositedAmountPerUser[tokenX][Alice]` (which equals 0). This results in an underflow, causing the transaction to revert.
    2. Second scenario. Bob(malicious actor) is about to see that owner imposes the check on the deposit limit. Bob front-run and deposit the 100 tokens 3 times (*but ensures that it fails on L2). Then the limit is imposed. 
        
        Bob then deposits 100 tokenY successfully, reaching the new limit. However, he finds a loophole: by reclaiming one of his earlier failed deposits, his total deposited amount is reset to 0. This allows him to deposit another 100 tokenY. Bob repeats this process, bypassing the deposit cap and depositing a total of 400 tokenY, despite the limit being set at 100.
        
    
**How to find it next time**:
    
    The dev stated that this functionality will be removed because it is active only during the alpha version. Pay attention on it and check how it would behave in the current audit
    
# Issue explanation: **Timestamp Constraints Leading to Number of Blocks Creation Limitations**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/316
    
**Core problem**:
    
    When the system processes transactions, the **bootloader** initiates a new batch using the `setNewBatch` function from the `SystemContext` contract. The system checks that the new batch's timestamp is **greater** than the previous batch's timestamp and the timestamp of the last block in that previous batch.
    
    As the tx is processed, the `setL2Block` is called, this action ensures that the timestamp of the block is not lower than the timestamp of the current batch. 
    
    ```solidity
     require(
          _l2BlockTimestamp >= currentBatchTimestamp,
          "The timestamp of the L2 block must be greater than or equal to the timestamp of the current batch"
    );
    ```
    
    Once the processing of all transactions is completed, an additional fictive block is generated, serving as the final block within the batch. It just `setL2Block` in the end of the bootloader.yul
    
    Finally, the `publishTimestampDataToL1` is disclosed to L1 for verification.
    
    After that, we move to the L1, where the actual verification of the blob take place. `_verifyBatchTimestamp` is called, to confirm the accuracy of the timestamps. 
    
    Key checks performed:
    
- The batch’s timestamp must be **greater than** the timestamp of the **previous batch**.
- The batch’s timestamp must be **greater than or equal to** the current block's timestamp minus a constant (`COMMIT_TIMESTAMP_NOT_OLDER` (3 days)).
    - The last block’s timestamp in the batch must not be **greater than** the current block’s timestamp plus a constant (`COMMIT_TIMESTAMP_APPROXIMATION_DELTA` (1 hours).
    
    The vulnerability could happen if the **operator sets the timestamp** for a batch **too close to the maximum limit** defined by `COMMIT_TIMESTAMP_APPROXIMATION_DELTA` (1 hours).
    
For example:
    
- **Batch 1000** is created with a timestamp of `timeStamp_A + COMMIT_TIMESTAMP_APPROXIMATION_DELTA - 1`.
- The fictive(last) block has a timestamp of `timeStamp_A + COMMIT_TIMESTAMP_APPROXIMATION_DELTA`
    
Once this batch will be committed to L1, it would work fine, because:
    
    ```solidity
    timeStamp_A + COMMIT_TIMESTAMP_APPROXIMATION_DELTA <= blockTimestamp1000 + COMMIT_TIMESTAMP_APPROXIMATION_DELTA
    ```
    
    The problem could happen with the next batch:
    
The **next batch (1001)** must have a timestamp greater than `timeStamp_A + COMMIT_TIMESTAMP_APPROXIMATION_DELTA` because each batch must have a **later timestamp** than the previous one.
    
    - Suppose, `timeStamp_A + COMMIT_TIMESTAMP_APPROXIMATION_DELTA + Y`, with a fictive block having `timeStamp_A + COMMIT_TIMESTAMP_APPROXIMATION_DELTA + Y + K`
    
    Once, the batch will be committed to L1, the following check will be:
    
    ```solidity
    timeStamp_A + COMMIT_TIMESTAMP_APPROXIMATION_DELTA + Y + K <= blockTimestamp1001 + COMMIT_TIMESTAMP_APPROXIMATION_DELTA
    ```
    
    We simplify the condition into the following
    
    ```solidity
    Y + K <= blockTimestamp1001 - blockTimestamp1000
    ```
    
    As i understood, the couple of problems could arise from it.
    
    1. If both batches 1001 and 1000 are to be committed on L1 at the same time `blockTimestamp1000 = blockTimestamp1001` (in the same Ethereum block), it is not allowed, as `K <= -1`. So, if it happens in one block, the batch could be reverted, because it was set too far in the future.
    2. The second problem is highly interconnected with the overall gas that is dedicated to the batch. 
        - What happens if the operator set the batchTimeStamp too far in the future
            
The **L2_TX_MAX_GAS_LIMIT** plays a key role in determining how many transactions can be included in a single batch on Layer 2 (L2) in zkSync. Here’s how it factors into the process and contributes to the issue discussed:
            
### What is L2_TX_MAX_GAS_LIMIT?
            
- **L2_TX_MAX_GAS_LIMIT** refers to the maximum amount of gas that a single transaction on Layer 2 (zkSync) can consume. In this case, it is set to **80,000,000** gas units.
- Each transaction in zkSync requires gas to be processed, and this limit ensures that no single transaction exceeds this gas limit.
            
### The Connection Between L2_TX_MAX_GAS_LIMIT and Batch Processing:
            
1. **Batch Gas Limit:**
- The total **computation gas** available for all transactions within a batch is set to **2^32** gas units (about 4.29 billion gas).
- The total gas available for a batch sets a limit on how many transactions can be included before the batch is "sealed" and another batch must be created.
2. **How L2_TX_MAX_GAS_LIMIT Affects the Number of Transactions:**
- Since the **maximum gas per transaction** is capped at **80,000,000**, the number of transactions that can fit within a single batch is determined by dividing the total gas available in the batch by the gas limit per transaction:
                \[
                \frac{2^32}{80,000,000} \approx 53 \text{ transactions}
                \]
                - This means that only about **53 maximum-gas transactions** can be included in a single batch before its gas capacity is exhausted, and a new batch must be created.
            
### How Does This Play into the Timestamp Issue?
            
- **Batch Sealing and Creation:**
- Once a batch’s gas capacity is reached, it must be "sealed," meaning no more transactions can be added to it. This triggers the need to create a **new batch** to continue processing further transactions.
- In a scenario with high transaction volume, many batches will need to be created frequently.
- **Timestamp Dependency:**
- Every new batch must have a **timestamp greater than the previous batch**. If the timestamp of a batch is set far into the future (e.g., `block.timestamp + 365 days`), the system is forced to **wait** before committing the next batch on L1, because the next batch's timestamp needs to exceed that of the previous one.
                - This delay creates a bottleneck, slowing down the overall batch processing and transaction finality.
            
### Example:
            
            1. Assume batch 100 is created with 53 transactions, each consuming the maximum gas limit (80,000,000). Once the gas capacity for the batch (2^32) is fully used, the batch is sealed.
            2. To continue processing, a **new batch (101)** must be created.
            3. However, if the timestamp for batch 100 is set to a far-future time (e.g., `block.timestamp + 365 days`), the system must **wait** before it can create batch 101, as the next batch must have a timestamp greater than batch 100’s timestamp.
            4. This introduces a delay between batch commitments, limiting how quickly the batches can be processed and committed on L1.
            
### Summary of the Role of L2_TX_MAX_GAS_LIMIT:
            
- **L2_TX_MAX_GAS_LIMIT** determines how many transactions can fit into a single batch (about 53 transactions if each uses the maximum gas).
- When the batch’s gas limit is reached, a new batch must be created, which leads to frequent batch sealing and creation.
- If the timestamp of a batch is set too far into the future, the system is forced to **wait** between batch commitments, further slowing down transaction processing and finality on L1.
- Therefore, **L2_TX_MAX_GAS_LIMIT** indirectly contributes to the timestamp issue by influencing how quickly batches are created, and when combined with the far-future timestamp, it exacerbates delays in processing.
        
    
**How to find it next time**:
    
    Pay a close attention on the how the batches works and how do they included into the L1. Brainstorm every possible scenario so the batches could not be delivered into L1.
    
# Issue explanation: **Governance logic may enter a deadlock**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/260
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/364
    
**Core problem**:
    
    Overall, in other contests it would be invalid, but here there is a reasonable explanation related how the governance could be breakd.
    
    If any of the governance actors, either securityCouncil or owner, gets compromised, the whole governance logic will enter a deadlock.
    
    The Governance contract could call itself via `execute`. Then, he could do the following 
    
    - `updateSecurityCouncil`
    - `updateDelay`
    
    if security council gets compromised, then he can spam `cancel` to ban all upgrades made by the owner , even the ones trying to remove the council by calling `updateSecurityCouncil`, as the  cannot call `executeInstant` and the proposals delay (although not enforced) is supposed to be non-zero. 
    
    ```solidity
    /// @dev Cancel the scheduled operation.
        /// @dev Both the owner and security council may cancel an operation.
        /// @param _id Proposal id value (see `hashOperation`)
        function cancel(bytes32 _id) external onlyOwnerOrSecurityCouncil {
            require(isOperationPending(_id), "Operation must be pending");
            delete timestamps[_id];
            emit OperationCancelled(_id);
        }
    ```
    
**How to find it next time**:
    
    The council consists of different entities. So examine the flow how they could be abused. Examine whether there is no logic inconsistencies in the updating/removing/e.t.c
    
     
    
# Issue explanation: **Mailbox.requestL2Transaction() checks the deposit limit of msg.sender (L1WethBridge) instead of the real depositor of weth from L1, as a result, after certain time, nobody will be able to deposit weth anymore from L1**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/246
    
### Summary of the Issue:
    
    The issue lies in how deposit limits are checked during WETH transfers from Layer 1 (L1) to Layer 2 (L2) in zkSync. When users deposit WETH from L1 to L2 via the `bridgeProxy.deposit()` function, the limit for deposits is checked against the **address of the L1WethBridge** contract (`msg.sender`) rather than the individual user addresses. This design flaw causes the following problem:
    
    - All user deposits are collectively counted under the **L1WethBridge contract's limit**.
    - Once the deposit limit for the **L1WethBridge** is reached, no further deposits can be made, regardless of whether an individual user has hit their own deposit limit or not.
    
### Detailed Impact:
    
    - **Deposit Limit Misapplication**: The deposit limit is supposed to restrict individual users, but because the limit check is on the `L1WethBridge` contract (the intermediary for WETH transfers), the total deposits of all users are pooled. Once the collective deposit limit for the bridge is reached, no more deposits can occur, effectively freezing any further WETH transfers from L1 to L2.
    - **User Deposits Blocked**: As more users deposit WETH, the system counts all their deposits under the same limit. Eventually, when this limit is reached, even users who have not exceeded their personal limit will be blocked from making new deposits.
    
### Example Scenario:
    
    1. The deposit limit is set to 10 ether.
    2. **User 1** deposits 3 ether of WETH.
    3. **User 2** deposits 4 ether of WETH.
    4. **User 3** deposits 2.7 ether of WETH, bringing the total deposited to 9.7 ether (just under the limit).
    5. When **User 3** tries to deposit an additional 1 ether, the total for the `L1WethBridge` exceeds 10 ether, and the transaction fails, even though **User 3** hasn’t personally exceeded their limit.
    
### Conclusion:
    
    The issue is that the deposit limit is applied to the **L1WethBridge contract** instead of the individual users. This will ultimately prevent all users from depositing WETH once the collective bridge limit is reached, making the bridge unusable for further deposits. The protocol needs to change how deposit limits are checked, ensuring they are applied per user, not per bridge contract.
    
**How to find it next time**:
    
    Check that across the protocol the check on the correct entities is used. That msg.sender is who it is expected to be.
    
# Issue explanation: **Synchronization Issue Between L1 and L2 Upgrades**
    
    https://github.com/code-423n4/2023-10-zksync-findings/issues/214
    
**Core problem**:
    
Interesting stuff, that could result in the sync failed during upgrades
    
Basically, the upgrades happen on l1 and l2. 
    
On l1, if no success → revert, and it is clear that update happens
    
On l2, it is done via the bootloader, and even if there is no success, it simply send the answer to the l1 that there is no success. However, on the L1 side, it does not care about the outcome of the L2 upgrade transaction on L2, it only cares about the execution of the L2 upgrade transaction, regardless of its success or failure.
    
    So, the sync could fail. So l1 updated, but the l2 not
    
**How to find it next time**:
    
    I have seen many findings related to the updating mechanism. So pay close attention on the every possible update flow on every instances of the protocol.
    
# Issue explanation: **Discrepancy in ECRECOVER Precompile when Using Delegatecall**
    
**Core problem**:
    
The zkSync implements the custom ecrecover precompile. It works differently compare to the L1. The bug is that if the the custom ecrecover will be used via the `delegateCall`, it can have significant impact leading to incorrect signature validation, potentially compromising data integrity and user funds.
    
In zkSync Era, when the ECRECOVER precompile contract is invoked using `delegatecall`, it diverges from the usual behavior by delegating the call to the contract itself and executing its code within the caller's context. This results in a returned value that does not align with the anticipated outcome of a `precompileCall`. Instead, it yields `bytes32(0)`.
    
**How to find it next time**:
    
Check the precompiled behaviour heavily from all of the edges.
    
# Issue explanation: **Discrepancy in Default Account Behavior**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/168
    
**Core problem**:
    
The core goal of the Default Account is to simulate the logic of the EOA, however it is not always the case. If the custom account would delegate call to the custom account, it would revert, because the Default Account’s fallback function is inconsistent.
    
    ```solidity
    fallback() external payable {
        // The fallback function of the default account should never be called by the bootloader
        assert(msg.sender != BOOTLOADER_FORMAL_ADDRESS);
    
        // If the contract is called directly, it should behave like an EOA.
    }
    
    receive() external payable {
        // If the contract is called directly, it should behave like an EOA.
    }
    ```
    
So, because the msg.sender isn’t the bootloader, it would revert.
    
**How to find it next time**:
    
It was interesting to discover that if do the delegate call, it would be forwarded into the fallback. But in the correct audit try to break the EOA invariant. Think in a way, at which edges it wouldn’t behave as an EOA. We need to revise the evm)
    
# Issue explanation: **Divergences in the Simulation of the extcodehash EVM Opcode**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/133
    
**Core problem**:
    
The vulnerability lies in the discrepancies between how zkSync Era emulates the `extcodehash` opcode compared to the Ethereum Virtual Machine (EVM) standard defined in EIP-1052. Specifically:
    
    1. **Empty Account Handling**: According to EIP-161, an account is considered empty if it has no code, a zero nonce, and a zero balance. In the EVM, if an account is not empty (i.e., it has a balance but no code), the `extcodehash` should return `keccak256("")`. However, zkSync Era returns `bytes32(0)` for such accounts, ignoring the account's balance and only considering the code and nonce.
    2. **Precompile Contracts**: In the EVM, precompiled contracts (such as address `0x02` for SHA-256) have no code but a non-zero balance. The `extcodehash` for such contracts should return `keccak256("")`. In zkSync Era, this behavior is consistent but doesn't account for the balance. It returns `keccak256("")` based on whether the address is a precompile, disregarding balance entirely.
    
### Potential Impact:
    
- Developers relying on zkSync Era's emulation of `extcodehash` might encounter **unexpected behavior** in their smart contracts, especially when handling accounts or precompiled contracts with balances.
- This divergence could lead to **inconsistent contract logic** between zkSync Era and the EVM, affecting the security and reliability of contracts ported between platforms.
    
The core issue is that zkSync Era's behavior does not fully align with the EVM's handling of account balance in the `extcodehash` operation, potentially causing security risks or logic errors in deployed contracts.
    
**How to find it next time**:
    
Ensure that every precompile / opcode that is integrated/create by the zkSync is consisted with the actual logic, as at evm. Check every documentation of every precompile / opcode. Search for the most rare one, check my twitter handle once. 
    
# Issue explanation: **Nonce Behavior Discrepancy Between zkSync Era and EIP-161**
    
    https://github.com/code-423n4/2023-10-zksync-findings/issues/92
    
**Core problem**:
    
    Th eip-161 refers to the State Trie Clearing, and it defines an "empty account" as an account that has:
    
- **No code** (i.e., the account is not a smart contract).
- **Nonce** of zero (i.e., the account has not initiated any transactions).
- **Balance** of zero (i.e., no Ether or tokens stored in the account)
    
There is a discrepancy between ZkEvm and EVM. 
    
- In **EVM**, when contracts are deployed, the deployment nonce for a new contract starts at **1**.
- In **zkSync Era**, the deployment nonce starts at **0**, which is a deviation from the EVM standard.
    
**Impact on Contract Address Predictions:**
    
- Contract factories or developers often rely on nonces to **predict the addresses** of child contracts before deployment.
- The different nonce starting points between zkSync Era and EVM can cause **incorrect address predictions**.
- This issue is particularly relevant for smart contracts that deploy other contracts, as their logic may assume a starting nonce of 1 (following EVM behavior).
    
**EIP-161 Reference:**
    
- EIP-161 specifies that the nonce should increment by **one** before the contract's initialization code is executed.
- zkSync Era, by starting the nonce at zero instead of one, violates this assumption, leading to unpredictable behavior in contract address generation.
    
**How to find it next time**:
    
It is a really nice one! The hole point about it, is to check the EIP’s heavily. Maybe there is some which are already added. So, check what updates where on Ethereum and how the Zk handles it. But overall check the discrepancies on the level on the EIPs(core level)
    
# Issue explanation: **Deployment Nonce Does not Increment For a Reverted Child Contract**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/91
    
**Core problem**:
    
In EVM, the **factory's nonce** is incremented **immediately** when a contract deployment begins, even if the deployment fails (i.e., if the child contract's constructor reverts). The nonce is **not rolled back** in case of failure, ensuring that future contract deployments are predictable
    
The failed contract creation returns `address(0)`, but the factory's nonce remains incremented, preventing issues with future deployments.
    
**zkSync Era Behavior:**
    
- In zkSync Era, the deployment nonce is incremented **only** during the deployment process, but if the child contract’s constructor reverts, the entire transaction is rolled back, including the **factory’s incremented nonce**.
- This rollback leads to a situation where the factory's nonce is **reset** after a failed contract creation, making it inconsistent with EVM behavior.
    
**How to find it next time**:
    
Check the nonce behaviours. One more time, check the EIP’s
    
# Issue explanation: **Potential Gas Manipulation via Bytecode Compression**
    
https://github.com/code-423n4/2023-10-zksync-findings/issues/71
    
**Core problem**:
    
The issue here revolves around the exploitation of a **compression mechanism** in the zkSync system, which is designed to reduce gas costs for users when publishing data from Layer 2 (L2) to Layer 1 (L1). The bug allows a **malicious operator** to manipulate the compression method in a way that artificially inflates the length of the data (or "dictionary") being compressed. This leads to **higher gas costs** without providing any real benefit in terms of data efficiency or compression.
    
### Key Concepts:
    
1. **Compression for Gas Efficiency**:
- When processing L2 transactions, zkSync compresses the data (such as `factoryDeps`) before sending it to L1. This compression reduces the gas fees users need to pay, as the cost is proportional to the length of the message transmitted to L1.
2. **Malicious Compression Manipulation**:
- In the normal case, compression reduces the data size by replacing repeated segments with shorter references. The compressed data includes a "dictionary" of unique segments and "encoded data" that refers to these dictionary segments.
- However, a **malicious operator** could manipulate the compression method to artificially extend the size of the dictionary by adding unnecessary data. This **inflated dictionary** would increase the gas fees users pay, as gas is determined by the length of the transmitted message, even if the extra dictionary data has no functional purpose.
    
**How to find it next time**:

When i will explore the compression, check whether we could extra data, whether could some malicious data be intervened, e.t.c. 
    
# Issue explanation: **deploying contracts with forceDeployOnAddress will break contracts when callConstructor is false**
    
**Core problem**:
    
    ```solidity
    function forceDeployOnAddress(ForceDeployment calldata _deployment, address _sender) external payable onlySelf {
            _ensureBytecodeIsKnown(_deployment.bytecodeHash);
            _storeConstructingByteCodeHashOnAddress(_deployment.newAddress, _deployment.bytecodeHash);
    
            AccountInfo memory newAccountInfo;
            newAccountInfo.supportedAAVersion = AccountAbstractionVersion.None;
            // Accounts have sequential nonces by default.
            newAccountInfo.nonceOrdering = AccountNonceOrdering.Sequential;
            _storeAccountInfo(_deployment.newAddress, newAccountInfo);
    
            if (_deployment.callConstructor) {
                _constructContract(_sender, _deployment.newAddress, _deployment.input, false);
            }
    
            emit ContractDeployed(_sender, _deployment.bytecodeHash, _deployment.newAddress);
        }
    ```
    
Here we have an issue. If we deploy the contract with the _deployment.callConstructor = false, it would lead to the disaster. Basically we will have the contract with bytecode but where the constructor wasn’t called. It for sure lead to the fund lost
    
- When a contract is deployed using the `forceDeployOnAddress()` function with `callConstructor = false`, the contract’s bytecode hash remains in a **"constructing"** state.
- This "constructing" state is meant to prevent the contract from being callable by other contracts until its constructor has been executed, ensuring the contract isn't interacted with before it's fully initialized.
- However, if the constructor is **never called** (because `callConstructor = false`), the contract remains in this **permanent constructing state**, which means it **cannot be called or interacted with**.
    
**How to find it next time**:
    
Check the contract deployment logic heavily and ensure that all works fine. Check new EIP’s some edges with the self-destruct, e.t.c.
    
# Issue explanation: **BlockTimestamp is inconsistent on ZKSync compare to EVM**
    
https://github.com/code-423n4/2023-03-zksync-findings/issues/70
    
**Core problem**:
    
    ```solidity
    function setNewBlock(
            bytes32 _prevBlockHash,
            uint256 _newTimestamp,
            uint256 _expectedNewNumber,
            uint256 _baseFee
        ) external onlyBootloader {
            (uint256 currentBlockNumber, uint256 currentBlockTimestamp) = getBlockNumberAndTimestamp();
            require(_newTimestamp >= currentBlockTimestamp, "Timestamps should be incremental");
            require(currentBlockNumber + 1 == _expectedNewNumber, "The provided block number is not correct");
    ........
    ```
    
The bug highlights that **time-sensitive contracts** may not function as expected when deployed on zkSync, due to significant differences in how blocks are handled compared to Ethereum.
    
    ### Summary:
    
1. **Issue with Block Number**: Many Ethereum-based contracts rely on **block number** (e.g., for measuring time or intervals) because it's seen as more stable than timestamps. For instance, a DeFi project might expect 144,000 blocks (about 20 days on Ethereum, assuming 12 seconds per block). However, on zkSync, block intervals are not consistent, potentially ranging from **30 seconds to 1 week** or more, causing extreme variation in the expected time duration (from **50 days to 2762 days**). It could result at least in the incorrect rewards distribution.
2. **Timestamp Manipulation**: Even contracts using **timestamps** could face issues. zkSync allows new blocks to be created with the **same timestamp** as previous blocks (but with an incremented block number). This could result in **frozen time**, leading to incorrect contract behavior.
    
**How to find it next time**:
    
Check the block production code, and brainstorm what if, what if re-org? E.t.c?
    
# Issue explanation: **Loosing funds in a loop during the force deployment**
    
    https://github.com/code-423n4/2023-03-zksync-findings/issues/64
    
**Core problem**:
    
This bug describes a flaw in the **force deployment** process in the `ContractDeployer` contract, where funds can be unintentionally locked if a deployment fails, making them difficult to recover.
    
### Summary:
    
- **Force Deployment Mechanism**: The `forceDeployOnAddresses` function is used during contract upgrades to deploy bytecode to specific addresses, transferring ETH to initialize these new contracts. The ETH sent must match the total amount needed for all deployments.
- **Problem with Failed Deployments**: If any deployment fails (e.g., due to unknown bytecode or issues in the constructor), the ETH meant for that failed deployment remains in the `ContractDeployer` contract, but can't be reused for future deployments.
- **Non-reverting Transactions**: The transaction doesn't revert on failure; instead, it continues attempting the next deployments, even though some ETH remains trapped. Since the function checks against `msg.value` and not the contract's balance, the locked funds cannot be easily recovered or repurposed for future deployments.
    
### Impact:
    
The locked ETH can accumulate if deployments frequently fail, which could lead to significant losses. Additionally, there is no straightforward way to retrieve this ETH once it's stuck in the `ContractDeployer` contract.
    
The bug is critical because it affects the system's ability to manage ETH properly during force deployment, potentially leading to financial and operational inefficiencies.
    
    ```solidity
    function forceDeployOnAddresses(ForceDeployment[] calldata _deployments) external payable {
            require(msg.sender == FORCE_DEPLOYER, "Can only be called by FORCE_DEPLOYER_CONTRACT");
    
            uint256 deploymentsLength = _deployments.length;
            // We need to ensure that the `value` provided by the call is enough to provide `value`
            // for all of the deployments
            uint256 sumOfValues = 0;
            for (uint256 i = 0; i < deploymentsLength; ++i) {
                sumOfValues += _deployments[i].value;
            }
            require(msg.value == sumOfValues, "`value` provided is not equal to the combined `value`s of deployments");
    
            for (uint256 i = 0; i < deploymentsLength; ++i) {
                this.forceDeployOnAddress{value: _deployments[i].value}(_deployments[i], msg.sender);
            }
        }
    
    ```
    
**How to find it next time**:
    
Check the logic of the contract deployment. Check every EIP that was introduced since last audit. Check how does it align with the logic.
