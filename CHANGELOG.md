## Diamond Node Software 3.3.5-hbbft-0.11.6
- [session double kill problem.](https://github.com/DMDcoin/diamond-node/issues/252)
- [Network Host logic: peer_id to NodeID consistency](https://github.com/DMDcoin/diamond-node/issues/251)
- [sealing messages probably not received](https://github.com/DMDcoin/diamond-node/issues/248)
- [disconnected from reservered peers](https://github.com/DMDcoin/diamond-node/issues/247)
- [separate handshakes and encrypted connections](https://github.com/DMDcoin/diamond-node/issues/254)

## Diamond Node Software 3.3.5-hbbft-0.11.5
- [Improved reliability of Hbbft targeted message delivery](https://github.com/DMDcoin/diamond-node/issues/248)

## Diamond Node Software 3.3.5-hbbft-0.11.4
- [Balanced lock approach for solving the lock problems in devp2p](https://github.com/DMDcoin/diamond-node/issues/236)

## Diamond Node Software 3.3.5-hbbft-0.11.3

- [deadlocks in transaction pools](https://github.com/DMDcoin/diamond-node/issues/236)

## Diamond Node Software 3.3.5-hbbft-0.11.2

- [shutdown on deadlock](https://github.com/DMDcoin/diamond-node/issues/231)
- [deadlock possibility in reserved peers management](https://github.com/DMDcoin/diamond-node/issues/229)

## Diamond Node Software 3.3.5-hbbft-0.11.1

- [caching of SyncStatus to prevent deadlocks](https://github.com/DMDcoin/diamond-node/issues/223)

## Diamond Node Software 3.3.5-hbbft-0.11.0

- [Fixed: Compile error on newer Linux Versions](https://github.com/DMDcoin/diamond-node/issues/145)
- [rust update to  1.85 and rust edition 2024](https://github.com/DMDcoin/diamond-node/issues/191)
- [updated dependencies](https://github.com/DMDcoin/diamond-node/issues/107)
- [Fixed: Service Transaction not allowed:](https://github.com/DMDcoin/diamond-node/issues/185)
- [reduced network usage:](https://github.com/DMDcoin/diamond-node/issues/163) 
- [additional prometheus counter and gauges, most of them for analysing](https://github.com/DMDcoin/diamond-node/issues/163) 
- [Improved transaction propagation for clients that are syncing](https://github.com/DMDcoin/diamond-node/issues/173)

## Diamond Node Software 3.3.5-hbbft-0.10.1

- Emergency fix to improve blockimports: only one block at a time is now requested throught the devp2p block sync protocol. https://github.com/DMDcoin/diamond-node/issues/209


## Diamond Node Software 3.3.5-hbbft-0.10.0

- Bonus Score finalization

## Diamond Node Software 3.3.5-hbbft-0.9.8

- Improved Hbbft "No Session Exists" handling: https://github.com/DMDcoin/diamond-node/issues/150
- Lock overhead reduction for validator actions
- Connect & Disconnect Report management: fixed double sending of reports: https://github.com/DMDcoin/diamond-node/issues/157
- Stage 3 Verification: Fixed State Pruning related error. https://github.com/DMDcoin/diamond-node/issues/161
- Added Network and DevP2P related Information to the Prometheus Metrics: https://github.com/DMDcoin/diamond-node/issues/163
- Early Epoch End: Treat any HBBFT Message as being a responsive partner node: https://github.com/DMDcoin/diamond-node/issues/87

## Diamond Node Software 3.3.5-hbbft-0.9.7

- [Nodes that are not a active validator seem to try to send connectivity reports] (https://github.com/DMDcoin/diamond-node/issues/153)

## Diamond Node Software 3.3.5-hbbft-0.9.6

- [Early Epoch End: only report disconnectivities that exist for longer than 60 Minutes] (https://github.com/DMDcoin/diamond-node/issues/87)
- [Improved Logging for Hbbft Session Management] (https://github.com/DMDcoin/diamond-node/issues/150)

## Diamond Node Software 3.3.5-hbbft-0.9.5

- [Improved Logging of ] (https://github.com/DMDcoin/diamond-node/issues/147)
- [Early Epoch end: Applying new time based rules]  (https://github.com/DMDcoin/diamond-node/issues/87)



## Diamond Node Software 3.3.5-hbbft-0.9.5

- [Improved Logging for Stage 5 Errors] (https://github.com/DMDcoin/diamond-node/issues/147)
- [Early Epoch end: Applying new time based rules]  (https://github.com/DMDcoin/diamond-node/issues/87)


## Diamond Node Software 3.3.5-hbbft-0.9.4

- [Fixed: is major syncing information is wrong.] (https://github.com/DMDcoin/diamond-node/issues/73)
- [Improvements for HBBFT Message Tracking] (https://github.com/DMDcoin/openethereum-3.x/issues/17)

## Diamond Node Software 3.3.5-hbbft-0.9.3

[Autoshutdown after a period without block import] https://github.com/DMDcoin/diamond-node/issues/78

Those examples show how to confige the node to activate this feature, restarting the node if no block import has been detected for 1800 seconds (30 minutes)

to activate feature via CLI Arg:
`--shutdown-on-missing-block-import=1800`

or in node.toml
node.toml:
```
[Misc]
shutdown_on_missing_block_import = 1800
```

## Diamond Node Software 3.3.5-hbbft-0.9.2

- [FIXED: pruning as root cause for stage 3 errors] https://github.com/DMDcoin/diamond-node/issues/68

## Diamond Node Software 3.3.5-hbbft-0.9.1

- [pruning protection for hbbft engine] https://github.com/DMDcoin/diamond-node/issues/62
- [reported fault: UnknownSender] https://github.com/DMDcoin/diamond-node/issues/69

## Diamond Node Software 3.3.5-hbbft-0.9.0

- Start of Alpha 2 Testnet
- Improved Stability
- Feature preparation for Hbbft Block Reward support

## Diamond Node Software 3.3.5-hbbft-0.8.9

- [fixed logspam because of syncing nodes](https://github.com/DMDcoin/diamond-node/issues/29)
- [prometheus: is_major_syncing](https://github.com/DMDcoin/diamond-node/issues/32) 

## Diamond Node Software 3.3.5-hbbft-0.8.8
Hotfix Release 

- https://github.com/DMDcoin/diamond-node/issues/23

## Diamond Node Software 3.3.5-hbbft-0.8.7

- removed deadlock detection from default config
- added missing categorisation from hbbft_message_memorium
- increased sleeping timer for hbbft_message_memoriumto increase performance, since we often have messages that can't be processed.

## Diamond Node Software 3.3.5-hbbft-0.8.6

- client Software now known as diamond-node
- [deadlock on locking HBBFT State after receiving Agreements](https://github.com/DMDcoin/diamond-node/issues/7)
- [Write random number fork block](https://github.com/DMDcoin/diamond-node/issues/1)
- [provide hbbft data by via Prometheus Interface](https://github.com/DMDcoin/diamond-node/issues/14)
- [Prometheus logging can result in a deadlock ](https://github.com/DMDcoin/diamond-node/issues/13)
- [Nonce problem with announce availability and setting IP address](https://github.com/DMDcoin/diamond-node/issues/8)
- [hbbft automatic reserved peers management](https://github.com/DMDcoin/diamond-node/issues/5)

## Diamond Node Software 3.3.5-hbbft-0.8.5

- [Automatic shutdown on validator candidate unavailability](https://github.com/DMDcoin/openethereum-3.x/issues/87)
- [Merge final set of changes](https://github.com/DMDcoin/openethereum-3.x/issues/103)
- [hardware specific optimizations](https://github.com/DMDcoin/openethereum-3.x/issues/117)
- [Unexpected IO error: Invalid argument (os error 22)](https://github.com/DMDcoin/openethereum-3.x/issues/124)
- [replace json formatter for HBBFT Messages](https://github.com/DMDcoin/openethereum-3.x/issues/108)
- [transaction subset contribution](https://github.com/DMDcoin/openethereum-3.x/issues/115)
- [check_for_epoch_change() called to often (performance)](https://github.com/DMDcoin/openethereum-3.x/issues/101)

## Diamond Node Software 3.3.4-hbbft-0.8.4

- [Reduced chance of DB corruptions](https://github.com/DMDcoin/openethereum-3.x/issues/87)

## Diamond Node Software 3.3.4-hbbft-0.8.3

Increased availability of nodes.

- [Automatic shutdown on validator candidate unavailability ](https://github.com/DMDcoin/openethereum-3.x/issues/87)


## Diamond Node Software 3.3.4-hbbft-0.8.2

Merge with OpenEthereum 3.3.4.

* Merge with OpenEthereum 3.3.4. Including all changes from 3.2.5 up to 3.3.4 from open ethereum
* [Key Gen Transactions not broadcasted](https://github.com/DMDcoin/openethereum-3.x/issues/81)

## Diamond Node Software 3.2.5-hbbft-0.8.1

Performance and stability improvement for active validator nodes.

*  [Multithreading for hbbft message analysis and logging](https://github.com/DMDcoin/openethereum-3.x/issues/76)

## Diamond Node Software 3.2.5-hbbft-0.8.0

Mandatory upgrade that switches to hbbft protocol version 2

*  [protocol upgrade to v2: Await full key sets for shared key generation.](https://github.com/DMDcoin/openethereum-3.x/issues/71)

## Diamond Node Software 3.2.5-hbbft-0.7.1

Fixes:
* block proposals with invalid transactions lead to 0-tx-Blocks (https://github.com/DMDcoin/openethereum-3.x/issues/58)

## Diamond Node Software 3.2.5-hbbft-0.7.0

Enhancements:
* configure skipped block reward calls (https://github.com/DMDcoin/openethereum-3.x/issues/49)

## Diamond Node Software 3.2.5-hbbft-0.7.0

Enhancements:
* configure skipped block reward calls (https://github.com/DMDcoin/openethereum-3.x/issues/49)

## Diamond Node Software 3.2.5-hbbft-0.6.0

Enhancements:
* Key Generation Round Counter
Fixes:
* Fixed stage 5 syncing error
* Support for POSDAO contract hardfork (#633)
* Update rpc server (#619)

## OpenEthereum v3.3.5
Enhancements:

* Support for POSDAO contract hardfork (#633)
* Update rpc server (#619)

## OpenEthereum v3.3.4

Enhancements:
* EIP-712: Update logos and rewrite type parser (now builds on Rust 1.58.1) (#463)
* Handling of incoming transactions with maxFeePerGas lower than current baseFee (#604)
* Update transaction replacement (#607)

## OpenEthereum v3.3.3

Enhancements:
* Implement eip-3607 (#593)

Bug fixes:
* Add type field for legacy transactions in RPC calls (#580)
* Makes eth_mining to return False if not is not allowed to seal (#581)
* Made nodes data concatenate as RLP sequences instead of bytes (#598)

## OpenEthereum v3.3.2

Enhancements:
* London hardfork block: Sokol (24114400)

Bug fixes:
* Fix for maxPriorityFeePerGas overflow

## OpenEthereum v3.3.1

Enhancements:
* Add eth_maxPriorityFeePerGas implementation (#570)
* Add a bootnode for Kovan

Bug fixes:
* Fix for modexp overflow in debug mode (#578)

## OpenEthereum v3.3.0

Enhancements:
* Add `validateServiceTransactionsTransition` spec option to be able to enable additional checking of zero gas price transactions by block verifier

## OpenEthereum v3.3.0-rc.15

* Revert eip1559BaseFeeMinValue activation on xDai at London hardfork block

## OpenEthereum v3.3.0-rc.14

Enhancements:
* Add eip1559BaseFeeMinValue and eip1559BaseFeeMinValueTransition spec options
* Activate eip1559BaseFeeMinValue on xDai at London hardfork block (19040000), set it to 20 GWei
* Activate eip1559BaseFeeMinValue on POA Core at block 24199500 (November 8, 2021), set it to 10 GWei
* Delay difficulty bomb to June 2022 for Ethereum Mainnet (EIP-4345)

## OpenEthereum v3.3.0-rc.13

Enhancements:
* London hardfork block: POA Core (24090200)

## OpenEthereum v3.3.0-rc.12

Enhancements:
* London hardfork block: xDai (19040000)

## OpenEthereum v3.3.0-rc.11

Bug fixes:
* Ignore GetNodeData requests only for non-AuRa chains

## OpenEthereum v3.3.0-rc.10

Enhancements:
* Add eip1559FeeCollector and eip1559FeeCollectorTransition spec options

## OpenEthereum v3.3.0-rc.9

Bug fixes:
* Add service transactions support for EIP-1559
* Fix MinGasPrice config option for POSDAO and EIP-1559

Enhancements:
* min_gas_price becomes min_effective_priority_fee
* added version 4 for TxPermission contract

## OpenEthereum v3.3.0-rc.8

Bug fixes:
* Ignore GetNodeData requests (#519)

## OpenEthereum v3.3.0-rc.7

Bug fixes:
* GetPooledTransactions is sent in invalid form (wrong packet id)

## OpenEthereum v3.3.0-rc.6

Enhancements:
* London hardfork block: kovan (26741100) (#502)

## OpenEthereum v3.3.0-rc.4

Enhancements:
* London hardfork block: mainnet (12,965,000) (#475)
* Support for eth/66 protocol version (#465)
* Bump ethereum/tests to v9.0.3
* Add eth_feeHistory

Bug fixes:
* GetNodeData from eth63 is missing (#466)
* Effective gas price not omitting (#477)
* London support in openethereum-evm (#479)
* gasPrice is required field for Transaction object (#481)

## OpenEthereum v3.3.0-rc.3

Bug fixes:
* Add effective_gas_price to eth_getTransactionReceipt #445 (#450)
* Update eth_gasPrice to support EIP-1559 #449 (#458)
* eth_estimateGas returns "Requires higher than upper limit of X" after London Ropsten Hard Fork #459 (#460)

## OpenEthereum v3.3.0-rc.2

Enhancements:
* EIP-1559: Fee market change for ETH 1.0 chain
* EIP-3198: BASEFEE opcode
* EIP-3529: Reduction in gas refunds
* EIP-3541: Reject new contracts starting with the 0xEF byte
* Delay difficulty bomb to December 2021 (EIP-3554)
* London hardfork blocks: goerli (5,062,605), rinkeby (8,897,988), ropsten (10,499,401)
* Add chainspecs for aleut and baikal
* Bump ethereum/tests to v9.0.2

## OpenEthereum v3.2.6

Enhancement:
* Berlin hardfork blocks: poacore (21,364,900), poasokol (21,050,600)

## OpenEthereum v3.2.5

Bug fixes:
* Backport: Block sync stopped without any errors. #277 (#286)
* Strict memory order (#306)

Enhancements:
* Executable queue for ancient blocks inclusion (#208)
* Backport AuRa commits for xdai (#330)
* Add Nethermind to clients that accept service transactions (#324)
* Implement the filter argument in parity_pendingTransactions (#295)
* Ethereum-types and various libs upgraded (#315)
* [evmbin] Omit storage output, now for std-json (#311)
* Freeze pruning while creating snapshot (#205)
* AuRa multi block reward (#290)
* Improved metrics. DB read/write. prometheus prefix config (#240)
* Send RLPx auth in EIP-8 format (#287)
* rpc module reverted for RPC JSON api (#284)
* Revert "Remove eth/63 protocol version (#252)"
* Support for eth/65 protocol version (#366)
* Berlin hardfork blocks: kovan (24,770,900), xdai (16,101,500)
* Bump ethereum/tests to v8.0.3

devops:
* Upgrade docker alpine to `v1.13.2`. for rust `v1.47`.
* Send SIGTERM instead of SIGHUP to OE daemon (#317)

## OpenEthereum v3.2.4

* Fix for Typed transaction broadcast.

## OpenEthereum v3.2.3

* Hotfix for berlin consensus error.

## OpenEthereum v3.2.2-rc.1

Bug fixes:
* Backport: Block sync stopped without any errors. #277 (#286)
* Strict memory order (#306)

Enhancements:
* Executable queue for ancient blocks inclusion (#208)
* Backport AuRa commits for xdai (#330)
* Add Nethermind to clients that accept service transactions (#324)
* Implement the filter argument in parity_pendingTransactions (#295)
* Ethereum-types and various libs upgraded (#315)
* Bump ethereum/tests to v8.0.2
* [evmbin] Omit storage output, now for std-json (#311)
* Freeze pruning while creating snapshot (#205)
* AuRa multi block reward (#290)
* Improved metrics. DB read/write. prometheus prefix config (#240)
* Send RLPx auth in EIP-8 format (#287)
* rpc module reverted for RPC JSON api (#284)
* Revert "Remove eth/63 protocol version (#252)"

devops:
* Upgrade docker alpine to `v1.13.2`. for rust `v1.47`.
* Send SIGTERM instead of SIGHUP to OE daemon (#317)

## OpenEthereum v3.2.1

Hot fix issue, related to initial sync:
* Initial sync gets stuck. (#318)

## OpenEthereum v3.2.0

Bug fixes:
* Update EWF's chains with Istanbul transition block numbers (#11482) (#254)
* fix Supplied instant is later than self (#169)
* ethcore/snapshot: fix double-lock in Service::feed_chunk (#289)

Enhancements:
* Berlin hardfork blocks: mainnet (12,244,000), goerli (4,460,644), rinkeby (8,290,928) and ropsten (9,812,189)
* yolo3x spec (#241)
* EIP-2930 RPC support
* Remove eth/63 protocol version (#252)
* Snapshot manifest block added to prometheus (#232)
* EIP-1898: Allow default block parameter to be blockHash
* Change ProtocolId to U64
* Update ethereum/tests
