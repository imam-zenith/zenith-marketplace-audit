# Zenith Marketplace Security Review

### Contract Address: 0xc6AE85bec45e127a91F97d5d4d9af0c11F0BACe3

## [L-01] Missing zero address validation should be avoided

This vulnerability can be found in several lines of code

```solidity
firstOwnerAddress.transfer(royaltyAmount) //Line 269 in function acceptDirectSellOrder

firstOwnerAddress.transfer(royaltyAmount) //Line 331 in function acceptBidandExecuteOrder

address(_receiverAddress).transfer(_amount) //Line 496 in function getFunds
```
### Proof of Concept
Bob is the current owner of contract C. He sends a transaction to the contract to update the owner without specifying a new owner. The onlyAdmin modifier is triggered and checks if the sender of the transaction is the owner. Since the sender of the transaction is Bob, the check fails, and Bob loses ownership of the contract.

```solidity
contract C {

  modifier onlyAdmin {
    if (msg.sender != owner) throw;
    _;
  }

  function updateOwner(address newOwner) onlyAdmin external {
    owner = newOwner;
  }
}
```

### Impact
The transaction will fail if the address is incorrect.

### Recommendation
Check that the address is not zero.



## [L-02] Reentrancy Vulnerabilities

```Solidity
Reentrancy in MarketPlace._createOrder(address,uint256,uint256) (Line 368-389):
        External calls:
        - tokenRegistry.safeTransferFrom(tokenOwner,address(this),_tokenId) (Line 377)
        State variables written after the call(s):
        - orderByTokenId[_tokenAddress][_tokenId] = Order(_orderId,address(msg.sender),_tokenAddress,_askingPrice,0) (Line 380-386)
```

```solidity
Reentrancy in MarketPlace.createDirectSellOrder(address,uint256,uint256) (Line 344-366):
        External calls:
        - tokenRegistry.safeTransferFrom(tokenOwner,address(this),_tokenId) (Line 352)
        State variables written after the call(s):
        - DirectorderByTokenId[_tokenAddress][_tokenId] = DirectOrder(_directOrderId,address(msg.sender),_tokenAddress,_askingPrice) (Line 356-362)
```

### Recommendation
To solve this issue, the following are recommended
- Use the ReentrancyGuard library. This library provides a set of functions that are designed to prevent reentrancy attacks.
- Utilize the "require" statement to check that the contract is not already in the middle of an execution before allowing a new external call.


## [L-03] Using timestamp for comparisons

```solidity
MarketPlace.acceptBidandExecuteOrder(address,uint256,uint256) (Line 295-342)
        Dangerous comparisons:
        - require(bool,string)(order.expiryTime < block.timestamp,Marketplace: Auction hasn't ended yet) (Line 299)
```

```solidity
MarketPlace._createBid(address,uint256,uint256) (Line 391-424)
        Dangerous comparisons:
        - require(bool,string)(order.expiryTime >= block.timestamp,Marketplace: Auction ended) (Line 399)
        - block.timestamp.add(900) > order.expiryTime (Line 400)
```

### Recommendation
Reference: https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/

## [I-01] Contract Code Size Exceeds Regular Limit

### Proof of Concept
Alice is a dapp developer and wants to deploy her contract to the mainnet. She has written the code for the contract and runs a test to check if it meets the requirements for being deployed. However, when she checks the size of the contract, she sees that it exceeds 24576 bytes but she tries to deploy it anyway.

Depending on the capability of the blockchain she is deploying to, the transaction may be reverted and the code will not be deployed on the blockchain. This may happen because transactions must fit within the block size limit, and larger contracts would exceed this limit. In addition, the blockchain network may not have sufficient resources to handle the larger contract.

### Impact
The contract may not be deployable on the mainnet, or if otherwise deployed, some functions may not work as expected.

### Recommendation
To solve this issue, it is recommended to enable the optimizer setting with a low "runs" value, turn off revert strings and use libraries. This will not only reduce the size of the contract code but also ensure its security.


## [I-02] Comparisons with a Boolean constant

```solidity
MarketPlace.acceptDirectSellOrder(address,uint256) (Line 234-291) compares to a boolean constant:
        -firstTransfer[_tokenId] != false (Line 248)
 ```
 
```solidity
MarketPlace.acceptBidandExecuteOrder(address,uint256,uint256) (Line 295-342) compares to a boolean constant:
        -firstTransfer[_tokenId] != false (Line 317)
```
### Recommendation
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#boolean-equality

