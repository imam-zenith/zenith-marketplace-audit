# Zenith Marketplace Security Review

### Contract Address: 0xc6AE85bec45e127a91F97d5d4d9af0c11F0BACe3

## [I-01] Contract Code Size Exceeds Regular Limit

### Proof of Concept
Alice is a dapp developer and wants to deploy her contract to the mainnet. She has written the code for the contract and runs a test to check if it meets the requirements for being deployed. However, when she checks the size of the contract, she sees that it exceeds 24576 bytes but she tries to deploy it anyway.

Depending on the capability of the blockchain she is deploying to, the transaction may be reverted and the code will not be deployed on the blockchain. This may happen because transactions must fit within the block size limit, and larger contracts would exceed this limit. In addition, the blockchain network may not have sufficient resources to handle the larger contract.

### Impact
The contract may not be deployable on the mainnet, or if otherwise deployed, some functions may not work as expected.

### Recommendation


## [L-01] Missing zero address validation should be avoided






MarketPlace.acceptDirectSellOrder(address,uint256).firstOwnerAddress (../../src/contracts/MarketPlace.sol#259) lacks a zero-check on :
                - firstOwnerAddress.transfer(royaltyAmount) (../../src/contracts/MarketPlace.sol#269)
MarketPlace.acceptBidandExecuteOrder(address,uint256,uint256).firstOwnerAddress (../../src/contracts/MarketPlace.sol#325) lacks a zero-check on :
                - firstOwnerAddress.transfer(royaltyAmount) (../../src/contracts/MarketPlace.sol#331)
MarketPlace.getFunds(address,uint256)._receiverAddress (../../src/contracts/MarketPlace.sol#491) lacks a zero-check on :
                - address(_receiverAddress).transfer(_amount) (../../src/contracts/MarketPlace.sol#496)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation

Reentrancy in MarketPlace._createOrder(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#368-389):
        External calls:
        - tokenRegistry.safeTransferFrom(tokenOwner,address(this),_tokenId) (../../src/contracts/MarketPlace.sol#377)
        State variables written after the call(s):
        - orderByTokenId[_tokenAddress][_tokenId] = Order(_orderId,address(msg.sender),_tokenAddress,_askingPrice,0) (../../src/contracts/MarketPlace.sol#380-386)
Reentrancy in MarketPlace.createDirectSellOrder(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#344-366):
        External calls:
        - tokenRegistry.safeTransferFrom(tokenOwner,address(this),_tokenId) (../../src/contracts/MarketPlace.sol#352)
        State variables written after the call(s):
        - DirectorderByTokenId[_tokenAddress][_tokenId] = DirectOrder(_directOrderId,address(msg.sender),_tokenAddress,_askingPrice) (../../src/contracts/MarketPlace.sol#356-362)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-2

Reentrancy in MarketPlace._cancelFixPriceOrder(bytes32,address,uint256,address) (../../src/contracts/MarketPlace.sol#464-470):
        External calls:
        - IERC721(_tokenAddress).safeTransferFrom(address(this),_seller,_tokenId) (../../src/contracts/MarketPlace.sol#467)
        Event emitted after the call(s):
        - DirectOrderCancelled(_orderId,_tokenId) (../../src/contracts/MarketPlace.sol#469)
Reentrancy in MarketPlace._cancelOrder(bytes32,address,uint256,address) (../../src/contracts/MarketPlace.sol#456-462):
        External calls:
        - IERC721(_tokenAddress).safeTransferFrom(address(this),_seller,_tokenId) (../../src/contracts/MarketPlace.sol#459)
        Event emitted after the call(s):
        - OrderCancelled(_orderId,_tokenId) (../../src/contracts/MarketPlace.sol#461)
Reentrancy in MarketPlace._createOrder(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#368-389):
        External calls:
        - tokenRegistry.safeTransferFrom(tokenOwner,address(this),_tokenId) (../../src/contracts/MarketPlace.sol#377)
        Event emitted after the call(s):
        - OrderCreated(_orderId,msg.sender,_tokenAddress,_tokenId,_askingPrice) (../../src/contracts/MarketPlace.sol#388)
Reentrancy in MarketPlace._executeOrder(bytes32,address,address,uint256,uint256) (../../src/contracts/MarketPlace.sol#426-437):
        External calls:
        - IERC721(_tokenAddress).flipContentLockedStatus(_tokenId) (../../src/contracts/MarketPlace.sol#431)
        - IERC721(_tokenAddress).safeTransferFrom(address(this),_buyer,_tokenId) (../../src/contracts/MarketPlace.sol#434)
        Event emitted after the call(s):
        - OrderSuccessful(_orderId,_tokenId,_buyer,_askingPrice) (../../src/contracts/MarketPlace.sol#436)
Reentrancy in MarketPlace.acceptDirectSellOrder(address,uint256) (../../src/contracts/MarketPlace.sol#234-291):
        External calls:
        - IERC721(_tokenAddress).flipContentLockedStatus(_tokenId) (../../src/contracts/MarketPlace.sol#287)
        - IERC721(_tokenAddress).safeTransferFrom(address(this),msg.sender,_tokenId) (../../src/contracts/MarketPlace.sol#289)
        External calls sending eth:
        - directorder.seller.transfer(finalAmountAfterMarketplaceFee) (../../src/contracts/MarketPlace.sol#254)
        - firstOwnerAddress.transfer(royaltyAmount) (../../src/contracts/MarketPlace.sol#269)
        - directorder.seller.transfer(amountAfterRoyaltyCut) (../../src/contracts/MarketPlace.sol#273)
        - directorder.seller.transfer(finalAmountAfterMarketplaceFee) (../../src/contracts/MarketPlace.sol#281)
        Event emitted after the call(s):
        - DirectOrderSuccessful(directorder.orderId,_tokenId,msg.sender,msg.value) (../../src/contracts/MarketPlace.sol#290)
Reentrancy in MarketPlace.createDirectSellOrder(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#344-366):
        External calls:
        - tokenRegistry.safeTransferFrom(tokenOwner,address(this),_tokenId) (../../src/contracts/MarketPlace.sol#352)
        Event emitted after the call(s):
        - DirectOrderCreated(_directOrderId,msg.sender,_tokenAddress,_tokenId,_askingPrice) (../../src/contracts/MarketPlace.sol#364)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-3

MarketPlace.acceptBidandExecuteOrder(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#295-342) uses timestamp for comparisons
        Dangerous comparisons:
        - require(bool,string)(order.expiryTime < block.timestamp,Marketplace: Auction hasn't ended yet) (../../src/contracts/MarketPlace.sol#299)
MarketPlace._createBid(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#391-424) uses timestamp for comparisons
        Dangerous comparisons:
        - require(bool,string)(order.expiryTime >= block.timestamp,Marketplace: Auction ended) (../../src/contracts/MarketPlace.sol#399)
        - block.timestamp.add(900) > order.expiryTime (../../src/contracts/MarketPlace.sol#400)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#block-timestamp

Address.verifyCallResult(bool,bytes,string) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#201-221) uses assembly
        - INLINE ASM (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#213-216)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#assembly-usage

MarketPlace.acceptDirectSellOrder(address,uint256) (../../src/contracts/MarketPlace.sol#234-291) compares to a boolean constant:
        -firstTransfer[_tokenId] != false (../../src/contracts/MarketPlace.sol#248)
MarketPlace.acceptBidandExecuteOrder(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#295-342) compares to a boolean constant:
        -firstTransfer[_tokenId] != false (../../src/contracts/MarketPlace.sol#317)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#boolean-equality

Different versions of Solidity are used:
        - Version used: ['^0.8.0', '^0.8.1']
        - ^0.8.0 (../../src/contracts/MarketPlace.sol#2)
        - ^0.8.0 (../../src/contracts/imports/ERC721Holder.sol#1)
        - ^0.8.0 (../../src/contracts/imports/IERC721.sol#1)
        - ^0.8.0 (../../src/node_modules/@openzeppelin/contracts/access/Ownable.sol#4)
        - ^0.8.0 (../../src/node_modules/@openzeppelin/contracts/security/Pausable.sol#4)
        - ^0.8.0 (../../src/node_modules/@openzeppelin/contracts/token/ERC20/IERC20.sol#4)
        - ^0.8.0 (../../src/node_modules/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol#4)
        - ^0.8.0 (../../src/node_modules/@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol#4)
        - ^0.8.1 (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#4)
        - ^0.8.0 (../../src/node_modules/@openzeppelin/contracts/utils/Context.sol#4)
        - ^0.8.0 (../../src/node_modules/@openzeppelin/contracts/utils/introspection/IERC165.sol#4)
        - ^0.8.0 (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#4)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used

Address.functionCall(address,bytes) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#85-87) is never used and should be removed
Address.functionCall(address,bytes,string) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#95-101) is never used and should be removed
Address.functionCallWithValue(address,bytes,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#114-120) is never used and should be removed
Address.functionCallWithValue(address,bytes,uint256,string) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#128-139) is never used and should be removed
Address.functionDelegateCall(address,bytes) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#174-176) is never used and should be removed
Address.functionDelegateCall(address,bytes,string) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#184-193) is never used and should be removed
Address.functionStaticCall(address,bytes) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#147-149) is never used and should be removed
Address.functionStaticCall(address,bytes,string) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#157-166) is never used and should be removed
Address.isContract(address) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#36-42) is never used and should be removed
Address.sendValue(address,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#60-65) is never used and should be removed
Address.verifyCallResult(bool,bytes,string) (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#201-221) is never used and should be removed
Context._msgData() (../../src/node_modules/@openzeppelin/contracts/utils/Context.sol#21-23) is never used and should be removed
MarketPlace._getValidOrder(address,uint256) (../../src/contracts/MarketPlace.sol#439-444) is never used and should be removed
MarketPlace._requireERC721(address) (../../src/contracts/MarketPlace.sol#476-486) is never used and should be removed
SafeERC20._callOptionalReturn(IERC20,bytes) (../../src/node_modules/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol#88-98) is never used and should be removed
SafeERC20.safeApprove(IERC20,address,uint256) (../../src/node_modules/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol#45-58) is never used and should be removed
SafeERC20.safeDecreaseAllowance(IERC20,address,uint256) (../../src/node_modules/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol#69-80) is never used and should be removed
SafeERC20.safeIncreaseAllowance(IERC20,address,uint256) (../../src/node_modules/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol#60-67) is never used and should be removed
SafeERC20.safeTransfer(IERC20,address,uint256) (../../src/node_modules/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol#21-27) is never used and should be removed
SafeERC20.safeTransferFrom(IERC20,address,address,uint256) (../../src/node_modules/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol#29-36) is never used and should be removed
SafeMath.div(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#135-137) is never used and should be removed
SafeMath.div(uint256,uint256,string) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#191-200) is never used and should be removed
SafeMath.mod(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#151-153) is never used and should be removed
SafeMath.mod(uint256,uint256,string) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#217-226) is never used and should be removed
SafeMath.mul(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#121-123) is never used and should be removed
SafeMath.sub(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#107-109) is never used and should be removed
SafeMath.sub(uint256,uint256,string) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#168-177) is never used and should be removed
SafeMath.tryAdd(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#22-28) is never used and should be removed
SafeMath.tryDiv(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#64-69) is never used and should be removed
SafeMath.tryMod(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#76-81) is never used and should be removed
SafeMath.tryMul(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#47-57) is never used and should be removed
SafeMath.trySub(uint256,uint256) (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#35-40) is never used and should be removed
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#dead-code

Pragma version^0.8.0 (../../src/contracts/MarketPlace.sol#2) allows old versions
Pragma version^0.8.0 (../../src/contracts/imports/ERC721Holder.sol#1) allows old versions
Pragma version^0.8.0 (../../src/contracts/imports/IERC721.sol#1) allows old versions
Pragma version^0.8.0 (../../src/node_modules/@openzeppelin/contracts/access/Ownable.sol#4) allows old versions
Pragma version^0.8.0 (../../src/node_modules/@openzeppelin/contracts/security/Pausable.sol#4) allows old versions
Pragma version^0.8.0 (../../src/node_modules/@openzeppelin/contracts/token/ERC20/IERC20.sol#4) allows old versions
Pragma version^0.8.0 (../../src/node_modules/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol#4) allows old versions
Pragma version^0.8.0 (../../src/node_modules/@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol#4) allows old versions
Pragma version^0.8.1 (../../src/node_modules/@openzeppelin/contracts/utils/Address.sol#4) allows old versions
Pragma version^0.8.0 (../../src/node_modules/@openzeppelin/contracts/utils/Context.sol#4) allows old versions
Pragma version^0.8.0 (../../src/node_modules/@openzeppelin/contracts/utils/introspection/IERC165.sol#4) allows old versions
Pragma version^0.8.0 (../../src/node_modules/@openzeppelin/contracts/utils/math/SafeMath.sol#4) allows old versions
solc-0.8.9 is not recommended for deployment
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity

Reentrancy in MarketPlace._cancelBid(bytes32,address,uint256,address,uint256) (../../src/contracts/MarketPlace.sol#446-453):
        External calls:
        - _bidder.transfer(_escrowAmount) (../../src/contracts/MarketPlace.sol#449)
        Event emitted after the call(s):
        - BidCancelled(_bidId) (../../src/contracts/MarketPlace.sol#452)
Reentrancy in MarketPlace._createBid(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#391-424):
        External calls:
        - _cancelBid(bid.bidId,_tokenAddress,_tokenId,bid.bidder,bid.bidPrice) (../../src/contracts/MarketPlace.sol#408)
                - _bidder.transfer(_escrowAmount) (../../src/contracts/MarketPlace.sol#449)
        State variables written after the call(s):
        - bidByOrderId[_tokenAddress][_tokenId] = Bid(bidId,address(msg.sender),value) (../../src/contracts/MarketPlace.sol#417-422)
        Event emitted after the call(s):
        - BidCreated(bidId,_tokenAddress,_tokenId,msg.sender,value) (../../src/contracts/MarketPlace.sol#423)
Reentrancy in MarketPlace.acceptBidandExecuteOrder(address,uint256,uint256) (../../src/contracts/MarketPlace.sol#295-342):
        External calls:
        - order.seller.transfer(finalAmountAfterMarketplaceFee) (../../src/contracts/MarketPlace.sol#321)
        - firstOwnerAddress.transfer(royaltyAmount) (../../src/contracts/MarketPlace.sol#331)
        - order.seller.transfer(amountAfterRoyaltyCut) (../../src/contracts/MarketPlace.sol#333)
        - order.seller.transfer(finalAmountAfterMarketplaceFee) (../../src/contracts/MarketPlace.sol#339)
        Event emitted after the call(s):
        - OrderSuccessful(_orderId,_tokenId,_buyer,_askingPrice) (../../src/contracts/MarketPlace.sol#436)
                - _executeOrder(order.orderId,bid.bidder,_tokenAddress,_tokenId,_bidPrice) (../../src/contracts/MarketPlace.sol#341)
Reentrancy in MarketPlace.acceptDirectSellOrder(address,uint256) (../../src/contracts/MarketPlace.sol#234-291):
        External calls:
        - directorder.seller.transfer(finalAmountAfterMarketplaceFee) (../../src/contracts/MarketPlace.sol#254)
        - firstOwnerAddress.transfer(royaltyAmount) (../../src/contracts/MarketPlace.sol#269)
        - directorder.seller.transfer(amountAfterRoyaltyCut) (../../src/contracts/MarketPlace.sol#273)
        - directorder.seller.transfer(finalAmountAfterMarketplaceFee) (../../src/contracts/MarketPlace.sol#281)
        Event emitted after the call(s):
        - DirectOrderSuccessful(directorder.orderId,_tokenId,msg.sender,msg.value) (../../src/contracts/MarketPlace.sol#290)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-4

