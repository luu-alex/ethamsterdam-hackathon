// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.1;

import "./Enum.sol";

interface GnosisSafe {
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, Enum.Operation operation)
        external
        returns (bool success);
}

contract safeModule {
    // Safe -> delegates - keeps track of the delegates within the safe  
    mapping(address => Delegate) public delegates;
    // when the safe triggers the deadman switch, transfer tokens over to new recipient safe
    GnosisSafe safe;
    address safeAddress;
    address payable public beneficiary;
    address public creator;
    uint public timeToDie; // how many seconds pass by before funds transfer to beneficiary
    uint public lastTransactionTime; // how long ago was the last transaction
    
    constructor(address currentSafe, uint dieTime, address payable newSafe) {
        // add the safe address as the owner
        safeAddress = currentSafe;
        safe = GnosisSafe(currentSafe);
        timeToDie = dieTime;
        creator = msg.sender;
        beneficiary = newSafe;
    }

    struct Delegate {
        address delegate;
        bool voted;
    }

    struct VotingRule {
        uint8 signersRequired;
        uint8 numberOfSigned;
        uint8 numberOfSigners;
    }
    // mapping for voting in safes
    VotingRule public safeVoting;


    event Vote();
    event AddDelegate(address indexed safe, address delegate);
    event UpdateBeneficiary(address indexed safe, address beneficiary);
    event ExecuteTransferSafe(address indexed safe, address beneficiary, uint96 amount);
    
    function safeCheck(address addy) private view{
        require(creator == addy, "must be an owner");
    }
    
    function transferSafe (uint96 amount) public {
        safeCheck(msg.sender);
            // drain funds into new safe 
            // its now someone elses problem
        executeTransferSafe(beneficiary, amount);
        emit ExecuteTransferSafe(safeAddress, beneficiary, amount);
    }
    // vote for transferring safe
    function vote(address delegate, bytes memory signature) public view {
        // this now requires verifying that delegate exists and sender is from safe
        safeCheck(msg.sender);
        Delegate memory delegateAddress = delegates[delegate];
        require(delegateAddress.delegate != delegate, 'error');

        checkSignature(delegate, signature);


    }

    function getTimeToDie() public view returns (uint) {
        return timeToDie;
    }

    function getLastTransactionTime() public view returns (uint) {
        return lastTransactionTime;
    }

    function checkSignature(address expectedDelegate, bytes memory signature) private view {
        address signer = recoverSignature(signature);
        require(signer == expectedDelegate);
    }

    function recoverSignature(bytes memory signature) private view returns (address owner) {
        // If there is no signature data msg.sender should be used
        if (signature.length == 0) return msg.sender;
        // Check that the provided signature data is as long as 1 encoded ecsda signature
        require(signature.length == 65, "signatures.length == 65");
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = signatureSplit(signature, 0);
        // If v is 0 then it is a contract signature
        if (v == 0) {
            revert("Contract signatures are not supported by this module");
        } else if (v == 1) {
            // If v is 1 we also use msg.sender, this is so that we are compatible to the GnosisSafe signature scheme
            owner = msg.sender;
        }
        // 0 for the recovered owner indicates that an error happened.
        require(owner != address(0), "owner != address(0)");
    }
    // update the beneficiary of the safe
    function updateBeneficiary (address payable newBeneficiary) public {

        require(newBeneficiary != address(0), "address cannot be 0");
        beneficiary = newBeneficiary;
        emit UpdateBeneficiary(msg.sender, newBeneficiary);
    }
    // add delegate to delegates
    // delegates can only be accessed by safe
    function addDelegate(address delegate) public {
        require(delegate != address(0), "address cannot be 0");
        address currentDelegate = delegates[delegate].delegate;
        if(currentDelegate == delegate) {
            // We have a collision for the indices of delegates
            require(currentDelegate == delegate, "currentDelegate == delegate");
            // Delegate already exists, nothing to do
            return;
        }
        delegates[delegate] = Delegate(delegate, false);
        safeVoting.numberOfSigners++;
        emit AddDelegate(msg.sender, delegate);
    }

    function updateLastTransactionTime() public {
        lastTransactionTime = block.timestamp;
    }

    function executeTransferSafe(address payable to, uint96 amount) public {
        // require(creator == msg.sender, "not the same people");
        safe.execTransactionFromModule(to, amount, "", Enum.Operation.Call);
    }

        function signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            // Here we are loading the last 32 bytes, including 31 bytes
            // of 's'. There is no 'mload8' to do this.
            //
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
        }
    }
}