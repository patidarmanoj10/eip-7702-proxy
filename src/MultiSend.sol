pragma solidity ^0.8.23;

contract MultiSend {
    event Executed(address indexed to, uint256 value, bytes data);

    bool public flag;
    uint256 public counter; 

    struct Call {
        bytes data;
        address to;
        uint256 value;
    }

    function setFlag(bool _flag) external {
        flag = _flag;
    }

    function setCounter(uint256 _counter) external {
        counter = _counter;
    }

    function execute(Call[] memory calls) external payable {
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];
            (bool success, bytes memory result) = call.to.call{
                value: call.value
            }(call.data);
            require(success, string(result));
            emit Executed(call.to, call.value, call.data);
        }
    }

    receive() external payable {}
}
