// These contracts ensure that setUp hooks work as expected.
contract TestContract {
    bool public state = false;

    function setUp() public {
        state = true;
    }

    function one() public {
        assert(state);
    }

    function two() public {
        assert(state);
    }

    function three() public {
        assert(state);
    }
}

contract TestContract2 {
    uint256 public num = 0;

    function setUp() public {
        num = 3;
    }

    function fuzz_one() public returns (bool) {
        return num == 3;
    }

    function fuzz_two() public returns (bool) {
        return num == 3;
    }

    function fuzz_three() public returns (bool) {
        return num == 3;
    }
}
