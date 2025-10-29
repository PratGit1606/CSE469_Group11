# tests/test_blockchain.py
import pytest
from unittest.mock import Mock, patch, mock_open, MagicMock
from bchoc.chain.blockchain import (
    add_block,
    verify_chain,
    blocks_by_item,
    blocks_by_case,
    blocks_by_history,
    _iterate_raw_blocks,
    _filter_blocks
)
from bchoc.utils.block import Block, ZERO32


# ========== FIXTURES ========== #

@pytest.fixture
def mock_genesis_block():
    block = Block()
    block.prev_hash = ZERO32
    block.timestamp = 0.0
    block.case_id = b"0" * 32
    block.item_id = b"0" * 32
    block.state = "INITIAL"
    block.creator = ""
    block.owner = ""
    block.data_length = 14
    block.data = b"Initial block\0"
    return block


@pytest.fixture
def mock_regular_block():
    block = Block()
    block.prev_hash = b"A" * 32
    block.timestamp = 123456789.0
    block.case_id = b"C" * 32
    block.item_id = b"I" * 32
    block.state = "CHECKEDIN"
    block.creator = "creator1"
    block.owner = "owner1"
    block.data_length = 0
    block.data = b""
    return block


@pytest.fixture
def sample_block_bytes():
    return b"X" * 144  


# ========== add_block TESTS ========== #

@patch('bchoc.chain.blockchain.persistence.resolve_path', create=True)
@patch('bchoc.chain.blockchain.persistence.open_chain', create=True)
@patch('bchoc.chain.blockchain.persistence.append_block', create=True)
def test_add_block_success(mock_append, mock_open, mock_resolve, sample_block_bytes):
    mock_resolve.return_value = "/path/to/blockchain"
    mock_file = MagicMock()
    mock_open.return_value.__enter__.return_value = mock_file
    
    result = add_block(sample_block_bytes)
    
    assert result is True
    mock_resolve.assert_called_once()
    mock_open.assert_called_once_with("/path/to/blockchain", mode="ab")
    mock_append.assert_called_once_with(mock_file, sample_block_bytes)


@patch('bchoc.chain.blockchain.persistence.resolve_path', create=True)
@patch('bchoc.chain.blockchain.persistence.open_chain', create=True)
def test_add_block_failure(mock_open, mock_resolve, sample_block_bytes):
    mock_resolve.return_value = "/path/to/blockchain"
    mock_open.side_effect = IOError("File error")
    
    result = add_block(sample_block_bytes)
    
    assert result is False


# ========== verify_chain TESTS ========== #

@patch('bchoc.chain.blockchain._iterate_raw_blocks')
def test_verify_chain_no_blocks(mock_iterate):
    """Test verify_chain with no blocks"""
    mock_iterate.return_value = iter([])
    
    result = verify_chain()
    
    assert result["count"] == 0
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "NO_BLOCKS"


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
def test_verify_chain_invalid_genesis(mock_unpack, mock_iterate):
    # Create a non-genesis block as first block
    bad_genesis = Mock()
    bad_genesis.is_genesis.return_value = False
    bad_genesis.prev_hash = b"\x01" * 32
    
    mock_block_bytes = b"X" * 144
    mock_iterate.return_value = iter([mock_block_bytes])
    mock_unpack.return_value = bad_genesis
    
    result = verify_chain()
    
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "INVALID_GENESIS"
    assert result["bad_block_index"] == 0


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
@patch('bchoc.chain.blockchain.cryptography.compute_block_hash', create=True)
def test_verify_chain_hash_mismatch(mock_hash, mock_unpack, mock_iterate):
    # Genesis block
    genesis = Mock()
    genesis.is_genesis.return_value = True
    genesis.prev_hash = ZERO32
    
    # Second block with wrong prev_hash
    block2 = Mock()
    block2.is_genesis.return_value = False
    block2.prev_hash = b"WRONG" + b"\x00" * 27
    block2.item_id = b"item1" + b"\x00" * 27
    block2.state = "CHECKEDIN"
    
    mock_blocks = [b"genesis_bytes", b"block2_bytes"]
    mock_iterate.return_value = iter(mock_blocks)
    mock_unpack.side_effect = [genesis, block2]
    
    # Mock hash computation
    expected_hash = b"CORRECT" + b"\x00" * 25
    mock_hash.return_value = expected_hash
    
    result = verify_chain()
    
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "HASH_MISMATCH"
    assert result["bad_block_index"] == 1
    assert result["expected_prev_hash"] == expected_hash.hex()


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
@patch('bchoc.chain.blockchain.cryptography.compute_block_hash', create=True)
def test_verify_chain_duplicate_parent(mock_hash, mock_unpack, mock_iterate):
    genesis = Mock()
    genesis.is_genesis.return_value = True
    genesis.item_id = b"genesis" + b"\x00" * 25
    genesis.state = "INITIAL"
    
    parent_hash = b"parent" + b"\x00" * 26
    
    block1 = Mock()
    block1.is_genesis.return_value = False
    block1.prev_hash = parent_hash
    block1.item_id = b"item1" + b"\x00" * 27
    block1.state = "CHECKEDIN"
    
    block2 = Mock()
    block2.is_genesis.return_value = False
    block2.prev_hash = parent_hash  # Same parent!
    block2.item_id = b"item2" + b"\x00" * 27
    block2.state = "CHECKEDIN"
    
    mock_blocks = [b"gen", b"b1", b"b2"]
    mock_iterate.return_value = iter(mock_blocks)
    mock_unpack.side_effect = [genesis, block1, block2]
    mock_hash.return_value = parent_hash
    
    result = verify_chain()
    
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "DUPLICATE_PARENT"
    assert result["bad_block_index"] == 2


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
@patch('bchoc.chain.blockchain.cryptography.compute_block_hash', create=True)
def test_verify_chain_duplicate_item(mock_hash, mock_unpack, mock_iterate):
    genesis = Mock()
    genesis.is_genesis.return_value = True
    genesis.item_id = b"genesis" + b"\x00" * 25
    genesis.state = "INITIAL"
    
    same_item_id = b"item1" + b"\x00" * 27
    
    block1 = Mock()
    block1.is_genesis.return_value = False
    block1.prev_hash = b"hash1" + b"\x00" * 27
    block1.item_id = same_item_id
    block1.state = "CHECKEDIN"
    
    block2 = Mock()
    block2.is_genesis.return_value = False
    block2.prev_hash = b"hash2" + b"\x00" * 27
    block2.item_id = same_item_id  # Same item checked in again without checkout
    block2.state = "CHECKEDIN"
    
    mock_blocks = [b"gen", b"b1", b"b2"]
    mock_iterate.return_value = iter(mock_blocks)
    mock_unpack.side_effect = [genesis, block1, block2, genesis, block1, block2]
    
    # Mock different hashes for each block
    mock_hash.side_effect = [b"hash1" + b"\x00" * 27, b"hash2" + b"\x00" * 27]
    
    result = verify_chain()
    
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "DUPLICATE_ITEM"
    assert result["bad_block_index"] == 2


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
@patch('bchoc.chain.blockchain.cryptography.compute_block_hash', create=True)
def test_verify_chain_action_after_removal(mock_hash, mock_unpack, mock_iterate):
    genesis = Mock()
    genesis.is_genesis.return_value = True
    genesis.item_id = b"genesis" + b"\x00" * 25
    genesis.state = "INITIAL"
    
    item_id = b"item1" + b"\x00" * 27
    
    # First, item must be checked in
    block1 = Mock()
    block1.is_genesis.return_value = False
    block1.prev_hash = b"hash1" + b"\x00" * 27
    block1.item_id = item_id
    block1.state = "CHECKEDIN"
    
    # Then item is disposed
    block2 = Mock()
    block2.is_genesis.return_value = False
    block2.prev_hash = b"hash2" + b"\x00" * 27
    block2.item_id = item_id
    block2.state = "DISPOSED"
    
    # Then someone tries to check it out (action after removal!)
    block3 = Mock()
    block3.is_genesis.return_value = False
    block3.prev_hash = b"hash3" + b"\x00" * 27
    block3.item_id = item_id
    block3.state = "CHECKEDOUT"  # Action after disposal!
    
    mock_blocks = [b"gen", b"b1", b"b2", b"b3"]
    mock_iterate.return_value = iter(mock_blocks)
    mock_unpack.side_effect = [
        genesis, block1, block2, block3,  # First 4 calls
        genesis, block1, block2, block3   # Next 4 calls
    ]
    mock_hash.side_effect = [
        b"hash1" + b"\x00" * 27,
        b"hash2" + b"\x00" * 27,
        b"hash3" + b"\x00" * 27
    ]
    
    result = verify_chain()
    
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "ACTION_AFTER_REMOVAL"


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
@patch('bchoc.chain.blockchain.cryptography.compute_block_hash', create=True)
def test_verify_chain_double_checkout(mock_hash, mock_unpack, mock_iterate):
    genesis = Mock()
    genesis.is_genesis.return_value = True
    genesis.item_id = b"genesis" + b"\x00" * 25
    genesis.state = "INITIAL"
    
    item_id = b"item1" + b"\x00" * 27
    
    block1 = Mock()
    block1.is_genesis.return_value = False
    block1.prev_hash = b"hash1" + b"\x00" * 27
    block1.item_id = item_id
    block1.state = "CHECKEDOUT"
    
    block2 = Mock()
    block2.is_genesis.return_value = False
    block2.prev_hash = b"hash2" + b"\x00" * 27
    block2.item_id = item_id
    block2.state = "CHECKEDOUT"  # Double checkout!
    
    mock_blocks = [b"gen", b"b1", b"b2"]
    mock_iterate.return_value = iter(mock_blocks)
    mock_unpack.side_effect = [genesis, block1, block2, genesis, block1, block2]
    mock_hash.side_effect = [b"hash1" + b"\x00" * 27, b"hash2" + b"\x00" * 27]
    
    result = verify_chain()
    
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "DOUBLE_CHECKOUT"


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
@patch('bchoc.chain.blockchain.cryptography.compute_block_hash', create=True)
def test_verify_chain_double_remove(mock_hash, mock_unpack, mock_iterate):
    genesis = Mock()
    genesis.is_genesis.return_value = True
    genesis.item_id = b"genesis" + b"\x00" * 25
    genesis.state = "INITIAL"
    
    item_id = b"item1" + b"\x00" * 27
    
    block1 = Mock()
    block1.is_genesis.return_value = False
    block1.prev_hash = b"hash1" + b"\x00" * 27
    block1.item_id = item_id
    block1.state = "DISPOSED"
    
    block2 = Mock()
    block2.is_genesis.return_value = False
    block2.prev_hash = b"hash2" + b"\x00" * 27
    block2.item_id = item_id
    block2.state = "DESTROYED" 
    mock_blocks = [b"gen", b"b1", b"b2"]
    mock_iterate.return_value = iter(mock_blocks)

    mock_unpack.side_effect = [genesis, block1, block2, genesis, block1, block2]
    mock_hash.side_effect = [b"hash1" + b"\x00" * 27, b"hash2" + b"\x00" * 27]
    
    result = verify_chain()
    
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "DOUBLE_REMOVE"


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
@patch('bchoc.chain.blockchain.cryptography.compute_block_hash', create=True)
def test_verify_chain_clean(mock_hash, mock_unpack, mock_iterate):
    genesis = Mock()
    genesis.is_genesis.return_value = True
    genesis.item_id = b"genesis" + b"\x00" * 25
    genesis.state = "INITIAL"
    
    item_id = b"item1" + b"\x00" * 27
    
    block1 = Mock()
    block1.is_genesis.return_value = False
    block1.prev_hash = b"hash0" + b"\x00" * 27
    block1.item_id = item_id
    block1.state = "CHECKEDIN"
    
    block2 = Mock()
    block2.is_genesis.return_value = False
    block2.prev_hash = b"hash1" + b"\x00" * 27
    block2.item_id = item_id
    block2.state = "CHECKEDOUT"
    
    mock_blocks = [b"gen", b"b1", b"b2"]
    mock_iterate.return_value = iter(mock_blocks)

    mock_unpack.side_effect = [genesis, block1, block2, genesis, block1, block2]
    mock_hash.side_effect = [b"hash0" + b"\x00" * 27, b"hash1" + b"\x00" * 27]
    
    result = verify_chain()
    
    assert result["state"] == "CLEAN"
    assert result["count"] == 3
    assert result["error_kind"] is None


# ========== blocks_by_item TESTS ========== #

@patch('bchoc.chain.blockchain._filter_blocks')
def test_blocks_by_item(mock_filter):
    item_id = b"item123" + b"\x00" * 25
    expected_blocks = [b"block1", b"block2"]
    mock_filter.return_value = expected_blocks
    
    result = blocks_by_item(item_id)
    
    assert result == expected_blocks
    mock_filter.assert_called_once_with(
        case_id=None,
        item_id=item_id,
        limit=None,
        reverse=False
    )


# ========== blocks_by_case TESTS ========== #

@patch('bchoc.chain.blockchain._filter_blocks')
def test_blocks_by_case(mock_filter):
    case_id = b"case456" + b"\x00" * 25
    expected_blocks = [b"block1", b"block2", b"block3"]
    mock_filter.return_value = expected_blocks
    
    result = blocks_by_case(case_id)
    
    assert result == expected_blocks
    mock_filter.assert_called_once_with(
        case_id=case_id,
        item_id=None,
        limit=None,
        reverse=False
    )


# ========== blocks_by_history TESTS ========== #

@patch('bchoc.chain.blockchain._filter_blocks')
def test_blocks_by_history_all_params(mock_filter):
    case_id = b"case1" + b"\x00" * 27
    item_id = b"item1" + b"\x00" * 27
    expected_blocks = [b"block1", b"block2"]
    mock_filter.return_value = expected_blocks
    
    result = blocks_by_history(case_id, item_id, 5, True)
    
    assert result == expected_blocks
    mock_filter.assert_called_once_with(
        case_id=case_id,
        item_id=item_id,
        limit=5,
        reverse=True
    )


@patch('bchoc.chain.blockchain._filter_blocks')
def test_blocks_by_history_minimal(mock_filter):
    expected_blocks = [b"block1"]
    mock_filter.return_value = expected_blocks
    
    result = blocks_by_history(None, None, None, False)
    
    assert result == expected_blocks
    mock_filter.assert_called_once_with(
        case_id=None,
        item_id=None,
        limit=None,
        reverse=False
    )


# ========== _filter_blocks TESTS ========== #

@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
def test_filter_blocks_by_case_id(mock_unpack, mock_iterate):
    target_case = b"case1" + b"\x00" * 27
    other_case = b"case2" + b"\x00" * 27
    
    block1 = Mock()
    block1.case_id = target_case
    block1.item_id = b"item1" + b"\x00" * 27
    
    block2 = Mock()
    block2.case_id = other_case
    block2.item_id = b"item2" + b"\x00" * 27
    
    block3 = Mock()
    block3.case_id = target_case
    block3.item_id = b"item3" + b"\x00" * 27
    
    raw_blocks = [b"raw1", b"raw2", b"raw3"]
    mock_iterate.return_value = iter(raw_blocks)
    mock_unpack.side_effect = [block1, block2, block3]
    
    result = _filter_blocks(case_id=target_case, item_id=None, limit=None, reverse=False)
    
    assert result == [b"raw1", b"raw3"]
    assert len(result) == 2


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
def test_filter_blocks_by_item_id(mock_unpack, mock_iterate):
    target_item = b"item1" + b"\x00" * 27
    
    block1 = Mock()
    block1.case_id = b"case1" + b"\x00" * 27
    block1.item_id = target_item
    
    block2 = Mock()
    block2.case_id = b"case1" + b"\x00" * 27
    block2.item_id = b"item2" + b"\x00" * 27
    
    raw_blocks = [b"raw1", b"raw2"]
    mock_iterate.return_value = iter(raw_blocks)
    mock_unpack.side_effect = [block1, block2]
    
    result = _filter_blocks(case_id=None, item_id=target_item, limit=None, reverse=False)
    
    assert result == [b"raw1"]


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
def test_filter_blocks_with_limit(mock_unpack, mock_iterate):
    blocks = [Mock() for _ in range(5)]
    for i, block in enumerate(blocks):
        block.case_id = b"case1" + b"\x00" * 27
        block.item_id = f"item{i}".encode() + b"\x00" * 27
    
    raw_blocks = [f"raw{i}".encode() for i in range(5)]
    mock_iterate.return_value = iter(raw_blocks)
    mock_unpack.side_effect = blocks
    
    result = _filter_blocks(case_id=b"case1" + b"\x00" * 27, item_id=None, limit=3, reverse=False)
    
    assert len(result) == 3


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
def test_filter_blocks_with_reverse(mock_unpack, mock_iterate):
    blocks = [Mock() for _ in range(3)]
    for i, block in enumerate(blocks):
        block.case_id = b"case1" + b"\x00" * 27
        block.item_id = b"item1" + b"\x00" * 27
    
    raw_blocks = [b"raw0", b"raw1", b"raw2"]
    mock_iterate.return_value = iter(raw_blocks)
    mock_unpack.side_effect = blocks
    
    result = _filter_blocks(case_id=None, item_id=None, limit=None, reverse=True)
    
    assert result == [b"raw2", b"raw1", b"raw0"]


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
def test_filter_blocks_no_matches(mock_unpack, mock_iterate):
    block = Mock()
    block.case_id = b"case1" + b"\x00" * 27
    block.item_id = b"item1" + b"\x00" * 27
    
    mock_iterate.return_value = iter([b"raw1"])
    mock_unpack.return_value = block
    
    result = _filter_blocks(case_id=b"case2" + b"\x00" * 27, item_id=None, limit=None, reverse=False)
    
    assert result == []


# ========== _iterate_raw_blocks TESTS ========== #

@patch('bchoc.chain.blockchain.persistence.resolve_path', create=True)
@patch('bchoc.chain.blockchain.persistence.file_exists', create=True)
def test_iterate_raw_blocks_no_file(mock_exists, mock_resolve):
    mock_resolve.return_value = "/path/to/chain"
    mock_exists.return_value = False
    
    result = list(_iterate_raw_blocks())
    
    assert result == []


@patch('bchoc.chain.blockchain.persistence.resolve_path', create=True)
@patch('bchoc.chain.blockchain.persistence.file_exists', create=True)
@patch('bchoc.chain.blockchain.persistence.open_chain', create=True)
@patch('bchoc.chain.blockchain.persistence.read_blocks', create=True)
def test_iterate_raw_blocks_success(mock_read, mock_open, mock_exists, mock_resolve):
    mock_resolve.return_value = "/path/to/chain"
    mock_exists.return_value = True
    mock_file = MagicMock()
    mock_open.return_value.__enter__.return_value = mock_file
    
    mock_read.return_value = iter([
        (0, b"block1"),
        (144, b"block2"),
        (288, b"block3")
    ])
    
    result = list(_iterate_raw_blocks())
    
    assert result == [b"block1", b"block2", b"block3"]
    mock_open.assert_called_once_with("/path/to/chain", mode="rb")


# ========== EDGE CASES ========== #

@patch('bchoc.chain.blockchain._iterate_raw_blocks')
@patch('bchoc.chain.blockchain.Block.unpack_block')
@patch('bchoc.chain.blockchain.cryptography.compute_block_hash', create=True)
def test_verify_chain_checkin_after_checkout_valid(mock_hash, mock_unpack, mock_iterate):
    genesis = Mock()
    genesis.is_genesis.return_value = True
    genesis.item_id = b"genesis" + b"\x00" * 25
    genesis.state = "INITIAL"
    
    item_id = b"item1" + b"\x00" * 27
    
    block1 = Mock()
    block1.is_genesis.return_value = False
    block1.prev_hash = b"hash0" + b"\x00" * 27
    block1.item_id = item_id
    block1.state = "CHECKEDIN"
    
    block2 = Mock()
    block2.is_genesis.return_value = False
    block2.prev_hash = b"hash1" + b"\x00" * 27
    block2.item_id = item_id
    block2.state = "CHECKEDOUT"
    
    block3 = Mock()
    block3.is_genesis.return_value = False
    block3.prev_hash = b"hash2" + b"\x00" * 27
    block3.item_id = item_id
    block3.state = "CHECKEDIN"  # Valid: checkin after checkout
    
    mock_blocks = [b"gen", b"b1", b"b2", b"b3"]
    mock_iterate.return_value = iter(mock_blocks)

    mock_unpack.side_effect = [
        genesis, block1, block2, block3,  
        genesis, block1, block2, block3 
    ]
    mock_hash.side_effect = [
        b"hash0" + b"\x00" * 27,
        b"hash1" + b"\x00" * 27,
        b"hash2" + b"\x00" * 27
    ]
    
    result = verify_chain()
    
    assert result["state"] == "CLEAN"


@patch('bchoc.chain.blockchain._iterate_raw_blocks')
def test_verify_chain_handles_exception(mock_iterate):
    mock_iterate.side_effect = Exception("Unexpected error")
    
    result = verify_chain()
    
    assert result["state"] == "ERROR"
    assert result["error_kind"] == "EXCEPTION"
    assert "Unexpected error" in result["exception"]