# tests/test_block.py
import struct
import pytest
from bchoc.utils.block import Block, HEADER_SIZE, HEADER_FORMAT, ZERO32

# builds a minimally valid Block to test with 
def make_block(**overrides):
    b = Block()
    b.prev_hash = overrides.get("prev_hash", ZERO32)
    b.timestamp = overrides.get("timestamp", 0.0)
    b.case_id   = overrides.get("case_id", b"A"*32)
    b.item_id   = overrides.get("item_id", b"B"*32)
    b.state     = overrides.get("state", "INITIAL")
    b.creator   = overrides.get("creator", "system")
    b.owner     = overrides.get("owner", "owner")
    b.data      = overrides.get("data", b"")

    # normalize None here so tests don’t error
    if b.data is None:
        b.data = b""

    b.data_length = len(b.data)
    return b

# ---- MAIN FUNCTIONALITY ------ #

# makes sure a genesis status is correctly detected
def test_genesis_predicate_true():
    blk = make_block(prev_hash=ZERO32, timestamp=0.0)
    assert blk.is_genesis() is True

# makes sure a genesis status is correctly detected
def test_genesis_predicate_false():
    blk = make_block(prev_hash=b"\x01"*32, timestamp=0.0)
    assert blk.is_genesis() is False

# makes sure header checks work 
def test_pack_header_size_and_layout():
    blk = make_block()
    hdr = blk.pack_header()
    assert isinstance(hdr, (bytes, bytearray))
    assert len(hdr) == HEADER_SIZE
    # Quick sanity: struct can unpack it back to a tuple of correct length
    tup = struct.unpack(HEADER_FORMAT, hdr)
    assert len(tup) == 8  # 8 header fields

# this packs and unpacks a block
def test_pack_block_and_round_trip():
    payload = b"hello world"
    blk = make_block(data=payload)
    blob = blk.pack_block()
    assert len(blob) == HEADER_SIZE + len(payload)
    # Round trip
    blk2 = Block.unpack_block(blob)
    assert blk2.prev_hash == blk.prev_hash
    assert blk2.timestamp == blk.timestamp
    assert blk2.case_id   == blk.case_id
    assert blk2.item_id   == blk.item_id
    assert blk2.state     == "INITIAL"    # NULs stripped on unpack
    assert blk2.creator   == "system"
    assert blk2.owner     == "owner"
    assert blk2.data      == payload
    assert blk2.data_length == len(payload)

# makes sure the padding/truncation is correctly working
def test_fixed_width_string_padding_and_truncation():
    # Over-long strings should be truncated to 12 bytes; short strings padded with NULs
    long_state = "X"*50
    blk = make_block(state=long_state, creator="abc", owner="12345678901234567890")
    hdr = blk.pack_header()
    fields = struct.unpack(HEADER_FORMAT, hdr)
    state_b, creator_b, owner_b = fields[4], fields[5], fields[6]
    # All three fixed-width fields are exactly 12 bytes on disk
    assert len(state_b) == 12 and len(creator_b) == 12 and len(owner_b) == 12
    # Truncation: packed bytes should be exactly 12 and start with our text
    assert state_b.startswith(b"X"*12)
    # Padding: 'abc' becomes b'abc' + NULs
    assert creator_b[:3] == b"abc" and creator_b[3:] == b"\x00"*9

# confirms that the tuple types are in the correct order
def test_unpack_header_tuple_types_and_order():
    blk = make_block()
    hdr = blk.pack_header()
    tup = Block.unpack_header(hdr)
    # order: prev_hash, timestamp, case_id, item_id, state_b, creator_b, owner_b, dlen
    assert isinstance(tup[0], (bytes, bytearray)) and len(tup[0]) == 32
    assert isinstance(tup[1], float)
    assert isinstance(tup[2], (bytes, bytearray)) and len(tup[2]) == 32
    assert isinstance(tup[3], (bytes, bytearray)) and len(tup[3]) == 32
    assert isinstance(tup[4], (bytes, bytearray)) and len(tup[4]) == 12
    assert isinstance(tup[5], (bytes, bytearray)) and len(tup[5]) == 12
    assert isinstance(tup[6], (bytes, bytearray)) and len(tup[6]) == 12
    assert isinstance(tup[7], int)

# makes sure data length == data_length check works
def test_unpack_block_raises_on_truncated_payload():
    blk = make_block(data=b"abcdef")
    blob = blk.pack_block()
    bad = blob[:-2]
    with pytest.raises(ValueError, match="data .* data_length"):
        Block.unpack_block(bad)

# rejects inputs that are shorter than the header size
def test_unpack_block_raises_on_short_header():
    with pytest.raises(ValueError, match="shorter than header"):
        Block.unpack_block(b"too short")


# ---- EDGE CASES ------ #

# -----  wrong sizes should fail  ----
def test_invalid_prev_hash_size_raises():
    blk = make_block(prev_hash=b"\x00"*31)
    with pytest.raises(ValueError, match="prev_hash"):
        blk.pack_header()

def test_invalid_case_id_size_raises():
    blk = make_block(case_id=b"C"*31)
    with pytest.raises(ValueError, match="case_id"):
        blk.pack_header()

def test_invalid_item_id_size_raises():
    blk = make_block(item_id=b"I"*33)
    with pytest.raises(ValueError, match="item_id"):
        blk.pack_header()
# ----------------------------------------

# None should be treated like an empty payload
def test_none_data_treated_as_zero_length():
    blk = make_block(data=None)
    blob = blk.pack_block()
    assert len(blob) == HEADER_SIZE  # no payload
    # round trip
    blk2 = Block.unpack_block(blob)
    assert blk2.data == b""
    assert blk2.data_length == 0

# unpack should consume one block and ignore trailing bytes
def test_trailing_bytes_are_ignored_by_unpack_block():
    payload = b"xyz"
    blk = make_block(data=payload)
    blob = blk.pack_block()
    extra = blob + b"TRAILING"
    b2 = Block.unpack_block(extra)
    assert b2.data == payload
    assert len(extra) > HEADER_SIZE + len(payload)  # ensure we actually had extra

# make sure the data_length is actually calculated
def test_header_recomputes_data_length_not_stored_field():
    blk = make_block(data=b"abc")
    blk.data_length = 999999  # lie on purpose
    blob = blk.pack_block()
    # data_length in the packed header must be 3, not 999999
    dlen = struct.unpack(HEADER_FORMAT, blob[:HEADER_SIZE])[7]
    assert dlen == 3

# make sure pack->unpack->pack->unpack gives the same values
def test_double_round_trip_idempotent():
    blk = make_block(data=b"roundtrip")
    blob1 = blk.pack_block()
    b2 = Block.unpack_block(blob1)
    blob2 = b2.pack_block()
    b3 = Block.unpack_block(blob2)
    assert b3.prev_hash == blk.prev_hash
    assert b3.case_id   == blk.case_id
    assert b3.item_id   == blk.item_id
    assert b3.state     == blk.state
    assert b3.creator   == blk.creator
    assert b3.owner     == blk.owner
    assert b3.data      == blk.data
