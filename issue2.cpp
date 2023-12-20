// UNREACHABLE at /__w/zkLLVM/zkLLVM/libs/assigner/include/nil/blueprint/parser.hpp:1282
// Unsupported opcode type : freeze

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <cstdint>

using namespace nil::crypto3;

using hash_type = hashes::sha2<256>;
using block_type = hash_type::block_type;

constexpr std::size_t BEACON_STATE_FIELD_INCLUSION_PROOF_LENGTH = 5;
constexpr std::size_t VALIDATORS_FIELD_INDEX = 11;
constexpr std::size_t BEACON_BLOCK_FIELDS_COUNT = 5;

template <size_t ProofSize>
block_type verify_inclusion_proof(size_t field_index, block_type field_hash, block_type merkle_root, std::array<block_type, ProofSize> inclusion_proof)
{
  size_t cur_index = field_index;
  block_type current_hash = field_hash;
  block_type return_block = field_hash;

  for (int i = 0; i < inclusion_proof.size(); i++)
  {
    block_type inclusion_step = inclusion_proof[i];

    if (cur_index % 2 == 0)
    {
      current_hash = hash<hash_type>(current_hash, inclusion_step);
    }
    else
    {
      current_hash = hash<hash_type>(inclusion_step, current_hash);
    }
    cur_index = cur_index / 2;
  }
  return current_hash; // is_same(current_hash, merkle_root);
}

[[circuit]] block_type circuit(
    block_type expected_validators_hash,
    block_type beacon_state_hash,
    [[private]] std::array<block_type, BEACON_STATE_FIELD_INCLUSION_PROOF_LENGTH> validators_hash_inclusion_proof)
{

  return verify_inclusion_proof(VALIDATORS_FIELD_INDEX, expected_validators_hash, beacon_state_hash, validators_hash_inclusion_proof);
}