// in the hash lines use empty_block instead of inclusion_step and current_hash - no problems

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

    typename hashes::sha2<256>::block_type empty_block = {0, 0};

    block_type first;
    block_type second;

    size_t modulo = cur_index % 2;

    first = inclusion_step;

    if (cur_index % 2 == 0)
    {
      current_hash = hash<hash_type>(empty_block, empty_block);
    }
    else
    {
      current_hash = hash<hash_type>(empty_block, empty_block);
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