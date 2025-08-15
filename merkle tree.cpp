#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define SM3_HASH_SIZE 32
#define MAX_LEAVES 100000 

void sm3(const uint8_t* message, size_t message_len, uint8_t output[SM3_HASH_SIZE]);

typedef struct MerkleNode {
    uint8_t hash[SM3_HASH_SIZE];
    struct MerkleNode* left;
    struct MerkleNode* right;
} MerkleNode;

MerkleNode* create_leaf(const uint8_t* data) {
    MerkleNode* leaf = (MerkleNode*)malloc(sizeof(MerkleNode));
    sm3(data, strlen((const char*)data), leaf->hash);
    leaf->left = leaf->right = NULL;
    return leaf;
}

MerkleNode* create_node(MerkleNode* left, MerkleNode* right) {
    MerkleNode* node = (MerkleNode*)malloc(sizeof(MerkleNode));
    uint8_t combined[2 * SM3_HASH_SIZE];
    memcpy(combined, left->hash, SM3_HASH_SIZE);
    memcpy(combined + SM3_HASH_SIZE, right->hash, SM3_HASH_SIZE);
    sm3(combined, sizeof(combined), node->hash);
    node->left = left;
    node->right = right;
    return node;
}

MerkleNode* build_merkle_tree(uint8_t leaves[MAX_LEAVES][SM3_HASH_SIZE], size_t leaf_count) {
    MerkleNode** nodes = (MerkleNode**)malloc(leaf_count * sizeof(MerkleNode*));
    for (size_t i = 0; i < leaf_count; i++) {
        nodes[i] = create_leaf(leaves[i]);
    }

    size_t current_count = leaf_count;
    while (current_count > 1) {
        size_t new_count = (current_count + 1) / 2;
        for (size_t i = 0; i < current_count / 2; i++) {
            nodes[i] = create_node(nodes[2 * i], nodes[2 * i + 1]);
        }
        if (current_count % 2 == 1) {
            nodes[new_count - 1] = nodes[current_count - 1]; 
            new_count++; // 增加一个节点
        }
        current_count = new_count;
    }

    MerkleNode* root = nodes[0];
    free(nodes);
    return root;
}

void generate_existence_proof(MerkleNode* root, uint8_t leaves[MAX_LEAVES][SM3_HASH_SIZE], size_t leaf_count, size_t leaf_index, uint8_t proofs[MAX_LEAVES][SM3_HASH_SIZE], size_t* proof_count) {
    MerkleNode* node = root;
    size_t index = leaf_index;
    *proof_count = 0;

    while (node->left != NULL && node->right != NULL) {
        if (index % 2 == 0) { 
            memcpy(proofs[*proof_count], node->right->hash, SM3_HASH_SIZE);
        }
        else { 
            memcpy(proofs[*proof_count], node->left->hash, SM3_HASH_SIZE);
        }
        (*proof_count)++;
        index /= 2; 
        node = (index % 2 == 0) ? node->left : node->right;
    }
}

void generate_nonexistence_proof(MerkleNode* root, size_t leaf_count, size_t leaf_index, uint8_t proofs[MAX_LEAVES][SM3_HASH_SIZE], size_t* proof_count) {
    *proof_count = 1;
    memcpy(proofs[0], root->hash, SM3_HASH_SIZE);
}

void free_merkle_tree(MerkleNode* node) {
    if (node) {
        free_merkle_tree(node->left);
        free_merkle_tree(node->right);
        free(node);
    }
}

int main() {
    uint8_t leaves[MAX_LEAVES][SM3_HASH_SIZE];
    for (size_t i = 0; i < MAX_LEAVES; i++) {
        snprintf((char*)leaves[i], SM3_HASH_SIZE, "Leaf %zu", i);
    }

    MerkleNode* root = build_merkle_tree(leaves, MAX_LEAVES);

    size_t leaf_index = 12345; 
    uint8_t existence_proofs[MAX_LEAVES][SM3_HASH_SIZE];
    size_t proof_count;
    generate_existence_proof(root, leaves, MAX_LEAVES, leaf_index, existence_proofs, &proof_count);

    printf("Existence Proof for leaf %zu:\\n", leaf_index);
    for (size_t i = 0; i < proof_count; i++) {
        printf("Proof Hash %zu: ", i);
        for (int j = 0; j < SM3_HASH_SIZE; j++) {
            printf("%02x", existence_proofs[i][j]);
        }
        printf("\\n");
    }

    uint8_t nonexistence_proofs[MAX_LEAVES][SM3_HASH_SIZE];
    generate_nonexistence_proof(root, MAX_LEAVES, leaf_index, nonexistence_proofs, &proof_count);

    printf("Non-existence Proof for leaf %zu:\\n", leaf_index);
    for (size_t i = 0; i < proof_count; i++) {
        printf("Root Hash: ");
        for (int j = 0; j < SM3_HASH_SIZE; j++) {
            printf("%02x", nonexistence_proofs[i][j]);
        }
        printf("\\n");
    }

    free_merkle_tree(root);
    return 0;
}
