const { buildPoseidon } = require("circomlibjs");

class MerkleTree {
    constructor(levels, poseidon) {
        this.levels = levels;
        this.poseidon = poseidon;
        this.F = poseidon.F;
        this.totalLeaves = 2 ** levels;
        this.zeroValue = BigInt(0);

        // Precompute zero hashes for each level
        this.zeros = new Array(levels + 1);
        this.zeros[0] = this.zeroValue;
        for (let i = 1; i <= levels; i++) {
            this.zeros[i] = this.hash(this.zeros[i - 1], this.zeros[i - 1]);
        }

        this.leaves = [];
    }

    static async create(levels) {
        const poseidon = await buildPoseidon();
        return new MerkleTree(levels, poseidon);
    }

    hash(left, right) {
        const h = this.poseidon([left, right]);
        return BigInt(this.F.toString(h));
    }

    insert(leaf) {
        if (this.leaves.length >= this.totalLeaves) {
            throw new Error("Merkle tree is full");
        }
        this.leaves.push(BigInt(leaf));
        return this.leaves.length - 1;
    }

    getRoot() {
        let currentLevel = [...this.leaves];
        // Pad to next power of 2 at the bottom level if needed
        while (currentLevel.length < this.totalLeaves) {
            currentLevel.push(this.zeros[0]);
        }

        for (let level = 0; level < this.levels; level++) {
            const nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                nextLevel.push(this.hash(currentLevel[i], currentLevel[i + 1]));
            }
            currentLevel = nextLevel;
        }

        return currentLevel[0];
    }

    getProof(index) {
        if (index < 0 || index >= this.leaves.length) {
            throw new Error("Leaf index out of bounds");
        }

        const pathElements = [];
        const pathIndices = [];

        let currentLevel = [...this.leaves];
        while (currentLevel.length < this.totalLeaves) {
            currentLevel.push(this.zeros[0]);
        }

        let currentIndex = index;

        for (let level = 0; level < this.levels; level++) {
            const isRight = currentIndex % 2 === 1;
            const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

            pathElements.push(currentLevel[siblingIndex]);
            pathIndices.push(isRight ? 1 : 0);

            const nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                nextLevel.push(this.hash(currentLevel[i], currentLevel[i + 1]));
            }
            currentLevel = nextLevel;
            currentIndex = Math.floor(currentIndex / 2);
        }

        return {
            root: currentLevel[0],
            pathElements,
            pathIndices,
        };
    }
}

module.exports = { MerkleTree };
