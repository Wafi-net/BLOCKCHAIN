import hashlib
import time
import json
import threading
import datetime
import random
from typing import List, Dict, Any, Optional
import base64
import ecdsa
import uuid
import pickle
import os
from collections import defaultdict

# Configuration parameters for scalability
BLOCK_SIZE_LIMIT = 1024 * 1024  # 1MB block size limit
DIFFICULTY_ADJUSTMENT_INTERVAL = 10  # Blocks
TARGET_TIME_PER_BLOCK = 10  # Seconds
INITIAL_DIFFICULTY = 4  # Number of leading zeros required

class Transaction:
    """Transaction Class - represents transfers between wallets"""
    def __init__(self, sender: str, recipient: str, amount: float, fee: float = 0.0, signature: str = None, timestamp: float = None, tx_id: str = None):
        self.sender = sender  # Sender's public key
        self.recipient = recipient  # Recipient's public key
        self.amount = amount  # Amount to transfer
        self.fee = fee  # Transaction fee
        self.timestamp = timestamp or time.time()
        self.tx_id = tx_id or self._generate_tx_id()
        self.signature = signature  # Digital signature to verify authenticity
        
    def _generate_tx_id(self) -> str:
        """Generate a unique transaction ID"""
        data = f"{self.sender}{self.recipient}{self.amount}{self.fee}{self.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction to dictionary"""
        return {
            "tx_id": self.tx_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "signature": self.signature
        }
    
    @classmethod
    def from_dict(cls, tx_dict: Dict[str, Any]) -> 'Transaction':
        """Create a transaction from dictionary"""
        return cls(
            sender=tx_dict["sender"],
            recipient=tx_dict["recipient"],
            amount=tx_dict["amount"],
            fee=tx_dict.get("fee", 0.0),
            signature=tx_dict.get("signature"),
            timestamp=tx_dict.get("timestamp"),
            tx_id=tx_dict.get("tx_id")
        )
    
    def sign(self, private_key: ecdsa.SigningKey) -> None:
        """Sign the transaction using the sender's private key"""
        message = f"{self.sender}{self.recipient}{self.amount}{self.fee}{self.timestamp}".encode()
        signature = private_key.sign(message)
        self.signature = base64.b64encode(signature).decode()
    
    def verify_signature(self) -> bool:
        """Verify the transaction signature"""
        if self.sender == "coinbase":  # Mining rewards don't need signatures
            return True
        
        if not self.signature:
            return False
        
        try:
            message = f"{self.sender}{self.recipient}{self.amount}{self.fee}{self.timestamp}".encode()
            public_key = ecdsa.VerifyingKey.from_string(
                base64.b64decode(self.sender), 
                curve=ecdsa.SECP256k1
            )
            public_key.verify(
                base64.b64decode(self.signature),
                message
            )
            return True
        except Exception:
            return False


class MerkleTree:
    """Merkle Tree implementation for efficiently verifying transactions"""
    
    @staticmethod
    def create_merkle_root(transactions: List[Transaction]) -> str:
        """Create a Merkle Root from a list of transactions"""
        if not transactions:
            return hashlib.sha256("".encode()).hexdigest()
        
        # Get transaction hashes
        tx_hashes = [tx.tx_id for tx in transactions]
        
        # Ensure even number of elements by duplicating the last one if necessary
        if len(tx_hashes) % 2 == 1:
            tx_hashes.append(tx_hashes[-1])
        
        # Build the Merkle tree
        while len(tx_hashes) > 1:
            next_level = []
            # Process pairs of hashes
            for i in range(0, len(tx_hashes), 2):
                combined = tx_hashes[i] + tx_hashes[i + 1]
                next_hash = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(next_hash)
            tx_hashes = next_level
            
            # If odd number at this level, duplicate the last element
            if len(tx_hashes) % 2 == 1 and len(tx_hashes) > 1:
                tx_hashes.append(tx_hashes[-1])
        
        return tx_hashes[0]  # The root of the Merkle tree


class Block:
    """Block Class - contains multiple transactions"""
    def __init__(self, index: int, previous_hash: str, timestamp: float, transactions: List[Transaction], nonce: int = 0, difficulty: int = INITIAL_DIFFICULTY):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.merkle_root = MerkleTree.create_merkle_root(transactions)
        self.nonce = nonce
        self.difficulty = difficulty
        self.hash = self.calculate_hash()
        self.size = self._calculate_size()
    
    def _calculate_size(self) -> int:
        """Calculate size of block in bytes"""
        return len(pickle.dumps(self))
    
    def calculate_hash(self) -> str:
        """Calculate hash of the block"""
        data = (
            f"{self.index}{self.previous_hash}{self.timestamp}"
            f"{self.merkle_root}{self.nonce}{self.difficulty}"
        )
        return hashlib.sha256(data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary"""
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "hash": self.hash,
            "size": self.size
        }
    
    @classmethod
    def from_dict(cls, block_dict: Dict[str, Any]) -> 'Block':
        """Create a block from dictionary"""
        transactions = [Transaction.from_dict(tx) for tx in block_dict["transactions"]]
        block = cls(
            index=block_dict["index"],
            previous_hash=block_dict["previous_hash"],
            timestamp=block_dict["timestamp"],
            transactions=transactions,
            nonce=block_dict["nonce"],
            difficulty=block_dict["difficulty"]
        )
        # Verify hash consistency
        calculated_hash = block.calculate_hash()
        if calculated_hash != block_dict["hash"]:
            raise ValueError(f"Block hash mismatch: {calculated_hash} vs {block_dict['hash']}")
        block.hash = block_dict["hash"]
        return block


class Wallet:
    """Wallet Class - for creating and managing keys and transactions"""
    def __init__(self, private_key: ecdsa.SigningKey = None):
        """Create a new wallet or load from existing private key"""
        if private_key:
            self.private_key = private_key
        else:
            # Generate new private key
            self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        
        # Generate public key
        self.public_key = self.private_key.get_verifying_key()
        # Convert to string format
        self.public_key_string = base64.b64encode(self.public_key.to_string()).decode()
    
    def create_transaction(self, recipient: str, amount: float, fee: float = 0.001) -> Transaction:
        """Create a new transaction"""
        tx = Transaction(
            sender=self.public_key_string,
            recipient=recipient,
            amount=amount,
            fee=fee
        )
        tx.sign(self.private_key)
        return tx
    
    @staticmethod
    def verify_transaction(tx: Transaction) -> bool:
        """Verify a transaction's signature"""
        return tx.verify_signature()
    
    def save_to_file(self, filename: str) -> None:
        """Save wallet to file"""
        private_key_bytes = self.private_key.to_string()
        with open(filename, 'wb') as f:
            f.write(private_key_bytes)
    
    @classmethod
    def load_from_file(cls, filename: str) -> 'Wallet':
        """Load wallet from file"""
        with open(filename, 'rb') as f:
            private_key_bytes = f.read()
        private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        return cls(private_key)


class Blockchain:
    """Blockchain Class - manages the chain of blocks and consensus"""
    def __init__(self):
        self.chain = []
        self.mempool = []  # Pending transactions
        self.utxo = defaultdict(float)  # Unspent Transaction Outputs (address -> balance)
        self.peers = set()  # Network peers
        self.lock = threading.RLock()  # Thread lock for concurrent access
        self.mining_reward = 50.0  # Initial mining reward
        self.halving_interval = 210000  # Blocks between reward halvings
        
        # Create the genesis block
        self._create_genesis_block()
    
    def _create_genesis_block(self) -> None:
        """Create the genesis block"""
        coinbase_tx = Transaction(
            sender="coinbase",
            recipient="genesis_address",
            amount=self.mining_reward,
            fee=0.0
        )
        
        genesis_block = Block(
            index=0,
            previous_hash="0" * 64,
            timestamp=time.time(),
            transactions=[coinbase_tx],
            difficulty=INITIAL_DIFFICULTY
        )
        
        self.chain.append(genesis_block)
        self._update_utxo(genesis_block)
        self._save_block_to_file(genesis_block)
    
    def create_block(self, miner_address: str) -> Block:
        """Create a new block with transactions from the mempool"""
        with self.lock:
            # Sort transactions by fee (highest fee first)
            sorted_transactions = sorted(
                self.mempool, 
                key=lambda tx: tx.fee, 
                reverse=True
            )
            
            valid_transactions = []
            block_size = 0
            
            # Create coinbase transaction (mining reward)
            current_height = len(self.chain)
            reward = self.mining_reward / (2 ** (current_height // self.halving_interval))
            
            coinbase_tx = Transaction(
                sender="coinbase",
                recipient=miner_address,
                amount=reward,
                fee=0.0
            )
            valid_transactions.append(coinbase_tx)
            block_size += len(pickle.dumps(coinbase_tx))
            
            # Add transactions from mempool until block size limit is reached
            for tx in sorted_transactions:
                if not self._validate_transaction(tx):
                    continue
                
                tx_size = len(pickle.dumps(tx))
                if block_size + tx_size > BLOCK_SIZE_LIMIT:
                    break
                
                valid_transactions.append(tx)
                block_size += tx_size
            
            # Remove added transactions from mempool
            for tx in valid_transactions[1:]:  # Skip coinbase
                if tx in self.mempool:
                    self.mempool.remove(tx)
            
            # Create new block
            last_block = self.chain[-1]
            difficulty = self._adjust_difficulty()
            
            new_block = Block(
                index=last_block.index + 1,
                previous_hash=last_block.hash,
                timestamp=time.time(),
                transactions=valid_transactions,
                difficulty=difficulty
            )
            
            return new_block
    
    def _adjust_difficulty(self) -> int:
        """Dynamically adjust mining difficulty"""
        current_height = len(self.chain)
        
        # Only adjust difficulty at specified intervals
        if current_height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 or current_height == 0:
            return self.chain[-1].difficulty
        
        # Calculate time taken for the last DIFFICULTY_ADJUSTMENT_INTERVAL blocks
        start_block = self.chain[current_height - DIFFICULTY_ADJUSTMENT_INTERVAL]
        end_block = self.chain[-1]
        time_taken = end_block.timestamp - start_block.timestamp
        expected_time = TARGET_TIME_PER_BLOCK * DIFFICULTY_ADJUSTMENT_INTERVAL
        
        # Adjust difficulty based on time taken
        current_difficulty = self.chain[-1].difficulty
        
        # Prevent rapid difficulty changes by limiting adjustment to factor of 4
        if time_taken < expected_time / 4:
            return current_difficulty + 1
        elif time_taken > expected_time * 4:
            return max(1, current_difficulty - 1)
        
        # Normal adjustment
        if time_taken < expected_time * 0.8:
            return current_difficulty + 1
        elif time_taken > expected_time * 1.2:
            return max(1, current_difficulty - 1)
        
        return current_difficulty
    
    def _validate_transaction(self, tx: Transaction) -> bool:
        """Validate a transaction before adding to mempool or block"""
        # Skip validation for coinbase transactions
        if tx.sender == "coinbase":
            return True
        
        # Verify signature
        if not tx.verify_signature():
            return False
        
        # Check if sender has enough balance
        if self.utxo[tx.sender] < tx.amount + tx.fee:
            return False
        
        return True
    
    def add_transaction_to_mempool(self, tx: Transaction) -> bool:
        """Add a transaction to the mempool if valid"""
        with self.lock:
            if self._validate_transaction(tx):
                self.mempool.append(tx)
                return True
            return False
    
    def add_block(self, block: Block) -> bool:
        """Add a validated block to the blockchain"""
        with self.lock:
            # Check if block is valid
            if not self._is_valid_block(block):
                return False
            
            # Add block to chain
            self.chain.append(block)
            
            # Update UTXO set
            self._update_utxo(block)
            
            # Remove transactions from mempool
            self._remove_block_transactions_from_mempool(block)
            
            # Save block to file
            self._save_block_to_file(block)
            
            return True
    
    def _is_valid_block(self, block: Block) -> bool:
        """Check if a block is valid"""
        # Check block index
        if block.index != len(self.chain):
            return False
        
        # Check previous hash
        if block.previous_hash != self.chain[-1].hash:
            return False
        
        # Check block hash meets difficulty requirement
        if not block.hash.startswith("0" * block.difficulty):
            return False
        
        # Check block hash is correct
        if block.hash != block.calculate_hash():
            return False
        
        # Check merkle root
        if block.merkle_root != MerkleTree.create_merkle_root(block.transactions):
            return False
        
        # Verify all transactions
        coinbase_count = 0
        for tx in block.transactions:
            # Only one coinbase transaction allowed
            if tx.sender == "coinbase":
                coinbase_count += 1
                continue
            
            if not self._validate_transaction(tx):
                return False
        
        if coinbase_count != 1:
            return False
        
        return True
    
    def _update_utxo(self, block: Block) -> None:
        """Update Unspent Transaction Outputs after adding a block"""
        for tx in block.transactions:
            # Add to recipient
            self.utxo[tx.recipient] += tx.amount
            
            # Subtract from sender (except for coinbase)
            if tx.sender != "coinbase":
                self.utxo[tx.sender] -= (tx.amount + tx.fee)
    
    def _remove_block_transactions_from_mempool(self, block: Block) -> None:
        """Remove transactions in the block from mempool"""
        tx_ids = {tx.tx_id for tx in block.transactions}
        self.mempool = [tx for tx in self.mempool if tx.tx_id not in tx_ids]
    
    def _save_block_to_file(self, block: Block) -> None:
        """Save block to a file"""
        if not os.path.exists("blocks"):
            os.makedirs("blocks")
        
        filename = f"blocks/block_{block.index}.json"
        with open(filename, 'w') as f:
            json.dump(block.to_dict(), f, indent=4)
    
    def get_balance(self, address: str) -> float:
        """Get the balance of an address"""
        with self.lock:
            return self.utxo[address]
    
    def get_blockchain_info(self) -> Dict[str, Any]:
        """Get information about the blockchain"""
        with self.lock:
            return {
                "height": len(self.chain) - 1,
                "latest_hash": self.chain[-1].hash,
                "difficulty": self.chain[-1].difficulty,
                "mempool_size": len(self.mempool),
                "total_transactions": sum(len(block.transactions) for block in self.chain),
                "mining_reward": self.mining_reward / (2 ** (len(self.chain) // self.halving_interval))
            }
    
    def validate_chain(self) -> bool:
        """Validate the entire blockchain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Check hash connection
            if current.previous_hash != previous.hash:
                return False
            
            # Check current block hash
            if current.hash != current.calculate_hash():
                return False
            
            # Check block meets difficulty
            if not current.hash.startswith("0" * current.difficulty):
                return False
        
        return True
    
    def resolve_conflicts(self, chains: List[List[Block]]) -> bool:
        """Consensus algorithm: choose the longest valid chain"""
        with self.lock:
            max_length = len(self.chain)
            new_chain = None
            
            # Find the longest valid chain
            for chain in chains:
                if len(chain) > max_length:
                    # Check if chain is valid
                    if self._validate_chain(chain):
                        max_length = len(chain)
                        new_chain = chain
            
            # Replace our chain if a longer valid one is found
            if new_chain:
                self.chain = new_chain
                
                # Reset and recalculate UTXO
                self.utxo = defaultdict(float)
                for block in self.chain:
                    self._update_utxo(block)
                
                return True
            
            return False
    
    def _validate_chain(self, chain: List[Block]) -> bool:
        """Validate a chain of blocks"""
        # Check genesis block
        if chain[0].hash != self.chain[0].hash:
            return False
        
        # Check each block's connection and validity
        for i in range(1, len(chain)):
            current = chain[i]
            previous = chain[i-1]
            
            # Check hash connection
            if current.previous_hash != previous.hash:
                return False
            
            # Check current block hash
            if current.hash != current.calculate_hash():
                return False
            
            # Check block meets difficulty
            if not current.hash.startswith("0" * current.difficulty):
                return False
        
        return True


class ProofOfWork:
    """Proof of Work Class - handles the mining process"""
    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.mining_thread = None
        self.stop_mining = False
    
    def mine_block(self, miner_address: str) -> Optional[Block]:
        """Mine a new block"""
        block = self.blockchain.create_block(miner_address)
        
        # Try different nonces until a valid hash is found
        nonce = 0
        while not self.stop_mining:
            block.nonce = nonce
            block.hash = block.calculate_hash()
            
            # Check if hash meets difficulty requirement
            if block.hash.startswith("0" * block.difficulty):
                break
            
            nonce += 1
        
        # If mining was stopped, return None
        if self.stop_mining:
            self.stop_mining = False
            return None
        
        # Add block to blockchain
        success = self.blockchain.add_block(block)
        if success:
            print(f"Block {block.index} mined with hash: {block.hash}")
            print(f"Nonce: {block.nonce}, Difficulty: {block.difficulty}")
            return block
        
        return None
    
    def start_mining(self, miner_address: str) -> None:
        """Start mining in a separate thread"""
        if self.mining_thread and self.mining_thread.is_alive():
            print("Mining already in progress")
            return
        
        self.stop_mining = False
        self.mining_thread = threading.Thread(
            target=self._continuous_mining,
            args=(miner_address,)
        )
        self.mining_thread.daemon = True
        self.mining_thread.start()
    
    def _continuous_mining(self, miner_address: str) -> None:
        """Continuously mine blocks until stopped"""
        while not self.stop_mining:
            result = self.mine_block(miner_address)
            if not result:
                break
            
            # Small pause between mining blocks
            time.sleep(0.1)
    
    def stop(self) -> None:
        """Stop the mining process"""
        self.stop_mining = True
        if self.mining_thread and self.mining_thread.is_alive():
            self.mining_thread.join(timeout=1.0)


class Node:
    """Node Class - handles network communications and node operations"""
    def __init__(self, host: str = '127.0.0.1', port: int = 5000):
        self.blockchain = Blockchain()
        self.pow = ProofOfWork(self.blockchain)
        self.host = host
        self.port = port
        self.node_id = str(uuid.uuid4()).replace('-', '')
        self.peers = set()
        
        # Create wallet for this node
        self.wallet = Wallet()
        print(f"Node initialized with address: {self.wallet.public_key_string}")
    
    def start(self) -> None:
        """Start the node"""
        print(f"Node {self.node_id} starting on {self.host}:{self.port}")
        print(f"Genesis block: {self.blockchain.chain[0].hash}")
        self._handle_commands()
    
    def _handle_commands(self) -> None:
        """Simple command handler for demonstration"""
        print("\nAvailable commands:")
        print("1. mine - Start mining blocks")
        print("2. balance - Show wallet balance")
        print("3. transfer <address> <amount> - Transfer coins")
        print("4. info - Show blockchain info")
        print("5. exit - Exit the node")
        
        while True:
            command = input("\nEnter command: ").strip().lower()
            
            if command == "mine":
                self.pow.start_mining(self.wallet.public_key_string)
                print("Mining started in background")
            
            elif command == "balance":
                balance = self.blockchain.get_balance(self.wallet.public_key_string)
                print(f"Current balance: {balance}")
            
            elif command.startswith("transfer "):
                parts = command.split()
                if len(parts) == 3:
                    _, recipient, amount = parts
                    try:
                        amount = float(amount)
                        self._create_transfer(recipient, amount)
                    except ValueError:
                        print("Invalid amount format")
                else:
                    print("Usage: transfer <address> <amount>")
            
            elif command == "info":
                info = self.blockchain.get_blockchain_info()
                print("\nBlockchain Info:")
                for key, value in info.items():
                    print(f"{key}: {value}")
            
            elif command == "exit":
                print("Stopping mining...")
                self.pow.stop()
                print("Exiting node...")
                break
            
            else:
                print("Unknown command")
    
    def _create_transfer(self, recipient: str, amount: float) -> None:
        """Create and broadcast a transfer transaction"""
        if amount <= 0:
            print("Amount must be positive")
            return
        
        balance = self.blockchain.get_balance(self.wallet.public_key_string)
        fee = 0.001  # Fixed fee for simplicity
        
        if balance < amount + fee:
            print(f"Insufficient balance: {balance} < {amount + fee}")
            return
        
        tx = self.wallet.create_transaction(recipient, amount, fee)
        if self.blockchain.add_transaction_to_mempool(tx):
            print(f"Transaction created: {tx.tx_id}")
            print(f"Amount: {amount}, Fee: {fee}")
        else:
            print("Failed to create transaction")


# Demo usage
if __name__ == "__main__":
    print("Starting blockchain node...")
    node = Node()
    node.start()
    # Note: In a real-world scenario, you would implement network communication
    # to connect to other nodes and share blocks/transactions.
    
# # Create new wallet with random keys
# wallet = Wallet()

# # Get your public address to share with others
# my_address = wallet.public_key_string
# print(f"My address: {my_address}")

# # Save wallet to file (important!)
# wallet.save_to_file("my_wallet.dat")

# # Later, load wallet from file
# loaded_wallet = Wallet.load_from_file("my_wallet.dat")