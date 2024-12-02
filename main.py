# 引入所需的加密套件和工具
from hashlib import sha256  # 用於計算 SHA-256 哈希
from Crypto.PublicKey import RSA  # 用於生成 RSA 公私鑰對
from Crypto.Cipher import AES  # 用於加密解密
from Crypto.Signature import pkcs1_15  # 用於簽名和驗證簽名
from Crypto.Hash import SHA256  # 用於生成 SHA-256 哈希值
import base64  # 用於編碼解碼
import os  # 用於生成隨機數據
import datetime  # 用於處理時間和日期
import chardet  # 用於檢測文件的編碼格式

# 區塊定義
class Block:
    def __init__(self, index, previous_hash, data, timestamp):
        # 初始化區塊的索引、上一個區塊的哈希值、區塊數據以及時間戳
        self.index = index
        self.previous_hash = previous_hash
        self.data = data
        self.timestamp = timestamp
        # 根據區塊內容計算區塊的哈希
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # 利用 SHA-256 計算區塊的哈希值，將區塊的各項內容作為字串進行編碼後計算哈希
        block_string = f"{self.index}{self.previous_hash}{self.data}{self.timestamp}"
        return sha256(block_string.encode()).hexdigest()

# 區塊鏈定義
class Blockchain:
    def __init__(self):
        # 初始化區塊鏈，創建創世區塊（即區塊鏈的第一個區塊）
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        # 創建創世區塊，這是一個固定的區塊，索引為 0，且沒有前一個區塊
        return Block(0, "0", "Genesis Block", "2024-01-01 00:00:00")

    def get_latest_block(self):
        # 獲取區塊鏈中的最後一個區塊
        return self.chain[-1]

    def add_block(self, new_block):
        # 添加新的區塊到區塊鏈中，並更新該區塊的哈希值
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

    def is_chain_valid(self):
        # 驗證區塊鏈的結構，檢查每個區塊的哈希與前一個區塊的哈希是否一致
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # 如果區塊的哈希與計算出的哈希不一致，則返回無效
            if current_block.hash != current_block.calculate_hash():
                return False
            # 如果區塊的上一個哈希與前一個區塊的哈希不一致，則返回無效
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

# 檢測文件編碼
def detect_file_encoding(file_path):
    """檢測文件編碼"""
    with open(file_path, "rb") as file:
        result = chardet.detect(file.read())  # 使用 chardet 檢測文件編碼
    return result['encoding']

# 文件加密
def encrypt_file(data, key):
    """加密文件內容"""
    cipher = AES.new(key, AES.MODE_EAX)  # 創建 AES 加密對象，使用 EAX 模式
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())  # 加密文件內容並生成加密標籤
    # 將 nonce、標籤與密文結合並編碼成 base64 字串
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# 計算文件哈希值
def calculate_file_hash(file_path):
    """計算文件的 SHA-256 哈希值"""
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()  # 讀取文件內容
        return sha256(file_content).hexdigest()  # 返回文件的 SHA-256 哈希值
    except FileNotFoundError:
        print(f"找不到文件：{file_path}")
        return None

# 區塊鏈驗證（新增文件哈希驗證邏輯）
def verify_blockchain_and_files(blockchain, file_path=None):
    """同時驗證區塊鏈結構與文件完整性"""
    # 驗證區塊鏈結構
    is_chain_valid = blockchain.is_chain_valid()
    print("區塊鏈結構驗證結果:", is_chain_valid)

    if not is_chain_valid:
        return False

    # 如果有指定文件進行驗證
    if file_path:
        print("正在驗證文件內容與區塊鏈內紀錄是否一致...")

        # 計算驗證文件的哈希值
        file_hash = calculate_file_hash(file_path)

        if file_hash:
            # 顯示原始文件哈希與驗證文件哈希
            print(f"原始文件的哈希值: {blockchain.chain[1].data['document_hash']}")
            print(f"驗證文件的哈希值: {file_hash}")

            # 比對文件哈希值與區塊鏈內的哈希值
            original_hash_in_chain = blockchain.chain[1].data["document_hash"]
            if file_hash == original_hash_in_chain:
                print("文件驗證成功，未被修改！")
                return True
            else:
                print("警告：文件已被修改！")
                return False
        else:
            print("文件哈希計算失敗！")
            return False

    # 如果沒有文件需要驗證，只驗證區塊鏈
    return is_chain_valid

# 主程式
if __name__ == "__main__":
    blockchain = Blockchain()  # 初始化區塊鏈
    aes_key = os.urandom(16)  # 隨機生成 AES 密鑰，用於文件加密

    # 前置作業
    print("前置作業開始：")
    original_file_path = input("請輸入原始公文文件的路徑：")
    original_file_hash = calculate_file_hash(original_file_path)  # 計算原始文件的哈希值

    if original_file_hash:
        print("原始文件哈希值:", original_file_hash)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 獲取當前時間戳

        # 檢測文件編碼並加密文件內容
        encoding = detect_file_encoding(original_file_path)
        print(f"檢測到的文件編碼為: {encoding}")

        try:
            with open(original_file_path, "r", encoding=encoding) as file:
                original_content = file.read()  # 讀取原始文件內容
        except Exception as e:
            print(f"文件讀取失敗: {e}")
            exit()

        encrypted_document = encrypt_file(original_content, aes_key)  # 加密文件內容
        print("加密文件內容:", encrypted_document)

        # 模擬智能合約審核文件真實性
        print("正在進行智能合約審核文件真實性...")
        is_valid = True  # 模擬審核通過
        if is_valid:
            print("文件審核通過。")

            # 上鏈儲存加密文件與審核結果
            blockchain.add_block(Block(1, blockchain.get_latest_block().hash, {
                "document_hash": original_file_hash,  # 儲存原始文件哈希
                "encrypted_document": encrypted_document,  # 儲存加密文件
                "audit_result": "Approved"  # 儲存審核結果
            }, timestamp))
            print("加密文件與審核結果已上鏈。")
        else:
            print("文件審核失敗，結束流程。")
            exit()

    # 驗證功能
    verify_choice = input("是否需要驗證文件完整性？ (y/n): ").lower()
    if verify_choice == "y":
        print("驗證功能啟動：")
        verification_file_path = input("請輸入待驗證文件的路徑：")
        # 同時驗證區塊鏈和文件
        verify_result = verify_blockchain_and_files(blockchain, verification_file_path)
        if verify_result:
            print("驗證完成：區塊鏈與文件均未被修改！")
        else:
            print("驗證失敗：區塊鏈或文件已被修改！")
    else:
        print("流程完成，未進行驗證。")

    # 顯示區塊鏈內容
    for block in blockchain.chain:
        print(f"區塊索引: {block.index}, 資料: {block.data}, 哈希值: {block.hash}")
