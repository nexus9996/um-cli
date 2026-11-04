import mmkv

mmkv_root = "/Users/wangning/Library/Containers/com.tencent.QQMusicMac/Data/Library/Application Support/QQMusicMac/iData"
kv = mmkv.MMKV(mmapID="808h18", rootPath=mmkv_root)

# 列出所有 key，通常密钥存在特定的 key 下，比如 "key"、"qmc_key" 等
print("Total keys:", kv.count())
for key in kv.allKeys():
    data = kv.getBytes(key)
    if data:
        print(f"Key: {key}  (len={len(data)}): {data.hex()}")
    else:
        str_val = kv.getString(key)
        print(f"Key: {key}  (str): {str_val}")
