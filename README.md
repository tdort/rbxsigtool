# rbxsigtool
A python tool used for verifying signatures for roblox revivals. (mainly used for 2016 though more versions coming)
## Report bugs [here](https://github.com/tdort/rbxsigtool/issues)
# Usage
python rbxkeytool.py gen [out.pem] -> new 1024-bit keypair (default private.pem)                                                                                                  
python rbxkeytool.py patch <key.pem> <exe> -> writes <exe>.patched with the public key of key.pem                                                                                 
python rbxkeytool.py check <key.pem> <exe> -> says whether each exe already carries that key                                                                                      
python rbxkeytool.py verify <key.pem> <join.txt> -> checks a saved Join.ashx response the way the client does                                                                     
  
