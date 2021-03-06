package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

const (
	// FixedSalt is used for KDF functions
	FixedSalt = "ThisIsVeryRandom"
	// FixedIV is used for CFBEncrypter/Decrypter, should be of length aes.BlockSize
	// FixedIV = "ThisIsVeryRandom"
)

var (
	// KeyLen for KDF generated keys
	KeyLen = uint32(userlib.AESKeySize)
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	_ = json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 // Do not modify this variable

// setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// Inode for file storage
type Inode struct {
	FileSize       int
	DirectPointers []uuid.UUID
	SingleIndirect uuid.UUID
	DoubleIndirect uuid.UUID
}

func NewInode() *Inode {
	return &Inode{
		FileSize:       0,
		DirectPointers: make([]uuid.UUID, 12),
	}
}

// FileEntry for a filename
type FileEntry struct {
	InodeAddress  uuid.UUID
	FileSecretKey []byte
	HmacKey       []byte
}

// User : User structure used to store the user information
type User struct {
	Username   string
	SecretKey  []byte
	HmacKey    []byte
	PrivateKey *userlib.PrivateKey
	OwnedFiles map[string]FileEntry
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// NewUser returns a initialised User struct
func NewUser(username string, secretKey, hmacKey []byte, privateKey *userlib.PrivateKey) *User {
	return &User{
		Username:   username,
		SecretKey:  secretKey,
		HmacKey:    hmacKey,
		PrivateKey: privateKey,
		OwnedFiles: make(map[string]FileEntry),
	}
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) error {
	if len(data)%configBlockSize != 0 {
		return errors.New("data not a multiple of blocksize")
	}

	if err := userdata.loadUser(); err != nil {
		return err
	}

	if fe, ok := userdata.OwnedFiles[filename]; ok {
		if err := userdata.destroyFile(filename, fe); err != nil {
			return err
		}

		delete(userdata.OwnedFiles, filename)
		if err := userdata.saveUser(); err != nil {
			return err
		}
	}

	return userdata.AppendFile(filename, data)
}

func (userdata *User) destroyFile(filename string, fe FileEntry) error {
	if err := userdata.loadUser(); err != nil {
		return err
	}

	var inode Inode
	inodeJSON, err := SecureDatastoreGet(fe.FileSecretKey, fe.HmacKey, fe.InodeAddress)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(inodeJSON, &inode); err != nil {
		return err
	}

	for inode.FileSize > 0 {
		var key uuid.UUID
		switch {
		case inode.FileSize < 12:
			key = inode.DirectPointers[inode.FileSize]
		case inode.FileSize-12 < uuidsPerBlock():
			var directPointers []uuid.UUID
			directPointers, err = getUUIDBlock(fe.FileSecretKey, fe.HmacKey, inode.SingleIndirect)
			if err != nil {
				return err
			}

			key = directPointers[inode.FileSize-12]
			if inode.FileSize == 12 {
				SecureDatastoreDelete(fe.FileSecretKey, inode.SingleIndirect)
			}
		default:
			// assume that data would fit in the double indirect block
			singleIndirectPointers, err := getUUIDBlock(fe.FileSecretKey, fe.HmacKey, inode.DoubleIndirect)
			if err != nil {
				return err
			}

			offset := (inode.FileSize - 12 - uuidsPerBlock()) / uuidsPerBlock()
			id := (inode.FileSize - 12 - uuidsPerBlock()) % uuidsPerBlock()

			directPointers, err := getUUIDBlock(fe.FileSecretKey, fe.HmacKey, singleIndirectPointers[offset])
			if err != nil {
				return err
			}
			key = directPointers[id]
			if id == 0 {
				// need to destroy a single indirect block
				SecureDatastoreDelete(fe.FileSecretKey, singleIndirectPointers[offset])

				if offset == 0 {
					SecureDatastoreDelete(fe.FileSecretKey, inode.DoubleIndirect)
				}
			}

		}

		SecureDatastoreDelete(fe.FileSecretKey, key)
		inode.FileSize--
	}

	if err := SecureDatastoreDelete(fe.FileSecretKey, fe.InodeAddress); err != nil {
		return err
	}

	return nil
}

// appendBlock adds a block of data to the inode and saves it on the datastore
// Does not store inode on the Datastore
func appendBlock(inode *Inode, fileSecretKey, hmacKey, data []byte) (err error) {
	key := uuid.New()

	switch {
	case inode.FileSize < 12:
		inode.DirectPointers[inode.FileSize] = key
	case inode.FileSize == 12:
		// need to initiallize a single indirect block
		if inode.SingleIndirect, err = initUUIDBlock(fileSecretKey, hmacKey); err != nil {
			return err
		}
		fallthrough
	case inode.FileSize-12 < uuidsPerBlock():
		var directPointers []uuid.UUID
		directPointers, err = getUUIDBlock(fileSecretKey, hmacKey, inode.SingleIndirect)
		if err != nil {
			return err
		}

		directPointers[inode.FileSize-12] = key
		if err = setUUIDBlock(fileSecretKey, hmacKey, inode.SingleIndirect, directPointers); err != nil {
			return err
		}
	case inode.FileSize-12 == uuidsPerBlock():
		// need to initialize double inderect block
		if inode.DoubleIndirect, err = initUUIDBlock(fileSecretKey, hmacKey); err != nil {
			return err
		}
		fallthrough
	default:
		// assume that data would fit in the double indirect block
		singleIndirectPointers, err := getUUIDBlock(fileSecretKey, hmacKey, inode.DoubleIndirect)
		if err != nil {
			return err
		}

		offset := (inode.FileSize - 12 - uuidsPerBlock()) / uuidsPerBlock()
		id := (inode.FileSize - 12 - uuidsPerBlock()) % uuidsPerBlock()
		if id == 0 {
			// need to initialize single indirect block
			if singleIndirectPointers[offset], err = initUUIDBlock(fileSecretKey, hmacKey); err != nil {
				return err
			}
		}

		directPointers, err := getUUIDBlock(fileSecretKey, hmacKey, singleIndirectPointers[offset])
		if err != nil {
			return err
		}

		directPointers[id] = key
		if err := setUUIDBlock(fileSecretKey, hmacKey, singleIndirectPointers[offset], directPointers); err != nil {
			return err
		}
	}
	inode.FileSize++

	return SecureDatastoreSet(fileSecretKey, hmacKey, key, data)
}

func uuidsPerBlock() int {
	return configBlockSize / len(uuid.Nil)
}

func initUUIDBlock(fileSecretKey, hmacKey []byte) (key uuid.UUID, err error) {
	uuids := make([]uuid.UUID, uuidsPerBlock())
	key = uuid.New()

	err = setUUIDBlock(fileSecretKey, hmacKey, key, uuids)
	return
}

func getUUIDBlock(fileSecretKey, hmacKey []byte, key uuid.UUID) ([]uuid.UUID, error) {
	var pointers []uuid.UUID
	data, err := SecureDatastoreGet(fileSecretKey, hmacKey, key)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &pointers); err != nil {
		return nil, err
	}

	return pointers, nil
}

func setUUIDBlock(fileSecretKey, hmacKey []byte, key uuid.UUID, uuids []uuid.UUID) error {
	data, err := json.Marshal(uuids)
	if err != nil {
		return err
	}

	if err := SecureDatastoreSet(fileSecretKey, hmacKey, key, data); err != nil {
		return err
	}

	return nil
}

func (userdata *User) createNewFile(filename string) (err error) {
	inodeAddress := uuid.New()

	fileSecretKey := userlib.RandomBytes(int(KeyLen))
	hmacKey := userlib.RandomBytes(int(KeyLen))
	userdata.OwnedFiles[filename] = FileEntry{
		InodeAddress:  inodeAddress,
		FileSecretKey: fileSecretKey,
		HmacKey:       hmacKey,
	}

	return userdata.saveUser()
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) error {
	if len(data)%configBlockSize != 0 {
		return errors.New("data not a multiple of blocksize")
	}

	if err := userdata.loadUser(); err != nil {
		return err
	}

	var inode Inode
	if fe, ok := userdata.OwnedFiles[filename]; !ok {
		if err := userdata.createNewFile(filename); err != nil {
			return err
		}

		inode = *NewInode()
	} else {
		// file exists, load the inode from datastore
		inodeJSON, err := SecureDatastoreGet(fe.FileSecretKey, fe.HmacKey, fe.InodeAddress)
		if err != nil {
			return err
		}

		err = json.Unmarshal(inodeJSON, &inode)
		if err != nil {
			return err
		}
	}

	fe := userdata.OwnedFiles[filename]
	buffer := data
	for len(buffer) > 0 {
		if err := appendBlock(&inode, fe.FileSecretKey, fe.HmacKey, buffer[:configBlockSize]); err != nil {
			return err
		}
		buffer = buffer[configBlockSize:]
	}

	inodeJSON, err := json.Marshal(inode)
	if err != nil {
		return err
	}

	return SecureDatastoreSet(fe.FileSecretKey, fe.HmacKey, fe.InodeAddress, inodeJSON)
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) ([]byte, error) {
	if err := userdata.loadUser(); err != nil {
		return nil, err
	}

	fe := userdata.OwnedFiles[filename]
	var inode Inode
	inodeJSON, err := SecureDatastoreGet(fe.FileSecretKey, fe.HmacKey, fe.InodeAddress)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(inodeJSON, &inode)
	if err != nil {
		return nil, err
	}

	return loadFileAtOffset(&inode, fe.FileSecretKey, fe.HmacKey, offset)
}

func loadFileAtOffset(inode *Inode, fileSecretKey, hmacKey []byte, offset int) ([]byte, error) {
	if offset >= inode.FileSize {
		userlib.DebugMsg("invalid block offset")
		return nil, errors.New("offset invalid or does not exist")
	}

	var key uuid.UUID
	switch {
	case offset < 12:
		key = inode.DirectPointers[offset]
	case offset < uuidsPerBlock():
		directPointers, err := getUUIDBlock(fileSecretKey, hmacKey, inode.SingleIndirect)
		if err != nil {
			return nil, err
		}
		key = directPointers[offset-12]
	default:
		// assume that the filesize would be less than the double indirect pointer storage capacity
		indirectPointers, err := getUUIDBlock(fileSecretKey, hmacKey, inode.DoubleIndirect)
		if err != nil {
			return nil, err
		}

		indirectBlockID := (offset - 12 - uuidsPerBlock()) / uuidsPerBlock()
		id := (inode.FileSize - 12 - uuidsPerBlock()) % uuidsPerBlock()

		directPointers, err := getUUIDBlock(fileSecretKey, hmacKey, indirectPointers[indirectBlockID])
		if err != nil {
			return nil, err
		}

		key = directPointers[id]
	}

	data, err := SecureDatastoreGet(fileSecretKey, hmacKey, key)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (string, error) {
	if err := userdata.loadUser(); err != nil {
		return "", err
	}

	fe := userdata.OwnedFiles[filename]
	feJSON, err := json.Marshal(fe)
	if err != nil {
		return "", err
	}

	// userlib.DebugMsg("json length: %v", len(feJSON))
	sign, err := userlib.RSASign(userdata.PrivateKey, feJSON)
	if err != nil {
		return "", err
	}

	// userlib.DebugMsg("sign length: %v", len(sign))
	userlib.DebugMsg("feJSON=%s, sign=%v", feJSON, sign)
	// prepare data to send
	sharingRecordData := append(sign, feJSON...)
	sharingRecordKey := userlib.RandomBytes(int(KeyLen))
	sharingRecordHmac := userlib.RandomBytes(int(KeyLen))
	sharingRecordAddress := uuid.New()

	err = SecureDatastoreSet(sharingRecordKey, sharingRecordHmac, sharingRecordAddress, sharingRecordData)
	if err != nil {
		return "", err
	}

	pubKey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("recipient not found")
	}

	userlib.DebugMsg("sharingRecordKey=%v, sharingRecordAddress=%s", sharingRecordKey, sharingRecordAddress)
	data := append(sharingRecordKey, sharingRecordAddress.String()...)
	data = append(data, sharingRecordHmac...)
	userlib.DebugMsg("Total data length: %v", len(data))
	encryptedData, err := userlib.RSAEncrypt(&pubKey, data, nil)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(encryptedData), nil
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	if err := userdata.loadUser(); err != nil {
		return err
	}

	encryptedData, err := hex.DecodeString(msgid)
	if err != nil {
		return err
	}

	data, err := userlib.RSADecrypt(userdata.PrivateKey, encryptedData, nil)
	if err != nil {
		return err
	}

	sharingRecordKey := data[:KeyLen]
	data = data[KeyLen:]

	sharingRecordAddress, err := uuid.Parse(string(data[:len(uuid.Nil.String())]))
	if err != nil {
		return err
	}

	sharingRecordHmac := data[len(uuid.Nil.String()):]
	userlib.DebugMsg("sharingRecordKey=%v, sharingRecordAddress=%s", sharingRecordKey, sharingRecordAddress)
	sharingRecordData, err := SecureDatastoreGet(sharingRecordKey, sharingRecordHmac, sharingRecordAddress)
	if err != nil {
		return err
	}

	sign := sharingRecordData[:256]
	feJSON := sharingRecordData[256:]
	pubKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("sender not found")
	}

	userlib.DebugMsg("feJSON=%s, sign=%v", feJSON, sign)
	if err := userlib.RSAVerify(&pubKey, feJSON, sign); err != nil {
		userlib.DebugMsg("RSA signature verification failed")
		return err
	}

	var fe FileEntry
	if err := json.Unmarshal(feJSON, &fe); err != nil {
		return err
	}

	userdata.OwnedFiles[filename] = fe
	return userdata.saveUser()
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) error {
	if err := userdata.loadUser(); err != nil {
		return err
	}

	feOld := userdata.OwnedFiles[filename]
	var inodeOld Inode
	inodeOldJSON, err := SecureDatastoreGet(feOld.FileSecretKey, feOld.HmacKey, feOld.InodeAddress)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(inodeOldJSON, &inodeOld); err != nil {
		return err
	}

	delete(userdata.OwnedFiles, filename)
	if err := userdata.saveUser(); err != nil {
		return err
	}

	for offset := 0; offset < inodeOld.FileSize; offset++ {
		var buffer []byte
		if buffer, err = loadFileAtOffset(
			&inodeOld, feOld.FileSecretKey, feOld.HmacKey, offset,
		); err != nil {
			return err
		}

		if err = userdata.AppendFile(filename, buffer); err != nil {
			return err
		}
	}

	return userdata.destroyFile(filename, feOld)
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

// InitUser : function used to create user
func InitUser(username string, password string) (*User, error) {
	userlib.DebugMsg("InitUser called")
	if username == "" || password == "" {
		return nil, errors.New("Invalid username or password")
	}

	if _, ok := userlib.KeystoreGet(username); ok {
		// user already exists
		return nil, errors.New("User already exists, aborted")
	}

	secretKey := userlib.Argon2Key([]byte(password+username), makeSalt([]byte(username)), KeyLen)
	hmacKey := userlib.Argon2Key([]byte(username+password), makeSalt([]byte(username)), KeyLen)
	privKey, err := userlib.GenerateRSAKey()
	if err != nil {
		userlib.DebugMsg("GenerateRSAKey failed")
		return nil, err
	}

	// Register the public key on the keystore
	userlib.KeystoreSet(username, privKey.PublicKey)
	// store User struct on datastore
	userdataptr := NewUser(username, secretKey, hmacKey, privKey)
	userlib.DebugMsg("user=%+v", userdataptr)

	if err = userdataptr.saveUser(); err != nil {
		return nil, err
	}

	return userdataptr, nil
}

func (userdata *User) loadUser() error {
	userLoc := bytesToUUID(makeSalt([]byte(userdata.Username)))

	userJSON, err := SecureDatastoreGet(userdata.SecretKey, userdata.HmacKey, userLoc)
	if err != nil {
		return err
	}

	return json.Unmarshal(userJSON, userdata)
}

func (userdata *User) saveUser() error {
	userJSON, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	// userlib.DebugMsg("userJSON=%s", userJSON)
	userLoc := bytesToUUID(makeSalt([]byte(userdata.Username)))

	return SecureDatastoreSet(userdata.SecretKey, userdata.HmacKey, userLoc, userJSON)
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
// GetUser : function used to get the user details
func GetUser(username string, password string) (*User, error) {
	userlib.DebugMsg("GetUser called")

	secretKey := userlib.Argon2Key(
		[]byte(password+username), makeSalt([]byte(username)), KeyLen,
	)
	hmacKey := userlib.Argon2Key([]byte(username+password), makeSalt([]byte(username)), KeyLen)

	userLoc := bytesToUUID(makeSalt([]byte(username)))

	userJSON, err := SecureDatastoreGet(secretKey, hmacKey, userLoc)
	if err != nil {
		userlib.DebugMsg("failed to DatastoreGet for username=%s", username)
		return nil, err
	}

	// userlib.DebugMsg("userJSON=%s", userJSON)
	var userdata User
	if err = json.Unmarshal(userJSON, &userdata); err != nil {
		userlib.DebugMsg("Unmarshal failed")
		return nil, err
	}

	userlib.DebugMsg("user=%+v", userdata)
	// userlib.DebugMsg("map is nil: %v", userdataptr.OwnedFiles)
	return &userdata, nil
}

func makeSalt(b []byte) []byte {
	sha := userlib.NewSHA256()
	sha.Write(b)
	return sha.Sum(nil)[:16]
}

func uuidFromBytes(b []byte) (uuid.UUID, error) {
	key := userlib.Argon2Key(
		b, makeSalt(b), uint32(len(uuid.Nil)),
	)
	return uuid.FromBytes(key)
}

// func uuidFromBytes(b []byte) (uuid.UUID, error) {
// 	return bytesToUUID(makeSalt(b)), nil
// }

// SecureDatastoreSet is secure version of DatastoreSet
func SecureDatastoreSet(secretKey, hmacKey []byte, dataKey uuid.UUID, dataValue []byte) error {
	maskedLocation, err := uuidFromBytes([]byte(dataKey.String()))
	if err != nil {
		return err
	}

	hmacWriter := userlib.NewHMAC(hmacKey)
	_, _ = hmacWriter.Write([]byte(maskedLocation.String()))
	_, _ = hmacWriter.Write(dataValue)
	data := append(hmacWriter.Sum(nil), dataValue...)
	userlib.DebugMsg("hmac=%v", hmacWriter.Sum(nil))

	iv := userlib.RandomBytes(userlib.BlockSize) // generate an new iv everytime
	encrypter := userlib.CFBEncrypter(secretKey, iv)
	encrypter.XORKeyStream(data, data) // this encrypts data in-place
	userlib.DatastoreSet(
		maskedLocation.String(),
		append(iv, data...),
	)

	return nil
}

// SecureDatastoreGet is secure version of DatastoreGet
func SecureDatastoreGet(secretKey, hmacKey []byte, dataKey uuid.UUID) (dataValue []byte, err error) {
	maskedLocation, err := uuidFromBytes([]byte(dataKey.String()))
	if err != nil {
		return
	}

	data, ok := userlib.DatastoreGet(maskedLocation.String())
	if !ok {
		return nil, errors.New("key not found in datastore")
	}

	iv := data[:userlib.BlockSize]
	data = data[userlib.BlockSize:]

	decrypter := userlib.CFBDecrypter(secretKey, iv)
	decrypter.XORKeyStream(data, data) // this decrypts data in-place
	oldHmac := data[:userlib.HashSize]
	dataValue = data[userlib.HashSize:]

	hmacWriter := userlib.NewHMAC(hmacKey)
	_, _ = hmacWriter.Write([]byte(maskedLocation.String()))
	_, _ = hmacWriter.Write(dataValue)
	userlib.DebugMsg("hmac=%v", hmacWriter.Sum(nil))

	if !userlib.Equal(oldHmac, hmacWriter.Sum(nil)) {
		return nil, errors.New("integrity check failed")
	}

	return
}

// SecureDatastoreDelete is secure version of DatastoreDelete
func SecureDatastoreDelete(secretKey []byte, dataKey uuid.UUID) error {
	maskedLocation, err := uuidFromBytes([]byte(dataKey.String()))
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(maskedLocation.String())
	return nil
}
