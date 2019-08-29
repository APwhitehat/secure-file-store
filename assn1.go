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
	// KeyLen for KDF generated keys
	KeyLen = 256
	// FixedIV is used for CFBEncrypter/Decrypter, should be of length aes.BlockSize
	FixedIV = "ThisIsVeryRandom"
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
}

// User : User structure used to store the user information
type User struct {
	Username   string
	SecretKey  []byte
	PrivateKey *userlib.PrivateKey
	OwnedFiles map[string]FileEntry
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// NewUser returns a initialised User struct
func NewUser(username string, secretKey []byte, privateKey *userlib.PrivateKey) *User {
	return &User{
		Username:   username,
		SecretKey:  secretKey,
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

	if _, ok := userdata.OwnedFiles[filename]; !ok {
		if err := userdata.createNewFile(filename); err != nil {
			return err
		}
	}

	fe := userdata.OwnedFiles[filename]
	inode := NewInode()
	buffer := data
	for len(buffer) > 0 {
		if err := appendBlock(inode, fe.FileSecretKey, buffer[:configBlockSize]); err != nil {
			return err
		}
		buffer = buffer[configBlockSize:]
	}

	inodeJSON, err := json.Marshal(inode)
	if err != nil {
		return err
	}

	return SecureDatastoreSet(fe.FileSecretKey, fe.InodeAddress, inodeJSON)
}

// appendBlock add a block of data to the inode and saves it on the datastore
func appendBlock(inode *Inode, fileSecretKey, data []byte) error {
	key, err := uuid.FromBytes(userlib.RandomBytes(len(uuid.Nil)))
	if err != nil {
		return err
	}

	switch {
	case inode.FileSize < 12:
		inode.DirectPointers[inode.FileSize] = key
	case inode.FileSize == 12:
		// need to initiallize a single indirect block
		if inode.SingleIndirect, err = initUUIDBlock(fileSecretKey); err != nil {
			return err
		}
		fallthrough
	case inode.FileSize-12 < uuidsPerBlock():
		directPointers, err := getUUIDBlock(fileSecretKey, inode.SingleIndirect)
		if err != nil {
			return err
		}

		directPointers[inode.FileSize-12] = key
		if err := setUUIDBlock(fileSecretKey, inode.SingleIndirect, directPointers); err != nil {
			return err
		}
	case inode.FileSize-12 == uuidsPerBlock():
		// need to initialize double inderect block
		if inode.DoubleIndirect, err = initUUIDBlock(fileSecretKey); err != nil {
			return err
		}
		fallthrough
	default:
		// assume that data would fit in the double indirect block
		singleIndirectPointers, err := getUUIDBlock(fileSecretKey, inode.DoubleIndirect)
		if err != nil {
			return err
		}

		offset := (inode.FileSize - 12 - uuidsPerBlock()) / uuidsPerBlock()
		id := (inode.FileSize - 12 - uuidsPerBlock()) % uuidsPerBlock()
		if id == 0 {
			// need to initialize single indirect block
			if singleIndirectPointers[offset], err = initUUIDBlock(fileSecretKey); err != nil {
				return err
			}
		}

		directPointers, err := getUUIDBlock(fileSecretKey, singleIndirectPointers[offset])
		if err != nil {
			return err
		}

		directPointers[id] = key
		if err := setUUIDBlock(fileSecretKey, singleIndirectPointers[offset], directPointers); err != nil {
			return err
		}
	}
	inode.FileSize++

	return SecureDatastoreSet(fileSecretKey, key, data)
}

func uuidsPerBlock() int {
	return configBlockSize / len(uuid.Nil)
}

func initUUIDBlock(fileSecretKey []byte) (key uuid.UUID, err error) {
	uuids := make([]uuid.UUID, uuidsPerBlock())
	key, err = uuid.FromBytes(userlib.RandomBytes(len(uuid.Nil)))
	if err != nil {
		return
	}

	err = setUUIDBlock(fileSecretKey, key, uuids)
	return
}

func getUUIDBlock(fileSecretKey []byte, key uuid.UUID) ([]uuid.UUID, error) {
	var pointers []uuid.UUID
	data, err := SecureDatastoreGet(fileSecretKey, key)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, pointers); err != nil {
		return nil, err
	}

	return pointers, nil
}

func setUUIDBlock(fileSecretKey []byte, key uuid.UUID, uuids []uuid.UUID) error {
	data, err := json.Marshal(uuids)
	if err != nil {
		return err
	}

	if err := SecureDatastoreSet(fileSecretKey, key, data); err != nil {
		return err
	}

	return nil
}

func (userdata *User) createNewFile(filename string) (err error) {
	inodeAddress, err := uuid.FromBytes(userlib.RandomBytes(len(uuid.Nil)))
	if err != nil {
		return
	}

	fileSecretKey := userlib.RandomBytes(KeyLen)
	userdata.OwnedFiles[filename] = FileEntry{
		InodeAddress:  inodeAddress,
		FileSecretKey: fileSecretKey,
	}

	return nil
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
	return
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	return
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) (err error) {
	return
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	return
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
func InitUser(username string, password string) (userdataptr *User, err error) {
	userlib.DebugMsg("InitUser called")

	secretKey := userlib.Argon2Key([]byte(password), []byte(FixedSalt), KeyLen)
	privKey, err := userlib.GenerateRSAKey()
	if err != nil {
		userlib.DebugMsg("GenerateRSAKey failed")
		return
	}

	// Register the public key on the keystore
	userlib.KeystoreSet(username, privKey.PublicKey)
	// store User struct on datastore
	userdataptr = NewUser(username, secretKey, privKey)
	userJSON, err := json.Marshal(userdataptr)
	if err != nil {
		return
	}

	userLoc, err := uuidFromString(username)
	if err != nil {
		return
	}

	err = SecureDatastoreSet(secretKey, userLoc, userJSON)
	return
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
// GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	userlib.DebugMsg("GetUser called")

	secretKey := userlib.Argon2Key(
		[]byte(password), []byte(FixedSalt), KeyLen,
	)

	userLoc, err := uuidFromString(username)
	if err != nil {
		return
	}

	userJSON, err := SecureDatastoreGet(secretKey, userLoc)
	if err != nil {
		return
	}

	if err = json.Unmarshal(userJSON, userdataptr); err != nil {
		return
	}

	userlib.DebugMsg("map is nil: %v", userdataptr.OwnedFiles == nil)
	return
}

func uuidFromString(s string) (uuid.UUID, error) {
	key := userlib.Argon2Key(
		[]byte(s), []byte(FixedSalt), uint32(len(uuid.Nil)),
	)
	return uuid.FromBytes(key)
}

// SecureDatastoreSet is secure version of DatastoreSet
func SecureDatastoreSet(secretKey []byte, dataKey uuid.UUID, dataValue []byte) error {
	kdfBytes := userlib.Argon2Key(
		append(secretKey, []byte(dataKey.String())...),
		[]byte(FixedSalt), KeyLen,
	)
	maskedLocation, err := uuid.FromBytes(kdfBytes)
	if err != nil {
		return err
	}

	hmac := userlib.NewHMAC(secretKey).Sum(
		append([]byte(maskedLocation.String()), dataValue...),
	)
	data := append(hmac, dataValue...)
	encrypter := userlib.CFBEncrypter(secretKey, []byte(FixedIV))
	encrypter.XORKeyStream(data, data) // this encrypts data in-place
	userlib.DatastoreSet(
		maskedLocation.String(),
		data,
	)

	return nil
}

// SecureDatastoreGet is secure version of DatastoreGet
func SecureDatastoreGet(secretKey []byte, dataKey uuid.UUID) (dataValue []byte, err error) {
	kdfBytes := userlib.Argon2Key(
		append(secretKey, []byte(dataKey.String())...),
		[]byte(FixedSalt), KeyLen,
	)
	maskedLocation, err := uuid.FromBytes(kdfBytes)
	if err != nil {
		return
	}

	data, ok := userlib.DatastoreGet(maskedLocation.String())
	if !ok {
		return nil, errors.New("key not found in datastore")
	}

	decrypter := userlib.CFBDecrypter(secretKey, []byte(FixedIV))
	decrypter.XORKeyStream(data, data) // this decrypts data in-place
	oldHmac := data[:userlib.HashSize]
	dataValue = data[userlib.HashSize:]

	hmac := userlib.NewHMAC(secretKey).Sum(
		append([]byte(maskedLocation.String()), dataValue...),
	)

	if !userlib.Equal(oldHmac, hmac) {
		return nil, errors.New("integrity check failed")
	}

	return
}

// SecureDatastoreDelete is secure version of DatastoreDelete
func SecureDatastoreDelete(secretKey []byte, dataKey uuid.UUID) error {
	kdfBytes := userlib.Argon2Key(
		append(secretKey, []byte(dataKey.String())...),
		[]byte(FixedSalt), KeyLen,
	)
	maskedLocation, err := uuid.FromBytes(kdfBytes)
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(maskedLocation.String())
	return nil
}
