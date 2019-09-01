package assn1

import "github.com/sarkarbidya/CS628-assn1/userlib"
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUser(t *testing.T) {
	userlib.KeystoreClear()
	userlib.DatastoreClear()
	t.Log("Initialization test")
	// userlib.DebugPrint = true

	// Invalid user
	_, err1 := InitUser("", "")
	if err1 != nil {
		t.Log("Failed to initialize invalid user")
	} else {
		t.Error("Initialized invalid user")
	}

	// valid user
	_, err1 = InitUser("foo", "bar")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
	} else {
		t.Log("Successfully initialized user")
	}
	// add more test cases here
}

func TestUserStorage(t *testing.T) {
	userlib.KeystoreClear()
	userlib.DatastoreClear()
	// userlib.DebugPrint = true
	u, err := GetUser("", "fubar")
	if err != nil {
		t.Log("Cannot load data for invalid user", u)
	} else {
		t.Error("Data loaded for invalid user", err)
	}

	_, _ = InitUser("foo", "bar")
	u, err = GetUser("foo", "bar")
	if err != nil {
		t.Error("Cannot load data for valid user", err)
	} else {
		t.Log("Loaded data for valid user", u)
	}
	// add more test cases here
}

func TestFileStoreLoadAppend(t *testing.T) {
	userlib.KeystoreClear()
	userlib.DatastoreClear()
	u1, _ := InitUser("foo", "bar")

	// userlib.DebugPrint = true

	data1 := userlib.RandomBytes(4096)
	_ = u1.StoreFile("file1", data1)

	data2, _ := u1.LoadFile("file1", 0)

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}

	// repeat
	data1 = userlib.RandomBytes(4096)
	_ = u1.StoreFile("file1", data1)

	data2, _ = u1.LoadFile("file1", 0)

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}

	// test append
	data1 = userlib.RandomBytes(4096)
	_ = u1.AppendFile("file1", data1)

	data2, _ = u1.LoadFile("file1", 1)

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}
	// add test cases here
}

func TestMultipleInstanceUser(t *testing.T) {
	userlib.KeystoreClear()
	userlib.DatastoreClear()

	t.Log("Multiple Instance for User Test")
	_, _ = InitUser("foo", "bar")
	userlib.DebugPrint = true

	_, err := InitUser("foo", "bar")
	if err != nil {
		t.Log("Successfully failed multiple initialization of user: ", err)

	} else {
		t.Error("Initialized multiple user")
	}
	// add more test cases here

	u1, _ := GetUser("foo", "bar")
	data1 := userlib.RandomBytes(4096)
	_ = u1.StoreFile("file1", data1)
	u1, _ = GetUser("foo", "bar")
	data2, err := u1.LoadFile("file1", 0)
	if err != nil {
		t.Error("failed to get file: ", err)
	}

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}
}

func TestFileShareReceive(t *testing.T) {
	userlib.KeystoreClear()
	userlib.DatastoreClear()

	u1, _ := InitUser("foo", "bar")
	u2, _ := InitUser("foo2", "bar1")

	data1 := userlib.RandomBytes(4096)
	_ = u1.StoreFile("file1", data1)

	// userlib.DebugPrint = true

	m, err := u1.ShareFile("file1", "foo2")
	if err != nil {
		t.Error("Failed to share file1: ", err)
	}

	err = u2.ReceiveFile("copyOfFile1", "foo", m)
	if err != nil {
		t.Error("Failed to receive file", err)
	}

	data2, _ := u2.LoadFile("copyOfFile1", 0)

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}
	// add test cases here
}

func TestFileShareRevoke(t *testing.T) {
	userlib.KeystoreClear()
	userlib.DatastoreClear()
	u1, _ := InitUser("foo", "bar1")
	u2, _ := InitUser("foo2", "bar2")
	u3, _ := InitUser("foo3", "bar3")

	data1 := userlib.RandomBytes(4096)
	_ = u1.StoreFile("file1", data1)

	m, err := u1.ShareFile("file1", "foo2")
	if err != nil {
		t.Error("Failed to share file1: ", err)
	}

	err = u2.ReceiveFile("copyOfFile1", "foo", m)
	if err != nil {
		t.Error("Failed to receive file", err)
	}

	m, err = u2.ShareFile("copyOfFile1", "foo3")
	if err != nil {
		t.Error("Failed to share copyOfFile1: ", err)
	}

	err = u3.ReceiveFile("copyOfCopyOfFile1", "foo2", m)
	if err != nil {
		t.Error("Failed to receive file", err)
	}

	userlib.DebugPrint = true

	err = u2.RevokeFile("copyOfFile1")
	if err != nil {
		t.Error("Failed to Revoke file", err)
	}

	data2, err := u1.LoadFile("file1", 0)

	if err == nil && reflect.DeepEqual(data1, data2) {
		t.Error("Correct Data Received")
	} else {
		t.Log("data not fetched: ", err)
	}

	data2, err = u3.LoadFile("copyOfCopyOfFile1", 0)

	if err == nil && reflect.DeepEqual(data1, data2) {
		t.Error("Correct Data Received")
	} else {
		t.Log("data not fetched: ", err)
	}

	data2, err = u2.LoadFile("copyOfFile1", 0)

	if err != nil || !reflect.DeepEqual(data1, data2) {
		t.Error("Corrupt Data Received: ", err)
	} else {
		t.Log("data fetched")
	}
	// add test cases here
}

func TestFileShareRevokeMutate(t *testing.T) {
	userlib.KeystoreClear()
	userlib.DatastoreClear()
	u1, _ := InitUser("foo", "bar1")
	u2, _ := InitUser("foo2", "bar2")
	u3, _ := InitUser("foo3", "bar3")

	data1 := userlib.RandomBytes(4096)
	_ = u1.StoreFile("file1", data1)

	data2 := userlib.RandomBytes(4096)
	_ = u2.StoreFile("file2", data2)

	// m1, err := u1.ShareFile("file1", "foo3")
	// if err != nil {
	// 	t.Error("Failed to share file1: ", err)
	// }

	m2, err := u2.ShareFile("file2", "foo3")
	if err != nil {
		t.Error("Failed to share file2: ", err)
	}

	_ = u3.ReceiveFile("sameFile", "foo2", m2)
	_ = u3.ReceiveFile("sameFile", "foo2", m2)

	data3, err := u3.LoadFile("sameFile", 0)
	if err != nil || !reflect.DeepEqual(data2, data3) {
		t.Error("Corrupt Data Received: ", err)
	} else {
		t.Log("data fetched")
	}
	// add test cases here
}
