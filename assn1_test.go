package assn1

import "github.com/sarkarbidya/CS628-assn1/userlib"
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUser(t *testing.T) {
	t.Log("Initialization test")
	// userlib.DebugPrint = true
	_, err1 := InitUser("", "")
	if err1 != nil {
		t.Log("Failed to initialize invalid user")
	} else {
		t.Error("Initialized invalid user")
	}

	_, err1 = InitUser("foo", "bar")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
	} else {
		t.Log("Successfully initialized user")
	}
	// add more test cases here
}

func TestUserStorage(t *testing.T) {
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
	_, _ = InitUser("foo", "bar")
	u1, _ := GetUser("foo", "bar")

	userlib.DebugPrint = true

	data1 := userlib.RandomBytes(4096)
	_ = u1.StoreFile("file1", data1)

	data2, _ := u1.LoadFile("file1", 0)

	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}

	// add test cases here
}

func TestFileShareReceive(t *testing.T) {
	userlib.DebugPrint = true
	// add test cases here
}
