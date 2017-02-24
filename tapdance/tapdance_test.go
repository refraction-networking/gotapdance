package tapdance

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const key_path = "/home/sfrolov/go/src/github.com/SergeyFrolov/gotapdance/assets/"

func asTestHandshakeLaunchProxy(t *testing.T) {
	// hangs, as it fails to read anything from nc
	// TODO: check if got an expected result during a handshake
	var errChan = make(chan error, 0)
	go func() {
		// exec, because has to be different process
		time.Sleep(time.Second * 5)
		grepCmd := exec.Command("wget", "-e", "use_proxy=yes", "-e", "127.0.0.1:10500", "https://twitter.com")
		grepOut, _ := grepCmd.StdoutPipe()
		grepCmd.Start()
		grepBytes, err := ioutil.ReadAll(grepOut)
		errChan <- err
		grepCmd.Wait()
		fmt.Println(grepBytes)
	}()
	tap_dance_proxy := NewTapdanceProxy(10500)
	go func() {
		err := tap_dance_proxy.Listen()
		errChan <- err
	}()
	err := <-errChan
	tap_dance_proxy.Stop()
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
}

func TestObfuscate(t *testing.T) {
	for i := 0; i < 1; i++ {
		var randStr []byte = make([]byte, 186)
		rand.Read(randStr)
		obfuscated, err := obfuscateTag(randStr, td_station_pubkey)
		if err != nil {
			Logger.Errorf("Error: ", err.Error())
			os.Exit(1)
		} else {
			printHex(obfuscated, "obfuscated")
		}
	}
}

func TestAES_GCM_EncryptDecrypt(t *testing.T) {
	iv, _ := hex.DecodeString("156738805e207a6f2c50413a")
	key, _ := hex.DecodeString("13c8ff335b01aaf970cbc7b7e3072249")
	plaintext, _ := hex.DecodeString("560b81b86b1f30da6d66a982310be6af471f2e9de248a58aa2731bd9b746532c98666d9e9963b1d02ec1d759c228f599411229cd98f2bfd71ad6007f71e4d6bc20a3e2a00322df06159536534480ec97288929dc87cbd658c49894d40b1997292bfa720625e18661fa66999cf4e7030c8bf4cfbe15d77d47c13d5236a8c797e95e80df9d7af6730d35f9a7aa9f5e478b739516bd6e0e5e64dcbc6cda669fdc5f0efbac5e23b25a3ad91e005e276d39438285bfe00c3b53b33f7127becc49ff9825d78f3cab06d315e22aea83a12cb69547d40a5d36c1d5cd288efc678a627cab2583c80f1d81bc3e3d27a4bd")
	expectedCryptotext, _ := hex.DecodeString("8ba27bd00b04ec8c8448d517d444b732e8e7179153eaaa9ffdddc8733d88e97dd86fee5eedf96395ba6bfbf98e0e9c74e72baa90ad0271fb621500eb9e15a0c984aa9c886db3f4cb1aab16b42aad4be78b477e9b57ada945fe7e3eb063bf0aff1800d9ec5a9c3be895ef0b785165a592f18fdf3184d167db2be93cd4b6e5e8dd533ee3bca05e19abea75d50aa68fa1ffd2da37090f6e73e94b1372ea2585eabd8f9c388d1cb4e058bbc72e2cd2d286135665944d0bd99bfea1ec06213ffd451252cf16b13828eee7e5688ad78d959d6447c841d4f52e58eac03baab1f2ba86f6fd0a9e68ac0e4d375a764507229a075d0e87661d84887a6d74d71297")

	cryptotext, err := AesGcmEncrypt(plaintext, key, iv)
	if err != nil {
		t.Fatalf(err.Error())
	}
	rePlaintext, err := AesGcmDecrypt(cryptotext, key, iv)

	printHex(iv, "iv")
	printHex(key, "key")
	printHex(plaintext, "plaintext")
	printHex(rePlaintext, "re_plaintext")
	printHex(cryptotext, "cryptotext")

	if err != nil {
		t.Fatalf(err.Error())
	}

	if strings.Compare(string(plaintext), string(rePlaintext)) != 0 {
		fmt.Println("Decrypt(Encrypt(text)) != text")
		t.Fail()
	}

	if strings.Compare(string(cryptotext), string(expectedCryptotext)) != 0 {
		fmt.Println("Encrypt(text) != expected_cryptotext")
		t.Fail()
	}

}

func TestReverseEncrypt(t *testing.T) {
	tag := []byte{192, 165, 165, 138, 112, 105, 67, 167, 10, 78, 204, 32, 77, 236, 146, 173, 91, 175, 146, 53, 43, 15, 69, 55, 133, 158, 89, 221, 140, 12, 117, 34, 155, 231, 154, 103, 195, 18, 139, 225, 245, 92, 240, 135, 121, 95, 51, 38, 110, 231, 27, 218, 38, 127, 128, 35, 170, 52, 162, 219, 27, 24, 249, 191, 194, 251, 188, 93, 85, 211, 229, 150, 151, 189, 34, 252, 105, 173, 227, 169, 97, 191, 137, 37, 110, 235, 72, 170, 99, 143, 98, 201, 2, 80, 226, 224, 2, 143, 7, 116, 26, 29, 199, 232, 112, 105, 209, 37, 55, 108, 161, 205, 10, 43, 172, 78, 169, 94, 44, 130, 201, 232, 192, 37, 1, 127, 33, 89, 183, 114, 83, 210, 122, 132, 135, 242, 96, 115, 61, 147, 41, 179, 237, 34, 72, 153, 81, 47, 11, 117, 95, 224, 60, 198, 211, 181, 221, 185, 117, 3, 172, 6, 189, 90, 237, 81, 147, 118, 8, 31, 165, 59, 143, 60, 120, 39, 228, 156, 199, 166, 140, 165, 241, 150, 242, 198}
	keystream := []byte{246, 204, 136, 183, 208, 201, 249, 218, 131, 117, 96, 249, 155, 7, 222, 35, 221, 95, 82, 237, 27, 90, 158, 165, 132, 44, 1, 229, 127, 116, 20, 135, 203, 220, 175, 224, 16, 136, 75, 172, 14, 20, 128, 238, 168, 192, 231, 133, 209, 154, 71, 205, 161, 135, 195, 135, 9, 66, 207, 28, 238, 90, 252, 4, 121, 229, 79, 84, 246, 167, 123, 187, 73, 65, 97, 219, 229, 93, 188, 135, 236, 84, 230, 5, 207, 105, 254, 181, 177, 68, 222, 192, 190, 182, 177, 33, 252, 118, 161, 101, 60, 35, 233, 36, 22, 242, 198, 8, 20, 151, 249, 172, 207, 58, 95, 110, 19, 84, 169, 17, 185, 3, 120, 102, 48, 13, 40, 238, 150, 10, 174, 204, 0, 144, 21, 250, 4, 39, 211, 85, 164, 90, 12, 104, 43, 130, 224, 77, 113, 79, 142, 97, 205, 71, 156, 211, 73, 42, 51, 169, 30, 81, 132, 85, 217, 18, 151, 184, 166, 32, 188, 0, 170, 67, 80, 80, 253, 165, 42, 5, 6, 27, 72, 62, 57, 7, 174, 156, 198, 72, 224, 132, 199, 175, 28, 175, 193, 17, 242, 143, 4, 152, 83, 205, 50, 26, 171, 28, 27, 190, 226, 5, 214, 152, 232, 131, 212, 104, 186, 219, 178, 172, 234, 35, 1, 177, 25, 79, 79, 166, 185, 85, 167, 110, 88, 114, 49, 201, 163, 201, 20, 139, 106, 125, 151, 191, 47, 160, 254, 34, 173, 229}
	result := reverseEncrypt(tag, keystream)
	expected_result := "FF^RrnxsSO|sHknCNA`pOpJ`OUN|@@pjEVygP{`SFJuQyNbakMFYXV[uJReyipbbKSO@EbDiCoqhWw\\jeE|`UuN^AkUJHgwYMUGCeOInHci{o]ITTrfyrg^ao\\ddCcNVbRK]Q}guYre~GHMftRlB_fJfCfz^HAklOgUPBRGnuZwvf_BcMxBz}IMv^bujvTfUfy~Ja_zSfSqCweileGpVbXE{}QvfugUCpgjA^EiylGVVE}owA}LrPdf"
	if strings.Compare(expected_result, result) != 0 {
		fmt.Println("expected_result != result")
		fmt.Println("result: ", result)
		fmt.Println("expected_result: ", expected_result)

		t.Fail()
	}
}

func TestGetRandInt(t *testing.T) {
	n_values := 20000
	results := make([]int, n_values)
	fmt.Println("Generating", n_values, " values between 6 and 14")
	var avg int
	for i := 0; i < n_values; i++ {
		n := getRandInt(0, 14)
		results[i] = n
		avg += n
	}
	// fmt.Println("Values are:", results)
	fmt.Println("Average:", float64(avg)/float64(n_values))

}
