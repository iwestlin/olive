package olivetv

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/tjfoc/gmsm/sm3"
	"golang.org/x/text/encoding/charmap"
)

// StringProcessor 字符串处理工具
type StringProcessor struct{}

func (sp StringProcessor) toCharStr(bytes []byte) string {
	// 直接使用 UTF-8 编码，与 JS 的 Buffer.from(result).toString() 行为一致
	return string(bytes)
}

func (sp StringProcessor) toCharArray(s string) []byte {
	// 使用 Latin-1 编码确保字符正确转换为字节值
	encoder := charmap.ISO8859_1.NewEncoder()
	b, _ := encoder.Bytes([]byte(s))
	return b
}

func (sp StringProcessor) GenerateRandomBytes(length int) string {
	// JS uses push(), so we need 4 bytes per iteration
	result := make([]byte, 0, length*4)
	for i := 0; i < length; i++ {
		rd := rand.Intn(10000)
		result = append(result, byte((rd&255&170)|1))
		result = append(result, byte((rd&255&85)|2))
		result = append(result, byte(((rd>>8)&170)|5))
		result = append(result, byte(((rd>>8)&85)|40))
	}
	return sp.toCharStr(result)
}

// CryptoUtility 加密工具
type CryptoUtility struct {
	salt           string
	base64Alphabet [2][]byte
	bigArray       []byte
}

func NewCryptoUtility() *CryptoUtility {
	bigArray := []byte{
		121, 243, 55, 234, 103, 36, 47, 228, 30, 231, 106, 6, 115, 95, 78, 101, 250, 207, 198, 50,
		139, 227, 220, 105, 97, 143, 34, 28, 194, 215, 18, 100, 159, 160, 43, 8, 169, 217, 180, 120,
		247, 45, 90, 11, 27, 197, 46, 3, 84, 72, 5, 68, 62, 56, 221, 75, 144, 79, 73, 161, 178, 81,
		64, 187, 134, 117, 186, 118, 16, 241, 130, 71, 89, 147, 122, 129, 65, 40, 88, 150, 110, 219,
		199, 255, 181, 254, 48, 4, 195, 248, 208, 32, 116, 167, 69, 201, 17, 124, 125, 104, 96, 83,
		80, 127, 236, 108, 154, 126, 204, 15, 20, 135, 112, 158, 13, 1, 188, 164, 210, 237, 222, 98,
		212, 77, 253, 42, 170, 202, 26, 22, 29, 182, 251, 10, 173, 152, 58, 138, 54, 141, 185, 33,
		157, 31, 252, 132, 233, 235, 102, 196, 191, 223, 240, 148, 39, 123, 92, 82, 128, 109, 57, 24,
		38, 113, 209, 245, 2, 119, 153, 229, 189, 214, 230, 174, 232, 63, 52, 205, 86, 140, 66, 175,
		111, 171, 246, 133, 238, 193, 99, 60, 74, 91, 225, 51, 76, 37, 145, 211, 166, 151, 213, 206,
		0, 200, 244, 176, 218, 44, 184, 172, 49, 216, 93, 168, 53, 21, 183, 41, 67, 85, 224, 155, 226,
		242, 87, 177, 146, 70, 190, 12, 162, 19, 137, 114, 25, 165, 163, 192, 23, 59, 9, 94, 179, 107,
		35, 7, 142, 131, 239, 203, 149, 136, 61, 249, 14, 156,
	}
	character := "Dkdpgh2ZmsQB80/MfvV36XI1R45-WUAlEixNLwoqYTOPuzKFjJnry79HbGcaStCe"
	character2 := "ckdp1h4ZKsUB80/Mfvw36XIgR25+WQAlEi7NLboqYTOPuzmFjJnryx9HVGDaStCe"

	cu := &CryptoUtility{
		salt:           "cus",
		base64Alphabet: [2][]byte{},
		bigArray:       bigArray,
	}
	cu.base64Alphabet[0] = []byte(character)
	cu.base64Alphabet[1] = []byte(character2)
	return cu
}

func (cu *CryptoUtility) Sm3ToArray(input []byte) []byte {
	// 单层 SM3
	h := sm3.New()
	h.Write(input)
	return h.Sum(nil)
}

func (cu *CryptoUtility) ParamsToArray(param string, addSalt bool) []byte {
	processed := param
	if addSalt {
		processed = processed + cu.salt
	}
	return cu.Sm3ToArray([]byte(processed))
}

func (cu *CryptoUtility) TransformBytes(valuesList []byte) []byte {
	result := make([]byte, len(valuesList))
	indexB := int(cu.bigArray[1])
	var initialValue, valueE byte
	arrayLen := len(cu.bigArray)

	for index := 0; index < len(valuesList); index++ {
		var sumInitial int
		if index == 0 {
			initialValue = cu.bigArray[indexB]
			sumInitial = int(indexB) + int(initialValue)
			cu.bigArray[1] = initialValue
			cu.bigArray[indexB] = byte(indexB)
		} else {
			sumInitial = int(initialValue) + int(valueE)
		}
		sumInitialIdx := sumInitial % arrayLen
		valueF := cu.bigArray[sumInitialIdx]
		result[index] = valuesList[index] ^ valueF

		nextIdx := (index + 2) % arrayLen
		valueE = cu.bigArray[nextIdx]
		newSumInitialIdx := (indexB + int(valueE)) % arrayLen
		initialValue = cu.bigArray[newSumInitialIdx]

		cu.bigArray[newSumInitialIdx], cu.bigArray[nextIdx] = cu.bigArray[nextIdx], cu.bigArray[newSumInitialIdx]
		indexB = newSumInitialIdx
	}
	return result
}

func (cu *CryptoUtility) Base64Encode(bytes []byte, selectedAlphabet int) string {
	alphabet := cu.base64Alphabet[selectedAlphabet]
	output := strings.Builder{}

	for i := 0; i < len(bytes); i += 3 {
		b1 := int(bytes[i])
		b2 := 0
		b3 := 0
		if i+1 < len(bytes) {
			b2 = int(bytes[i+1])
		}
		if i+2 < len(bytes) {
			b3 = int(bytes[i+2])
		}
		n := (b1 << 16) | (b2 << 8) | b3

		output.WriteByte(alphabet[(n>>18)&63])
		output.WriteByte(alphabet[(n>>12)&63])
		if i+1 < len(bytes) {
			output.WriteByte(alphabet[(n>>6)&63])
		}
		if i+2 < len(bytes) {
			output.WriteByte(alphabet[n&63])
		}
	}

	// Padding
	for output.Len()%4 != 0 {
		output.WriteByte('=')
	}
	return output.String()
}

func (cu *CryptoUtility) AbogusEncode(values []byte, selectedAlphabet int) string {
	alphabet := cu.base64Alphabet[selectedAlphabet]
	output := strings.Builder{}

	for i := 0; i < len(values); i += 3 {
		v1 := int(values[i])
		v2 := 0
		v3 := 0
		if i+1 < len(values) {
			v2 = int(values[i+1])
		}
		if i+2 < len(values) {
			v3 = int(values[i+2])
		}
		n := (v1 << 16) | (v2 << 8) | v3

		output.WriteByte(alphabet[(n >> 18) & 63])
		output.WriteByte(alphabet[(n >> 12) & 63])
		if i+1 < len(values) {
			output.WriteByte(alphabet[(n >> 6) & 63])
		}
		if i+2 < len(values) {
			output.WriteByte(alphabet[n & 63])
		}
	}

	for output.Len()%4 != 0 {
		output.WriteByte('=')
	}
	return output.String()
}

// RC4Encrypt RC4 加密
func RC4Encrypt(key []byte, plaintext string) []byte {
	S := make([]byte, 256)
	for ii := 0; ii < 256; ii++ {
		S[ii] = byte(ii)
	}
	j := 0
	for ii := 0; ii < 256; ii++ {
		j = (j + int(S[ii]) + int(key[ii%len(key)])) & 0xff
		S[ii], S[j] = S[j], S[ii]
	}

	i := 0
	j = 0
	ptBytes := []byte(plaintext)
	ct := make([]byte, len(ptBytes))

	for idx, charVal := range ptBytes {
		i = (i + 1) & 0xff
		j = (j + int(S[i])) & 0xff
		S[i], S[j] = S[j], S[i]
		k := S[(int(S[i]) + int(S[j])) & 0xff]
		ct[idx] = charVal ^ k
	}
	return ct
}

// BrowserFingerprintGenerator 浏览器指纹生成器
type BrowserFingerprintGenerator struct{}

func (fg BrowserFingerprintGenerator) GenerateFingerprint() string {
	randFn := func(min, max int) int {
		// 使用当前时间和简单哈希生成伪随机数
		seed := time.Now().UnixNano()
		seed = seed*1103515245 + 12345
		seed = seed & 0x7fffffff
		rangeSize := max - min + 1
		return min + int(int64(seed)%int64(rangeSize))
	}

	innerWidth := randFn(1024, 1920)
	innerHeight := randFn(768, 1080)
	outerWidth := innerWidth + randFn(24, 32)
	outerHeight := innerHeight + randFn(75, 90)
	screenX := 0
	screenY := []int{0, 30}[randFn(0, 1)]
	sizeWidth := randFn(1024, 1920)
	sizeHeight := randFn(768, 1080)
	availWidth := randFn(1280, 1920)
	availHeight := randFn(800, 1080)

	return fmt.Sprintf("%d|%d|%d|%d|%d|%d|0|0|%d|%d|%d|%d|%d|%d|24|24|Win32",
		innerWidth, innerHeight, outerWidth, outerHeight, screenX, screenY,
		sizeWidth, sizeHeight, availWidth, availHeight, innerWidth, innerHeight)
}

// ABogus 签名生成器
type ABogus struct {
	CryptoUtility *CryptoUtility
	UserAgent     string
	BrowserFp     string
	Options       [3]int
	PageId        int
	Aid           int
	UaKey         []byte
	SortIndex     []int
	SortIndex2    []int
}

func NewABogus() *ABogus {
	fg := BrowserFingerprintGenerator{}
	return &ABogus{
		CryptoUtility: NewCryptoUtility(),
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
		BrowserFp:     fg.GenerateFingerprint(),
		Options:       [3]int{0, 1, 14},
		PageId:        0,
		Aid:           6383,
		UaKey:         []byte{0x00, 0x01, 0x0e},
		SortIndex: []int{
			18, 20, 52, 26, 30, 34, 58, 38, 40, 53, 42, 21, 27, 54, 55, 31, 35, 57, 39, 41, 43, 22, 28,
			32, 60, 36, 23, 29, 33, 37, 44, 45, 59, 46, 47, 48, 49, 50, 24, 25, 65, 66, 70, 71,
		},
		SortIndex2: []int{
			18, 20, 26, 30, 34, 38, 40, 42, 21, 27, 31, 35, 39, 41, 43, 22, 28, 32, 36, 23, 29, 33, 37,
			44, 45, 46, 47, 48, 49, 50, 24, 25, 52, 53, 54, 55, 57, 58, 59, 60, 65, 66, 70, 71,
		},
	}
}

func (a *ABogus) GenerateAbogus(params string, body string) (string, string) {
	abDir := make(map[int]int)
	abDir[8] = 3
	abDir[18] = 44  // 这个值 JS 中有设置
	abDir[66] = 0
	abDir[69] = 0
	abDir[70] = 0
	abDir[71] = 0

	startEncryption := time.Now().UnixMilli()

	// Hash(Hash(params))
	paramsHash1 := a.CryptoUtility.ParamsToArray(params, true)
	array1 := a.CryptoUtility.Sm3ToArray(paramsHash1)

	// Hash(Hash(body))
	bodyHash1 := a.CryptoUtility.ParamsToArray(body, true)
	array2 := a.CryptoUtility.Sm3ToArray(bodyHash1)

	// Hash(Base64(RC4(user_agent)))
	rc4Ua := RC4Encrypt(a.UaKey, a.UserAgent)
	uaB64 := a.CryptoUtility.Base64Encode(rc4Ua, 1)
	array3 := a.CryptoUtility.ParamsToArray(uaB64, false)

	endEncryption := time.Now().UnixMilli()

	// Dynamic fill abDir
	abDir[20] = int((startEncryption >> 24) & 0xff)
	abDir[21] = int((startEncryption >> 16) & 0xff)
	abDir[22] = int((startEncryption >> 8) & 0xff)
	abDir[23] = int(startEncryption & 0xff)
	abDir[24] = int(math.Floor(float64(startEncryption) / 0x100000000))
	abDir[25] = int(math.Floor(float64(startEncryption) / 0x10000000000))

	abDir[26] = int((a.Options[0] >> 24) & 0xff)
	abDir[27] = int((a.Options[0] >> 16) & 0xff)
	abDir[28] = int((a.Options[0] >> 8) & 0xff)
	abDir[29] = int(a.Options[0] & 0xff)

	abDir[30] = int(math.Floor(float64(a.Options[1]) / 256)) & 0xff
	abDir[31] = a.Options[1] % 256
	abDir[32] = int((a.Options[1] >> 24) & 0xff)
	abDir[33] = int((a.Options[1] >> 16) & 0xff)

	abDir[34] = int((a.Options[2] >> 24) & 0xff)
	abDir[35] = int((a.Options[2] >> 16) & 0xff)
	abDir[36] = int((a.Options[2] >> 8) & 0xff)
	abDir[37] = int(a.Options[2] & 0xff)

	abDir[38] = int(array1[21])
	abDir[39] = int(array1[22])
	abDir[40] = int(array2[21])
	abDir[41] = int(array2[22])
	abDir[42] = int(array3[23])
	abDir[43] = int(array3[24])

	abDir[44] = int((endEncryption >> 24) & 0xff)
	abDir[45] = int((endEncryption >> 16) & 0xff)
	abDir[46] = int((endEncryption >> 8) & 0xff)
	abDir[47] = int(endEncryption & 0xff)
	abDir[48] = abDir[8]
	abDir[49] = int(math.Floor(float64(endEncryption) / 0x100000000))
	abDir[50] = int(math.Floor(float64(endEncryption) / 0x10000000000))

	abDir[51] = int((a.PageId >> 24) & 0xff)
	abDir[52] = int((a.PageId >> 16) & 0xff)
	abDir[53] = int((a.PageId >> 8) & 0xff)
	abDir[54] = int(a.PageId & 0xff)
	abDir[55] = a.PageId
	abDir[56] = a.Aid
	abDir[57] = int(a.Aid & 0xff)
	abDir[58] = int((a.Aid >> 8) & 0xff)
	abDir[59] = int((a.Aid >> 16) & 0xff)
	abDir[60] = int((a.Aid >> 24) & 0xff)

	abDir[64] = len(a.BrowserFp)
	abDir[65] = len(a.BrowserFp)

	sortedValues := make([]byte, len(a.SortIndex))
	for i, idx := range a.SortIndex {
		sortedValues[i] = byte(abDir[idx])
	}

	sp := StringProcessor{}
	fpArray := sp.toCharArray(a.BrowserFp)

	abXor := 0
	for idx, key := range a.SortIndex2 {
		val := abDir[key]
		if idx == 0 {
			abXor = val
		} else {
			abXor ^= val
		}
	}

	allValues := append(sortedValues, fpArray...)
	allValues = append(allValues, byte(abXor))
	transformedValues := a.CryptoUtility.TransformBytes(allValues)

	randomPrefix := []byte(sp.GenerateRandomBytes(3))
	finalValues := append(randomPrefix, transformedValues...)
	abogus := a.CryptoUtility.AbogusEncode(finalValues, 0)
	finalParams := params + "&a_bogus=" + abogus

	return finalParams, abogus
}

// GenerateAbogusWithFP 使用指定的 fingerprint 生成 a_bogus
func GenerateAbogusWithFP(params string, fp string) (string, string) {
	ab := NewABogus()
	ab.BrowserFp = fp
	return ab.GenerateAbogus(params, "")
}

// GenerateDouyinParams 生成抖音请求参数
func GenerateDouyinParams(roomID string) (string, string, error) {
	// 生成随机指纹
	fg := BrowserFingerprintGenerator{}
	fp := fg.GenerateFingerprint()

	params := fmt.Sprintf("aid=6383&live_id=1&device_platform=web&language=zh-CN&enter_from=web_live&cookie_enabled=true&screen_width=1920&screen_height=1080&browser_language=zh-CN&browser_platform=MacIntel&browser_name=Chrome&browser_version=108.0.0.0&web_rid=%s&Room-Enter-User-Login-Ab=0&is_need_double_stream=false", roomID)

	ab := NewABogus()
	ab.BrowserFp = fp
	finalParams, abogus := ab.GenerateAbogus(params, "")

	return finalParams, abogus, nil
}
