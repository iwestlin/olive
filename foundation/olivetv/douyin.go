package olivetv

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/iawia002/lux/request"

	"github.com/go-olive/olive/foundation/olivetv/model"
	"github.com/imroc/req/v3"
	jsoniter "github.com/json-iterator/go"
	"github.com/tidwall/gjson"
)

var (
	ErrCookieNotSet = errors.New("cookie not configured")
)

func init() {
	registerSite("douyin", &douyin{})
}

type douyin struct {
	base
}

func (this *douyin) Name() string {
	return "抖音"
}

func (this *douyin) Snap(tv *TV) error {
	tv.Info = &Info{
		Timestamp: time.Now().Unix(),
	}
	return this.set(tv)
}

func (this *douyin) set(tv *TV) error {
	// 获取 ttwid cookie
	ttwid, err := this.ttwid()
	if err != nil {
		return err
	}
	cookie := "ttwid=" + ttwid

	// 生成带 a_bogus 签名的请求参数
	fg := BrowserFingerprintGenerator{}
	fp := fg.GenerateFingerprint()

	params := fmt.Sprintf("aid=6383&live_id=1&device_platform=web&language=zh-CN&enter_from=web_live&cookie_enabled=true&screen_width=1920&screen_height=1080&browser_language=zh-CN&browser_platform=MacIntel&browser_name=Chrome&browser_version=108.0.0.0&web_rid=%s&Room-Enter-User-Login-Ab=0&is_need_double_stream=false", tv.RoomID)

	ab := NewABogus()
	ab.BrowserFp = fp
	finalParams, abogus := ab.GenerateAbogus(params, "")

	api := `https://live.douyin.com/webcast/room/web/enter/?` + finalParams

	resp, err := req.R().
		SetHeaders(map[string]string{
			HeaderUserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
			"referer":         "https://live.douyin.com/",
			"cookie":          cookie,
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Cache-Control":   "no-cache",
			"xBogus":          abogus,
		}).
		Get(api)
	if err != nil {
		return err
	}
	text := resp.String()

	if !strings.Contains(text, "data") {
		return errors.New("empty text = " + text)
	}

	text = gjson.Get(text, "data.data.0").String()

	// 设置房间信息（无论是否开播）
	tv.roomName = gjson.Get(text, "title").String()
	tv.streamerName = gjson.Get(text, "owner.nickname").String()

	// 抖音 status == 2 代表是开播的状态
	if gjson.Get(text, "status").String() != "2" {
		return nil
	}

	streamDataStr := gjson.Get(text, "stream_url.live_core_sdk_data.pull_data.stream_data").String()
	var streamData model.DouyinStreamData
	err = jsoniter.UnmarshalFromString(streamDataStr, &streamData)
	if err != nil {
		return err
	}
	flv := streamData.Data.Origin.Main.Flv
	hls := streamData.Data.Origin.Main.Hls
	_ = hls
	tv.streamURL = flv
	tv.roomOn = true

	return nil
}

func (this *douyin) ttwid() (string, error) {
	body := map[string]interface{}{
		"aid":           1768,
		"union":         true,
		"needFid":       false,
		"region":        "cn",
		"cbUrlProtocol": "https",
		"service":       "www.ixigua.com",
		"migrate_info":  map[string]string{"ticket": "", "source": "node"},
	}
	bytes, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	payload := strings.NewReader(string(bytes))
	resp, err := request.Request(http.MethodPost, "https://ttwid.bytedance.com/ttwid/union/register/", payload, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() // nolint
	cookie := resp.Header.Get("Set-Cookie")
	re := regexp.MustCompile(`ttwid=([^;]+)`)
	if match := re.FindStringSubmatch(cookie); match != nil {
		return match[1], nil
	}
	return "", errors.New("douyin ttwid request failed")
}
