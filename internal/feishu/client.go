package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/int-wc/dlp-agent-gateway/internal/store"
)

const officialBaseURL = "https://open.feishu.cn"

// These names are documented behavior-audit events that can indicate an
// export, download, share, or permission change. They are observations, not
// content inspection results or confirmed policy violations.
var supportedEvents = map[string]bool{
	"space_export_doc":               true,
	"space_download_file":            true,
	"space_front_export_csv":         true,
	"space_share_to_3rdApp":          true,
	"space_update_collaborator_doc":  true,
	"space_update_share_setting_doc": true,
	"space_print_doc":                true,
	"space_copy_content":             true,
	"im_forward_file":                true,
	"im_chat_uploadfile":             true,
	"im_download_file":               true,
	"email_batchexport":              true,
	"email_downloadfile":             true,
	"email_editforward":              true,
	"email_sharefile":                true,
	"vc_exportmeta":                  true,
}

type Client struct {
	appID     string
	appSecret string
	baseURL   string
	http      *http.Client
}

func New(appID, appSecret string) (*Client, error) {
	if appID == "" || appSecret == "" {
		return nil, errors.New("Feishu app ID and secret are required")
	}
	return &Client{
		appID: appID, appSecret: appSecret, baseURL: officialBaseURL,
		http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func (c *Client) token(ctx context.Context) (string, error) {
	body, err := json.Marshal(map[string]string{"app_id": c.appID, "app_secret": c.appSecret})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/open-apis/auth/v3/tenant_access_token/internal", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := c.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("Feishu token request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Feishu token HTTP status %d", response.StatusCode)
	}
	var result struct {
		Code  int    `json:"code"`
		Token string `json:"tenant_access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 32*1024)).Decode(&result); err != nil {
		return "", errors.New("invalid Feishu token response")
	}
	if result.Code != 0 || result.Token == "" {
		return "", fmt.Errorf("Feishu token API code %d", result.Code)
	}
	return result.Token, nil
}

// Fetch reads one bounded, paginated window. Only the minimal projection of
// selected behavior-audit events is returned to the storage layer.
func (c *Client) Fetch(ctx context.Context, start, end time.Time) ([]store.FeishuEvent, int, error) {
	if !start.Before(end) || end.Sub(start) > 24*time.Hour {
		return nil, 0, errors.New("Feishu audit window must be within 24 hours")
	}
	token, err := c.token(ctx)
	if err != nil {
		return nil, 0, err
	}
	items := []store.FeishuEvent{}
	pageToken := ""
	seenTokens := map[string]bool{}
	for page := 1; page <= 50; page++ {
		endpoint, err := url.Parse(c.baseURL + "/open-apis/admin/v1/audit_infos")
		if err != nil {
			return nil, page - 1, err
		}
		query := endpoint.Query()
		query.Set("oldest", strconv.FormatInt(start.Unix(), 10))
		query.Set("latest", strconv.FormatInt(end.Unix(), 10))
		query.Set("page_size", "200")
		query.Set("user_id_type", "open_id")
		if pageToken != "" {
			query.Set("page_token", pageToken)
		}
		endpoint.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, page - 1, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := c.http.Do(request)
		if err != nil {
			return nil, page - 1, fmt.Errorf("Feishu audit request failed: %w", err)
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return nil, page - 1, fmt.Errorf("Feishu audit HTTP status %d", response.StatusCode)
		}
		var result struct {
			Code int `json:"code"`
			Data struct {
				HasMore   bool   `json:"has_more"`
				PageToken string `json:"page_token"`
				Items     []struct {
					UniqueID      string `json:"unique_id"`
					EventName     string `json:"event_name"`
					EventModule   int    `json:"event_module"`
					OperatorType  int    `json:"operator_type"`
					OperatorValue string `json:"operator_value"`
					EventTime     int64  `json:"event_time"`
					Objects       []struct {
						ObjectType  string `json:"object_type"`
						ObjectValue string `json:"object_value"`
					} `json:"objects"`
				} `json:"items"`
			} `json:"data"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(&result)
		response.Body.Close()
		if decodeErr != nil {
			return nil, page - 1, errors.New("invalid Feishu audit response")
		}
		if result.Code != 0 {
			return nil, page - 1, fmt.Errorf("Feishu audit API code %d", result.Code)
		}
		for _, raw := range result.Data.Items {
			if !supportedEvents[raw.EventName] {
				continue
			}
			if raw.UniqueID == "" || len(raw.UniqueID) > 256 || raw.EventTime <= 0 {
				return nil, page - 1, errors.New("invalid Feishu audit event identity")
			}
			item := store.FeishuEvent{
				UniqueID: raw.UniqueID, EventTime: time.Unix(raw.EventTime, 0).UTC().Format(time.RFC3339),
				EventName: raw.EventName, EventModule: raw.EventModule,
				OperatorType: raw.OperatorType, OperatorValue: limitRunes(raw.OperatorValue, 256),
			}
			if len(raw.Objects) > 0 {
				item.ObjectType = limitRunes(raw.Objects[0].ObjectType, 128)
				item.ObjectValue = limitRunes(raw.Objects[0].ObjectValue, 256)
			}
			items = append(items, item)
		}
		if !result.Data.HasMore {
			return items, page, nil
		}
		if result.Data.PageToken == "" || seenTokens[result.Data.PageToken] {
			return nil, page, errors.New("invalid Feishu audit pagination token")
		}
		seenTokens[result.Data.PageToken] = true
		pageToken = result.Data.PageToken
	}
	return nil, 50, errors.New("Feishu audit window exceeded 50 pages")
}

func limitRunes(value string, max int) string {
	runes := []rune(value)
	if len(runes) > max {
		return string(runes[:max])
	}
	return value
}
