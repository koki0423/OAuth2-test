package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v2"
)

// --- グローバル変数と定数 ---

var (
	googleOauthConfig *oauth2.Config
	// 簡易的なセッションストア
	sessions = map[string]sessionData{}
	mutex    = &sync.Mutex{}
)

var (
	oauthStateString  = "random-string-for-security"
	sessionCookieName = "go_oauth_session"

	// 疑似的な管理者として扱うメールアドレス
	// OAuthでログインしたメールアドレスにするとそれが管理者として扱われる
	adminEmail = ""
)

// --- 構造体定義 ---

// Googleから取得するユーザー情報
type UserInfo struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// サーバーで保持するセッションデータ
type sessionData struct {
	UserInfo UserInfo
	IsAdmin  bool
}

type Config struct {
	Version      string `yaml:"version"`
	AdminEmail   string `yaml:"admin_email"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// --- 初期化処理 ---

func init() {
	config, err := initConfig()
	if err != nil {
		log.Fatalf("設定の読み込みに失敗しました: %v", err)
		return
	}

	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	adminEmail = config.AdminEmail
}

func initConfig() (Config, error) {
	// config.yamlから設定を読み込む
	config := Config{}
	b, err := os.ReadFile("config.yaml")
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}
	yaml.Unmarshal(b, &config)

	return config, nil
}

// --- main関数: サーバー起動とルーティング ---

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleGoogleLogin)
	http.HandleFunc("/callback", handleGoogleCallback)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/user", handleUserPage)
	http.HandleFunc("/admin", handleAdminPage)

	fmt.Println("サーバーを起動しました: http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// --- ハンドラ関数 ---

// "/" トップページ（ログイン前・後で表示切替）
func handleMain(w http.ResponseWriter, r *http.Request) {
	session, ok := getSession(r)

	// 未ログインの場合
	if !ok {
		html := `
		<html><body>
			<h2>ようこそ</h2>
			<p>Googleアカウントでログインしてください。</p>
			<a href="/login" style="font-size: 1.2em; padding: 10px; background-color: #4285F4; color: white; text-decoration: none; border-radius: 5px;">Google Log In</a>
		</body></html>`
		fmt.Fprint(w, html)
		return
	}

	// ログイン済みの場合
	// 管理者かどうかで表示を切り替える
	role := "一般ユーザー"
	adminLink := ""
	if session.IsAdmin {
		role = "管理者"
		adminLink = `<li><a href="/admin">管理者専用ページ</a></li>`
	}

	html := fmt.Sprintf(`
	<html><body>
		<h2>ログイン成功</h2>
		<p>こんにちは, %s さん (%s)</p>
		<p>あなたの権限: <strong>%s</strong></p>
		<ul>
			<li><a href="/user">利用者ページ</a></li>
			%s
		</ul>
		<br>
		<a href="/logout">ログアウト</a>
	</body></html>`, session.UserInfo.Name, session.UserInfo.Email, role, adminLink)
	fmt.Fprint(w, html)
}

// "/login" Googleの認証ページへリダイレクト
func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// "/callback" Googleからのリダイレクト先
func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// stateの検証
	if r.FormValue("state") != oauthStateString {
		fmt.Println("invalid oauth state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// codeからトークンを取得
	token, err := googleOauthConfig.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		fmt.Printf("code exchange failed: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// トークンを使ってユーザー情報を取得
	userInfo, err := getUserInfoFromGoogle(token)
	if err != nil {
		fmt.Printf("failed getting user info: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// セッションを作成・保存
	sessionID := createSession(userInfo)

	// CookieにセッションIDをセット
	http.SetCookie(w, &http.Cookie{
		Name:    sessionCookieName,
		Value:   sessionID,
		Expires: time.Now().Add(24 * time.Hour),
		Path:    "/",
	})

	// トップページへリダイレクト
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// "/logout" ログアウト処理
func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		// セッションストアから削除
		mutex.Lock()
		delete(sessions, cookie.Value)
		mutex.Unlock()
	}

	// Cookieを無効化
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		MaxAge: -1, // 即時削除
		Path:   "/",
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// "/user" ログインユーザー向けページ
func handleUserPage(w http.ResponseWriter, r *http.Request) {
	session, ok := getSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	html := fmt.Sprintf(`
	<html><body>
		<h1>利用者専用ページ</h1>
		<p>こんにちは, %s さん！</p>
		<p>このページはログインしているユーザーなら誰でも見ることができます。</p>
		<a href="/">トップに戻る</a>
	</body></html>`, session.UserInfo.Name)
	fmt.Fprint(w, html)
}

// "/admin" 管理者専用ページ
func handleAdminPage(w http.ResponseWriter, r *http.Request) {
	session, ok := getSession(r)
	// ログインしていない、または管理者でない場合はアクセス拒否
	if !ok || !session.IsAdmin {
		http.Error(w, "アクセス権がありません (Forbidden)", http.StatusForbidden)
		return
	}

	html := fmt.Sprintf(`
	<html><body>
		<h1>👑 管理者専用ページ</h1>
		<p>ようこそ, 管理者の %s さん！</p>
		<p>このページは特別な権限を持つあなただけが見ることができます。</p>
		<a href="/">トップに戻る</a>
	</body></html>`, session.UserInfo.Name)
	fmt.Fprint(w, html)
}

// --- ヘルパー関数 ---

// Google APIからユーザー情報を取得
func getUserInfoFromGoogle(token *oauth2.Token) (*UserInfo, error) {
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	var userInfo UserInfo
	err = json.Unmarshal(contents, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %s", err.Error())
	}

	return &userInfo, nil
}

// 新しいセッションを作成し、セッションIDを返す
func createSession(userInfo *UserInfo) string {
	sessionID, _ := generateRandomString(32)
	isAdmin := userInfo.Email == adminEmail

	mutex.Lock()
	sessions[sessionID] = sessionData{
		UserInfo: *userInfo,
		IsAdmin:  isAdmin,
	}
	mutex.Unlock()

	return sessionID
}

// リクエストからセッション情報を取得
func getSession(r *http.Request) (sessionData, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return sessionData{}, false
	}

	mutex.Lock()
	session, ok := sessions[cookie.Value]
	mutex.Unlock()

	return session, ok
}

// 安全なランダム文字列を生成
func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
