# 網頁資訊安全處理筆記

## SQL Injection

>注入攻擊實作：
>在 Textbox 內輸入字串內容 ` ' OR '1'='1 `
>或是 ` '; DROP TABLE Employees; `

**防範措施：**

- 參數化查詢。而不是使用「組字串」的方式來執行SQL。
- 對輸入的數據進行驗證，以確保數據符合預期的格式或範圍。

>[什麼是 SQL Injection？該如何避免？](https://www.explainthis.io/zh-hant/swe/sql-injection)

## Poor Error Handling: Unhandled Exception

在程式碼中，應該改善錯誤處理，以避免未處理的例外情況，並提供更友好和有用的錯誤訊息。

**防範措施：**

- 在程式碼中使用 try-catch 區塊，以捕獲可能發生的例外情況。
- 在 catch 區塊中，應該適當地記錄錯誤訊息，並向使用者提供有用的錯誤訊息，以便他們理解問題所在。
- 可以使用 ASP.NET 的全局錯誤處理事件（Application_Error）來捕獲未處理的例外情況，並將它們記錄下來或顯示自定義的錯誤頁面。

這些修改將幫助改善網頁伺服器的配置安全性和錯誤處理，使程式碼更堅固和安全。請按照上述建議進行修改後，重新審查程式碼並測試確保正常運作。

## Cross-Site Scripting: Reflected

跨站腳本攻擊(Cross-Site Scripting, XSS)：反射型

>黑箱掃描工具的攻擊實作：
>
>- `https://xxx.com/InventoryMgmt/Home/(A(WeBiNsPeCt))/Index`
>- `https://xxx.com/InventoryMgmt/Home/(A())/Index`
>
>正常的網址應該是
>
>- `https://xxx.com/InventoryMgmt/Home/Index`

**防範措施：**
在 Global.asax.cs 內加入程式嗎

```csharp=
protected void Application_BeginRequest(object sender, EventArgs e)
{
    // 到這時，Url 已被改成沒包含 SessionId
    // 但它的值會放在 Response._appPathModifier 變數之中
    FieldInfo appPathModifierFieldInfo = Context.Response.GetType().GetField("_appPathModifier", BindingFlags.NonPublic | BindingFlags.Instance);
    object appPathModifier = appPathModifierFieldInfo.GetValue(Context.Response);
    if (appPathModifier != null)
    {
        // Url 中有 SessionId
        throw new HttpException(404, "Not found");
    }

    // deny HTTP GET with request body
    if (Request.HttpMethod == "GET" && Request.ContentLength > 0)
    {
        throw new HttpException(403, "Forbidden");
    }
}
```

>- [為什麼 Url 中有 (A(XXXX)) 在 ASP.NET 中，卻不會噴 404 或是錯誤，反而回正常的頁面(200)呢?](https://rainmakerho.github.io/2020/11/11/aspnet-cookieless-url/)

## Reflected XSS All Clients

主要透過用戶發出惡意的請求，倘若後端沒有過濾而直接將結果回傳前端的話，就有可能執行到惡意的程式碼。

**防範措施：**

```csharp=
using Ganss.Xss; // NuGet 加入 HtmlSanitizer 套件

#region XSS 的第一道防線：Sanitization (AntiXSS，HtmlSanitizer)

/// <summary>
/// 通過使用 HtmlSanitizer 來過濾輸入字串，再 HtmlEncode 以防止跨站腳本（XSS）攻擊。
/// </summary>
public static string SanitizeHtmlEncode(string inputStr)
{
    if (string.IsNullOrWhiteSpace(inputStr))
        return string.Empty;

    var sanitizer = new HtmlSanitizer();
    //sanitizer.AllowedAttributes.Add("class");
    //sanitizer.AllowedAttributes.Add("id");
    //sanitizer.AllowedSchemes.Add("mailto"); // 允許 <a href="mailto:"

    // 使用 HtmlSanitizer 進行消毒處理 (https://github.com/mganss/HtmlSanitizer)
    string sanitized = sanitizer.Sanitize(inputStr);
    string encoded = HttpUtility.HtmlEncode(sanitized);

    return encoded;
}

/// <summary>
/// 在數據輸出到網頁時進行欄位內容過濾，以防止儲存型跨網站指令碼（Stored XSS）攻擊。
/// </summary>
public static DataTable SanitizeHtmlEncodeInDataTable(DataTable dataTable)
{
    foreach (DataRow row in dataTable.Rows)
    {
        foreach (DataColumn column in dataTable.Columns)
        {
            if (row[column] != DBNull.Value && !column.ReadOnly)
            {
                row[column] = SanitizeHtmlEncode(row[column].ToString());
            }
        }
    }
    return dataTable;
}

#endregion XSS 的第一道防線：Sanitization (AntiXSS，HtmlSanitizer)
```

## Reflected XSS Specific Clients

**防範措施：**
同 Reflected XSS All Clients

## Stored XSS

被保存在資料庫中的 Javascript 引起的攻擊稱為 Stored XSS。
最常見的就是文章、留言等，因為用戶可以任意輸入內容，若沒有檢查，則 `<script>` 等標籤就會被視為正常的 HTML 做執行。

**防範措施：**
Reflected XSS All Clients 的 `SanitizeHtmlEncodeInDataTable` 方法

## Code Injection

>漏洞描述：
>用 Invoke 動態執行 Web service URL

**防範措施：**
透過加入 Web 參考，以靜態的方式連線 Web service

## Cross-Frame Scripting

>攻擊實作：
>[Clickjacking 點擊劫持攻擊](https://blog.huli.tw/2021/09/26/what-is-clickjacking/)

**防範措施：**

- [X-Frame-Options](https://a42033.gitbooks.io/system/content/security/user/X_Frame_Options.html)

```xml
<add name="X-Frame-Options" value="SAMEORIGIN" />
```

- 內容安全策略(Content-Security-Policy, CSP)

```xml
<add name="Content-Security-Policy" value="child-src 'self';" />
```

```xml!
<add name="Content-Security-Policy" value="frame-ancestors 'self' tw.yahoo.com www.google.com;" />
```

iframe_test.html 舉證、驗證

```html=
<!DOCTYPE html>
<html>
<head>
    <title>iframe test</title>
</head>
<body>
    <h1>iframe test</h1>
    <iframe src="要嵌入的網頁網址" width="600px" height="400px" frameborder="0" scrolling="no"></iframe>
</body>  
</html>
```

## HTML5: Missing Content Security Policy

HTML5 引入了 Content-Security-Policy（CSP），這是一種用於增強網站安全性的機制。
當網站沒有設定 Content-Security-Policy 時，就稱為 Missing Content Security Policy。

**防範措施：**

- [內容安全策略(Content-Security-Policy, CSP)](https://content-security-policy.com/)

>Google 提供的網站：[CSP Evaluator](https://csp-evaluator.withgoogle.com/)，它會偵測你的 CSP 是否有錯誤，以及是不是安全。

## HTML5: Overly Permissive Message Posting Policy

HTML5 的新機制 Message Posting Policy 主要是指跨文件通訊的設定規則。這個機制允許使用 Script 腳本在不同窗口或框架之間傳送消息。在設定這個機制時，使用者可以指定目標窗口的來源，以確保只有特定合法來源的窗口才能接收消息。
當 Message Posting Policy 過於寬鬆時，也就是認為了使用不當而導致安全風險的情況下，就稱為 Overly Permissive Message Posting Policy。

JavaScript/TypeScript:

```javascript
o.contentWindow.postMessage(message, '*');
```

使用 `*` 做為目標來源值，代表 Script 會傳送訊息至視窗而不論其來源。

**防範措施：**

- 不要使用萬用字元 `*`，改為指定目標窗口的來源。

## HTML5: CORS Functionality Abuse

同 Cache Management: Headers

## Web Server Misconfiguration: Insecure Content-Type Setting

**防範措施：**

```xml
<add name="X-Content-Type-Options" value="nosniff" />
```

## Insecure Transport: HSTS not Set

HTTP Strict-Transport-Security 回應標頭 (HSTS) 告知瀏覽器該站點應僅使用 HTTPS 訪問，並且所有將來的 HTTP 訪問應自動轉換為 HTTPS。

**防範措施：**

```xml
<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
```

## ASP.NET Misconfiguration: Missing Error Handling

Web.config 檢測到

```xml
<customErrors mode="Off" />
```

**防範措施：**

```xml
<customErrors mode="On" defaultRedirect="Errors/ErrorPage.aspx">
  <error statusCode="404" redirect="Errors/NotFound.aspx" />
  <error statusCode="500" redirect="Errors/ServerError.aspx" />
</customErrors>
```

## Compliance Failure: Missing Privacy Policy

對掃描範圍內可存取的所有網頁進行採樣，以取得通常構成隱私權政策聲明的文字內容。
**解決方法：**

- 新增隱私權政策（Privacy Policy）的靜態頁面。

## Cache Management: Headers

```xml
<!-- CORS_Origins 因應資訊安全「同源政策」，請加入主機網域網址(含開發機, 測試機, 正式機)。若未加入會顯示 HTTP ERROR 403 -->
<add key="CORS_Origins" value="http://主機網域網址1, https://主機網域網址1, http://主機網域網址2, https://主機網域網址2" />

```

```csharp=
protected void Application_BeginRequest(object sender, EventArgs e)
{
    /** 修復資訊安全漏洞 
     * Cache Management: Headers
     * HTML5: CORS Functionality Abuse
     */
    string cors_origins = ConfigurationManager.AppSettings["CORS_Origins"] ?? "";

    // 允許的來源列表
    var allowedOrigins = new List<string>(cors_origins.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
    // 去除字串前後的空白
    allowedOrigins = allowedOrigins.ConvertAll(o => o.Trim());

    HttpContext context = HttpContext.Current;
    string origin = context.Request.Headers["Origin"];

    // 如果是非跨域請求（沒有 Origin），跳過 CORS 驗證
    if (string.IsNullOrEmpty(origin))
    {
        return; // 直接返回，不執行 CORS 邏輯
    }

    // 檢查來源
    if (allowedOrigins.Contains(origin))
    {
        // 設置 CORS 標頭
        context.Response.AddHeader("Access-Control-Allow-Origin", origin);
        context.Response.AddHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        context.Response.AddHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    }
    else
    {
        context.Response.StatusCode = 403; // 禁止訪問
        //Logger.Warn($"未授權的 CORS 來源: {origin}");
        context.Response.End();
        return;
    }

    // 處理 OPTIONS 方法
    if (context.Request.HttpMethod == "OPTIONS")
    {
        context.Response.End();
    }           
}
```

## Cache Management: Insecure Policy

不安全的快取策略可能允許攻擊者進行內容欺騙或資訊竊取攻擊。

>瀏覽器 F12 進入開發人員畫面 => 選擇 Network => 選擇網頁名稱
>可看到 Response Headers 的 Cache-Control: 內容為 no-cache, no-store

**防範措施：**

- ASP.NET MVC 在 Global.asax.cs 內加入

```csharp=
protected void Application_PreSendRequestHeaders(object sender, EventArgs e)
{
    HttpContext.Current.Response.Cache.SetCacheability(HttpCacheability.NoCache);
    HttpContext.Current.Response.Cache.SetNoStore();
}
```

- ASP.NET WebForms 在 Web.config 內加入

```xml=
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Cache-Control" value="no-cache, no-store, must-revalidate" />
      <add name="Pragma" value="no-cache" />
      <add name="Expires" value="0" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

## HTML5: Cross-Site Scripting Protection

**防範措施：**

```xml
<add name="X-XSS-Protection" value="1; mode=block" />
```

## Web Server Misconfiguration: Server Error Message

Web 伺服器配置不當（Web Server Misconfiguration）是指在設置和管理 Web 伺服器（如 IIS）時出現的錯誤或不正確的配置。
比如 HTTP Response Headers 配置。

## CSRF

>[零基礎資安系列（一）-認識 CSRF（Cross Site Request Forgery）](https://tech-blog.cymetrics.io/posts/jo/zerobased-cross-site-request-forgery/)
>想像你到一家餐廳吃飯，陌生人`(駭客)`拿了一張有你桌號的菜單`(Request)`點餐之後給老闆`(Server)`，結果老闆問也不問便收了菜單並將帳記到了你的身上，這就是 CSRF 的基礎概念。

>[如何防範？](https://www.explainthis.io/zh-hant/swe/what-is-csrf#csrf-%E9%98%B2%E7%A6%A6%E6%96%B9%E6%B3%95)
>1. 加上驗證
>2. 不要用 `GET` 請求來做關鍵操作
>3. 檢查 Referrer
>4. 使用 CSRF token
>5. 瀏覽器本身防護 - SameSite cookies

**實際的防範措施：**

- 不要使用 `GET` 請求來做關鍵操作

```csharp=
if (!IsPostBack)
{
}
else
{
    // CSRF 防護：限制僅接受 POST 請求，防止 GET 請求觸發狀態變更。
    if (Request.HttpMethod != "POST")
    {
        throw new InvalidOperationException($"資訊安全：{Request.HttpMethod} 為不允許的請求方法。僅接受 POST 請求。");
    }
}
```

- 調整程式碼執行流程

```csharp=
//string logonid = HttpUtility.HtmlEncode(Request.QueryString["logonid"] ?? "");
if (!IsPostBack)
{
    string logonid = HttpUtility.HtmlEncode(Request.QueryString["logonid"] ?? "");
    string NTUser = Utility.DecryptNTUser(logonid);

```

## Data Filter Injection

使用 DataTable.Select 方法進行查詢時，當查詢條件是通過**字符串拼接**產生的（如 "ID='" + id + "'"），就存在 Data Filter Injection 的風險。

>攻擊場景：
>假設攻擊者將 id 設置為 `1' OR '1'='1`.
>查詢語句將被解析為：ID='1' OR '1'='1'，這樣會返回所有行，從而泄露不應該訪問的數據。

```csharp=
// 資訊安全漏洞：Data Filter Injection
//DataRow[] dr = dt.Select("ID='" + id + "'");
// 修復：改用 LINQ 查詢
DataRow[] dr = dt.AsEnumerable()
    .Where(r => r.Field<decimal>("ID").ToString() == id)
    .ToArray();
```

## Persistent Connection String

## Client Potential XSS

**防範措施：**

- 前端使用 [DOMPurify](https://github.com/cure53/DOMPurify) 避免 XSS 攻擊

```javascript=
$('.inject-defense').each(function () {
    var inputVal = $(this).val();
    if (inputVal) {
        var cleanHTML = DOMPurify.sanitize(inputVal, {
            USE_PROFILES: {
                html: false
            }
        });
        $(this).val(cleanHTML);
    }
});
```

## Privacy Violation: Autocomplete

**防範措施：**
`<asp:TextBox>` 和 `<input type="text">` 的元素都加上 `autocomplete="off"`

## Privacy Violation

>[Checkmarx | 使用 DefaultRequestHeaders.Authorization 卻被 Checkmarx 判斷有 Privacy Violation 的 Issue](https://rainmakerho.github.io/2022/11/25/checkmarx-headers-authorization-privacy-violation/)

**防範措施：**
將變數名稱 `string userAccount` 調整成 `string user`。

## Insufficient Connection String Encryption

## Path Traversal/Stored Path Traversal

```csharp=
XmlReaderSettings settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit, // 禁用 DTD
    XmlResolver = null, // 禁用外部資源解析
    IgnoreWhitespace = true, // 忽略空白
    IgnoreComments = true // 忽略註解
};
XmlDocument xmlDoc = new XmlDocument();
using (var reader = XmlReader.Create(new StringReader(vendorData), settings))
{
    xmlDoc.Load(reader);
}
```

## Missing HSTS Header

HTTP Strict-Transport-Security 回應標頭 (HSTS) 告知瀏覽器該站點應僅使用 HTTPS 訪問，並且所有將來的 HTTP 訪問應自動轉換為 HTTPS。

**防範措施：**

```xml
<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
```

## SSL Verification Bypass

>```csharp
>ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
>```
>
>這段程式碼會禁用所有 SSL 憑證的驗證，無論伺服器的憑證是否可信都會自動接受。這可能導致攻擊者進行中間人攻擊 (MITM)，攔截和篡改 HTTPS 傳輸中的敏感資料。

**修復方法：** 移除不安全的憑證驗證邏輯

```csharp
ServicePointManager.ServerCertificateValidationCallback = null;
```

## Often Misused: File Upload

**防範措施：**

- 前端對上傳的檔案進行副檔名限制

```html
<asp:FileUpload ID="oFileUpload" runat="server" accept=".xlsx,.xls"  />
```

- 後端對上傳的檔案進行副檔名、content-type 檢查

```csharp=
// 取得檔案副檔名
string fileExtension = Path.GetExtension(oFileUpload.FileName);
// 取得 MIME 類型
string contentType = oFileUpload.PostedFile.ContentType;
if (fileExtension.ToLower() != ".xls" &&
    fileExtension.ToLower() != ".xlsx" &&
    contentType != "application/vnd.ms-excel" &&
    contentType != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
{
    Utility.Alert("僅允許上傳 Excel (.xls, .xlsx) 檔案。", this, false);
    return;
}
```
