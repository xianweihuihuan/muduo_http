#pragma once
#include <sys/stat.h>
#include <fstream>
#include <regex>
#include "server.hpp"

#define MAX_LINE 8192

std::unordered_map<int, std::string> _statu_msg = {
    {100, "Continue"},
    {101, "Switching Protocol"},
    {102, "Processing"},
    {103, "Early Hints"},
    {200, "OK"},
    {201, "Created"},
    {202, "Accepted"},
    {203, "Non-Authoritative Information"},
    {204, "No Content"},
    {205, "Reset Content"},
    {206, "Partial Content"},
    {207, "Multi-Status"},
    {208, "Already Reported"},
    {226, "IM Used"},
    {300, "Multiple Choice"},
    {301, "Moved Permanently"},
    {302, "Found"},
    {303, "See Other"},
    {304, "Not Modified"},
    {305, "Use Proxy"},
    {306, "unused"},
    {307, "Temporary Redirect"},
    {308, "Permanent Redirect"},
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {402, "Payment Required"},
    {403, "Forbidden"},
    {404, "Not Found"},
    {405, "Method Not Allowed"},
    {406, "Not Acceptable"},
    {407, "Proxy Authentication Required"},
    {408, "Request Timeout"},
    {409, "Conflict"},
    {410, "Gone"},
    {411, "Length Required"},
    {412, "Precondition Failed"},
    {413, "Payload Too Large"},
    {414, "URI Too Long"},
    {415, "Unsupported Media Type"},
    {416, "Range Not Satisfiable"},
    {417, "Expectation Failed"},
    {418, "I'm a teapot"},
    {421, "Misdirected Request"},
    {422, "Unprocessable Entity"},
    {423, "Locked"},
    {424, "Failed Dependency"},
    {425, "Too Early"},
    {426, "Upgrade Required"},
    {428, "Precondition Required"},
    {429, "Too Many Requests"},
    {431, "Request Header Fields Too Large"},
    {451, "Unavailable For Legal Reasons"},
    {501, "Not Implemented"},
    {502, "Bad Gateway"},
    {503, "Service Unavailable"},
    {504, "Gateway Timeout"},
    {505, "HTTP Version Not Supported"},
    {506, "Variant Also Negotiates"},
    {507, "Insufficient Storage"},
    {508, "Loop Detected"},
    {510, "Not Extended"},
    {511, "Network Authentication Required"}};

std::unordered_map<std::string, std::string> _mime_msg = {
    {".aac", "audio/aac"},
    {".abw", "application/x-abiword"},
    {".arc", "application/x-freearc"},
    {".avi", "video/x-msvideo"},
    {".azw", "application/vnd.amazon.ebook"},
    {".bin", "application/octet-stream"},
    {".bmp", "image/bmp"},
    {".bz", "application/x-bzip"},
    {".bz2", "application/x-bzip2"},
    {".csh", "application/x-csh"},
    {".css", "text/css"},
    {".csv", "text/csv"},
    {".doc", "application/msword"},
    {".docx",
     "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".eot", "application/vnd.ms-fontobject"},
    {".epub", "application/epub+zip"},
    {".gif", "image/gif"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".ico", "image/vnd.microsoft.icon"},
    {".ics", "text/calendar"},
    {".jar", "application/java-archive"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".js", "text/javascript"},
    {".json", "application/json"},
    {".jsonld", "application/ld+json"},
    {".mid", "audio/midi"},
    {".midi", "audio/x-midi"},
    {".mjs", "text/javascript"},
    {".mp3", "audio/mpeg"},
    {".mpeg", "video/mpeg"},
    {".mpkg", "application/vnd.apple.installer+xml"},
    {".odp", "application/vnd.oasis.opendocument.presentation"},
    {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {".odt", "application/vnd.oasis.opendocument.text"},
    {".oga", "audio/ogg"},
    {".ogv", "video/ogg"},
    {".ogx", "application/ogg"},
    {".otf", "font/otf"},
    {".png", "image/png"},
    {".pdf", "application/pdf"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".pptx",
     "application/"
     "vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".rar", "application/x-rar-compressed"},
    {".rtf", "application/rtf"},
    {".sh", "application/x-sh"},
    {".svg", "image/svg+xml"},
    {".swf", "application/x-shockwave-flash"},
    {".tar", "application/x-tar"},
    {".tif", "image/tiff"},
    {".tiff", "image/tiff"},
    {".ttf", "font/ttf"},
    {".txt", "text/plain"},
    {".vsd", "application/vnd.visio"},
    {".wav", "audio/wav"},
    {".weba", "audio/webm"},
    {".webm", "video/webm"},
    {".webp", "image/webp"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".xhtml", "application/xhtml+xml"},
    {".xls", "application/vnd.ms-excel"},
    {".xlsx",
     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".xml", "application/xml"},
    {".xul", "application/vnd.mozilla.xul+xml"},
    {".zip", "application/zip"},
    {".3gp", "video/3gpp"},
    {".3g2", "video/3gpp2"},
    {".7z", "application/x-7z-compressed"}};

class HttpRequest {
 public:
  std::string _method;
  std::string _version;
  std::string _path;
  std::string _body;
  std::smatch _smatch;
  std::unordered_map<std::string, std::string> _headers;
  std::unordered_map<std::string, std::string> _params;

 public:
  HttpRequest() : _version("HTTP/1.1") {}

  void SetHeader(const std::string& key, const std::string& val) {
    _headers.emplace(key, val);
  }

  void SetParam(const std::string& key, const std::string& val) {
    _params.emplace(key, val);
  }

  bool HasHeader(const std::string& key) const {
    auto it = _headers.find(key);
    if (it == _headers.end()) {
      return false;
    }
    return true;
  }

  std::string GetHead(const std::string& key) const {
    auto it = _headers.find(key);
    if (it == _headers.end()) {
      return "";
    }
    return it->second;
  }

  bool HasParam(const std::string& key) const {
    auto it = _params.find(key);
    if (it == _params.end()) {
      return false;
    }
    return true;
  }

  std::string GetParam(const std::string& key) const {
    auto it = _params.find(key);
    if (it == _params.end()) {
      return "";
    }
    return it->second;
  }

  size_t GetContentLength() const {
    bool ret = HasHeader("Content-Length");
    if (!ret) {
      return 0;
    }
    return std::stoi(GetHead("Content-Length"));
  }

  bool IsClose() const {
    if (HasHeader("Connection") && GetHead("Connection") == "keep-alive") {
      return false;
    }
    return true;
  }

  void Reset() {
    _method.clear();
    _version = "HTTP/1.1";
    _path.clear();
    _headers.clear();
    _params.clear();
    std::smatch tmp;
    _smatch.swap(tmp);
    _body.clear();
  }
};

class Util {
 public:
  static size_t Split(const std::string& src,
                      const std::string& sep,
                      std::vector<std::string>* arry) {
    size_t offset = 0;
    while (offset < src.size()) {
      auto pos = src.find(sep, offset);
      if (pos == std::string::npos) {
        if (pos == src.size())
          break;
        arry->emplace_back(src.substr(offset));
        break;
      }
      if (pos == offset) {
        offset = pos + sep.size();
        continue;
      }
      arry->emplace_back(src.substr(offset, pos - offset));
      offset = pos + sep.size();
    }
    return arry->size();
  }

  static bool ReadFile(const std::string& filename, std::string* buf) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) {
      LOG_ERROR("File open fail", filename.c_str());
      return false;
    }
    size_t fsize = 0;
    in.seekg(0, in.end);
    fsize = in.tellg();
    in.seekg(0, in.beg);
    buf->resize(fsize);
    in.read(&(*buf)[0], fsize);
    if (!in.good()) {
      LOG_ERROR("File {} read fail", filename.c_str());
      in.close();
      return false;
    }
    in.close();
    return true;
  }

  static bool WriteFile(const std::string& filename, const std::string& buf) {
    std::ofstream out(filename, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
      LOG_ERROR("File {} open fail", filename.c_str());
      return false;
    }
    out.write(buf.c_str(), buf.size());
    if (!out.good()) {
      LOG_ERROR("File {} write fail", filename.c_str());
      out.close();
      return false;
    }
    out.close();
    return true;
  }

  static std::string UrlEncode(const std::string& url,
                               bool convert_space_to_plus) {
    std::string ret;
    for (const auto& c : url) {
      if (c == '.' || c == '-' || c == '_' || c == '~' || isalnum(c)) {
        ret += c;
        continue;
      }
      if (c == ' ' && convert_space_to_plus) {
        ret += '+';
        continue;
      }
      char tmp[4] = {0};
      snprintf(tmp, 4, "%%%02X", c);
      ret += tmp;
    }
    return std::move(ret);
  }

  static char HEXTOI(const char& h) {
    if (h >= '0' && h <= '9') {
      return h - '0';
    }
    if (h >= 'a' && h <= 'z') {
      return h - 'a' + 10;
    }
    if (h >= 'A' && h <= 'Z') {
      return h - 'A' + 10;
    }
    return -1;
  }

  static std::string UrlDecode(const std::string& url,
                               bool convert_plus_to_space) {
    std::string ret;
    for (int i = 0; i < url.size(); ++i) {
      if (url[i] == '+' && convert_plus_to_space) {
        ret += ' ';
        continue;
      }
      if (url[i] == '%') {
        char v1 = HEXTOI(url[i + 1]);
        char v2 = HEXTOI(url[i + 2]);
        char v = v1 * 16 + v2;
        ret += v;
        i += 2;
        continue;
      }
      ret += url[i];
    }
    return std::move(ret);
  }

  static std::string StatuDesc(const int& statu) {
    auto it = _statu_msg.find(statu);
    if (it != _statu_msg.end()) {
      return it->second;
    }
    return "Unknow";
  }

  static std::string ExtMime(const std::string& filename) {
    size_t pos = filename.find('.');
    if (pos == std::string::npos) {
      return "application/octet-stream";
    }
    std::string ext = filename.substr(pos);
    auto it = _mime_msg.find(ext);
    if (it != _mime_msg.end()) {
      return it->second;
    }
    return "application/octet-stream";
  }

  static bool IsDirectory(const std::string& filename) {
    struct stat st;
    int tmp = stat(filename.c_str(), &st);
    if (tmp < 0) {
      return false;
    }
    return S_ISDIR(st.st_mode);
  }

  static bool IsRegular(const std::string& filename) {
    struct stat st;
    int tmp = stat(filename.c_str(), &st);
    if (tmp < 0) {
      return false;
    }
    return S_ISREG(st.st_mode);
  }

  static bool ValidPath(const std::string& path) {
    std::vector<std::string> ret;
    Split(path, "/", &ret);
    int level = 0;
    for (auto& x : ret) {
      if (x == "..") {
        level--;
        if (level < 0) {
          return false;
        }
        continue;
      }
      level++;
    }
    return true;
  }
};

class HttpResponse {
 public:
  int _statu;
  bool _redirect_flag;
  std::string _body;
  std::string _redirect_url;
  std::unordered_map<std::string, std::string> _headers;

 public:
  HttpResponse() : _statu(200), _redirect_flag(false) {}
  HttpResponse(int statu) : _statu(statu), _redirect_flag(false) {}
  void SetHeader(const std::string& key, const std::string& val) {
    _headers.emplace(key, val);
  }

  bool HasHeader(const std::string& key) const {
    auto it = _headers.find(key);
    if (it != _headers.end()) {
      return true;
    }
    return false;
  }

  std::string GetHeader(const std::string& key) const {
    auto it = _headers.find(key);
    if (it == _headers.end()) {
      return "";
    }
    return it->second;
  }

  void ReSet() {
    _statu = 200;
    _redirect_flag = false;
    _body.clear();
    _redirect_url.clear();
    _headers.clear();
  }

  void SetContent(const std::string& body,
                  const std::string& type = "text/html") {
    _body = body;
    SetHeader("Content-Type", type);
  }

  void SetRedirect(const std::string& url, int statu = 302) {
    _statu = statu;
    _redirect_flag = true;
    _redirect_url = url;
  }

  bool Isclose() {
    if (HasHeader("Connection") == true &&
        GetHeader("Connection") == "keep-alive") {
      return false;
    }
    return true;
  }
};

enum HttpRecvStatu {
  RECV_HTTP_ERROR,
  RECV_HTTP_LINE,
  RECV_HTTP_HEAD,
  RECV_HTTP_BODY,
  RECV_HTTP_OVER
};

class HttpContext {
 private:
  int _statu;
  HttpRecvStatu _recv_statu;
  HttpRequest _req;

 private:
  bool ParseHttpLine(const std::string& line) {
    std::smatch matchs;
    std::regex e(
        "(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))? "
        "(HTTP/1\\.[01])(?:\n|\r\n)?",
        std::regex::icase);
    bool ret = std::regex_match(line, matchs, e);
    if (ret == false) {
      _statu = 400;
      _recv_statu = RECV_HTTP_ERROR;
      return false;
    }
    _req._method = matchs[1];
    std::transform(_req._method.begin(), _req._method.end(),
                   _req._method.begin(), toupper);
    _req._path = Util::UrlDecode(matchs[2], false);
    _req._version = matchs[4];
    std::vector<std::string> re;
    std::string par = matchs[3];
    Util::Split(par, "&", &re);
    for (const auto& x : re) {
      auto pos = x.find('=');
      if (pos == std::string::npos) {
        _recv_statu = RECV_HTTP_ERROR;
        _statu = 400;
        return false;
      }
      std::string key = Util::UrlDecode(x.substr(0, pos), true);
      std::string val = Util::UrlDecode(x.substr(pos + 1), true);
      _req.SetParam(key, val);
    }
    return true;
  }

  bool RecvHttpLine(Buffer* buf) {
    if (_recv_statu != RECV_HTTP_LINE) {
      return false;
    }
    std::string line = buf->GetlineAndPop();
    //std::cout << line << std::endl;
    if (line.size() == 0) {
      if (buf->ReadableSize() > MAX_LINE) {
        _statu = 414;
        _recv_statu = RECV_HTTP_ERROR;
        return false;
      }
      return true;
    }
    if (line.size() > MAX_LINE) {
      _statu = 414;
      _recv_statu = RECV_HTTP_ERROR;
      return false;
    }
    bool ret = ParseHttpLine(line);
    if (ret == false) {
      return false;
    }
    _recv_statu = RECV_HTTP_HEAD;
    return true;
  }

  bool ParseHttpHead(std::string& line) {
    if (line.back() == '\n') {
      line.pop_back();
    }
    if (line.back() == '\r') {
      line.pop_back();
    }
    auto pos = line.find(": ");
    if (pos == std::string::npos) {
      _recv_statu = RECV_HTTP_ERROR;
      _statu = 400;
      return false;
    }
    std::string key = line.substr(0, pos);
    std::string val = line.substr(pos + 2);
    _req.SetHeader(key, val);
    return true;
  }

  bool RecvHttpHead(Buffer* buf) {
    if (_recv_statu != RECV_HTTP_HEAD) {
      return false;
    }
    while (true) {
      std::string line = buf->GetlineAndPop();
      if (line.size() == 0) {
        if (buf->ReadableSize() > MAX_LINE) {
          _statu = 414;
          _recv_statu = RECV_HTTP_ERROR;
          return false;
        }
        return true;
      }
      if (line.size() > MAX_LINE) {
        _statu = 414;
        _recv_statu = RECV_HTTP_ERROR;
        return false;
      }
      if (line == "\n" || line == "\r\n") {
        break;
      }
      bool ret = ParseHttpHead(line);
      if (!ret) {
        return false;
      }
    }
    _recv_statu = RECV_HTTP_BODY;
    return true;
  }

  bool RecvHttpBody(Buffer* buf) {
    if (_recv_statu != RECV_HTTP_BODY) {
      return false;
    }
    int sz = _req.GetContentLength();
    if (sz == 0) {
      _recv_statu = RECV_HTTP_OVER;
      return true;
    }
    int reallen = sz - _req._body.size();
    if (buf->ReadableSize() >= reallen) {
      _req._body.append(buf->ReadPostition(), reallen);
      buf->MoveReadIndex(reallen);
      _recv_statu = RECV_HTTP_OVER;
      return true;
    }
    _req._body.append(buf->ReadPostition(), buf->ReadableSize());
    buf->MoveReadIndex(buf->ReadableSize());
    _recv_statu = RECV_HTTP_OVER;
    return true;
  }

 public:
  HttpContext() : _statu(200), _recv_statu(RECV_HTTP_LINE) {}

  void Reset() {
    _recv_statu = RECV_HTTP_LINE;
    _req.Reset();
  }

  HttpRecvStatu RecvStatu() { return _recv_statu; }
  HttpRequest& Requst() { return _req; }

  void RecvHttpRequst(Buffer* buf) {
    switch (_recv_statu) {
      case RECV_HTTP_LINE:
        RecvHttpLine(buf);
      case RECV_HTTP_HEAD:
        RecvHttpHead(buf);
      case RECV_HTTP_BODY:
        RecvHttpBody(buf);
    }
    return;
  }
};

#define DEFAULT_TIMEOUT 10
class HttpServer {
 private:
  using handle = std::function<void(HttpRequest&, HttpResponse*)>;
  using handles = std::vector<std::pair<std::regex, handle>>;
  handles _get_route;
  handles _post_route;
  handles _put_route;
  handles _delete_route;
  TcpServer _server;
  std::string _basedir;

 private:
  void WriteResponse(const PtrConnection& conn,
                     const HttpRequest& req,
                     HttpResponse& rsp) {
    if (req.IsClose()) {
      rsp.SetHeader("Connection", "close");
    } else {
      rsp.SetHeader("Connetcion", "keep-alive");
    }
    if (!rsp._body.empty() && !rsp.HasHeader("Content-Length")) {
      rsp.SetHeader("Content-Length", std::to_string(rsp._body.size()));
    }
    if (!rsp._body.empty() && !rsp.HasHeader("Content-Type")) {
      rsp.SetHeader("Content-Type", "application/actet-stream");
    }
    if (rsp._redirect_flag) {
      rsp.SetHeader("Location", rsp._redirect_url);
    }
    std::stringstream str;
    str << req._version << " " << std::to_string(rsp._statu) << " "
        << Util::StatuDesc(rsp._statu) << "\r\n";
    for (const auto& x : rsp._headers) {
      str << x.first << ": " << x.second << "\r\n";
    }
    str << "\r\n";
    str << rsp._body;
    conn->Send(str.str().c_str(), str.str().size());
  }

  void ErrorHandler(const HttpRequest& req, HttpResponse* rsp) {
    // 1. 组织一个错误展示页面
    std::string body;
    body += "<html>";
    body += "<head>";
    body +=
        "<meta http-equiv='Content-Type' content='text/html;charset=utf-8'>";
    body += "</head>";
    body += "<body>";
    body += "<h1>";
    body += std::to_string(rsp->_statu);
    body += " ";
    body += Util::StatuDesc(rsp->_statu);
    body += "</h1>";
    body += "</body>";
    body += "</html>";
    // 2. 将页面数据，当作响应正文，放入rsp中
    rsp->SetContent(body, "text/html");
  }

  void OnMessage(const PtrConnection& conn, Buffer* buf) {
    while (buf->ReadableSize() > 0) {
      HttpContext* context = conn->GetCneContext()->Get<HttpContext>();
      context->RecvHttpRequst(buf);
      HttpRequest& req = context->Requst();
      HttpResponse rsp(context->RecvStatu());
      if (context->RecvStatu() >= 400) {
        ErrorHandler(req, &rsp);
        WriteResponse(conn, req, rsp);
        context->Reset();
        buf->MoveReadIndex(buf->ReadableSize());
        conn->Shutdown();
        return;
      }
      if (context->RecvStatu() != RECV_HTTP_OVER) {
        return;
      }
      Route(req, &rsp);
      WriteResponse(conn, req, rsp);
      context->Reset();
      if (rsp.Isclose()) {
        conn->Shutdown();
      }
    }
  }

  void OnConnect(const PtrConnection& conn) {
    conn->SetContext(HttpContext());
    LOG_DEBUG("NEW CONNECTION : {}", conn->Fd());
  }

  void OnClose(const PtrConnection& conn) {
    LOG_DEBUG("CONNECTION CLOSE : {}", conn->Fd());
  }

  void Dispactor(HttpRequest& req, HttpResponse* rsp, const handles& handles) {
    for (const auto& it : handles) {
      const std::regex& re = it.first;
      const handle& func = it.second;
      bool ret = std::regex_match(req._path, req._smatch, re);
      if (ret) {
        func(req, rsp);
      }
    }
    rsp->_statu = 404;
  }

  bool IsFilehander(const HttpRequest& req) {
    if (_basedir.empty()) {
      return false;
    }
    if (req._method != "GET" && req._method != "HEAD") {
      return false;
    }
    std::string req_path = _basedir;
    req_path += req._path;
    if (req_path.back() == '/') {
      req_path += "index.html";
      //std::cout << req_path << std::endl;
    }
    if (!Util::IsRegular(req_path)) {
      return false;
    }
    if (!Util::ValidPath(req._path)) {
      return false;
    }
    return true;
  }

  void FileHandle(HttpRequest& req, HttpResponse* rsp) {
    std::string req_path = _basedir + req._path;
    if (req_path.back() == '/') {
      req_path += "index.html";
    }
    bool ret = Util::ReadFile(req_path, &rsp->_body);
    if (!ret) {
      return;
    }
    std::string mime = Util::ExtMime(req_path);
    rsp->SetHeader("Content-type", mime);
    return;
  }

  void Route(HttpRequest& req, HttpResponse* rsp) {
    if (IsFilehander(req)) {
      return FileHandle(req, rsp);
    }
    if (req._method == "GET" || req._method == "HEAD") {
      Dispactor(req, rsp, _get_route);
      return;
    }
    if (req._method == "POST") {
      Dispactor(req, rsp, _post_route);
      return;
    }
    if (req._method == "PUT") {
      Dispactor(req, rsp, _put_route);
      return;
    }
    if (req._method == "DELETE") {
      Dispactor(req, rsp, _delete_route);
      return;
    }
    rsp->_statu = 405;
  }

 public:
  HttpServer(int port, int timeout = DEFAULT_TIMEOUT) : _server(port) {
    _server.EnableInactiveRelease(timeout);
    _server.SetMessageCallback(std::bind(&HttpServer::OnMessage, this,
                                         std::placeholders::_1,
                                         std::placeholders::_2));
    _server.SetConnectCallback(
        std::bind(&HttpServer::OnConnect, this, std::placeholders::_1));
    _server.SetClosedCallback(
        std::bind(&HttpServer::OnClose, this, std::placeholders::_1));
  }

  void SetBasedir(const std::string basedir) { _basedir = basedir; }

  void Get(const std::string& pattern, const handle& handler) {
    _get_route.push_back(std::make_pair(std::regex(pattern), handler));
  }

  void Post(const std::string& pattern, const handle& handler) {
    _post_route.push_back(std::make_pair(std::regex(pattern), handler));
  }

  void Put(const std::string& pattern, const handle& handler) {
    _put_route.push_back(std::make_pair(std::regex(pattern), handler));
  }

  void Delete(const std::string& pattern, const handle& handler) {
    _delete_route.push_back(std::make_pair(std::regex(pattern), handler));
  }

  void SetThreadCount(int count) { _server.SetThreadCount(count); }

  void Listen() { _server.Start(); }
};