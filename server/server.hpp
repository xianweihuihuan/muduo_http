#pragma once
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <typeinfo>
#include <unordered_map>
#include <vector>
#include "logger.hpp"

#define MAX_LISTEN_SIZE 1024
class Socket {
 private:
  int _sockfd;

 public:
  Socket() : _sockfd(-1) {}
  Socket(int fd) : _sockfd(fd) {}

  bool Create() {
    _sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (_sockfd < 0) {
      LOG_ERROR("创建套接字失败");
      return false;
    }
    return true;
  }

  int Fd() { return _sockfd; }

  bool Bind(const std::string& ip, uint16_t port) {
    sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    socklen_t len = sizeof(sockaddr_in);
    int tmp = bind(_sockfd, (sockaddr*)&addr, len);
    if (tmp < 0) {
      LOG_ERROR("套接字绑定失败");
      return false;
    }
    return true;
  }

  bool Listen(int backlog = MAX_HANDLE_SZ) {
    int tmp = listen(_sockfd, backlog);
    if (tmp < 0) {
      LOG_ERROR("设置监听状态失败");
      return false;
    }
    return true;
  }

  int Accept() {
    int newfd = accept(_sockfd, nullptr, nullptr);
    if (newfd < 0) {
      LOG_ERROR("建立连接失败");
      return -1;
    }
    LOG_DEBUG("建立一个新的连接，fd：{}", newfd);
    return newfd;
  }

  bool Connect(const std::string& ip, uint16_t port) {
    sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    socklen_t len = sizeof(sockaddr_in);
    int tmp = connect(_sockfd, (sockaddr*)&addr, len);
    if (tmp < 0) {
      LOG_ERROR("与客户端建立连接失败");
      return false;
    }
    return true;
  }

  void ReuseAddr() {
    int val = 1;
    setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, (void*)&val, sizeof(int));
    val = 1;
    setsockopt(_sockfd, SOL_SOCKET, SO_REUSEPORT, (void*)&val, sizeof(int));
  }

  void SetNonBlock() {
    int flag = fcntl(_sockfd, F_GETFL, 0);
    fcntl(_sockfd, F_SETFL, flag | O_NONBLOCK);
  }

  ssize_t Recv(void* buf, size_t len, int flag = 0) {
    size_t sz = recv(_sockfd, buf, len, flag);
    if (sz <= 0) {
      if (errno == EAGAIN || errno == EINTR) {
        return 0;
      }
      LOG_ERROR("fd:{}接受数据失败", _sockfd);
      return -1;
    }
    return sz;
  }

  ssize_t Send(const void* buf, size_t len, int flag = 0) {
    size_t sz = send(_sockfd, buf, len, flag);
    if (sz <= 0) {
      if (errno == EAGAIN || errno == EINTR) {
        return 0;
      }
      LOG_ERROR("fd:{}发送数据失败", _sockfd);
      return -1;
    }
    return sz;
  }

  size_t NonBlockSend(void* buf, size_t len) {
    if (len == 0) {
      return 0;
    }
    return Send(buf, len, MSG_DONTWAIT);
  }

  ssize_t NonBlockRecv(void* buf, size_t len) {
    if (len == 0) {
      return 0;
    }
    return Recv(buf, len, MSG_DONTWAIT);
  }

  bool CreateServer(uint16_t port,
                    const std::string& ip = "0.0.0.0",
                    bool block = false) {
    if (!Create()) {
      return false;
    }
    ReuseAddr();
    if (block) {
      SetNonBlock();
    }
    if (!Bind(ip, port)) {
      return false;
    }
    if (!Listen()) {
      return false;
    }

    return true;
  }

  bool CreateClient(uint16_t port, const std::string& ip) {
    if (!Create()) {
      return false;
    }
    if (!Connect(ip, port)) {
      return false;
    }
    return true;
  }

  void Close() {
    close(_sockfd);
    _sockfd = -1;
  }
};

#define BUFFER_DEFAULT_SIZE 1024
class Buffer {
 private:
  std::vector<char> _buf;
  uint64_t _read_index;
  uint64_t _wirte_index;

 private:
  char* Begin() { return &*_buf.begin(); }
  uint64_t TailFreeSize() { return _buf.size() - _wirte_index; }
  uint64_t HeadFreeSize() { return _read_index; }
  uint64_t FreeSize() { return HeadFreeSize() + TailFreeSize(); }

  void EnsureWriteSpace(uint64_t len) {
    if (TailFreeSize() >= len) {
      return;
    }
    if (FreeSize() >= len) {
      uint64_t rsz = ReadableSize();
      std::copy(ReadPostition(), WritePostition(), Begin());
      _read_index = 0;
      _wirte_index = rsz;
    } else {
      LOG_DEBUG("对缓冲区进行扩容");
      _buf.resize(_wirte_index + len);
    }
  }

  void Write(const void* buf, uint64_t len) {
    if (len == 0) {
      return;
    }
    EnsureWriteSpace(len);
    const char* d = (const char*)buf;
    std::copy(d, d + len, WritePostition());
  }

  void WriteString(const std::string& data) {
    Write(data.c_str(), data.size());
  }

  void WriteBuffer(Buffer& data) {
    Write(data.ReadPostition(), data.ReadableSize());
  }

  char* FindCRLF() {
    char* ret = (char*)memchr(ReadPostition(), '\n', ReadableSize());
    return ret;
  }

  void Read(void* buf, uint64_t len) {
    if (len > ReadableSize()) {
      LOG_FATAL("可读空间不足");
      abort();
    }
    std::copy(ReadPostition(), ReadPostition() + len, (char*)buf);
  }

  std::string ReadAsString(uint64_t len) {
    if (len > ReadableSize()) {
      LOG_FATAL("可读空间不足");
      abort();
    }
    std::string ret;
    ret.resize(len);
    Read(&ret[0], len);
    return std::move(ret);
  }

  std::string Getline() {
    char* pos = FindCRLF();
    if (pos != nullptr) {
      return std::move(ReadAsString(pos - ReadPostition() + 1));
    }
    return "";
  }

 public:
  Buffer() : _buf(BUFFER_DEFAULT_SIZE), _read_index(0), _wirte_index(0) {}
  char* ReadPostition() { return Begin() + _read_index; }
  char* WritePostition() { return Begin() + _wirte_index; }
  uint64_t ReadableSize() { return _wirte_index - _read_index; }

  void MoveReadIndex(uint64_t len) {
    if (len > ReadableSize()) {
      LOG_FATAL("将要移动的长度不能大于可读的空间");
      abort();
    }
    _read_index += len;
  }

  void MoveWriteIndex(uint64_t len) {
    if (len > TailFreeSize()) {
      LOG_FATAL("将要移动的长度不能大于尾部剩余的空间");
      abort();
    }
    _wirte_index += len;
  }

  void WriteAndPush(const void* buf, uint64_t len) {
    Write(buf, len);
    MoveWriteIndex(len);
  }

  void WriteAndPush(const std::string& data) {
    WriteString(data);
    MoveWriteIndex(data.size());
  }

  void WriteAndPush(Buffer& data) {
    WriteBuffer(data);
    MoveWriteIndex(data.ReadableSize());
  }

  void ReadAndPop(void* buf, uint64_t len) {
    Read(buf, len);
    MoveReadIndex(len);
  }

  std::string ReadAsStringAndPop(uint64_t len) {
    std::string ret = ReadAsString(len);
    MoveReadIndex(len);
    return std::move(ret);
  }

  std::string GetlineAndPop() {
    std::string ret = Getline();
    MoveReadIndex(ret.size());
    return std::move(ret);
  }

  void Clear() { _read_index = _wirte_index = 0; }
};

class EventLoop;
class Channel {
 private:
  int _fd;
  uint32_t _events;
  uint32_t _revents;
  EventLoop* _loop;
  using func_cb = std::function<void()>;
  func_cb _read_callback;
  func_cb _write_callback;
  func_cb _error_callback;
  func_cb _close_callback;
  func_cb _event_callback;

 public:
  Channel(EventLoop* loop, int fd)
      : _loop(loop), _fd(fd), _events(0), _revents(0) {}

  int Fd() { return _fd; }
  int Events() { return _events; }
  void SetRevents(uint32_t events) { _revents = events; }
  void SetReadcallback(func_cb read_cb) { _read_callback = read_cb; }
  void SetWritecallback(func_cb write_cb) { _write_callback = write_cb; }
  void SetErrorcallback(func_cb error_cb) { _error_callback = error_cb; }
  void SetClosecallback(func_cb close_cb) { _close_callback = close_cb; }
  void SetEventcallback(func_cb event_cb) { _event_callback = event_cb; }
  bool ReadAble() { return (_events & EPOLLIN); }
  bool WriteAble() { return (_events & EPOLLOUT); }

  void Update();

  void Remove();

  void EnableRead() {
    _events |= EPOLLIN;
    Update();
  }

  void EnableWrite() {
    _events |= EPOLLOUT;
    Update();
  }

  void DisableRead() {
    _events &= ~EPOLLIN;
    Update();
  }

  void DisableWrite() {
    _events &= ~EPOLLOUT;
    Update();
  }

  void DisableAll() {
    _events = 0;
    Update();
  }

  void HandleEvent() {
    if ((_revents & EPOLLIN) || (_revents & EPOLLRDHUP) ||
        (_revents & EPOLLPRI)) {
      if (_read_callback) {
        _read_callback();
      }
    }
    if (_revents & EPOLLOUT) {
      if (_write_callback) {
        _write_callback();
      }
    } else if (_revents & EPOLLERR) {
      if (_error_callback) {
        _error_callback();
      }
    } else if (_revents & EPOLLHUP) {
      if (_close_callback) {
        _close_callback();
      }
    }
    if (_event_callback) {
      _event_callback();
    }
  }
};

#define MAX_EPOLLEVENTS 1024

class Poller {
 private:
  int _epfd;
  epoll_event _evs[MAX_EPOLLEVENTS];
  std::unordered_map<int, Channel*> _channels;

 private:
  int Update(Channel* channel, int op) {
    int fd = channel->Fd();
    epoll_event ev;
    ev.data.fd = fd;
    ev.events = channel->Events();
    int ret = epoll_ctl(_epfd, op, fd, &ev);
    return ret;
  }

  bool HasChannel(Channel* channel) {
    int fd = channel->Fd();
    auto it = _channels.find(fd);
    if (it == _channels.end()) {
      return false;
    }
    return true;
  }

 public:
  Poller() {
    _epfd = epoll_create(1342);
    if (_epfd < 0) {
      LOG_FATAL("EPOLL创建失败");
      abort();
    }
  }

  void UpdateEvents(Channel* channel) {
    if (HasChannel(channel)) {
      int ret = Update(channel, EPOLL_CTL_MOD);
      if (ret < 0) {
        LOG_ERROR("Fd: {}更改关心事件失败", channel->Fd());
      }
      LOG_DEBUG("Fd: {}更改关心事件成功", channel->Fd());
    } else {
      int ret = Update(channel, EPOLL_CTL_ADD);
      _channels.insert(std::make_pair(channel->Fd(), channel));
      if (ret < 0) {
        LOG_ERROR("Fd: {}添加关心事件失败", channel->Fd());
      }
      LOG_DEBUG("Fd: {}添加关心事件成功", channel->Fd());
    }
  }

  void RemoveEvents(Channel* channel) {
    if (!HasChannel(channel)) {
      return;
    } else {
      int ret = Update(channel, EPOLL_CTL_DEL);
      if (ret < 0) {
        LOG_ERROR("Fd: {}解除关心失败", channel->Fd());
      }
      _channels.erase(channel->Fd());
    }
  }

  void Poll(std::vector<Channel*>& active) {
    int nfds = epoll_wait(_epfd, _evs, MAX_EPOLLEVENTS, -1);
    if (nfds < 0) {
      if (errno == EINTR) {
        return;
      }
      LOG_ERROR("Epoll等待失败");
      abort();
    }
    for (int i = 0; i < nfds; ++i) {
      auto it = _channels.find(_evs[i].data.fd);
      if (it != _channels.end()) {
        it->second->SetRevents(_evs[i].events);
        active.emplace_back(it->second);
      }
    }
  }
};

using Taskfunc = std::function<void()>;
using Releasefunc = std::function<void()>;
class Task {
 private:
  uint64_t _tid;
  uint32_t _timeout;
  bool _cancel;
  Taskfunc _task_cb;
  Releasefunc _destory_cb;

 public:
  Task(uint64_t tid, uint32_t timeout, Taskfunc tcb)
      : _tid(tid), _timeout(timeout), _task_cb(tcb), _cancel(false) {}

  ~Task() {
    if (_cancel == false) {
      _task_cb();
    }
    _destory_cb();
  }

  void SetRelease(const Releasefunc& dcb) { _destory_cb = dcb; }

  uint32_t Timeout() { return _timeout; }

  void Cancel() { _cancel = true; }
};

class TimerWheel {
 private:
  using Taskptr = std::shared_ptr<Task>;
  using Weakptr = std::weak_ptr<Task>;
  int _tick;
  int _capacity;
  std::vector<std::vector<Taskptr>> _wheel;
  std::unordered_map<uint64_t, Weakptr> _timers;
  int _timerfd;
  EventLoop* _loop;
  std::unique_ptr<Channel> _chan;

 private:
  void Remove(uint64_t tid) {
    auto it = _timers.find(tid);
    if (it != _timers.end()) {
      _timers.erase(it);
    }
  }

  static int Createtimerfd() {
    int tmp = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tmp < 0) {
      LOG_ERROR("Timerfd create fail");
      abort();
    }
    itimerspec itime;
    itime.it_value.tv_sec = 1;
    itime.it_value.tv_nsec = 0;
    itime.it_interval.tv_nsec = 0;
    itime.it_interval.tv_sec = 1;
    timerfd_settime(tmp, 0, &itime, nullptr);
    return tmp;
  }

  int ReadTmerfd() {
    uint64_t times;
    int ret = read(_timerfd, &times, 8);
    if (ret < 0) {
      LOG_ERROR("Read timerfd fail");
      abort();
    }
    return ret;
  }

  void OnTime() {
    int time = ReadTmerfd();
    for (int i = 0; i < time; ++i) {
      Run();
    }
  }

  void AddTaskInloop(uint64_t tid, uint32_t timeout, const Taskfunc& tcb) {
    Taskptr pt(new Task(tid, timeout, tcb));
    pt->SetRelease(std::bind(&TimerWheel::Remove, this, tid));
    int pos = (_tick + timeout) % _capacity;
    _wheel[pos].push_back(pt);
    _timers[tid] = Weakptr(pt);
  }

  void FlushTaskInloop(uint64_t tid) {
    auto it = _timers.find(tid);
    if (it != _timers.end()) {
      Taskptr pt = it->second.lock();
      uint32_t timeout = pt->Timeout();
      int pos = (_tick + timeout) % _capacity;
      _wheel[pos].emplace_back(pt);
    }
  }

  void CancelTaskInloop(uint64_t tid) {
    auto it = _timers.find(tid);
    if (it != _timers.end()) {
      Taskptr pt = it->second.lock();
      if (pt.get() != nullptr)
        pt->Cancel();
    }
  }

 public:
  TimerWheel(EventLoop* loop, int sz = 60)
      : _capacity(sz),
        _loop(loop),
        _tick(0),
        _wheel(_capacity),
        _timerfd(Createtimerfd()),
        _chan(std::make_unique<Channel>(_loop, _timerfd)) {
    _chan->SetReadcallback(std::bind(&TimerWheel::OnTime, this));
    _chan->EnableRead();
  }

  void AddTask(uint64_t tid, uint32_t timeout, const Taskfunc& tcb);

  void FlushTask(uint64_t tid);

  void CancelTask(uint64_t tid);
  void Run() {
    _tick = (_tick + 1) % _capacity;
    _wheel[_tick].clear();
  }

  bool HasTimer(uint64_t id) {
    auto it = _timers.find(id);
    if (it == _timers.end()) {
      return false;
    }
    return true;
  }
};

class EventLoop {
 private:
  using Functor = std::function<void()>;
  std::thread::id _thread_id;
  int _event_fd;
  std::unique_ptr<Channel> _event_channel;
  Poller _poller;
  std::vector<Functor> _task;
  std::mutex _lock;
  TimerWheel _timerwheel;

 private:
  static int CreateEventFd() {
    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (efd < 0) {
      LOG_FATAL("创建eventfd失败");
      abort();
    }
    return efd;
  }

  void ReadEventFd() {
    uint64_t res = 0;
    int ret = read(_event_fd, &res, sizeof(res));
    if (ret < 0) {
      LOG_FATAL("读取eventfd失败");
      abort();
    }
  }

  void WakeupEventFd() {
    uint64_t val = 1;
    int ret = write(_event_fd, &val, sizeof(val));
    if (ret < 0) {
      if (errno == EINTR)
        return;
      LOG_FATAL("唤醒eventfd失败");
      abort();
    }
  }
  bool IsInLoop() { return (_thread_id == std::this_thread::get_id()); }

  void EnterinLoop(const Functor& task) {
    {
      std::unique_lock<std::mutex> mtx(_lock);
      _task.emplace_back(task);
    }
    WakeupEventFd();
  }

  void RunAllTask() {
    std::vector<Functor> t;
    {
      std::unique_lock<std::mutex> mtx(_lock);
      _task.swap(t);
    }
    for (auto& x : t) {
      x();
    }
  }

 public:
  void Start() {
    while (true) {
      std::vector<Channel*> active;
      _poller.Poll(active);
      for (auto& x : active) {
        x->HandleEvent();
      }
      RunAllTask();
    }
  }

  EventLoop()
      : _thread_id(std::this_thread::get_id()),
        _event_fd(CreateEventFd()),
        _event_channel(std::make_unique<Channel>(this, _event_fd)),
        _timerwheel(this) {
    _event_channel->SetReadcallback(std::bind(&EventLoop::ReadEventFd, this));
    _event_channel->EnableRead();
  }

  void AssertInLoop() { assert(std::this_thread::get_id() == _thread_id); }

  void RunInLoop(const Functor& task) {
    if (IsInLoop()) {
      task();
    } else {
      EnterinLoop(task);
    }
  }

  void UpdateEvnet(Channel* channel) { _poller.UpdateEvents(channel); }
  void RemoveEvent(Channel* channel) { _poller.RemoveEvents(channel); }

  void AddTask(uint64_t id, uint32_t timeout, const Taskfunc& tk) {
    _timerwheel.AddTask(id, timeout, tk);
  }
  void FlushTask(uint64_t id) { _timerwheel.FlushTask(id); }
  void CancelTask(uint64_t id) { _timerwheel.CancelTask(id); }
  bool HasTimer(uint64_t id) { return _timerwheel.HasTimer(id); }
};

class LoopThread {
 private:
  std::mutex _lock;
  std::condition_variable _cond;
  std::thread _thread;
  EventLoop* _loop;

 private:
  void ThreadEntry() {
    EventLoop loop;
    {
      std::unique_lock<std::mutex> mtx(_lock);
      _loop = &loop;
      _cond.notify_all();
    }
    _loop->Start();
  }

 public:
  LoopThread()
      : _loop(nullptr),
        _thread(std::thread(std::bind(&LoopThread::ThreadEntry, this))) {}

  EventLoop* GetLoop() {
    EventLoop* loop = nullptr;
    {
      std::unique_lock<std::mutex> mtx(_lock);
      _cond.wait(mtx, [&]() { return _loop != nullptr; });
      loop = _loop;
    }
    return loop;
  }
};

class LoopThreadPool {
 private:
  int _count;
  int _index;
  EventLoop* _baseloop;
  std::vector<std::unique_ptr<LoopThread>> _threads;
  std::vector<EventLoop*> _loops;

 public:
  LoopThreadPool(EventLoop* baseloop)
      : _baseloop(baseloop), _count(0), _index(0) {}

  void SetThreadCount(int count) { _count = count; }

  void Create() {
    if (_count > 0) {
      _threads.resize(_count);
      _loops.resize(_count);
      for (int i = 0; i < _threads.size(); ++i) {
        _threads[i] = std::make_unique<LoopThread>();
        _loops[i] = _threads[i]->GetLoop();
      }
    }
  }

  EventLoop* NextLoop() {
    if (_count == 0) {
      return _baseloop;
    }
    int tmp = _index;
    _index = (_index + 1) % _count;
    return _loops[tmp];
  }
};

class Any {
 private:
  class holder {
   public:
    virtual ~holder() {}
    virtual const std::type_info& type() = 0;
    virtual holder* clone() = 0;
  };

  template <class T>
  class placeholder : public holder {
   public:
    T _val;

   public:
    placeholder(const T& val) : _val(val) {}

    const std::type_info& type() { return typeid(T); }

    ~placeholder() {}

    holder* clone() { return new placeholder<T>(_val); }
  };
  std::shared_ptr<holder> _val;

 public:
  Any() : _val(nullptr) {}

  Any(const Any& cp) : _val(cp._val ? cp._val->clone() : nullptr) {}

  template <class T>
  Any(const T& val) : _val(new placeholder<T>(val)) {}

  Any swap(Any& oth) {
    _val.swap(oth._val);
    return *this;
  }

  Any& operator=(const Any& oth) {
    Any(oth).swap(*this);
    return *this;
  }

  template <class T>
  Any& operator=(const T& val) {
    Any(val).swap(*this);
    return *this;
  }

  template <class T>
  T* Get() {
    assert(typeid(T) == _val->type());
    return &((placeholder<T>*)_val.get())->_val;
  }
};

class Acceptor {
 private:
  Socket _socket;
  EventLoop* _loop;
  Channel _channel;
  using AcceptCallback = std::function<void(int)>;
  AcceptCallback _accept_callback;

 private:
  void HandleRead() {
    int newfd = _socket.Accept();
    if (newfd < 0) {
      return;
    }
    if (_accept_callback) {
      _accept_callback(newfd);
    }
  }

  int CreateServer(int port) {
    Socket so;
    bool ret = so.CreateServer(port);
    assert(ret);
    return so.Fd();
  }

 public:
  Acceptor(EventLoop* loop, int port)
      : _socket(CreateServer(port)), _loop(loop), _channel(loop, _socket.Fd()) {
    _channel.SetReadcallback(std::bind(&Acceptor::HandleRead, this));
  }

  void SetAcceptCallback(const AcceptCallback& cb) { _accept_callback = cb; }

  void Listen() { _channel.EnableRead(); }
};

class Connection;
using PtrConnection = std::shared_ptr<Connection>;
enum ConnStatu { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING };
class Connection : public std::enable_shared_from_this<Connection> {
 private:
  EventLoop* _loop;
  uint64_t _conn_id;
  int _sockfd;
  bool _enable_inactive_release;
  Socket _socket;
  Channel _channel;
  Buffer _in_buffer;
  Buffer _out_buffer;
  ConnStatu _statu;
  Any _context;

  using ConnectCallback = std::function<void(const PtrConnection&)>;
  using MessageCallback = std::function<void(const PtrConnection&, Buffer*)>;
  using ClosedCallback = std::function<void(const PtrConnection&)>;
  using AnyEventCallback = std::function<void(const PtrConnection&)>;
  ConnectCallback _connect_callback;
  MessageCallback _message_callback;
  ClosedCallback _closed_callback;
  AnyEventCallback _anyevent_callback;
  ClosedCallback _server_closed_callback;

 private:
  void ReleaseInLoop() {
    _statu = DISCONNECTED;
    _channel.Remove();
    _socket.Close();
    if (_loop->HasTimer(_conn_id)) {
      CancelInactiveRelease();
    }
    if (_closed_callback) {
      _closed_callback(shared_from_this());
    }
    if (_server_closed_callback) {
      _server_closed_callback(shared_from_this());
    }
  }

  void ShutdownInLoop() {
    _statu = DISCONNECTING;
    if (_in_buffer.ReadableSize() > 0) {
      if (_message_callback) {
        _message_callback(shared_from_this(), &_in_buffer);
      }
    }
    if (_out_buffer.ReadableSize() > 0) {
      if (_channel.WriteAble() == false) {
        _channel.EnableWrite();
      }
    }
    if (_out_buffer.ReadableSize() == 0) {
      Release();
    }
  }

  void HandleRead() {
    char buf[65536];
    ssize_t ret = _socket.NonBlockRecv(buf, 65535);
    if (ret < 0) {
      Release();
    }
    _in_buffer.WriteAndPush(buf, ret);
    if (_in_buffer.ReadableSize() > 0) {
      _message_callback(shared_from_this(), &_in_buffer);
    }
  }

  void CancelInactiveReleaseInLoop() {
    _enable_inactive_release = false;
    if (_loop->HasTimer(_conn_id)) {
      _loop->CancelTask(_conn_id);
    }
  }

  void HandleWrite() {
    ssize_t ret = _socket.NonBlockSend(_out_buffer.ReadPostition(),
                                       _out_buffer.ReadableSize());
    if (ret < 0) {
      Release();
    }
    _out_buffer.MoveReadIndex(ret);
    if (_out_buffer.ReadableSize() == 0) {
      _channel.DisableWrite();
    }
  }

  void HandleClose() {
    if (_in_buffer.ReadableSize() > 0) {
      if (_message_callback) {
        _message_callback(shared_from_this(), &_in_buffer);
      }
      Release();
    }
  }

  void HandleError() { HandleClose(); }

  void HandleEvent() {
    if (_enable_inactive_release) {
      _loop->FlushTask(_conn_id);
    }
    if (_anyevent_callback) {
      _anyevent_callback(shared_from_this());
    }
  }

  void EstablishedInLoop() {
    assert(_statu = CONNECTING);
    _statu = CONNECTED;
    _channel.EnableRead();
    if (_connect_callback) {
      _connect_callback(shared_from_this());
    }
  }

  void EnableInactiveReleaseInLoop(int sec) {
    _enable_inactive_release = true;
    if (_loop->HasTimer(_conn_id)) {
      _loop->FlushTask(_conn_id);
      return;
    }
    _loop->AddTask(_conn_id, sec, std::bind(&Connection::Release, this));
  }

  void SendInLoop(Buffer& buf) {
    if (_statu == DISCONNECTED) {
      return;
    }
    _out_buffer.WriteAndPush(buf);
    if (_channel.WriteAble() == false) {
      _channel.EnableWrite();
    }
  }
  void UpgradeInLoop(const Any& context,
                     const ConnectCallback& conn,
                     const MessageCallback& msg,
                     const ClosedCallback& closed,
                     const AnyEventCallback& event) {
    _context = context;
    _connect_callback = conn;
    _message_callback = msg;
    _closed_callback = closed;
    _anyevent_callback = event;
  }

 public:
  Connection(EventLoop* loop, uint64_t conn_id, int sockfd)
      : _loop(loop),
        _conn_id(conn_id),
        _sockfd(sockfd),
        _enable_inactive_release(false),
        _statu(CONNECTING),
        _socket(_sockfd),
        _channel(_loop, _sockfd) {
    _channel.SetReadcallback(std::bind(&Connection::HandleRead, this));
    _channel.SetWritecallback(std::bind(&Connection::HandleWrite, this));
    _channel.SetClosecallback(std::bind(&Connection::HandleClose, this));
    _channel.SetErrorcallback(std::bind(&Connection::HandleError, this));
    _channel.SetEventcallback(std::bind(&Connection::HandleEvent, this));
  }

  int Fd() { return _sockfd; }

  int Id() { return _conn_id; }

  bool Connected() { return (_statu == CONNECTED); }

  void SetContext(const Any& context) { _context = context; }

  Any* GetCneContext() { return &_context; }

  void SetConnectedCallback(const ConnectCallback& cb) {
    _connect_callback = cb;
  }

  void SetMessageCallback(const MessageCallback& cb) { _message_callback = cb; }

  void SetClosedCallback(const ClosedCallback& cb) { _closed_callback = cb; }

  void SetAnyEventCallback(const AnyEventCallback& cb) {
    _anyevent_callback = cb;
  }

  void SetSrvClosedCallback(const ClosedCallback& cb) {
    _server_closed_callback = cb;
  }

  void Shutdown() {
    _loop->RunInLoop(std::bind(&Connection::ShutdownInLoop, this));
  }

  void Release() {
    _loop->RunInLoop(std::bind(&Connection::ReleaseInLoop, this));
  }

  void CancelInactiveRelease() {
    _loop->RunInLoop(std::bind(&Connection::CancelInactiveReleaseInLoop, this));
  }

  void Established() {
    _loop->RunInLoop(std::bind(&Connection::EstablishedInLoop, this));
  }

  void EnableInactiveRelease(int sec) {
    _loop->RunInLoop(
        std::bind(&Connection::EnableInactiveReleaseInLoop, this, sec));
  }

  void Send(const char* data, size_t len) {
    Buffer buf;
    buf.WriteAndPush(data, len);
    _loop->RunInLoop(std::bind(&Connection::SendInLoop, this, std::move(buf)));
  }

  void Upgrade(const Any& context,
               const ConnectCallback& conn,
               const MessageCallback& msg,
               const ClosedCallback& closed,
               const AnyEventCallback& event) {
    _loop->AssertInLoop();
    _loop->RunInLoop(std::bind(&Connection::UpgradeInLoop, this, context, conn,
                               msg, closed, event));
  }
};

class TcpServer {
 private:
  uint64_t _next_id;
  int _port;
  int _timeout;
  bool _enable_inactive_release;
  EventLoop _baseloop;
  Acceptor _acceptor;
  LoopThreadPool _pool;
  std::unordered_map<uint64_t, PtrConnection> _conns;

  using ConnectCallback = std::function<void(const PtrConnection&)>;
  using MessageCallback = std::function<void(const PtrConnection&, Buffer*)>;
  using ClosedCallback = std::function<void(const PtrConnection&)>;
  using AnyEventCallback = std::function<void(const PtrConnection&)>;
  using Functor = std::function<void()>;
  ConnectCallback _connect_callback;
  MessageCallback _message_callback;
  ClosedCallback _closed_callback;
  AnyEventCallback _anyevent_callback;
  ClosedCallback _server_closed_callback;

 private:
  void NewConnection(int fd) {
    PtrConnection conn(new Connection(_pool.NextLoop(), ++_next_id, fd));
    conn->SetMessageCallback(_message_callback);
    conn->SetClosedCallback(_closed_callback);
    conn->SetConnectedCallback(_connect_callback);
    conn->SetAnyEventCallback(_anyevent_callback);
    conn->SetSrvClosedCallback(
        std::bind(&TcpServer::RemoveConnetion, this, std::placeholders::_1));
    if (_enable_inactive_release) {
      conn->EnableInactiveRelease(_timeout);
    }
    conn->Established();
    _conns.insert(std::make_pair(_next_id, conn));
  }

  void RunAfterInLoop(const Functor& task, int delay) {
    _baseloop.AddTask(++_next_id, delay, task);
  }

  void RemoveConnectionInLoop(const PtrConnection& conn) {
    int id = conn->Id();
    auto it = _conns.find(id);
    if (it != _conns.end()) {
      _conns.erase(it);
    }
  }

  void RemoveConnetion(const PtrConnection& conn) {
    _baseloop.RunInLoop(
        std::bind(&TcpServer::RemoveConnectionInLoop, this, conn));
  }

 public:
  TcpServer(int port)
      : _port(port),
        _next_id(0),
        _enable_inactive_release(false),
        _acceptor(&_baseloop, port),
        _pool(&_baseloop) {
    _acceptor.SetAcceptCallback(
        std::bind(&TcpServer::NewConnection, this, std::placeholders::_1));
    _acceptor.Listen();
  }

  void SetThreadCount(int count) { return _pool.SetThreadCount(count); }
  void SetConnectCallback(const ConnectCallback& cb) { _connect_callback = cb; }
  void SetMessageCallback(const MessageCallback& cb) { _message_callback = cb; }
  void SetClosedCallback(const ClosedCallback& cb) { _closed_callback = cb; }
  void SetAnyEventCallback(const AnyEventCallback& cb) {
    _anyevent_callback = cb;
  }

  void EnableInactiveRelease(int timeout) {
    _timeout = timeout;
    _enable_inactive_release = true;
  }

  void RunAfter(const Functor& task, int delay = 0) {
    _baseloop.RunInLoop(
        std::bind(&TcpServer::RunAfterInLoop, this, task, delay));
  }

  void Start() {
    _pool.Create();
    _baseloop.Start();
  }
};

void Channel::Update() {
  _loop->UpdateEvnet(this);
}

void Channel::Remove() {
  _loop->RemoveEvent(this);
}

void TimerWheel::AddTask(uint64_t tid, uint32_t timeout, const Taskfunc& tcb) {
  _loop->RunInLoop(
      std::bind(&TimerWheel::AddTaskInloop, this, tid, timeout, tcb));
}

void TimerWheel::FlushTask(uint64_t tid) {
  _loop->RunInLoop(std::bind(&TimerWheel::FlushTaskInloop, this, tid));
}

void TimerWheel::CancelTask(uint64_t tid) {
  _loop->RunInLoop(std::bind(&TimerWheel::CancelTaskInloop, this, tid));
}