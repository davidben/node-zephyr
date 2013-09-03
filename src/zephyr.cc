#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

extern "C" {
#include <com_err.h>
#include <krb5/krb5.h>
#include <zephyr/zephyr.h>

#include "utf8proc.h"
}

using namespace v8;

namespace {

Persistent<Function> g_on_msg;
uv_loop_t *g_loop;
uv_poll_t g_zephyr_poll;
bool g_initialized, g_listener_active;

#define NODE_ZEPHYR_SYMBOL(sym) \
  Persistent<String> g_symbol_ ## sym ;
#include "symbols.h"
#undef NODE_ZEPHYR_SYMBOL

void CreateSymbols() {
#define NODE_ZEPHYR_SYMBOL(sym) \
  g_symbol_ ## sym = Persistent<String>::New(String::NewSymbol( #sym ));
#include "symbols.h"
#undef NODE_ZEPHYR_SYMBOL
}

const char* ErrorCodeToSymbol(Code_t code) {
  // Don't use switch-case because some errnos duplicate, but you
  // don't know for sure (EWOULDBLOCK/EAGAIN). It's dumb. Hopefully
  // the compiler's clever enough to optimize it anyway.
#define NODE_ZEPHYR_ERROR(name) \
  if (code == name) {		\
    return #name;		\
  }
#include "error_list.h"
#undef NODE_ZEPHYR_ERROR
  return "GENERIC";
}

Local<Value> ComErrException(Code_t code) {
  const char* msg = error_message(code);
  Local<Value> err = Exception::Error(String::New(msg));
  Local<Object> obj = err->ToObject();
  obj->Set(g_symbol_code, String::New(ErrorCodeToSymbol(code)));
  return err;
}

void CallWithError(Handle<Function> callback, Code_t code) {
  Local<Value> err = ComErrException(code);
  callback->Call(Context::GetCurrent()->Global(), 1, &err);
}

std::string ValueToString(const Handle<Value> str) {
  String::Utf8Value temp(Handle<String>::Cast(str));
  return std::string(*temp, temp.length());
}

Local<Value> ZUniqueIdToString(const ZUnique_Id_t& uid) {
  return node::Encode(&uid, sizeof(uid), node::BASE64);
}

bool CertRoutineFromString(const std::string& str, Z_AuthProc* proc) {
  if (str == "ZNOAUTH") {
    *proc = ZNOAUTH;
    return true;
  }
  if (str == "ZAUTH") {
    *proc = ZAUTH;
    return true;
  }
  return false;
}

void FreeCallback(char* data, void*) {
  free(data);
}

// A struct containing data to populate a ZNotice_t. Mostly for
// ownership purposes.
struct NoticeFields {
  ZNotice_Kind_t kind;
  unsigned short port;
  unsigned short charset;
  std::string msg_class;
  std::string instance;
  std::string default_format;
  std::string opcode;
  std::string recipient;
  std::string sender;
  std::string message;

  NoticeFields() : kind(ACKED), port(0), charset(ZCHARSET_UTF_8) { }

  // Resulting ZNotice_t only valid as long as the NoticeFields.
  void ToNotice(ZNotice_t* notice) {
    memset(notice, 0, sizeof(*notice));
    notice->z_kind = kind;
    notice->z_port = port;
    notice->z_charset = charset;
    notice->z_class = const_cast<char*>(msg_class.c_str());
    notice->z_class_inst = const_cast<char*>(instance.c_str());
    notice->z_default_format = const_cast<char*>(default_format.c_str());
    notice->z_opcode = const_cast<char*>(opcode.c_str());
    notice->z_recipient = const_cast<char*>(recipient.c_str());
    notice->z_sender = const_cast<char*>(sender.c_str());
    notice->z_message = const_cast<char*>(message.data());
    notice->z_message_len = message.length();
  }
};

#define ABORT_UNLESS_INITIALIZED()                      \
  do {                                                  \
    if (!g_initialized) {                               \
      ThrowException(Exception::Error(String::New(      \
          "Zephyr not initialized")));                  \
      return scope.Close(Undefined());                  \
    }                                                   \
  } while(0)

/*[ OPENPORT ]****************************************************************/

void InstallZephyrListener();
void RemoveZephyrListener();

Handle<Value> Initialize(const Arguments& args) {
  HandleScope scope;

  if (g_initialized) {
    ThrowException(Exception::Error(String::New(
        "Zephyr already initialized")));
    return scope.Close(Undefined());
  }

  Code_t ret = ZInitialize();
  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    return scope.Close(Undefined());
  }

  g_initialized = true;
  return scope.Close(Undefined());
}

Handle<Value> OpenPort(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  RemoveZephyrListener();
  Code_t ret = ZOpenPort(NULL);
  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    return scope.Close(Undefined());
  }
  InstallZephyrListener();

  return scope.Close(Undefined());
}

/*[ SESSIONS ]****************************************************************/

Handle<Value> LoadSession(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  if (args.Length() != 1 || !node::Buffer::HasInstance(args[0])) {
    ThrowException(Exception::TypeError(
        String::New("Parameter not a buffer")));
    return scope.Close(Undefined());
  }

  RemoveZephyrListener();
  v8::Local<v8::Object> obj = args[0]->ToObject();
  Code_t ret = ZLoadSession(node::Buffer::Data(obj),
                            node::Buffer::Length(obj));
  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    return scope.Close(Undefined());
  }
  InstallZephyrListener();

  return scope.Close(Undefined());
}

Handle<Value> DumpSession(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  char *buffer;
  int len;
  Code_t ret = ZDumpSession(&buffer, &len);
  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    return scope.Close(Undefined());
  }

  return scope.Close(
      node::Buffer::New(buffer, len, FreeCallback, NULL)->handle_);
}

/*[ MISC ]*******************************************************************/

Handle<Value> GetSender(const Arguments& args) {
  HandleScope scope;
  ABORT_UNLESS_INITIALIZED();
  return scope.Close(String::New(ZGetSender()));
}

Handle<Value> GetRealm(const Arguments& args) {
  HandleScope scope;
  ABORT_UNLESS_INITIALIZED();
  return scope.Close(String::New(ZGetRealm()));
}

Handle<Value> GetDestAddr(const Arguments& args) {
  HandleScope scope;
  ABORT_UNLESS_INITIALIZED();

  sockaddr_in addr = ZGetDestAddr();

  Local<Object> ret = Object::New();
  char ip[INET_ADDRSTRLEN];
  uv_inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof ip);
  ret->Set(g_symbol_host, String::New(ip));
  ret->Set(g_symbol_port, Integer::New(ntohs(addr.sin_port)));
  return scope.Close(ret);
}

/*[ CHECK ]*******************************************************************/

Local<String> TransliterateString(unsigned short charset,
                                  const char *str,
                                  int len) {
  const char *charset_str = ZCharsetToString(charset);
  // Assume UNKNOWN charset is UTF-8. zwgc seems to assume it is
  // ISO-8859-1 in X11 mode and assume it's the same as the tty
  // charset (so UTF-8 for sane environemnts).
  if (!strcmp(charset_str, "UNKNOWN") ||
      !strcmp(charset_str, "UTF-8")) {
    return String::New(str, len);
  }
  // Convert to UTF-8 first.
  char *out_str;
  int out_len;
  Code_t ret = ZTransliterate(const_cast<char*>(str), len,
                              const_cast<char*>(charset_str),
                              const_cast<char*>("UTF-8"),
                              &out_str, &out_len);
  if (ret != 0) {
    // Failed to ZTransliterate. Just assume UTF-8 again.
    return String::New(str, len);
  }

  // Yay. Now all 5 zephyrs sent with an explicit ISO-8859-1 charset
  // will get handled correctly. Whatever.
  Local<String> result = String::New(out_str, out_len);
  free(out_str);
  return result;
}

Local<Object> ZephyrToObject(ZNotice_t *notice) {
  Local<Object> target = Object::New();

  target->Set(g_symbol_version, String::New(notice->z_version));
  target->Set(g_symbol_port, Integer::New(ntohs(notice->z_port)));
  target->Set(g_symbol_checkedAuth, Integer::New(notice->z_checked_auth));
  target->Set(g_symbol_class, String::New(notice->z_class));
  target->Set(g_symbol_instance, String::New(notice->z_class_inst));
  target->Set(g_symbol_opcode, String::New(notice->z_opcode));
  target->Set(g_symbol_sender, String::New(notice->z_sender));
  target->Set(g_symbol_recipient, String::New(notice->z_recipient));
  target->Set(g_symbol_kind, Integer::New(notice->z_kind));
  target->Set(g_symbol_time, Date::New(notice->z_time.tv_sec * 1000.0 +
                                       notice->z_time.tv_usec / 1000.0));
  target->Set(g_symbol_auth, Integer::New(notice->z_auth));

  target->Set(g_symbol_uid, ZUniqueIdToString(notice->z_uid));

  target->Set(g_symbol_senderAddr,
              String::New(inet_ntoa(notice->z_sender_addr)));

  // Split up the body's components by NULs.
  //
  // TODO(davidben): Can I just implement this in JavaScript with
  // String.prototype.split? Minor nuisance is that we then do a UTF-8
  // to JS string conversion over the entire string. Which I'm... fair
  // sure is fine?
  //
  // TOOD(davidben): Pay attention to z_charset here? BarnOwl doesn't,
  // and we'd have to find a ISO-8859-1 decoder.
  Local<Array> body = Array::New();
  for (int offset = 0, i = 0; offset <= notice->z_message_len; i++) {
    const char* nul = static_cast<const char*>(
        memchr(notice->z_message + offset, 0, notice->z_message_len - offset));
    int nul_offset = nul ? (nul - notice->z_message) : notice->z_message_len;
    body->Set(i, TransliterateString(notice->z_charset,
                                     notice->z_message + offset,
                                     nul_offset - offset));
    offset = nul_offset + 1;
  }
  target->Set(g_symbol_body, body);

  Local<Array> other_fields = Array::New(notice->z_num_other_fields);
  for (int i = 0; i < notice->z_num_other_fields; ++i) {
    other_fields->Set(i, String::New(notice->z_other_fields[i]));
  }
  target->Set(g_symbol_otherFields, other_fields);

  return target;
}

void OnZephyrFDReady(uv_poll_t* handle, int status, int events) {
  HandleScope scope;

  Local<Function> callback = Local<Function>::New(g_on_msg);
  struct sockaddr_in from;
  ZNotice_t notice;

  while (true) {
    int len = ZPending();
    if (len < 0) {
      CallWithError(callback, errno);
      return;
    } else if (len == 0) {
      return;
    }

    int ret = ZReceiveNotice(&notice, &from);
    if (ret != ZERR_NONE) {
      CallWithError(callback, ret);
      return;
    }

    Local<Value> argv[2] = {
      Local<Value>::New(Null()),
      ZephyrToObject(&notice)
    };
    callback->Call(Context::GetCurrent()->Global(), 2, argv);
    ZFreeNotice(&notice);
  }
}

Handle<Value> SetNoticeCallback(const Arguments& args) {
  HandleScope scope;

  if (args.Length() != 1 || !args[0]->IsFunction()) {
    ThrowException(Exception::TypeError(
        String::New("Parameter not a function")));
    return scope.Close(Undefined());
  }

  g_on_msg = Persistent<Function>::New(Local<Function>::Cast(args[0]));

  return scope.Close(Undefined());
}

void InstallZephyrListener() {
  if (g_listener_active) {
    fprintf(stderr, "ERROR: Listener active!\n");
  }

  int fd = ZGetFD();
  if (fd < 0) {
    fprintf(stderr, "No zephyr FD\n");
    return;
  }

  int ret;
  ret = uv_poll_init(g_loop, &g_zephyr_poll, fd);
  if (ret != 0) {
    fprintf(stderr, "uv_poll_init: %d\n", ret);
    return;
  }

  ret = uv_poll_start(&g_zephyr_poll, UV_READABLE, OnZephyrFDReady);
  if (ret != 0) {
    fprintf(stderr, "uv_poll_start: %d\n", ret);
    return;
  }
}

void RemoveZephyrListener() {
  if (!g_listener_active)
    return;

  int ret = uv_poll_stop(&g_zephyr_poll);
  if (ret != 0) {
    fprintf(stderr, "uv_poll_stop: %d\n", ret);
    return;
  }
  g_listener_active = false;
}

/*[ SEND ]********************************************************************/

std::string GetStringProperty(Handle<Object> source,
                              Handle<String> key,
                              const char *default_value) {
  Local<Value> value = source->Get(key);
  if (value->IsUndefined())
    return default_value;
  return ValueToString(source->Get(key));
}

NoticeFields ObjectToNoticeFields(Handle<Object> obj) {
  NoticeFields ret;

  // TODO(davidben): Let you change kind? It'd also need to be
  // mirrored by punting HMACK/SERVACK stuff on the JS side. Possibly
  // put that logic in C++ actually, so JS gets two lists of uids?
  // Dunno.
  if (obj->Has(g_symbol_port))
    ret.port = ntohs(obj->Get(g_symbol_port)->ToUint32()->Value());
  ret.msg_class = GetStringProperty(obj, g_symbol_class, "MESSAGE");
  ret.instance = GetStringProperty(obj, g_symbol_instance, "PERSONAL");
  ret.default_format = GetStringProperty(obj, g_symbol_format,
                                         "http://zephyr.1ts.org/wiki/df");
  ret.opcode = GetStringProperty(obj, g_symbol_opcode, "");
  ret.recipient = GetStringProperty(obj, g_symbol_recipient, "");
  ret.sender = GetStringProperty(obj, g_symbol_sender, ZGetSender());

  // Assemble the body.
  Local<Value> body_value = obj->Get(g_symbol_body);
  if (body_value->IsArray()) {
    Local<Array> body_array = Local<Array>::Cast(body_value);
    for (uint32_t i = 0, len = body_array->Length(); i < len; i++) {
      String::Utf8Value value(body_array->Get(i));
      if (i > 0)
        ret.message.push_back('\0');
      // Intentionally truncate each string at a NUL. Better to
      // silently truncate a la all the other C strings rather than
      // inject field separators.
      char* p = static_cast<char*>(memchr(*value, '\0', value.length()));
      size_t truncated = p ? (p - *value) : value.length();
      ret.message.append(*value, truncated);
    }
  }

  return ret;
}

struct Packet {
  ZNotice_Kind_t kind;
  ZUnique_Id_t uid;
  std::vector<char> buffer;
};

std::vector<Packet> g_packets;

Code_t SendFunction(ZNotice_t* notice, char* packet, int len, int waitforack) {
  // Hold onto the packet for later. We'll send it in node.
  g_packets.push_back(Packet());
  g_packets.back().kind = notice->z_kind;
  g_packets.back().uid = notice->z_uid;
  g_packets.back().buffer.assign(packet, packet + len);
  return ZERR_NONE;
}

Local<Value> ReturnSavedPackets() {
  Local<Array> result = Array::New();
  for (unsigned i = 0; i < g_packets.size(); i++) {
    Local<Object> packet = Object::New();
    packet->Set(g_symbol_kind, Integer::New(g_packets[i].kind));
    packet->Set(g_symbol_uid, ZUniqueIdToString(g_packets[i].uid));
    packet->Set(g_symbol_buffer,
                node::Buffer::New(&g_packets[i].buffer[0],
                                  g_packets[i].buffer.size())->handle_);

    result->Set(i, packet);
  }
  g_packets.clear();
  return result;
}

Handle<Value> SendNotice(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  if (args.Length() != 2 || !args[0]->IsObject()) {
    ThrowException(Exception::TypeError(String::New(
        "Arguments: notice, certRoutine")));
    return scope.Close(Undefined());
  }

  // Assemble the notice.
  Local<Object> obj = Local<Object>::Cast(args[0]);
  NoticeFields fields = ObjectToNoticeFields(obj);
  ZNotice_t notice;
  fields.ToNotice(&notice);

  Z_AuthProc cert_routine;
  if (!CertRoutineFromString(ValueToString(args[1]), &cert_routine)) {
    ThrowException(Exception::Error(String::New("Invalid certRoutine")));
    return scope.Close(Undefined());
  }

  Code_t ret = ZSrvSendNotice(&notice, cert_routine, SendFunction);

  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    g_packets.clear();
    return scope.Close(Undefined());
  }
  return scope.Close(ReturnSavedPackets());
}

/*[ FORMAT ]******************************************************************/

Handle<Value> FormatNotice(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  if (args.Length() != 2 || !args[0]->IsObject()) {
    ThrowException(Exception::TypeError(String::New(
        "Arguments; notice, certRoutine")));
    return scope.Close(Undefined());
  }

  // Assemble the notice.
  Local<Object> obj = Local<Object>::Cast(args[0]);
  NoticeFields fields = ObjectToNoticeFields(obj);
  ZNotice_t notice;
  fields.ToNotice(&notice);

  Z_AuthProc cert_routine;
  if (!CertRoutineFromString(ValueToString(args[1]), &cert_routine)) {
    ThrowException(Exception::Error(String::New("Invalid certRoutine")));
    return scope.Close(Undefined());
  }

  char* buffer;
  int len;
  Code_t ret = ZFormatNotice(&notice, &buffer, &len, cert_routine);

  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    return scope.Close(Undefined());
  }
  return scope.Close(
      node::Buffer::New(buffer, len, FreeCallback, NULL)->handle_);
}


/*[ PARSE ]******************************************************************/

Handle<Value> ParseNotice(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  if (args.Length() != 1 || !node::Buffer::HasInstance(args[0])) {
    ThrowException(Exception::TypeError(
        String::New("Parameter not a buffer")));
    return scope.Close(Undefined());
  }

  Local<Object> buf = args[0]->ToObject();

  ZNotice_t notice;
  Code_t ret = ZParseNotice(node::Buffer::Data(buf),
                            node::Buffer::Length(buf),
                            &notice);
  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    return scope.Close(Undefined());
  }
  // No need to free anything. Data is still owned by the
  // buffer. ZParseNotice just references it.
  return scope.Close(ZephyrToObject(&notice));
}

/*[ SUBSCRIPTIONS ]***********************************************************/

Handle<Value> Subscriptions(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  if (args.Length() != 2 || !args[0]->IsArray()) {
    ThrowException(Exception::TypeError(String::New(
        "Arguments; subs, opcode")));
    return scope.Close(Undefined());
  }

  std::string opcode = ValueToString(args[1]);

  // Don't bother normalizing anything. Leave that to JS.
  Local<Array> array = Local<Array>::Cast(args[0]);
  std::vector<std::string> strings; strings.reserve(array->Length() * 3);
  std::vector<ZSubscription_t> subs; subs.reserve(array->Length());
  for (uint32_t i = 0; i < array->Length(); i++) {
    if (!array->Get(i)->IsArray()) {
      ThrowException(Exception::TypeError(String::New("Expected array")));
      return scope.Close(Undefined());
    }
    Local<Array> sub_array = Local<Array>::Cast(array->Get(i));
    ZSubscription_t sub;

    strings.push_back(ValueToString(sub_array->Get(0)));
    sub.zsub_class = const_cast<char*>(strings.back().c_str());

    strings.push_back(ValueToString(sub_array->Get(1)));
    sub.zsub_classinst = const_cast<char*>(strings.back().c_str());

    strings.push_back(ValueToString(sub_array->Get(2)));
    sub.zsub_recipient = const_cast<char*>(strings.back().c_str());

    subs.push_back(sub);
  }

  Code_t ret = ZSubscriptions(&subs[0], subs.size(), 0,
                              const_cast<char*>(opcode.c_str()),
                              SendFunction);
  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    g_packets.clear();
    return scope.Close(Undefined());
  }
  return scope.Close(ReturnSavedPackets());
}

/** DOWNCASE *********************************************/

int IsValidUtf8(const char* s) {
  ssize_t len;
  int32_t uc;

  while ((len = utf8proc_iterate((const unsigned char *)s, -1, &uc))) {
    if (len <=0) return 0; /* Not valid UTF-8 encoding. */
    /* Not valid unicode codepoint. */
    if (!(utf8proc_codepoint_valid(uc))) return 0;
    if (uc == 0) return 1; /* NULL, we're done. */
    s += len;
  }
  return 0; /* We shouldn't get here. */
}

// Modeled after zdowncase in zephyr's server/zstring.c.
Handle<Value> Downcase(const Arguments& args) {
  HandleScope scope;

  std::string arg = ValueToString(args[0]);

  // We go from JS strings to UTF-8, but this can probably still trip
  // up because JS strings can contain unmatched surrogate pairs.
  if (IsValidUtf8(arg.c_str())) {
    unsigned char *new_s_u; /* Avoid strict aliasing violation */

    /* Use utf8proc if we're dealing with UTF-8.
     * Rather than downcase, casefold and normalize to NFKC.
     */
    // C++ and JavaScript strings can contain NULs. utf8proc handles
    // this, but we intentionally use NULLTERM and
    // std::string::c_str. This way strings get silently truncated at
    // NULs, as they currently do in sendNotice. The intent is that
    // two class names with matching zephyr.downcase(className) will
    // result in equivalent subscriptions. By virtue of using C
    // strings, these bindings will implicitly truncate at NULs in
    // other functions.
    //
    // Possibly we should be being more picky and failing hard on
    // NULs or something.
    ssize_t len = utf8proc_map((const unsigned char *)arg.c_str(), 0,
                               (unsigned char **)&new_s_u,
                               UTF8PROC_NULLTERM |
                               UTF8PROC_STABLE | UTF8PROC_CASEFOLD |
                               UTF8PROC_COMPAT | UTF8PROC_COMPOSE);
    if (len < 0) {
      ThrowException(Exception::Error(String::New(
          utf8proc_errmsg(len))));
      return scope.Close(Undefined());
    }
    arg.assign((char*)new_s_u, len);
    free(new_s_u);
  } else {
    /* If not, fall back to old methods. */
    for (unsigned i = 0; i < arg.size(); i++) {
      if (isascii(arg[i]) && isupper(arg[i]))
        arg[i] = tolower(arg[i]);
    }
  }

  return scope.Close(String::New(arg.data(), arg.length()));
}

/*[ INIT ]********************************************************************/

void Init(Handle<Object> exports, Handle<Value> module) {
  CreateSymbols();

  g_loop = uv_default_loop();

  // TODO: Explicit close port and cancel subs commands. We don't
  // really clean up properly right now.
  exports->Set(g_symbol_initialize,
               FunctionTemplate::New(Initialize)->GetFunction());
  exports->Set(g_symbol_openPort,
               FunctionTemplate::New(OpenPort)->GetFunction());
  exports->Set(g_symbol_getSender,
               FunctionTemplate::New(GetSender)->GetFunction());
  exports->Set(g_symbol_getRealm,
               FunctionTemplate::New(GetRealm)->GetFunction());
  exports->Set(g_symbol_getDestAddr,
               FunctionTemplate::New(GetDestAddr)->GetFunction());
  exports->Set(g_symbol_setNoticeCallback,
               FunctionTemplate::New(SetNoticeCallback)->GetFunction());
  exports->Set(g_symbol_sendNotice,
               FunctionTemplate::New(SendNotice)->GetFunction());
  exports->Set(g_symbol_formatNotice,
               FunctionTemplate::New(FormatNotice)->GetFunction());
  exports->Set(g_symbol_parseNotice,
               FunctionTemplate::New(ParseNotice)->GetFunction());
  exports->Set(g_symbol_subscriptions,
               FunctionTemplate::New(Subscriptions)->GetFunction());
  exports->Set(g_symbol_downcase,
               FunctionTemplate::New(Downcase)->GetFunction());
  exports->Set(g_symbol_dumpSession,
               FunctionTemplate::New(DumpSession)->GetFunction());
  exports->Set(g_symbol_loadSession,
               FunctionTemplate::New(LoadSession)->GetFunction());
}

NODE_MODULE(zephyr, Init)

}  // namespace
