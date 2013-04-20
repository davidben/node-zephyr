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
#include <zephyr/zephyr.h>
}

// This doesn't need the extern "C", but com_err.h does, so make sure
// that's included afterwards.
#include <krb5/krb5.h>

using namespace v8;

namespace {

Persistent<Function> g_on_msg;
uv_loop_t *g_loop;
uv_poll_t g_zephyr_poll;
bool g_initialized;

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
  switch (code) {
#define NODE_ZEPHYR_ERROR(name) \
  case name: return #name;
#include "error_list.h"
#undef NODE_ZEPHYR_ERROR
  default:
    return "GENERIC";
  }
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

Local<Object> ZUniqueIdToBuffer(const ZUnique_Id_t& uid) {
  return Local<Object>::New(
      node::Buffer::New(reinterpret_cast<const char*>(&uid),
                        sizeof(uid))->handle_);
}

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

Handle<Value> OpenPort(const Arguments& args) {
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

  ret = ZOpenPort(NULL);
  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    return scope.Close(Undefined());
  }

  InstallZephyrListener();
  g_initialized = true;

  return scope.Close(Undefined());
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

/*[ CHECK ]*******************************************************************/

void ZephyrToObject(ZNotice_t *notice, Handle<Object> target) {
  target->Set(g_symbol_version, String::New(notice->z_version));
  target->Set(g_symbol_port, Number::New(notice->z_port));
  target->Set(g_symbol_checkedAuth, Number::New(notice->z_checked_auth));
  target->Set(g_symbol_authentLen, Number::New(notice->z_authent_len));
  // FIXME: This likely does terrible things with unicode. I think
  // it's not actually ASCII.
  target->Set(g_symbol_asciiAuthent, String::New(notice->z_ascii_authent));
  target->Set(g_symbol_class, String::New(notice->z_class));
  target->Set(g_symbol_instance, String::New(notice->z_class_inst));
  target->Set(g_symbol_opcode, String::New(notice->z_opcode));
  target->Set(g_symbol_sender, String::New(notice->z_sender));
  target->Set(g_symbol_recipient, String::New(notice->z_recipient));
  target->Set(g_symbol_kind, Number::New(notice->z_kind));
  target->Set(g_symbol_time, Date::New(notice->z_time.tv_sec * 1000.0 +
                                       notice->z_time.tv_usec / 1000.0));
  target->Set(g_symbol_auth, Number::New(notice->z_auth));

  target->Set(g_symbol_uid, ZUniqueIdToBuffer(notice->z_uid));

  target->Set(g_symbol_senderAddr,
              String::New(inet_ntoa(notice->z_sender_addr)));

  // Split up the body's components by NULs.
  Local<Array> body = Array::New();
  for (int offset = 0, i = 0; offset < notice->z_message_len; i++) {
    const char* nul = static_cast<const char*>(
        memchr(notice->z_message + offset, 0, notice->z_message_len - offset));
    int nul_offset = nul ? (nul - notice->z_message) : notice->z_message_len;
    body->Set(i, String::New(notice->z_message + offset,
                             nul_offset - offset));
    offset = nul_offset + 1;
  }
  target->Set(g_symbol_body, body);

  Local<Array> other_fields = Array::New(notice->z_num_other_fields);
  for (int i = 0; i < notice->z_num_other_fields; ++i) {
    other_fields->Set(i, String::New(notice->z_other_fields[i]));
  }
  target->Set(g_symbol_otherFields, other_fields);
}

void OnZephyrFDReady(uv_poll_t* handle, int status, int events) {
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

    Handle<Object> object = Object::New();
    Local<Value> argv[2] = {
      Local<Value>::New(Null()),
      Local<Object>::New(object)
    };
    ZephyrToObject(&notice, object);
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

/*[ SUB ]*********************************************************************/

Handle<Value> SubscribeTo(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  if (args.Length() != 1 || !args[0]->IsArray()) {
    ThrowException(Exception::TypeError(String::New("Invalid parameters")));
    return scope.Close(Undefined());
  }

  Local<Array> in_subs = Local<Array>::Cast(args[0]);
  // RAII ALL THE THINGS. It's nice to be able to early-return.
  std::vector<ZSubscription_t> subs;
  std::vector<std::string> cleanup;
  subs.reserve(in_subs->Length());
  cleanup.reserve(in_subs->Length() * 3);

  for (uint32_t i = 0; i < in_subs->Length(); ++i) {
    if (!in_subs->Get(i)->IsArray()) {
      ThrowException(Exception::TypeError(String::New("Expected array")));
      return scope.Close(Undefined());
    }

    Local<Array> sub_array = Local<Array>::Cast(in_subs->Get(i));
    ZSubscription_t sub = { NULL, NULL, NULL };
    sub.zsub_recipient = const_cast<char*>("");
    switch (sub_array->Length()) {
      case 3:
        if (!sub_array->Get(2)->IsString()) {
          ThrowException(Exception::TypeError(String::New("Expected string")));
          return scope.Close(Undefined());
        }
        cleanup.push_back(ValueToString(sub_array->Get(2)));
        sub.zsub_recipient = const_cast<char*>(cleanup.back().c_str());
        // fallthrough
      case 2:
        if (!sub_array->Get(1)->IsString()) {
          ThrowException(Exception::TypeError(String::New("Expected string")));
          return scope.Close(Undefined());
        }
        cleanup.push_back(ValueToString(sub_array->Get(1)));
        sub.zsub_classinst = const_cast<char*>(cleanup.back().c_str());

        if (!sub_array->Get(0)->IsString()) {
          ThrowException(Exception::TypeError(String::New("Expected string")));
          return scope.Close(Undefined());
        }
        cleanup.push_back(ValueToString(sub_array->Get(0)));
        sub.zsub_class = const_cast<char*>(cleanup.back().c_str());
        break;
      default:
        ThrowException(Exception::TypeError(
            String::New("Subs must be [ class, instance, recipient? ]")));
        return scope.Close(Undefined());
    }
    subs.push_back(sub);
  }

  int ret = ZSubscribeTo(&subs[0], subs.size(), 0);
  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    return scope.Close(Undefined());
  }
  return scope.Close(Undefined());
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

std::vector<ZUnique_Id_t> g_wait_on_uids;

Code_t SendFunction(ZNotice_t* notice, char* packet, int len, int waitforack) {
  // Send without blocking.
  Code_t ret = ZSendPacket(packet, len, 0);

  // Save the ZUnique_Id_t for waiting on. Arguably we do this better
  // than the real libzephyr; ZSendPacket doesn't get a notice
  // argument and parses the notice back out again.
  if (ret == ZERR_NONE && waitforack)
    g_wait_on_uids.push_back(notice->z_uid);

  return ret;
}

Handle<Value> SendNotice(const Arguments& args) {
  HandleScope scope;

  ABORT_UNLESS_INITIALIZED();

  if (args.Length() != 1 || !args[0]->IsObject()) {
    ThrowException(Exception::TypeError(String::New("Notice must be object")));
    return scope.Close(Undefined());
  }

  // Pull fields out of the object.
  Local<Object> obj = Local<Object>::Cast(args[0]);

  // Assemble the body.
  std::string body;
  Local<Value> body_value = obj->Get(String::New("body"));
  if (body_value->IsArray()) {
    Local<Array> body_array = Local<Array>::Cast(body_value);
    for (uint32_t i = 0, len = body_array->Length(); i < len; i++) {
      String::Utf8Value value(body_array->Get(i));
      if (i > 0)
        body.push_back('\0');
      body.append(*value, value.length());
    }
  }

  std::string msg_class = GetStringProperty(obj, g_symbol_class, "MESSAGE");
  std::string instance = GetStringProperty(obj, g_symbol_instance, "PERSONAL");
  std::string format = GetStringProperty(obj, g_symbol_format,
                                         "http://zephyr.1ts.org/wiki/df");
  std::string opcode = GetStringProperty(obj, g_symbol_opcode, "");
  std::string recipient = GetStringProperty(obj, g_symbol_recipient, "");

  // Assemble the notice.
  ZNotice_t notice;
  memset(&notice, 0, sizeof(notice));
  notice.z_message_len = body.length();
  notice.z_message = const_cast<char*>(body.data());
  notice.z_kind = ACKED;
  notice.z_class = const_cast<char*>(msg_class.c_str());
  notice.z_class_inst = const_cast<char*>(instance.c_str());
  notice.z_default_format = const_cast<char*>(format.c_str());
  notice.z_opcode = const_cast<char*>(opcode.c_str());
  notice.z_recipient = const_cast<char*>(recipient.c_str());

  Code_t ret = ZSrvSendNotice(&notice, ZAUTH, SendFunction);

  if (ret != ZERR_NONE) {
    ThrowException(ComErrException(ret));
    g_wait_on_uids.clear();
    return scope.Close(Undefined());
  }

  Local<Array> uids = Array::New();
  for (unsigned i = 0; i < g_wait_on_uids.size(); i++) {
    uids->Set(i, ZUniqueIdToBuffer(g_wait_on_uids[i]));
  }
  g_wait_on_uids.clear();
  return scope.Close(uids);
}

/*[ SEND ]********************************************************************/

void Init(Handle<Object> exports, Handle<Value> module) {
  CreateSymbols();

  g_loop = uv_default_loop();

  // TODO: Explicit close port and cancel subs commands. We don't
  // really clean up properly right now.
  exports->Set(g_symbol_openPort,
               FunctionTemplate::New(OpenPort)->GetFunction());
  exports->Set(g_symbol_getSender,
               FunctionTemplate::New(GetSender)->GetFunction());
  exports->Set(g_symbol_getRealm,
               FunctionTemplate::New(GetRealm)->GetFunction());
  exports->Set(g_symbol_setNoticeCallback,
               FunctionTemplate::New(SetNoticeCallback)->GetFunction());
  exports->Set(g_symbol_subscribeTo,
               FunctionTemplate::New(SubscribeTo)->GetFunction());
  exports->Set(g_symbol_sendNotice,
               FunctionTemplate::New(SendNotice)->GetFunction());
}

NODE_MODULE(zephyr, Init)

}  // namespace
