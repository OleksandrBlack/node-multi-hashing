#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "nan.h"

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    #include "neoscrypt.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "s3.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "x14.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "dcrypt.h"
    #include "jh.h"
    #include "x5.h"
    #include "c11.h"
    #include "whirlpoolx.h"
    #include "fresh.h"
    #include "zr5.h"
    #include "Lyra2RE.h"
}

#include "boolberry.h"
#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

using namespace node;
using namespace v8;

NAN_METHOD(quark) {

if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x11) {

    if (info.Length() < 1)
         return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(cryptonight) {

    bool fast = false;

    if (info.Length() < 1)
         return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    if (info.Length() >= 2) {
         if(!info[1]->IsBoolean())
             return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
         fast = info[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(lyra2re) {
    if (info.Length() < 1)
         return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2re_hash(input, output);

   info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(lyra2re2) {
    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2re2_hash(input, output);

   info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

void init(Handle<Object> exports) {
     exports->Set(Nan::New<String>("quark").ToLocalChecked(), Nan::New<FunctionTemplate>(quark)->GetFunction());
     exports->Set(Nan::New<String>("x11").ToLocalChecked(), Nan::New<FunctionTemplate>(x11)->GetFunction());
    exports->Set(Nan::New<String>("cryptonight").ToLocalChecked(), Nan::New<FunctionTemplate>(cryptonight)->GetFunction());
    exports->Set(Nan::New<String>("lyra2re").ToLocalChecked(), Nan::New<FunctionTemplate>(lyra2re)->GetFunction());
    exports->Set(Nan::New<String>("lyra2re2").ToLocalChecked(), Nan::New<FunctionTemplate>(lyra2re2)->GetFunction());
}

NODE_MODULE(multihashing, init)
