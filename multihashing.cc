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

Handle<Value> x5(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> scrypt(const Arguments& args) {
   HandleScope scope;

   if (args.Length() < 3)
       return except("You must provide buffer to hash, N value, and R value");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");
    
   Local<Number> numn = args[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = args[2]->ToNumber();
   unsigned int rValue = numr->Value();
   
   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);
   
   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}

Handle<Value> neoscrypt_hash(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2)
        return except("You must provide two arguments.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    neoscrypt(input, output, 0);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> scryptn(const Arguments& args) {
   HandleScope scope;

   if (args.Length() < 2)
       return except("You must provide buffer to hash and N factor.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   Local<Number> num = args[1]->ToNumber();
   unsigned int nFactor = num->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}

Handle<Value> scryptjane(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 5)
        return except("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("First should be a buffer object.");

    Local<Number> num = args[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = args[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = args[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = args[4]->ToNumber();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> yescrypt(const Arguments& args) {
   HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   char * input = Buffer::Data(target);
   char output[32];

   yescrypt_hash(input, output);

   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}

Handle<Value> keccak(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> bcrypt(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> skein(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    
    skein_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> groestl(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> groestlmyriad(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> blake(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> dcrypt(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    dcrypt_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> fugue(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> qubit(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> s3(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    s3_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> hefty1(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> shavite3(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
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

Handle<Value> x13(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> x14(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x14_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> boolberry(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2)
        return except("You must provide two arguments.");

    Local<Object> target = args[0]->ToObject();
    Local<Object> target_spad = args[1]->ToObject();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        return except("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        return except("Argument 2 should be a buffer object.");

    if(args.Length() >= 3)
        if(args[2]->IsUint32())
            height = args[2]->ToUint32()->Uint32Value();
        else
            return except("Argument 3 should be an unsigned integer.");

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> nist5(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> sha1(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> x15(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> fresh(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}	
	
Handle<Value> whirlpoolx(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    whirlpoolx_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
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


Handle<Value> zr5(const Arguments& args) {
    HandleScope scope;

	//printf("ZR5 DEBUG MARKER:\n");
    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    zr5_hash((uint8_t *)input, (uint8_t *)output, dSize);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> jh(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    jh_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> c11(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    c11_hash(input, output);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

void init(Handle<Object> exports) {
     exports->Set(Nan::New<String>("quark").ToLocalChecked(), Nan::New<FunctionTemplate>(quark)->GetFunction());
     exports->Set(Nan::New<String>("x11").ToLocalChecked(), Nan::New<FunctionTemplate>(x11)->GetFunction());
     exports->Set(Nan::New<String>("scrypt").ToLocalChecked(), Nan::New<FunctionTemplate>(scrypt)->GetFunction());
     exports->Set(Nan::New<String>("scryptn").ToLocalChecked(), Nan::New<FunctionTemplate>(scryptn)->GetFunction());
    exports->Set(Nan::New<String>("scryptjane").ToLocalChecked(), Nan::New<FunctionTemplate>(scryptjane)->GetFunction());
    exports->Set(Nan::New<String>("keccak").ToLocalChecked(), Nan::New<FunctionTemplate>(keccak)->GetFunction());
    exports->Set(Nan::New<String>("bcrypt").ToLocalChecked(), Nan::New<FunctionTemplate>(bcrypt)->GetFunction());
    exports->Set(Nan::New<String>("skein").ToLocalChecked(), Nan::New<FunctionTemplate>(skein)->GetFunction());
    exports->Set(Nan::New<String>("groestl").ToLocalChecked(), Nan::New<FunctionTemplate>(groestl)->GetFunction());
    exports->Set(Nan::New<String>("groestlmyriad").ToLocalChecked(), Nan::New<FunctionTemplate>(groestlmyriad)->GetFunction());
    exports->Set(Nan::New<String>("blake").ToLocalChecked(), Nan::New<FunctionTemplate>(blake)->GetFunction());
    exports->Set(Nan::New<String>("fugue").ToLocalChecked(), Nan::New<FunctionTemplate>(fugue)->GetFunction());
    exports->Set(Nan::New<String>("qubit").ToLocalChecked(), Nan::New<FunctionTemplate>(qubit)->GetFunction());
    exports->Set(Nan::New<String>("hefty1").ToLocalChecked(), Nan::New<FunctionTemplate>(hefty1)->GetFunction());
    exports->Set(Nan::New<String>("shavite3").ToLocalChecked(), Nan::New<FunctionTemplate>(shavite3)->GetFunction());
    exports->Set(Nan::New<String>("cryptonight").ToLocalChecked(), Nan::New<FunctionTemplate>(cryptonight)->GetFunction());
    exports->Set(Nan::New<String>("x13").ToLocalChecked(), Nan::New<FunctionTemplate>(x13)->GetFunction());
    exports->Set(Nan::New<String>("x14").ToLocalChecked(), Nan::New<FunctionTemplate>(x14)->GetFunction());
    exports->Set(Nan::New<String>("boolberry").ToLocalChecked(), Nan::New<FunctionTemplate>(boolberry)->GetFunction());
    exports->Set(Nan::New<String>("nist5").ToLocalChecked(), Nan::New<FunctionTemplate>(nist5)->GetFunction());
    exports->Set(Nan::New<String>("sha1").ToLocalChecked(), Nan::New<FunctionTemplate>(sha1)->GetFunction());
    exports->Set(Nan::New<String>("x15").ToLocalChecked(), Nan::New<FunctionTemplate>(x15)->GetFunction());
    exports->Set(Nan::New<String>("whirlpoolx").ToLocalChecked(), Nan::New<FunctionTemplate>(whirlpoolx)->GetFunction());
    exports->Set(Nan::New<String>("fresh").ToLocalChecked(), Nan::New<FunctionTemplate>(fresh)->GetFunction());
    exports->Set(Nan::New<String>("zr5").ToLocalChecked(), Nan::New<FunctionTemplate>(zr5)->GetFunction());
    exports->Set(Nan::New<String>("ziftr").ToLocalChecked(), Nan::New<FunctionTemplate>(zr5)->GetFunction());
    exports->Set(Nan::New<String>("neoscrypt").ToLocalChecked(), Nan::New<FunctionTemplate>(neoscrypt_hash)->GetFunction());
    exports->Set(Nan::New<String>("yescrypt").ToLocalChecked(), Nan::New<FunctionTemplate>(yescrypt)->GetFunction());
    exports->Set(Nan::New<String>("lyra2re").ToLocalChecked(), Nan::New<FunctionTemplate>(lyra2re)->GetFunction());
    exports->Set(Nan::New<String>("lyra2re2").ToLocalChecked(), Nan::New<FunctionTemplate>(lyra2re2)->GetFunction());
    exports->Set(Nan::New<String>("c11").ToLocalChecked(), Nan::New<FunctionTemplate>(c11)->GetFunction());
    exports->Set(Nan::New<String>("s3").ToLocalChecked(), Nan::New<FunctionTemplate>(s3)->GetFunction());
    exports->Set(Nan::New<String>("dcrypt").ToLocalChecked(), Nan::New<FunctionTemplate>(dcrypt)->GetFunction());
    exports->Set(Nan::New<String>("jh").ToLocalChecked(), Nan::New<FunctionTemplate>(jh)->GetFunction());
    exports->Set(Nan::New<String>("c11").ToLocalChecked(), Nan::New<FunctionTemplate>(c11)->GetFunction());
}

NODE_MODULE(multihashing, init)
