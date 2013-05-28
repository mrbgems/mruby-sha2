#include <string.h>
#include "mruby.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "sha2.h"

static void
sha2_free(mrb_state *mrb, void *ptr)
{
  mrb_free(mrb, ptr);
}

static struct mrb_data_type sha256_type = { "SHA256", sha2_free };
static struct mrb_data_type sha384_type = { "SHA384", sha2_free };
static struct mrb_data_type sha512_type = { "SHA512", sha2_free };

static struct RClass *digest_module;
static struct RClass *base_class;
static struct RClass *sha256_class;
static struct RClass *sha384_class;
static struct RClass *sha512_class;

static mrb_value
sha256_initialize(mrb_state *mrb, mrb_value self)
{
  char *str;
  int len;
  SHA256_CTX *ctx = (SHA256_CTX*)mrb_malloc(mrb, sizeof(SHA256_CTX));
  SHA256_Init(ctx);

  DATA_TYPE(self) = &sha256_type;
  DATA_PTR(self) = ctx;

  if (mrb_get_args(mrb, "|s", &str, &len) == 1) {
    SHA256_Update(ctx, (const u_int8_t *)str, len);
  }

  return self;
}

static mrb_value
sha256_update(mrb_state *mrb, mrb_value self)
{
  char *str;
  int len;
  SHA256_CTX *ctx = (SHA256_CTX*)DATA_PTR(self);

  mrb_get_args(mrb, "s", &str, &len);
  SHA256_Update(ctx, (const u_int8_t *)str, len);
  
  return self;
}

static mrb_value
sha256_reset(mrb_state *mrb, mrb_value self)
{
  SHA256_CTX *ctx = (SHA256_CTX*)DATA_PTR(self);
  SHA256_Init(ctx);
  return self;
}

static mrb_value
sha256_clone(mrb_state *mrb, mrb_value self)
{
  SHA256_CTX *ctx = (SHA256_CTX*)DATA_PTR(self);
  SHA256_CTX *ctx_copy = (SHA256_CTX*)mrb_malloc(mrb, sizeof(SHA256_CTX));
  memcpy(ctx_copy, ctx, sizeof(SHA256_CTX));

  struct RData *c = mrb_data_object_alloc(mrb, sha256_class, ctx_copy, &sha256_type);
  return mrb_obj_value(c);
}

static mrb_value
sha256_digest(mrb_state *mrb, mrb_value self)
{
  char *digest = (char*)mrb_malloc(mrb, SHA256_DIGEST_LENGTH);
  SHA256_CTX ctx = *(SHA256_CTX*)DATA_PTR(self);
  SHA256_Final((u_int8_t *)digest, &ctx);
  return mrb_str_new(mrb, digest, SHA256_DIGEST_LENGTH);
}

static mrb_value
sha256_hexdigest(mrb_state *mrb, mrb_value self)
{
  char *hexdigest = (char*)mrb_malloc(mrb, SHA256_DIGEST_STRING_LENGTH);
  SHA256_CTX ctx = *(SHA256_CTX*)DATA_PTR(self);
  SHA256_End(&ctx, hexdigest);
  return mrb_str_new_cstr(mrb, hexdigest);
}

static mrb_value
sha256_digest_length(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(SHA256_DIGEST_LENGTH);
}

static mrb_value
sha256_block_length(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(SHA256_BLOCK_LENGTH);
}

static mrb_value
sha256_file(mrb_state *mrb, mrb_value self)
{

#ifdef ENABLE_FILE_DIGEST
  SHA256_CTX *ctx = (SHA256_CTX*)DATA_PTR(self);
  char *filename;
  char block[SHA256_BLOCK_LENGTH];
  size_t len;
  FILE *fp;

  mrb_get_args(mrb, "z", &filename);
  if((fp = fopen(filename, "rb")) == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "cannot open: %S", mrb_str_new_cstr(mrb, filename));
  }

  while((len = fread(block, 1, SHA256_BLOCK_LENGTH, fp)) > 0) {
    SHA256_Update(ctx, (const u_int8_t *)block, len);
  }
  
  fclose(fp);
#else
  mrb_raise(mrb, E_NOTIMP_ERROR, "Digest::SHA256#file not implemented");
#endif

  return self;
}

static mrb_value
sha384_initialize(mrb_state *mrb, mrb_value self)
{
  char *str;
  int len;
  SHA384_CTX *ctx = (SHA384_CTX*)mrb_malloc(mrb, sizeof(SHA384_CTX));
  SHA384_Init(ctx);

  DATA_TYPE(self) = &sha384_type;
  DATA_PTR(self) = ctx;

  if (mrb_get_args(mrb, "|s", &str, &len) == 1) {
    SHA384_Update(ctx, (const u_int8_t *)str, len);
  }

  return self;
}

static mrb_value
sha384_update(mrb_state *mrb, mrb_value self)
{
  char *str;
  int len;
  SHA384_CTX *ctx = (SHA384_CTX*)DATA_PTR(self);

  mrb_get_args(mrb, "s", &str, &len);
  SHA384_Update(ctx, (const u_int8_t *)str, len);
  
  return self;
}

static mrb_value
sha384_reset(mrb_state *mrb, mrb_value self)
{
  SHA384_CTX *ctx = (SHA384_CTX*)DATA_PTR(self);
  SHA384_Init(ctx);
  return self;
}

static mrb_value
sha384_clone(mrb_state *mrb, mrb_value self)
{
  SHA384_CTX *ctx = (SHA384_CTX*)DATA_PTR(self);
  SHA384_CTX *ctx_copy = (SHA384_CTX*)mrb_malloc(mrb, sizeof(SHA384_CTX));
  memcpy(ctx_copy, ctx, sizeof(SHA384_CTX));

  struct RData *c = mrb_data_object_alloc(mrb, sha384_class, ctx_copy, &sha384_type);
  return mrb_obj_value(c);
}

static mrb_value
sha384_digest(mrb_state *mrb, mrb_value self)
{
  char *digest = (char*)mrb_malloc(mrb, SHA384_DIGEST_LENGTH);
  SHA384_CTX ctx = *(SHA384_CTX*)DATA_PTR(self);
  SHA384_Final((u_int8_t *)digest, &ctx);
  return mrb_str_new(mrb, digest, SHA384_DIGEST_LENGTH);
}

static mrb_value
sha384_hexdigest(mrb_state *mrb, mrb_value self)
{
  char *hexdigest = (char*)mrb_malloc(mrb, SHA384_DIGEST_STRING_LENGTH);
  SHA384_CTX ctx = *(SHA384_CTX*)DATA_PTR(self);
  SHA384_End(&ctx, hexdigest);
  return mrb_str_new_cstr(mrb, hexdigest);
}

static mrb_value
sha384_digest_length(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(SHA384_DIGEST_LENGTH);
}

static mrb_value
sha384_block_length(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(SHA384_BLOCK_LENGTH);
}

static mrb_value
sha384_file(mrb_state *mrb, mrb_value self)
{

#ifdef ENABLE_FILE_DIGEST
  SHA384_CTX *ctx = (SHA384_CTX*)DATA_PTR(self);
  char *filename;
  char block[SHA384_BLOCK_LENGTH];
  size_t len;
  FILE *fp;

  mrb_get_args(mrb, "z", &filename);
  if((fp = fopen(filename, "rb")) == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "cannot open: %S", mrb_str_new_cstr(mrb, filename));
  }

  while((len = fread(block, 1, SHA384_BLOCK_LENGTH, fp)) > 0) {
    SHA384_Update(ctx, (const u_int8_t *)block, len);
  }
  
  fclose(fp);
#else
  mrb_raise(mrb, E_NOTIMP_ERROR, "Digest::SHA384#file not implemented");
#endif

  return self;
}

static mrb_value
sha512_initialize(mrb_state *mrb, mrb_value self)
{
  char *str;
  int len;
  SHA512_CTX *ctx = (SHA512_CTX*)mrb_malloc(mrb, sizeof(SHA512_CTX));
  SHA512_Init(ctx);

  DATA_TYPE(self) = &sha512_type;
  DATA_PTR(self) = ctx;

  if (mrb_get_args(mrb, "|s", &str, &len) == 1) {
    SHA512_Update(ctx, (const u_int8_t *)str, len);
  }

  return self;
}

static mrb_value
sha512_update(mrb_state *mrb, mrb_value self)
{
  char *str;
  int len;
  SHA512_CTX *ctx = (SHA512_CTX*)DATA_PTR(self);

  mrb_get_args(mrb, "s", &str, &len);
  SHA512_Update(ctx, (const u_int8_t *)str, len);
  
  return self;
}

static mrb_value
sha512_reset(mrb_state *mrb, mrb_value self)
{
  SHA512_CTX *ctx = (SHA512_CTX*)DATA_PTR(self);
  SHA512_Init(ctx);
  return self;
}

static mrb_value
sha512_clone(mrb_state *mrb, mrb_value self)
{
  SHA512_CTX *ctx = (SHA512_CTX*)DATA_PTR(self);
  SHA512_CTX *ctx_copy = (SHA512_CTX*)mrb_malloc(mrb, sizeof(SHA512_CTX));
  memcpy(ctx_copy, ctx, sizeof(SHA512_CTX));

  struct RData *c = mrb_data_object_alloc(mrb, sha512_class, ctx_copy, &sha512_type);
  return mrb_obj_value(c);
}

static mrb_value
sha512_digest(mrb_state *mrb, mrb_value self)
{
  char *digest = (char*)mrb_malloc(mrb, SHA512_DIGEST_LENGTH);
  SHA512_CTX ctx = *(SHA512_CTX*)DATA_PTR(self);
  SHA512_Final((u_int8_t *)digest, &ctx);
  return mrb_str_new(mrb, digest, SHA512_DIGEST_LENGTH);
}

static mrb_value
sha512_hexdigest(mrb_state *mrb, mrb_value self)
{
  char *hexdigest = (char*)mrb_malloc(mrb, SHA512_DIGEST_STRING_LENGTH);
  SHA512_CTX ctx = *(SHA512_CTX*)DATA_PTR(self);
  SHA512_End(&ctx, hexdigest);
  return mrb_str_new_cstr(mrb, hexdigest);
}

static mrb_value
sha512_digest_length(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(SHA512_DIGEST_LENGTH);
}

static mrb_value
sha512_block_length(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(SHA512_BLOCK_LENGTH);
}

static mrb_value
sha512_file(mrb_state *mrb, mrb_value self)
{

#ifdef ENABLE_FILE_DIGEST
  SHA512_CTX *ctx = (SHA512_CTX*)DATA_PTR(self);
  char *filename;
  char block[SHA512_BLOCK_LENGTH];
  size_t len;
  FILE *fp;

  mrb_get_args(mrb, "z", &filename);
  if((fp = fopen(filename, "rb")) == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "cannot open: %S", mrb_str_new_cstr(mrb, filename));
  }

  while((len = fread(block, 1, SHA512_BLOCK_LENGTH, fp)) > 0) {
    SHA512_Update(ctx, (const u_int8_t *)block, len);
  }
  
  fclose(fp);
#else
  mrb_raise(mrb, E_NOTIMP_ERROR, "Digest::SHA512#file not implemented");
#endif

  return self;
}

void
mrb_mruby_sha2_gem_init(mrb_state* mrb)
{
  digest_module = mrb_define_module(mrb, "Digest");
  base_class    = mrb_define_class_under(mrb, digest_module, "Base",   mrb->object_class);
  sha256_class  = mrb_define_class_under(mrb, digest_module, "SHA256", base_class);
  sha384_class  = mrb_define_class_under(mrb, digest_module, "SHA384", base_class);
  sha512_class  = mrb_define_class_under(mrb, digest_module, "SHA512", base_class);
  
  MRB_SET_INSTANCE_TT(sha256_class, MRB_TT_DATA);
  MRB_SET_INSTANCE_TT(sha384_class, MRB_TT_DATA);
  MRB_SET_INSTANCE_TT(sha512_class, MRB_TT_DATA);

  mrb_define_method(mrb, sha256_class, "initialize",    sha256_initialize,    ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "update",        sha256_update,        ARGS_REQ(1));
  mrb_define_method(mrb, sha256_class, "<<",            sha256_update,        ARGS_REQ(1));
  mrb_define_method(mrb, sha256_class, "reset",         sha256_reset,         ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "clone",         sha256_clone,         ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "dup",           sha256_clone,         ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "digest",        sha256_digest,        ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "hexdigest",     sha256_hexdigest,     ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "to_s",          sha256_hexdigest,     ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "digest_length", sha256_digest_length, ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "block_length",  sha256_block_length,  ARGS_NONE());
  mrb_define_method(mrb, sha256_class, "file",          sha256_file,          ARGS_REQ(1));

  mrb_define_method(mrb, sha384_class, "initialize",    sha384_initialize,    ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "update",        sha384_update,        ARGS_REQ(1));
  mrb_define_method(mrb, sha384_class, "<<",            sha384_update,        ARGS_REQ(1));
  mrb_define_method(mrb, sha384_class, "reset",         sha384_reset,         ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "clone",         sha384_clone,         ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "dup",           sha384_clone,         ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "digest",        sha384_digest,        ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "hexdigest",     sha384_hexdigest,     ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "to_s",          sha384_hexdigest,     ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "digest_length", sha384_digest_length, ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "block_length",  sha384_block_length,  ARGS_NONE());
  mrb_define_method(mrb, sha384_class, "file",          sha384_file,          ARGS_REQ(1));

  mrb_define_method(mrb, sha512_class, "initialize",    sha512_initialize,    ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "update",        sha512_update,        ARGS_REQ(1));
  mrb_define_method(mrb, sha512_class, "<<",            sha512_update,        ARGS_REQ(1));
  mrb_define_method(mrb, sha512_class, "reset",         sha512_reset,         ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "clone",         sha512_clone,         ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "dup",           sha512_clone,         ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "digest",        sha512_digest,        ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "hexdigest",     sha512_hexdigest,     ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "to_s",          sha512_hexdigest,     ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "digest_length", sha512_digest_length, ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "block_length",  sha512_block_length,  ARGS_NONE());
  mrb_define_method(mrb, sha512_class, "file",          sha512_file,          ARGS_REQ(1));
}

void
mrb_mruby_sha2_gem_final(mrb_state* mrb)
{

}
