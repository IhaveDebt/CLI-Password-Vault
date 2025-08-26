#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Simple Ruby Password Vault (AES-256-GCM, PBKDF2 key derivation)
# Usage:
#   ruby vault.rb init
#   ruby vault.rb add <name>
#   ruby vault.rb get <name>
#   ruby vault.rb list
#   ruby vault.rb delete <name>
#   ruby vault.rb change_master
#
require "json"
require "openssl"
require "io/console"
require "securerandom"
require "base64"

VAULT_FILE = "vault.dat" # encrypted blob
META_FILE  = "vault.meta" # salt + kdf info (not secret)

def prompt_hidden(label)
  print(label)
  STDIN.noecho(&:gets).tap { puts }.to_s.strip
end

def derive_key(password, salt, iters, key_len = 32)
  OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: iters, length: key_len, hash: "sha256")
end

def encrypt_bytes(key, plaintext)
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.encrypt
  nonce = SecureRandom.random_bytes(12)
  cipher.key = key
  cipher.iv  = nonce
  ciphertext = cipher.update(plaintext) + cipher.final
  tag = cipher.auth_tag
  { "n" => Base64.strict_encode64(nonce),
    "c" => Base64.strict_encode64(ciphertext),
    "t" => Base64.strict_encode64(tag) }
end

def decrypt_bytes(key, blob)
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.decrypt
  cipher.key = key
  cipher.iv  = Base64.decode64(blob["n"])
  cipher.auth_tag = Base64.decode64(blob["t"])
  cipher.update(Base64.decode64(blob["c"])) + cipher.final
end

def load_meta!
  raise "Vault not initialized. Run: ruby vault.rb init" unless File.exist?(META_FILE)
  JSON.parse(File.read(META_FILE))
end

def load_vault(key)
  return {} unless File.exist?(VAULT_FILE)
  blob = JSON.parse(File.read(VAULT_FILE))
  decrypted = decrypt_bytes(key, blob)
  JSON.parse(decrypted)
rescue OpenSSL::Cipher::CipherError
  abort "Error: wrong master password or corrupted vault."
end

def save_vault(key, data)
  plaintext = JSON.pretty_generate(data)
  blob = encrypt_bytes(key, plaintext)
  File.write(VAULT_FILE, JSON.dump(blob))
end

def cmd_init
  if File.exist?(META_FILE) || File.exist?(VAULT_FILE)
    abort "Vault already initialized."
  end
  puts "Initializing new vault…"
  pass1 = prompt_hidden("Create master password: ")
  pass2 = prompt_hidden("Confirm master password: ")
  abort "Passwords do not match." unless pass1 == pass2 && !pass1.empty?
  salt  = SecureRandom.random_bytes(16)
  iters = 200_000
  key   = derive_key(pass1, salt, iters)
  save_vault(key, {})
  meta = { "kdf" => "pbkdf2-hmac-sha256", "iters" => iters, "salt" => Base64.strict_encode64(salt) }
  File.write(META_FILE, JSON.dump(meta))
  puts "Vault created ✅"
end

def cmd_add(name)
  meta = load_meta!
  master = prompt_hidden("Master password: ")
  key = derive_key(master, Base64.decode64(meta["salt"]), meta["iters"])
  vault = load_vault(key)
  if vault.key?(name)
    print "Entry '#{name}' exists. Overwrite? (y/N): "
    ans = STDIN.gets.to_s.strip.downcase
    abort "Canceled." unless ans == "y"
  end
  username = (print "Username: "; STDIN.gets.to_s.strip)
  password = prompt_hidden("Password (leave blank to generate): ")
  if password.empty?
    password = Base64.strict_encode64(SecureRandom.random_bytes(18)) # ~24 chars
    puts "Generated password: #{password}"
  end
  notes = (print "Notes (optional): "; STDIN.gets.to_s.strip)
  vault[name] = { "username" => username, "password" => password, "notes" => notes, "updated_at" => Time.now.utc.iso8601 }
  save_vault(key, vault)
  puts "Saved entry '#{name}' ✅"
end

def cmd_get(name)
  meta = load_meta!
  master = prompt_hidden("Master password: ")
  key = derive_key(master, Base64.decode64(meta["salt"]), meta["iters"])
  vault = load_vault(key)
  entry = vault[name] or abort "No entry named '#{name}'."
  puts "— #{name} —"
  puts "Username : #{entry["username"]}"
  puts "Password : #{entry["password"]}"
  puts "Notes    : #{entry["notes"]}"
  puts "Updated  : #{entry["updated_at"]}"
end

def cmd_list
  meta = load_meta!
  master = prompt_hidden("Master password: ")
  key = derive_key(master, Base64.decode64(meta["salt"]), meta["iters"])
  vault = load_vault(key)
  if vault.empty?
    puts "(empty)"
  else
    puts "Entries (#{vault.size}):"
    vault.keys.sort.each { |k| puts "- #{k}" }
  end
end

def cmd_delete(name)
  meta = load_meta!
  master = prompt_hidden("Master password: ")
  key = derive_key(master, Base64.decode64(meta["salt"]), meta["iters"])
  vault = load_vault(key)
  abort "No entry named '#{name}'." unless vault.key?(name)
  print "Delete '#{name}'? This cannot be undone. (y/N): "
  ans = STDIN.gets.to_s.strip.downcase
  abort "Canceled." unless ans == "y"
  vault.delete(name)
  save_vault(key, vault)
  puts "Deleted '#{name}' ✅"
end

def cmd_change_master
  meta = load_meta!
  old_master = prompt_hidden("Current master password: ")
  old_key = derive_key(old_master, Base64.decode64(meta["salt"]), meta["iters"])
  vault = load_vault(old_key)

  new1 = prompt_hidden("New master password: ")
  new2 = prompt_hidden("Confirm new master password: ")
  abort "Passwords do not match." unless new1 == new2 && !new1.empty?

  new_salt = SecureRandom.random_bytes(16)
  new_iters = 250_000
  new_key = derive_key(new1, new_salt, new_iters)
  save_vault(new_key, vault)
  new_meta = { "kdf" => "pbkdf2-hmac-sha256", "iters" => new_iters, "salt" => Base64.strict_encode64(new_salt) }
  File.write(META_FILE, JSON.dump(new_meta))
  puts "Master password updated ✅"
end

# -------- CLI --------
cmd = ARGV.shift
case cmd
when "init"           then cmd_init
when "add"            then name = ARGV.shift or abort "Usage: ruby vault.rb add <name>"; cmd_add(name)
when "get"            then name = ARGV.shift or abort "Usage: ruby vault.rb get <name>"; cmd_get(name)
when "list"           then cmd_list
when "delete"         then name = ARGV.shift or abort "Usage: ruby vault.rb delete <name>"; cmd_delete(name)
when "change_master"  then cmd_change_master
else
  puts <<~HELP
    Usage:
      ruby vault.rb init
      ruby vault.rb add <name>
      ruby vault.rb get <name>
      ruby vault.rb list
      ruby vault.rb delete <name>
      ruby vault.rb change_master
  HELP
end
