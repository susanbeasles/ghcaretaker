import hashlib,pathlib,shutil,subprocess,sys,tempfile
root=pathlib.Path(__file__).resolve().parents[1]
proposal=root/'.gitleaks.toml'
cases=[('private-key','src/vault-core.mjs',11),('private-key','test/fakes.mjs',105),('private-key','test/security.test.mjs',59),('generic-api-key','scripts/check-config.mjs',34)]
# Read the checked-in config, never regenerate exceptions from current source.
binary=str(pathlib.Path(sys.argv[1]).resolve()) if len(sys.argv)>1 else shutil.which('gitleaks')
if not binary:
 raise SystemExit('gitleaks is required; pass the verified binary path')
def scan(directory):
 result=subprocess.run([binary,'detect','--no-git','--source','.', '--config',str(proposal),'--redact','--no-banner'],cwd=directory,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 assert result.returncode in [0,1],result.stderr.decode()
 return result.returncode
with tempfile.TemporaryDirectory(prefix='ghcaretaker-allowlist-tests-') as tmp:
 tmp=pathlib.Path(tmp)
 for _,path,_ in cases:
  target=tmp/path;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/path,target)
 assert scan(tmp)==0,'known non-credential expressions were not narrowly allowed'
 count=1
 for rule,path,n in cases:
  target=tmp/path;original=target.read_text()
  # Intentionally invalid synthetic PEM, never used to authenticate/sign.
  synthetic='const syntheticFixture = "-----BEGIN'+' PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCYp6rUs4nBt2zJw8xCq5hDv9mKf3aLc7eYp6rUs4nBt2zJw8xCq5hDv9mKf3aLc7eYp6rUs4nBt2zJw8xCq5hDv9mKf3aLc7eYp6rUs4nBt2zJw8xCq5hDv9mKf3aLc7eYp6rUs4nBt2zJw8xCq5hDv9mKf3aLc7eYp6rUs4nBt2zJw8xCq5hDv9mKf3aLc7eYp6rUs4nBt2zJw8xCq5hDv9mKf3aLc7eYp6rUs4nBt2zJw8xCq5hDv9mKf3aLc7e\\n-----END'+' PRIVATE KEY-----";'
  if rule=='generic-api-key': synthetic="const SECRETS_STORE='"+hashlib.sha256(b'not-a-real-credential-allowlist-test').hexdigest()[:32]+"';"
  target.write_text(original+'\n'+synthetic+'\n')
  assert scan(tmp)==1,'new synthetic finding in allowed file must still be detected: '+path
  target.write_text(original);count+=1
  lines=original.splitlines();lines[n-1]=synthetic;target.write_text('\n'.join(lines)+'\n')
  assert scan(tmp)==1,'replacement on original line must still be detected'
  target.write_text(original);count+=1
  other=tmp/'unlisted.mjs';other.write_text(original);assert scan(tmp)==1,'same expression in another file must not be allowed';other.unlink();count+=1
 print(f'{count} allowlist specificity checks passed')
