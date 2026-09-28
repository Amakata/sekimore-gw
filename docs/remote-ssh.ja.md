# Linux ホストを Remote-SSH で使う

*[English](remote-ssh.md)*

Mac の VS Code → Remote-SSH で Linux VM → VM の上で Dev Containers。狙いは Mac のときと同じで、
運用者の ssh-agent はゲートウェイには届き、dev コンテナには届かない。

- Mac の agent は `RemoteForward` で VM の固定パスに出し、ゲートウェイがそこを mount する
- VS Code が張る接続では agent forwarding（`SSH_AUTH_SOCK`）を切る。Dev Containers 拡張は
  VS Code サーバが持つ `SSH_AUTH_SOCK` をそのまま dev に渡し、サーバは最初に起動したときの
  環境を接続をまたいで持ち続ける

## Mac

`~/.ssh/config`: ターミナル用と VS Code 用で Host を分ける。

```
Host devvm
  HostName 192.168.56.11
  User dev
  ForwardAgent yes

Host devvm-vscode
  HostName 192.168.56.11
  User dev
  ForwardAgent no
  RemoteForward /home/dev/.sekimore/agent.sock ${SSH_AUTH_SOCK}
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%n:%p
  ControlPersist 10m
```

- `${SSH_AUTH_SOCK}` は接続時に ssh が展開する（OpenSSH 8.4 以降）。launchd のパスはログインの
  たびに変わるので直書きしない
- `ControlMaster` で接続を 1 本にする。同じ `RemoteForward` を 2 つのセッションが張ると、
  先に切れた方がソケットを消す
- VS Code から繋ぐものは全部 `devvm-vscode`（`code --remote ssh-remote+devvm-vscode …`）。
  一度でも `devvm` で繋ぐと、サーバが動いている間ずっと `SSH_AUTH_SOCK` を持ったままになる
- VS Code は普通に起動する。`sgw open` はアプリから `SSH_AUTH_SOCK` を消すので、
  `${SSH_AUTH_SOCK}` が展開できなくなる

VS Code の `settings.json`:

```json
"remote.SSH.enableAgentForwarding": false
```

これが on だと VS Code は ssh に `-A` を付け、コマンドラインのオプションは config より優先される。

## VM

```
mkdir -m 700 ~/.sekimore
printf 'Host *\n  IdentityAgent ~/.sekimore/agent.sock\n' >> ~/.ssh/config
echo 'StreamLocalBindUnlink yes' | sudo tee -a /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl restart ssh
```

- `StreamLocalBindUnlink` で、再接続のたびに sshd がソケットファイルを置き換えられる
- `IdentityAgent` で VM の `ssh` と `git` が Mac の鍵を使う。環境変数を経由しないので
  VS Code サーバに受け継がれない。`.bashrc` / `.zshrc` に `export SSH_AUTH_SOCK=…` は書かない
- 確認は `SSH_AUTH_SOCK=~/.sekimore/agent.sock ssh-add -l`

## プロジェクト

`.devcontainer/.env` には**ディレクトリ**を書く（ソケットではなく）。

```
SEKIMORE_AGENT_SOCK=/home/dev/.sekimore
```

ゲートウェイはこれを mount し、中の `agent.sock` を接続のたびに名前で探すので、sshd が作り直した
ソケットも `sgw recreate` なしで拾う。ソケットファイルそのものを書いても動くが、ファイルの
bind mount はコンテナ起動時の inode を掴んだままになり、再接続のたびにゲートウェイは死んだ
ソケットに話しかけて `sgw recreate` が要る。起動時にパスが無いと Docker がそこにディレクトリを作る。

## 立ち上げ

1. 「Remote-SSH: Kill VS Code Server on Host」を一度実行し、サーバに起動時の環境を忘れさせる
2. Mac から繋いでソケットを確かめる:
   ```
   ssh devvm-vscode 'SSH_AUTH_SOCK=~/.sekimore/agent.sock ssh-add -l'
   ```
3. VM で `sgw recreate` → `sgw check`（ssh-agent: N identities）→ `sgw verify`。
   `host:` の項目が、ソケットが答えるか、VS Code サーバが `SSH_AUTH_SOCK` を持っていないかを言う
4. プロジェクトをコンテナで開き直す。post-create が通り、VM 側の VS Code ターミナルで
   `echo $SSH_AUTH_SOCK` が空
