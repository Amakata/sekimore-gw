<!-- reviewed-up-to: 0.2.45 -->
# 更新のしかた：版ごとに必要な変更

*[English](UPGRADING.md)*

**このガイドに載せているのは、あなたが持っているファイルの変更が必要な版だけです。**
載っていない版は、`mise run upgrade:apply` を実行するだけで更新が完了します（base 0.2.20 より前は、
代わりにイメージのタグを上げて `mise run gw:recreate` を実行します）。各版で何が変わったかは
changelog を参照してください。
[ゲートウェイ](https://github.com/Amakata/sekimore-gw/blob/main/CHANGELOG.ja.md) /
[relay](https://github.com/Amakata/sekimore-gw/blob/main/relay/CHANGELOG.ja.md) /
[base](CHANGELOG.ja.md)

「あなたが持っているファイル」とは、雛形から複製したファイルのことです。

| ファイル | 持ち主 |
|---|---|
| `.devcontainer/config/config.yml` | あなた。関所（sekimore-relay）の設定が書かれています。 |
| `mise.toml` | あなた。ホスト側のタスクを include し、あなた自身のタスクを置きます。 |
| `.devcontainer/docker-compose.yml` | あなた。ゲートウェイのイメージタグが書かれています（`upgrade:apply` が書き換えるのはタグだけです）。 |
| `.devcontainer/sgw/` | base 0.2.20 からは**あなたのものではありません**。`upgrade:apply` が入れ替えます。base 0.2.20 より前は、`.devcontainer/scripts/sgw.sh` をあなたが持っていました。 |

## いまの版から読む場所

| いまのゲートウェイ | 読む節 |
|---|---|
| 0.0.x | [0.1.0](#010-関所-relay-が入った) 以降。関所を使わないなら、**何もする必要はありません**。 |
| 0.1.0 〜 0.1.8 | [0.1.9](#019-権限の書き方が変わった) 以降 |
| 0.1.9 〜 0.2.6 | [0.2.7](#027-projects-のボードを宣言する-破壊的) 以降 |
| 0.2.7 〜 0.2.14 | [0.2.15](#0215-秘密ストアが増えた) 以降 |
| 0.2.15 〜 0.2.18 | [0.2.19](#0219-解錠が必須になった) |
| 0.2.19 〜 0.2.21 | [0.2.22](#0222-proxy-の認証情報がストアに移った)。**上流 proxy がパスワードを要求する場合だけ** |
| 0.2.22 〜 0.2.26 | [0.2.27](#0227-タグは署名が必須になった)。**エージェントがタグを push する場合だけ** |
| 0.2.27 | [0.2.28](#0228-dependabot-アラートは任意)。**エージェントに Dependabot アラートを読ませたい場合だけ** |
| 0.2.28 | [0.2.29](#0229-解錠を自動化できるようになった)。**解錠を自動化したい場合、または AI のコミットを Verified のままにしたい場合だけ** |
| 0.2.29 〜 0.2.36 | [0.2.37](#0237-ゲートウェイに-pid-host-が要る)。**すべてのプロジェクト** |
| 0.2.37 〜 0.2.43 | [0.2.44](#0244-proxyjump-の踏み台のホスト鍵が必要になった)。**上流が `ProxyJump` の踏み台を使う場合だけ** |
| 0.2.44 | [0.2.45](#0245-gwlogin-は端末で尋ねホスト鍵が無ければ止まる)。**ゲートウェイが保存していないホスト鍵が上流に要る場合だけ** |

ゲートウェイの版とは別に、base 0.2.20 より前に作ったプロジェクトは、一度だけ手作業で
`.devcontainer/sgw/` に移行する必要があります。
[base 0.2.20](#base-0220-devcontainersgw-と-mise-run-upgrade) を参照してください。移行後は、
更新でまたぐこのガイドの節を `mise run upgrade` が一覧表示します。

---

## 0.1.0 関所 (relay) が入った

**関所は opt-in です。** `config.yml` に `domain_handlers` と `relay` が無ければ関所は起動せず、
ゲートウェイは 0.0.x と同じように動きます。DNS フィルタ、ファイアウォール、Squid は変わりません。
設定キーの削除や改名はありません。`allow_domains`、`block_domains`、`allow_ips`、`block_ips`、
`proxy`、`network`、`database_path` は、いずれも引き続き解釈されます。関所を使わずに新しい版に上げるだけなら、イメージのタグを上げて
`mise run gw:recreate` を実行します。

関所を導入する場合は、[0.0.x から関所を導入する](#00x-から関所を導入する)を参照してください。

### 0.0.x から関所を導入する

関所を使うには、0.0.x の構成にないものが必要になります。関所側の構成は独立した overlay compose
ファイルにまとまっているので、追加するのは次の 3 つです。

1. `config.yml` の `domain_handlers` と `relay`
   ([`config/config.sample.yml`](https://github.com/Amakata/sekimore-gw/blob/main/config/config.sample.yml) の末尾が現在の雛形)
2. [`docker-compose.relay.yml`](examples/sgw-sample/.devcontainer/docker-compose.relay.yml) の複製。
   `devcontainer.json` の `dockerComposeFile` に、`docker-compose.yml` の**後ろ**に並べます。
   ssh-agent のマウントと使い捨ての鍵の volume はこのファイルに入っています
3. `.env.sample` を `.env` に複製し、プロジェクト名などの値を埋めたもの (上の overlay が読みます)

そのあと `mise run gw:unlock`、`gw:login`、`dev:signing-key`、`relay:verify` を順に実行します。

関所の利用をやめるには、`dockerComposeFile` から overlay を外し、`config.yml` から
`domain_handlers` と `relay` を削除します。ゲートウェイは 0.0.x と同じ動作に戻ります。

これらをすべて追加すると `.devcontainer/` は 0.0.x の構成とは大きく異なるものになるため、
**雛形を複製し直して `allow_domains` などの設定を移すほうが早いです。**

このガイドの後の節にある破壊的変更 (0.1.9、0.2.7 など) が影響するのは、0.1.x から関所を使っている構成だけです。
0.0.x から上げる場合は現在の雛形で関所を新規に設定するので、どれも該当しません。

## 0.1.9 権限の書き方が変わった

`relay.allow_tags` と `relay.allow_delete` は非推奨になりました。**関所は引き続きこれらを読みます**。
起動時に警告を出し、`relay.project` の既定値に畳み込みます。そのまま残しても動作は壊れません。
移行する場合は、次のように書きます。

```yaml
relay:
  project:
    tags: ["*"]        # 旧 relay.allow_tags: true
    delete: true       # 旧 relay.allow_delete: true
```

## 0.2.7 Projects のボードを宣言する (破壊的)

**Projects v2 を使っている場合は作業が必要です。** このプロジェクトが操作してよいボードを列挙しないと、
関所は Projects の操作を**すべて**拒否します。ボードの node ID は不透明で、所有者を示しません。
そのため一覧が無いと、上流トークンから見える任意のボードにエージェントが届いてしまいます。

```yaml
relay:
  project:
    boards:
      - { org: acme, number: 3 }       # github.com/orgs/acme/projects/3
      - { user: someone, number: 1 }   # github.com/users/someone/projects/1
```

Projects を使っていなければ、作業は不要です。

同じ版で `handler: git-relay` が `handler: github` に改名されました。旧名は
**別名として引き続き使える**ので、書き換える必要はありません。

## 0.2.13 設定の反映に窓ができた

既定値は `auto` で、これまでと同じ動作です。ただし `config.yml` は dev コンテナから書き込めるため、
**エージェントに作業を渡す前に、反映の窓を閉じてください。**

```yaml
reload: manual        # または 30m のような時間
```

```bash
mise run gw:reload-freeze    # いますぐ窓を閉じる
mise run gw:reload-status    # 窓が開いているか閉じているかを表示する
```

これらのコマンドには、`mise.toml` に `gw:reload-*` の 3 つのタスクが必要です。雛形には含まれています。

## 0.2.15 秘密ストアが増えた

`mise.toml` には解錠のタスクが、`sgw.sh` には **`gw-tty`** の分岐が必要です。`gw-tty` は、
パスフレーズのプロンプトを端末につなぎます。通常の `gw` 分岐は、stdout も端末である場合にだけ
`-t` を付けます。タスクランナーは stdout をパイプにするので、`gw-tty` が無いとプロンプトに端末が
つながりません。

両方を雛形から取り込んでください。

```bash
diff -u <base>/examples/sgw-sample/mise.toml mise.toml
diff -u <base>/examples/sgw-sample/.devcontainer/scripts/sgw.sh .devcontainer/scripts/sgw.sh
```

必要なタスクは `gw:unlock`、`gw:lock`、`gw:store-status`、`gw:passphrase` です。

## 0.2.18 ストアの控えが取れるようになった

`mise.toml` に `gw:store-export` と `gw:store-import` を追加してください。export には鍵が不要なので、
施錠中のストアでも export できます。export したものは封じられたままですが、
**それを守るのはパスフレーズだけです**。

## 0.2.19 解錠が必須になった

**上流 API トークンが秘密ストアに保存されるようになったため、ストアを解錠するまで関所は GitHub API
に届きません。** git の push と pull は SSH を使うので影響を受けません。

- ゲートウェイを作り直したとき、または再起動したときは、**毎回** `mise run gw:unlock` を実行してください。
  鍵はメモリ上にしか存在しません。
- `whoami`、`check`、`logout` は関所の制御ソケットを使うため、関所が動いている必要があります。
- 既存の `/data/relay/upstream_token` は、関所が最初に読んだときにストアへ移され、その後削除されます。
  **手作業は不要です。**

0.2.15 を飛ばしている場合は、ここから先に進めません。`gw:unlock` が無く、追加しても `gw-tty` が
無いと動かないためです。先に 0.2.15 の節を済ませてください。

同じ版で、上流が既に広告しているタグを動かす push は拒否されるようになりました。
**新しいタグの作成には影響しない**ので、リリース手順は変わりません。

## 0.2.20 タスクが gateway から来るようになった

**この作業は任意ですが、一度実施することを推奨します。** イメージが自身の `gw:*` タスクを
持つようになったため、プロジェクト側で複製を持つ必要がなくなりました。

雛形（`examples/sgw-sample/`）は既にこの構成なので、新しいプロジェクトは雛形から始められます。
既存のプロジェクトは、`gw:sync-tasks` を追加して一度実行します。

```toml
# mise.toml — これだけは自分で持つ。イメージから取り出すタスクそのものなので、イメージからは配れない
[tasks."gw:sync-tasks"]
description = "動いているゲートウェイから gw:* タスクを取り出す (gw:recreate のあとに実行する)"
run = "bash \"$SGW\" gw cat /usr/local/share/sekimore/gateway.mise.ja.toml > \"$MISE_PROJECT_ROOT/.devcontainer/gateway.mise.toml\" && echo wrote"
```

```bash
mise run gw:sync-tasks      # .en.toml でもよい。違うのは `mise tasks` の表示だけ
```

```toml
# mise.toml — gw:* のタスクは消して、自分のタスクだけ残す
[task_config]
includes = [".devcontainer/gateway.mise.toml"]

[env]
SGW = "{{config_root}}/.devcontainer/scripts/sgw.sh"
```

`mise run gw:recreate` を実行するたびに、タスクを取り出し直してください。これでタスクは常に、
動いているゲートウェイのものと一致します。上の 0.2.15 と 0.2.19 の更新で作業を誤りやすかった原因である
複製のずれは、これで起きなくなります。

`sgw.sh` は引き続きあなたが持ち、`gw-tty` を含んでいる必要があります。同梱のタスクファイルの冒頭に、
タスクが使う `sgw.sh` の 4 つの基本操作が書かれています。

**取り出したファイルはコミットしてください。** `mise` は、include するファイルが無くても
**エラーも警告も出さずに無視します**。このファイルを `.gitignore` に入れると、次にリポジトリを clone
した人の環境には `gw:*` タスクが一つも存在せず、それを知らせるものもありません。コミットしておけば、
ゲートウェイの更新が `git diff` に現れます。更新が目に見えるのはそこだけです。

## 0.2.22 proxy の認証情報がストアに移った

**この節は、パスワードを要求する社内 proxy の背後にあるゲートウェイだけが対象です。** それ以外の場合、
作業は不要です。

`config.yml` の `upstream_proxy_username` と `upstream_proxy_password`、および環境変数
`SEKIMORE_UPSTREAM_PROXY_*` は、dev コンテナから読めます。`config.yml` は worktree の中にあり、
`.devcontainer/.env` はエージェント自身の `env_file` だからです。資格情報は秘密ストアに保存してください。

```bash
mise run gw:proxy-credential -- set     # ユーザー名とパスワードを端末で尋ねる
```

そのあと、`config.yml` から 2 つのキーを、設定していた場所から 2 つの環境変数を削除し、
`mise run gw:recreate` を実行します。残しておいてもゲートウェイは**引き続き読む**ので、破壊的変更では
ありません。ただし、露出をなくすには削除する必要があります。

ストアは起動時に封じられているため、次の 2 点が生じます。

- `mise run gw:unlock` を実行するまで、Squid は上流認証**なし**で動き、ストアが解錠されると自動で
  資格情報を読み込みます。匿名のリクエストを拒否する proxy の背後でもゲートウェイは起動します。解錠前に
  ゲートウェイから proxy を通る通信が無いためです。
- `gw:proxy-credential` はゲートウェイのタスクです。`mise run gw:sync-tasks` を実行すると、include
  （[0.2.20](#0220-タスクが-gateway-から来るようになった)）経由で使えるようになります。

0.2.21 と 0.2.23 〜 0.2.26 では作業は不要です。

## 0.2.27 タグは署名が必須になった

**この節は、`tags:` の glob でエージェントにタグの push を許しているプロジェクトだけが対象です。**
それ以外のプロジェクトでは作業は不要です。

push するタグは、署名を持つ注釈付きタグオブジェクトでなければならなくなりました。`git tag -s` で、
git が対応する任意の形式（OpenPGP、SSH、X.509）で作成します。関所は、軽量タグ（`git tag v1`）と
署名の無い注釈付きタグ（`git tag -a`）を、`[remote rejected]` と理由を示すメッセージとともに拒否します。
関所が確認するのは署名が**ある**ことだけで、誰の署名かは確認しません。

dev コンテナは既にタグに署名します。`agent-setup.sh` がエージェントの SSH 署名鍵で
`tag.gpgsign true` を設定するので、そこでは `git tag -s` も素の `git tag -a` も署名付きのタグになります。
この検査が捕まえるのは、この設定を**迂回した**タグです。たとえば `-c tag.gpgsign=false` を付けて
作ったタグや、設定の無いシェルから作ったタグです。ゲートウェイ自身の最初の `v0.2.18` タグは、
このようにして push されました。

この検査を無効にするには、任意の設定の層に 1 行追加します。

```yaml
# .devcontainer/config/config.yml
relay:
  project:
    signed_tags: false          # upstreams.<domain> の下でも、repos[] の 1 件にでも書ける
```

そのあと `mise run gw:recreate` を実行します。`mise run gw:check` は、リポジトリごとの実効値
（`signed_tags=true|false`）を表示します。

0.2.23 〜 0.2.26 では作業は不要です。

## 0.2.28 Dependabot アラートは任意

**Dependabot アラートを使わないなら、作業は不要です。** この版で権限キーが 2 つ追加されました。
`security:read`（リポジトリの Dependabot アラートの一覧と詳細の表示）と、`security:dismiss`
（理由を付けてアラートを却下する、または再度開く）です。既存の設定では、どちらも付与されません。

有効にするには、次のように書きます。

```yaml
# .devcontainer/config/config.yml
relay:
  project:
    permissions:
      - security:read
      # - security:dismiss      # 脆弱性を見えなくするのは別の権限。意図して付ける
```

そのあと `mise run gw:recreate` を実行し、**さらに `mise run gw:login` をもう一度実行してください**。
alerts API には `security_events` の OAuth スコープが必要ですが、0.2.28 より前の login は
このスコープを要求していませんでした。スコープが無いと、`sekimore security alerts` は GitHub から
403 を受け取ります。

## 0.2.29 解錠を自動化できるようになった

**解錠を自動化しないなら、作業は不要です。** `mise run gw:unlock` は変わらず、パスフレーズを
保存していないホストの動作もこれまでどおりです。

`mise run gw:sync-tasks` を実行して 2 つの新しいタスクを取り込み、各ホストで一度だけ次を実行します。

```bash
mise run gw:keychain-set     # パスフレーズを尋ね、このホストの keychain に入れる
```

以後は、`mise run gw:recreate` が自動でストアを解錠します。`docker restart` のあとは、
`mise run gw:unlock-auto` を実行すれば、パスフレーズを入力せずに解錠できます。

タスクは、次の場所をこの順番で探します。`<project>` は `MISE_PROJECT_ROOT` が指すディレクトリの名前です。
そのため、1 台のホストに 2 つのプロジェクトがあっても、別々の項目になります。

| ホスト | 置き場所 | パスフレーズをこのマシンに結び付けるもの |
|---|---|---|
| macOS | Keychain。service `sekimore-gw`、account `<project>` | あなたのログイン。ログインするまで Keychain は施錠されています。 |
| Linux デスクトップ | Secret Service（`secret-tool`）。`service=sekimore-gw project=<project>` | あなたのログインセッション |
| サーバー | `/etc/sekimore/<project>.passphrase.cred` を `systemd-creds decrypt` で読む | TPM またはホスト鍵。ディスクを複製しても、使えるパスフレーズは含まれません。 |
| サーバー（最後の手段） | `/etc/sekimore/<project>.passphrase`。root 所有、モード 0600 | **何もありません。** ファイルを読める人は誰でもパスフレーズを得られます。 |

どちらの keychain も無いホストでは、`gw:keychain-set` がサーバー向けの 2 つの方法の具体的なコマンドを
表示します。`/etc/sekimore` 自体のモードは 0755 のままにしてください。タスクは、sudo を使わずに
ファイルを見つけてから初めて `sudo -n` を使い、sudo のパスワードは決して尋ねません。
`gw:recreate` がパスワードの入力待ちで止まってはならないためです。

ここでいう `/etc/sekimore` は**ホスト側**のものです。ゲートウェイのコンテナの中にも同じ名前のディレクトリが
あります（`config.yml` がそこにあります）。ホスト側のディレクトリをゲートウェイに mount しないでください。
mount すると、この設計がゲートウェイから遠ざけているパスフレーズをゲートウェイに渡すことになります。

この版で**変わらない**ことが 2 つあります。

- ゲートウェイが新たに知ることはありません。パスフレーズはホストが読み、`sekimore-relay unlock --stdin`
  にパイプで渡します。パスフレーズは引き続き制御ソケット経由で届きます。dev コンテナは制御ソケットを
  mount しておらず、ゲートウェイの中からパスフレーズを探す手段もありません。export を守るのが
  パスフレーズだけである点も変わりません。
- 最初のパスフレーズは引き続き手で入力します。`unlock --stdin` は、一度も初期化されていないストアを
  拒否します。最初のパスフレーズは思い出すものではなく決めるものであり、プロンプトが確認のために
  2 回尋ねるからです。

作り直したあともゲートウェイを施錠したままにするには、1 台のホストでもすべてのホストでも、次を実行します。

```bash
SGW_NO_AUTO_UNLOCK=1 mise run gw:recreate
```

パスフレーズのファイルを `/etc/sekimore` 以外のディレクトリで探すには、`SGW_PASSPHRASE_DIR` を設定します。

## 0.2.29 署名鍵を人につき 1 本にする

**この作業は任意で、実施しなくても何も変わりません。** `relay.signing_key` が無ければ、dev コンテナは
これまでどおり自分で署名鍵を生成します。

生成される鍵は使い捨てですが、署名鍵は使い捨てにしてはなりません。署名鍵は手作業で GitHub に登録し、
削除するとその鍵が署名したすべてのコミットから Verified バッジが外れます。鍵の volume が消えると、
鍵は作り直されるのではなく失われ、以後のコミットはすべて GitHub が知らない鍵で署名されます。
これを知らせる仕組みはありませんでした。`commit.gpgsign` は無条件に設定され、鍵が登録されているかを
確認するものが無かったためです。

置き換える手順（人につき 1 本、登録は一度だけ）は次のとおりです。

1. この用途の鍵がまだ無ければ、手元のマシンで作成します。**自分自身の署名鍵は使わないでください**。
   別の鍵にしておくことで、履歴の中で AI のコミットを見分けられます。

   ```bash
   ssh-keygen -t ed25519 -C "sekimore AI signing key" -f ~/.ssh/sekimore_signing
   ssh-add ~/.ssh/sekimore_signing          # Mac では --apple-use-keychain を付ける
   ssh-keygen -lf ~/.ssh/sekimore_signing.pub   # SHA256:… の fingerprint を表示する
   ```

2. **公開鍵**を GitHub に一度だけ登録します。Settings → SSH and GPG keys →
   New SSH key → Key type: **Signing Key** の順に操作します。

3. fingerprint を `.devcontainer/config/config.yml` に書きます。

   ```yaml
   relay:
     signing_key:
       fingerprint: "SHA256:…"     # 手順 1 のもの
   ```

   自分の他の鍵は同じ agent に入れたままで構いません。関所が dev コンテナに渡すのは、
   この fingerprint にだけ応答し、git の署名以外には何も署名しない、**絞り込んだ** socket です。
   他の鍵は見えず、この socket で認証することもできません。

4. `.devcontainer/docker-compose.relay.yml` の**両方の**サービスに socket の volume を追加します
   （雛形には既に含まれています）。

   ```yaml
   services:
     sekimore-gw:
       volumes:
         - sekimore-signing:/run/sekimore
     dev:
       volumes:
         - sekimore-signing:/run/sekimore

   volumes:
     sekimore-signing:
       name: sekimore-signing-${DEVCONTAINER_ID}
   ```

5. `mise run gw:recreate` を実行し、続けて Rebuild Container を実行します。鍵が使われていることを
   確認します。

   ```bash
   mise run gw:check     # 「署名鍵: ホストの agent にある (…)」と表示される
   ```

   dev コンテナの中では、`ssh-add -l` が**ちょうど 1 本**の鍵を表示するようになります。絞り込んだ
   socket 越しの署名鍵です。`mise.toml` に、`ssh-add -l` が成功すると失敗する 0.1.x の
   `relay:verify` タスクがある場合は、そのブロックを次の内容に置き換えてください。

   ```bash
   echo "== dev: only the gateway's filtered signing key may be reachable"
   n=$(bash "$SGW" dev ssh-add -l 2>/dev/null | grep -c . || true)
   if [ "$n" = 1 ]; then
     echo "OK: exactly one key (the signing key, via the gateway's filtered agent)"
   elif [ "$n" = 0 ]; then
     echo "OK: no ssh-agent in dev"
   else
     echo "❌ FAIL: ssh-add -l lists $n keys inside dev — the operator's keys are exposed to the AI. Reopen with: mise run vscode"
     fail=1
   fi
   ```

古い `~/.ssh/sekimore/signing_ed25519` は削除されません。この鍵は履歴に残っているコミットに署名しており、
それらのコミットの Verified バッジを保つには、公開鍵を GitHub に登録したままにしておく必要があります。

**`signing: required`** はこれとは別の、任意の設定です。有効にすると、push に含まれるコミットに
署名の無いものが 1 つでもあれば、関所は branch への push を拒否します。この検査があれば、
未登録の鍵の問題を 20 コミット早く見つけられたはずです。既定値は `optional` なので、
既存のプロジェクトの動作は変わりません。

```yaml
relay:
  project:
    signing: required     # 上流ごと、repos[] ごとにも指定できる
```

有効にするのは、手順 5 が成功してからにしてください。鍵が無い状態で有効にすると、関所はすべての push を
拒否します。

`required` は**上流 API も必要とします**。push された履歴が pack の外に出る地点で、関所はそのコミットを
上流が既に持っているかを問い合わせます。この問い合わせが無いと、delta の後ろに隠れたコミットを
pack の中から区別できません。そのためゲートウェイが解錠され（`mise run gw:unlock`）、login 済みである
必要があります。そうでない場合、push は安全側に倒れて失敗し、どの条件が欠けているかをメッセージが示します。

## 0.2.37 ゲートウェイに pid: host が要る

**すべてのプロジェクトで作業が必要です。** これまでエージェントを閉じ込めていたのは、コンテナの中だけでした。
dev の root プロセスは `ip route replace default via <ブリッジの .1>` を実行すると、Docker 自身の NAT
を通って外に出られました。ゲートウェイのフィルタはどれも通りません。0.2.37 から、ゲートウェイはホストの
`DOCKER-USER` チェーンに FORWARD 規則を 2 つ追加します。内部ブリッジからの通信はゲートウェイの居るその
ブリッジの中にしか届かず、外へ出るものは落とされます。規則の追加には `nsenter` でホストの名前空間に
入るので、ゲートウェイはホストの PID 名前空間を必要とします。

`.devcontainer/docker-compose.yml` の `sekimore-gw` サービスに `pid: host` を追加します
（雛形には含まれています）。`dev` には追加しないでください。

```yaml
services:
  sekimore-gw:
    privileged: true
    pid: host                 # dev を閉じ込める FORWARD 規則はホストの DOCKER-USER チェーンにある
```

そのあと `mise run gw:recreate` を実行します。`pid: host` が無くてもゲートウェイは起動しますが、
エージェントは閉じ込められて**いません**。

規則が入ったことは、ゲートウェイのログで確認します。

```bash
docker logs "$(bash .devcontainer/sgw/sgw.sh id sekimore-gw)" 2>&1 | grep 'FORWARD enforcement'
```

"Host-side FORWARD enforcement in place" と表示されます。`pid: host` が無いと、
"Host-side FORWARD enforcement is not in place" と理由が表示されます。

`mise run relay:verify` も迂回そのものを確かめます。dev からブリッジ自身のルーター経由のホストルートを
追加し、接続が失敗することを期待します。

0.2.30 〜 0.2.36 では作業は不要です。

## 0.2.44 ProxyJump の踏み台のホスト鍵が必要になった

**このセクションは、`config.yml` の上流の `relay.ssh_options` に `ProxyJump` があるときだけ
当てはまります。** 踏み台が無ければ作業は不要です。

これまで踏み台へのホップは、関所の ssh の既定が許す形で接続していました。0.2.44 からは踏み台を含む
すべてのホップを、上流の known_hosts に対して `StrictHostKeyChecking yes` で検証します。鍵の無い
踏み台はもう確認を求めず、通りもしません。関所経由の git は閉じる方向で失敗し、実行すべき keyscan
のコマンドを表示します。

`mise run gw:recreate` のあと、次のどちらかを 1 回実行します。

```bash
mise run gw:login          # 不足している踏み台の鍵を取り、fingerprint を見せて yes/no を聞く
```

もう一度ログインせずに鍵だけ取るなら:

```bash
docker compose exec sekimore-gw sekimore-relay keyscan <踏み台> --port <ポート>
docker compose exec sekimore-gw sekimore-relay keyscan <上流のホスト> --port <ポート> --upstream <ドメイン>
```

2 つめは踏み台を経由するので、1 つめのあとに実行します。

0.2.38 〜 0.2.43 では作業は不要です。

## 0.2.45 `gw:login` は端末で尋ね、ホスト鍵が無ければ止まる

**このセクションは、`config.yml` の上流にゲートウェイがまだ保存していないホスト鍵が要るときだけ
当てはまります。** `ProxyJump` の踏み台、あるいは鍵を一度も keyscan していない上流です。

`gw:login` は device flow の前に必要なホスト鍵を取り、端末で yes/no を尋ねるようになりました。
必要な鍵を保存できなかったとき — 尋ねて断られた、端末が無い、keyscan が失敗した — ログインは
git が使えないトークンを渡す代わりに、非ゼロで終了します。

`mise run upgrade:apply` で新しいタスクファイルを取り、もう一度 `mise run gw:login` を実行します。

質問を出さずに済ませるなら、先に鍵を取ります。

```bash
mise run gw -- keyscan <踏み台> --port <ポート> --upstream <ドメイン>
mise run gw -- keyscan <上流のホスト> --port <ポート> --upstream <ドメイン>
```

2 つめは踏み台を経由するので、1 つめのあとに実行します。

## base 0.2.19 `mise run web` が自分でポートを引く

**base 0.2.20 に上げる場合は、この節を飛ばしてください。**
[base 0.2.20 の節](#base-0220-devcontainersgw-と-mise-run-upgrade)の作業で、両方のファイルが
まるごと入れ替わります。

**この作業は任意です。** 飛ばしても、Web UI の公開ポートを変えるまでは何も壊れません。
公開ポートを変えると、古い `web` タスクは誤った場所を開きます。

古いタスクにはポートがリテラルで書かれていましたが、実際のポートを決めるのは compose ファイルです。
8090 番ポートが既に使われているプロジェクトは公開ポートを変えますが、タスクは古い番号を開き続けます。
その結果、`mise run web` は何も無い場所に行き着くか、より悪い場合は別のプロジェクトのゲートウェイに
つながります。

この変更はゲートウェイの版には結び付いていません。雛形自身のファイルだけに関わる変更で、ゲートウェイは
変わっていません。

両方のファイルを雛形から取り込んでください。`sgw.sh` に `port` 分岐が追加され、`mise.toml` の
`web` タスクがそれを呼びます。

```bash
diff -u <base>/examples/sgw-sample/.devcontainer/scripts/sgw.sh .devcontainer/scripts/sgw.sh
diff -u <base>/examples/sgw-sample/mise.toml mise.toml
```

以後、`mise run web` は開く URL を表示するので、ポートが誤っていれば黙って失敗せずに目に見えます。

## base 0.2.20 `.devcontainer/sgw/` と `mise run upgrade`

**一度だけ手作業で移行します。以後の更新は `mise run upgrade:apply` を実行するだけです。**

ホスト側のスクリプトとタスクは `.devcontainer/sgw/` に移り、あなたのものではなくなります。
`mise run upgrade:apply` はこのディレクトリをまるごと入れ替えます。中のファイルが手で編集されていれば、
上書きせずに止まります。`mise.toml` には include とあなた自身のタスクだけが残ります。

1. `FROM` が `latest` を使っている場合は、base イメージを版で固定します。`upgrade` は base と
   ゲートウェイのイメージタグを読むため、`latest` タグは更新できません。

   ```dockerfile
   FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.20
   ```

2. `upgrade.sh` をダウンロードし、実行して残りのファイルを追加します。

   ```bash
   mkdir -p .devcontainer/sgw
   curl -fsSL -o .devcontainer/sgw/upgrade.sh \
     https://raw.githubusercontent.com/Amakata/sgw-devcontainer-base/v0.2.20/share/sgw/upgrade.sh
   bash .devcontainer/sgw/upgrade.sh --sync
   ```

   スクリプトは、`mise.toml` に書くべき include と、使われなくなった古いファイルを表示します。

3. `mise.toml` から、あなた自身のタスク以外をすべて削除します。**配布されるようになったタスクを
   削除してください**。対象は `vscode`、`vscode:check`、`vscode:restore-agent-env`、`web`、`ps`、
   `down`、`dev:*`、`relay:verify`、`gw:sync-tasks` です。`mise.toml` にあるタスクは同じ名前の
   配布タスクより優先されるので、古い複製が残っていると、そのタスクへの以後の修正がすべて隠れます。
   あなた自身のタスクは残し、次を追加します。

   ```toml
   [task_config]
   includes = [".devcontainer/sgw/tasks.mise.toml", ".devcontainer/sgw/gateway.mise.toml"]

   [env]
   SGW = "{{config_root}}/.devcontainer/sgw/sgw.sh"
   ```

4. 古い配置を削除します。

   ```bash
   git rm .devcontainer/scripts/sgw.sh .devcontainer/scripts/vscode.sh .devcontainer/gateway.mise.toml
   ```

5. `mise run upgrade` を実行します。版が一覧表示され、すべて最新であると表示されれば完了です。

`gw:sync-tasks` は廃止されました。`mise run upgrade:sync` が、ゲートウェイのタスクを他の配布ファイルと
一緒に取得します。タスクの説明とスクリプトの出力は `LC_ALL` / `LC_MESSAGES` / `LANG` に従います。
言語を固定するには、`[env]` に `SEKIMORE_LANG = "ja"`（または `"en"`）を書き、
`mise run upgrade:sync` を実行します。

## base 0.2.22 `postStartCommand` が `.devcontainer/sgw/post-start.sh` を実行する

**`devcontainer.json` の 1 行を一度だけ書き換えます。** 完了するまで、`mise run upgrade` がこの作業を
表示します。

```json
"postStartCommand": "sh /workspace/.devcontainer/sgw/post-start.sh",
```

`agent-setup` は `sudo` の下で動き、`sudo` は環境変数をリセットします。そのため `.env` の変数は、
`--preserve-env=` に名前が書かれている場合にだけ届き、一覧から漏れた変数は、設定されていても黙って
無視されていました。この一覧はあなたが持つ `devcontainer.json` にあり、agent-setup が新しい入力を
得るたびに（たとえば `SEKIMORE_GUIDE_LANG`）更新が遅れていました。`post-start.sh` はコンテナにある
`SEKIMORE_*` 変数をすべて渡し、続けて `docker-init.sh` とあなたの
`.devcontainer/scripts/post-create.sh` を実行します。これは以前の 1 行と同じ処理です。
`postStartCommand` で他に実行していたコマンドは、`post-create.sh` に移してください。

`.env` にある「`--preserve-env=` に変数を追加すること」という趣旨のコメントも削除して構いません。

## base 0.2.26 credential helper の除去は `post-start.sh` が行う

**`post-create.sh` に `disable_vscode_credential_helper` がある場合は、この作業が必須です。
削除するまで、コンテナは毎回起動に失敗します。**

`.devcontainer/sgw/post-start.sh` は、VS Code 拡張が `/etc/gitconfig` と `~/.gitconfig` に書き込む
HTTPS の credential helper を、起動のたびに、あなたの `post-create.sh` より先に取り除くようになりました。
`SEKIMORE_ALLOW_CREDENTIAL_HELPER=1` を設定すれば、これまでどおり helper を残せます。

古い雛形から作ったプロジェクトは、自分の `.devcontainer/scripts/post-create.sh` に
`disable_vscode_credential_helper` を持っています。この関数と、それを呼ぶ箇所を削除してください。
base 0.2.29 からは `post-start.sh` が起動のたびに警告を表示しますが、複製を削除するまで起動は失敗し続けます。
この複製は単に重複しているだけではありません。最後が `[ "$changed" = 1 ] && echo …` なので、取り除く
ものが無いと 1 を返します。`set -e` の下ではこの戻り値で `post-create.sh` が止まり、コンテナの起動も
止まります。さらに、雛形の複製は `/etc/gitconfig` を sudo 無しで書き換えていたため、システム側の
helper を一度も取り除けていませんでした。

## base 0.2.28 `gh` が無くなった

**この節は、あなたが実行するものが `gh` を呼んでいる場合だけが対象です。**

GitHub CLI はイメージから削除されました。`gh` は、関所の 443 passthrough を通って `api.github.com`
に届いていました。この経路はリクエストを読まずに転送するため、トークンを持つ `gh` は、関所が課す
操作ごとの権限をまったく受けずに GitHub を操作できました。たとえば `config.yml` で `pr:merge` を
拒否しても `gh pr merge` は止まらず、プロジェクト外のリポジトリも操作できました。

`sekimore` は同じ操作をエージェント API 経由で行います。そこでは関所が各操作をプロジェクトの設定と
照合し、記録します。

| 代わりに | 使うもの |
|---|---|
| `gh pr create` | `sekimore pr create --head <branch> --base <base> --title T --body="…"` |
| `gh pr merge` | `sekimore pr merge --number N` |
| `gh pr view` / `gh pr checks` | `sekimore pr status --number N` |
| `gh issue create` | `sekimore issue create --title T` |
| `gh run view` / `gh run view --log` | `sekimore ci jobs --number N` / `sekimore ci log --number N` |
| `gh release create` | `sekimore release create --tag vX.Y.Z` |

その他のコマンドは `sekimore guide` に一覧があります。自分のスクリプトが `gh` を必要とする場合は、
そのスクリプトを実行する環境に `gh` をインストールしてください。ただし、`gh` が行う操作は関所から
見えず、拒否することもできません。

## base 0.2.40 dev コンテナが上流プロキシを知るようになった

**この節は、`config.yml` に `proxy.upstream_proxy` を設定している場合だけが対象です。**

これまで dev 側は上流プロキシの存在を知らず、`curl`・`pip`・`npm`・言語のランタイムといった通常の
通信は、ゲートウェイの Squid と上流プロキシを通らずに直接出ていました。ゲートウェイがプロキシの
環境変数を書き出すようになり、dev がそれを読み込みます。

- ゲートウェイが `/etc/profile.d/sekimore-proxy.sh` と、`/etc/environment` の
  `# sekimore-proxy begin` / `# sekimore-proxy end` に挟まれた同じ内容を書く。中身は `HTTP_PROXY`、
  `HTTPS_PROXY`、`NO_PROXY` と、それぞれの小文字版。`NO_PROXY` には `domain_handlers` の宛先、
  運用者が書いた `proxy.no_proxy`、`localhost`、`127.0.0.1`、`sekimore-gw` が入る
- base 0.2.40 が `/etc/skel/zsh-rc.d/10-sekimore-proxy.zsh` を追加し、このファイルを読み込む。
  Debian の zsh は `/etc/profile.d` を読まず、Claude Code や `docker exec` は非ログインシェルで
  動くため、dev のすべてのシェルに行き渡らせるのは rc.d の役目

**プロジェクトが独自に `HTTP_PROXY` を設定している場合** — `devcontainer.json`、compose ファイル、
`post-create.sh`、プロジェクト固有の zsh rc.d のいずれであれ — それを外すか、ゲートウェイの値と
揃えてください。値が 2 種類あると、あるプロセスはプロキシに届き、別のプロセスは届かないという、
気づきにくい壊れ方になります。`10-` より後ろの番号の snippet は依然として勝つので、意図的な上書きは
そのまま動きます。

やること:

```bash
mise run gw:recreate       # ゲートウェイがファイルを書く
```

そのあと **Rebuild Container**（VS Code のコマンドパレットで `Dev Containers: Rebuild Container`）。
rc.d の snippet が入るのはこの作り直しのときです（post-create が `/etc/skel/zsh-rc.d/` を複製するのは
作成時だけです）。

確認:

```bash
env | grep -i proxy        # dev 内: HTTP_PROXY、HTTPS_PROXY、NO_PROXY と小文字版
mise run relay:verify      # ホスト側
```

`relay:verify` に `== dev: the upstream proxy is used for ordinary traffic` が増えました。上流
プロキシが未設定なら `SKIP` になります。ゲートウェイが古く egress の方針を報告しない場合も `SKIP`
です（そのゲートウェイは `HTTPS_PROXY` も書かないので、まだ確認すべきものがありません）。設定
されている場合は、dev に `HTTPS_PROXY` があること、およびそれを迂回する要求（`curl --noproxy '*'`）
が `allow_domains` のホストに届かないことを確認します。`proxy.direct_egress` が `deny` なのに
届いた場合は **FAIL** です（dev がプロキシを通らずに外へ出られる）。`allow` の場合は失敗ではなく
警告になります。
