# twsnmpv3proxy

[English](README.md) | 日本語

Windows標準のSNMPエージェント（または既存のSNMPv2cエージェント）をSNMPv3（セキュアな通信）に対応させるためのプロキシサーバーです。

SNMPv3マネージャーからの暗号化・認証されたリクエストを受信・解読し、対応するSNMPv2cリクエストに変換して背後のエージェントに中継します。

## 主な機能

- **SNMPv3 to SNMPv2c 相互変換**: セキュアな SNMPv3（USMモデル）と SNMPv2c の間を中継。
- **SNMPv3 AuthPriv（最高セキュリティレベル）対応**: MD5/SHA/SHA256などの認証およびDES/AESなどの暗号化に対応（gosnmpがサポートする暗号形式に準拠）。
- **SNMPv3 ディスカバリ対応**: EngineID 検出用の要求に対し、適切に `Report` PDU を返します。
- **主要なSNMP操作のサポート**: `GET`, `GETNEXT`, `GETBULK` に対応。
- **接続自動回復（ソケット再作成＆リトライ）**: エージェントとの通信エラー（Broken pipe等）発生時、自動でソケットを再作成し、指数バックオフウェイトを挟んで最大5回リトライ。
- **Windowsサービス対応**: Windows環境下ではOSのサービスとして登録、起動、停止、解除が可能です。
- **自動EngineID生成・永続化**: 設定ファイルに指定がない場合、企業番号 `17862` + ランダム値でEngineIDを自動生成し、起動回数（Boots）とともに設定ファイル（`config.ini`）に保存して再起動後も永続化します。

---

## クイックスタート (統合テストモード)

`-test` 引数を指定して実行すると、**自己完結型の統合テストモード**で起動します。
127.0.0.1のポート1162で動作するモックのSNMPv2cエージェントと、ポート1161で動作するSNMPv3プロキシをローカルで同時に立ち上げ、自動的にテストクエリを実行し結果を検証します。

```bash
# 統合テストの実行
go run . -test
```

---

## 起動オプション (CLIパラメータ)

```bash
twsnmpv3proxy [options]
```

| オプション | デフォルト値 | 説明 |
| :--- | :--- | :--- |
| `-config` | `config.ini` | 設定ファイルのパス。相対パスの場合、実行ファイルと同じディレクトリから解決されます。 |
| `-port` | （設定値を優先） | SNMPv3 プロキシ受付ポート（UDP）。（例: `1161`） |
| `-agent` | `127.0.0.1:161` | 転送先となるSNMPv2cエージェントのIPアドレスとポート。 |
| `-community` | （設定値を優先） | 転送先SNMPv2cエージェントのコミュニティ名。（例: `public`） |
| `-user` | （設定値を優先） | SNMPv3 USMのユーザー名。 |
| `-auth-pass` | （設定値を優先） | SNMPv3 認証パスワード（AuthPassphrase）。 |
| `-priv-pass` | （設定値を優先） | SNMPv3 暗号化パスワード（PrivPassphrase）。 |
| `-auth-proto` | （設定値を優先） | 認証モード（`MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `NoAuth`）。 |
| `-priv-proto` | （設定値を優先） | 暗号モード（`DES`, `AES`, `AES192`, `AES256`, `AES192C`, `AES256C`, `NoPriv`）。 |
| `-engine-id` | （設定値を優先） | SNMPv3 の EngineID（Hex文字列）。指定がない場合は自動生成します。 |
| `-local-ip` | （空） | プロキシからエージェントへリクエストを送信する際にバインドするローカルIPアドレス。 |
| `-mock` | `false` | プロキシ起動と同時に、ポート1162でモックのSNMPv2cエージェントをバックグラウンド起動する（テスト用）。 |
| `-test` | `false` | 自己完結型の統合テストモードで起動する。 |
| `-service` | （空） | Windowsサービス管理コマンド（`install`, `uninstall`, `start`, `stop`）。 |

※ **優先順位**: コマンドライン引数 ＞ 設定ファイル（`config.ini`） ＞ デフォルト値

---

## 設定ファイル (`config.ini`)

設定ファイルのサンプル（`config.ini.sample`）をベースに `config.ini` を作成してください。

```ini
proxy_port = 1161
v3_user = proxyuser
v3_auth_pass = authpassword
v3_priv_pass = privpassword
v3_auth_proto = SHA
v3_priv_proto = AES
v3_engine_id = 
v3_engine_boots = 1
agent_address = 127.0.0.1:161
agent_community = public
```

---

## Windowsサービスとしての利用方法

Windowsの管理者権限を持つコマンドプロンプトまたはPowerShellで以下を実行します。

### 1. サービスの登録 (インストール)
```cmd
twsnmpv3proxy.exe -service install -config C:\\path\\to\\config.ini
```
※ サービス起動時の作業ディレクトリ問題を防ぐため、`-config` には絶対パスを指定することを強く推奨します。

### 2. サービスの起動
```cmd
twsnmpv3proxy.exe -service start
```

### 3. サービスの停止
```cmd
twsnmpv3proxy.exe -service stop
```

### 4. サービスの削除 (アンインストール)
```cmd
twsnmpv3proxy.exe -service uninstall
```

---

## ビルドおよび開発

本プロジェクトはビルドおよび環境管理ツールとして `mise` に対応しています。

```bash
# ローカルビルド
mise run build

# Windows向けバイナリ (exe) のビルド
mise run build_windows

# 単体テストの実行
mise run test

# 統合テストの実行
mise run integration

# Windows向けリリースパッケージ (ZIP) のビルド
mise run package
```

---

## ライセンス

[LICENSE](LICENSE) ファイルを参照してください。
