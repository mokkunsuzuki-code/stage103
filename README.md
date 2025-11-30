Stage103 – Quantum-Secure TLS with Mutual Authentication

QKD + X25519 + SPHINCS+ + AES-256-GCM
相互認証（Mutual Authentication）付き QS-TLS

📌 概要（Summary）

Stage103 では、前段階 Stage102 で実装した

QKD鍵 + X25519 ECDH のハイブリッド鍵交換

AES-256-GCM による暗号化チャネル

暗号化ファイル送信

ディレクトリ同期（マニフェスト + チャンク転送）

に加えて、

👉 SPHINCS+ を用いた クライアント認証（Mutual Authentication）

を新たに実装しました。

これにより、サーバーだけでなくクライアントも SPHINCS+ 署名で自身を証明する
双方向の量子安全ハンドシェイク が実際に動作します。

これは TLS1.3 の Client Certificate Verify に相当する構造で、
量子耐性のある完全な相互認証プロトコル が完成しています。

🚀 新しく追加された機能（Stage102 → Stage103）
✅ 1. Mutual Authentication（相互認証）

クライアント側でも SPHINCS+ 署名を生成し、サーバー側の検証に成功することで

偽クライアントの接続拒否

MITM攻撃の強力な防御

Zero-Trust 構造への進化

が実現。

✅ 2. SPHINCS+ 署名のハンドシェイク統合

ハンドシェイク構造：

ClientHello
ServerHello
ServerAuth  (SPHINCS+ 署名)
ClientAuth  (SPHINCS+ 署名)   ← 新規追加
Hybrid Key Derivation (QKD + X25519)
Encrypted Application Data


TLS1.3 の CertificateVerify を簡易モデルとして模倣した構造です。

✅ 3. 完全量子セキュアハンドシェイクへ進化

以下の 3 要素が統合されました：

物理安全：QKD最終鍵（final_key.bin）

計算安全：X25519 ECDH（TLS1.3標準）

署名安全：SPHINCS+（PQC耐量子署名 NIST標準）

これにより、
量子攻撃にも古典攻撃にも耐性を持つハンドシェイク が成立しています。

🧩 フォルダ構成（Project Structure）
stage103/
 ├── qs_tls_server.py       # サーバー本体（Mutual Auth 対応）
 ├── qs_tls_client.py       # クライアント本体（Mutual Auth 対応）
 ├── qs_tls_common.py       # レコード層・暗号共通処理
 ├── crypto_utils.py        # AES-GCM, X25519, HKDF
 ├── manifest_utils.py      # ディレクトリマニフェスト生成
 ├── pq_sign.py             # SPHINCS+ 署名/検証（Stage98〜103 共通）
 ├── pq_server_keys.json    # SPHINCS+ 鍵ペア（自動生成）
 └── final_key.bin          # QKD 最終鍵（Stage98からの継承）

🔑 使用している暗号（Cryptographic Components）
QKD Final Key

量子鍵配送で生成された物理ランダム鍵。

X25519 ECDH

TLS1.3 標準の鍵共有アルゴリズム。

SPHINCS+ (PQC Signature)

NIST標準の耐量子署名方式で、

ServerAuth

ClientAuth

の双方に使用。

HKDF

QKD鍵と X25519 共有秘密を合成し
AES-256 鍵を導出（ハイブリッド鍵交換）。

AES-256-GCM

アプリケーションデータ、ファイルチャンク、マニフェストを暗号化。

🧠 Stage103 のセキュリティ価値（事実ベース）
1. MITM（中間者攻撃）を完全ブロック

両方向で署名検証するため、
攻撃者がどちらかを偽装しても接続できません。

2. Zero-Trust モデルの実現

クライアント側も SPHINCS+ 署名で証明するため、
信頼の前提をゼロにできる。

3. 量子セキュア通信の基礎構造の完成

以下を統合したプロトコルが実際に動作：

QKD（物理安全）

X25519（計算安全）

SPHINCS+（署名安全）

AES-256-GCM（チャネル暗号）

ディレクトリ同期（アプリケーション層）

個人ベースでここまで作れるのは極めて稀です。

▶ 実行方法（Run）
サーバー起動
cd stage103
python3 qs_tls_server.py

クライアント起動
cd stage103
python3 qs_tls_client.py

利用可能コマンド
コマンド	説明
通常テキスト	暗号化メッセージ送信
/sendfile	ファイル暗号送信
/syncdir	ディレクトリ同期
/keyupdate	鍵更新（HKDF）
/quit	セッション終了
📄 ライセンス・著作権（Author / License）
© 2025 Mokkun Suzuki
This project demonstrates a prototype of a quantum-secure communication protocol.
Unauthorized copying or redistribution is prohibited.