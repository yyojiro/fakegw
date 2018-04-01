# fakegw

## これは何？

サブネット通信傍受器です。
一応、Ubuntu14やWindows10で動作は確認しています。

### Linuxでの準備

* python2.7をインストールしておいてください。
* libpcapをインストールしておいてください。
* ipfowardingを有効化しておいてください。
    * こんな感じ`echo 1 >/proc/sys/net/ipv4/ip_forward`

### Windowsでの準備

* python2.7をインストールしておいてください。
* npcapをインストールしておいてください。
    * WinPcap API-compatible Modeにチェック入れておかないとダメです。
* WindowsのRouting and Remote Access Serviceを起動しておいてください。

## インストール

普通に拾ってきて、以下の様にインストールしてください。

```
git clone https://github.com/yyojiro/fakegw
cd fakegw
python setup.py install
```

アンインストールは `pip uninstall fakegw` です。

## 使い方

コマンドラインから下記のように使います。止めるときはctrl+cで止めます。標的のアドレスはカンマ区切りで複数指定できます。

`fakegw -g <gateway ip> -t <target ip>,<target ip>,...`

gatewayのアドレスは下記のように省略した場合は頑張って自動で探しますが、雑な実装なので下手すると固まります。

`fakegw -t <target ip>`

configファイル指定する場合は以下のようにします。configの書き方はconfig/fakegw.confでも参考に適当にやってください。

`fakegw -c <config file path>`

### 応用編

コールバック関数を書いたpythonファイルを指定すれば、受信したパケットをいろいろ処理できます。
CLIだと以下のように指定します。

`fakegw -g <gateway ip> -t <target ip> -p <callback_module>`

コールバック関数の書き方のルールは単に `def fakegw_callback(packet):` という名前の関数にするだけです。
引数の`packet`はscapyのpacketです。
あとは適当にやってください。

## 免責事項

当然ですが、使用に際してはすべて自己責任でお願いします。
あと、動作保証も何もありませんし、気まぐれで勝手に仕様も変えます。
