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

普通に拾ってきてインストール。

```
git clone https://github.com/yyojiro/fakegw
cd fakegw
python setup.py install
```

## 使い方

コマンドラインから下記のように使います。

`fakegw -g <gateway ip> -t <target ip> -i <interface name>`



## 免責事項

当然ですが、すべて自己責任でお願いします。
