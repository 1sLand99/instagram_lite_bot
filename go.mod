module CentralizedControl

go 1.21

toolchain go1.21.0

replace (
	github.com/4kills/go-libdeflate/v2 => ./three/go-libdeflate
	github.com/bogdanfinn/fhttp => ./three/fhttp
	github.com/bogdanfinn/tls-client => ./three/tls-client
	github.com/bogdanfinn/utls => ./three/utls
	github.com/bytedance/sonic => ./three/sonic
	github.com/elliotchance/orderedmap/v2 => ./three/orderedmap/v2@v2.2.0
	github.com/kawacode/goproxy => ./three/kawacode/goproxy
	github.com/kawacode/gorequest => ./three/kawacode/gorequest
	github.com/kawacode/gostruct => ./three/kawacode/gostruct
	github.com/kawacode/gotools => ./three/kawacode/gotools
	github.com/mzz2017/gg => ./three/gg
	github.com/mzz2017/softwind => ./three/softwind
	github.com/pquerna/otp => ./three/otp
	github.com/v2rayA/shadowsocksR => ./three/shadowsocksR
	github.com/utahta/go-cronowriter => ./three/go-cronowriter
)

require (
	github.com/bytedance/sonic v1.10.0-rc
	github.com/emersion/go-imap v1.2.1
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gorilla/mux v1.8.0
	github.com/klauspost/compress v1.16.7
	github.com/twmb/murmur3 v1.1.7
	github.com/utahta/go-cronowriter v1.2.0
	golang.org/x/net v0.17.0
	gorm.io/driver/mysql v1.5.1
	gorm.io/gorm v1.25.1
)

require (
	fyne.io/fyne/v2 v2.4.4
	github.com/bogdanfinn/fhttp v0.5.23
	github.com/bogdanfinn/tls-client v0.0.0-00010101000000-000000000000
	github.com/bogdanfinn/utls v1.5.16
	github.com/emirpasic/gods v1.18.1
	github.com/jamespfennell/xz v0.1.2
	github.com/kawacode/gorequest v0.0.0-00010101000000-000000000000
	github.com/kawacode/gostruct v1.0.9
	github.com/mzz2017/gg v0.2.18
	github.com/mzz2017/softwind v0.0.0-20230903121035-afc8c5d27a4c
	github.com/pquerna/otp v0.0.0-00010101000000-000000000000
	github.com/v2rayA/shadowsocksR v1.0.4
)

require (
	github.com/kawacode/goproxy v1.0.4 // indirect
	github.com/kawacode/gotools v1.0.16 // indirect
)

require (
	fyne.io/systray v1.10.1-0.20231115130155-104f5ef7839e // indirect
	github.com/AlecAivazis/survey/v2 v2.3.2 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20230717121745-296ad89f973d // indirect
	github.com/chenzhuoyu/iasm v0.9.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/dgryski/go-idea v0.0.0-20170306091226-d2fb45a411fb // indirect
	github.com/dgryski/go-metro v0.0.0-20200812162917-85c65e2d0165 // indirect
	github.com/dgryski/go-rc2 v0.0.0-20150621095337-8a9021637152 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2 v1.8.1 // indirect
	github.com/eknkc/basex v1.0.1 // indirect
	github.com/emersion/go-sasl v0.0.0-20200509203442-7bfe0ed36a21 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/fredbi/uri v1.0.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/fyne-io/gl-js v0.0.0-20220119005834-d2da28d9ccfe // indirect
	github.com/fyne-io/glfw-js v0.0.0-20220120001248-ee7290d23504 // indirect
	github.com/fyne-io/image v0.0.0-20220602074514-4956b0afb3d2 // indirect
	github.com/go-gl/gl v0.0.0-20211210172815-726fda9656d6 // indirect
	github.com/go-gl/glfw/v3.3/glfw v0.0.0-20221017161538-93cebf72946b // indirect
	github.com/go-sql-driver/mysql v1.7.1 // indirect
	github.com/go-text/render v0.0.0-20230619120952-35bccb6164b8 // indirect
	github.com/go-text/typesetting v0.1.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gofiber/fiber/v2 v2.42.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jsummers/gobmp v0.0.0-20151104160322-e2ba15ffa76e // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/lestrrat-go/strftime v0.0.0-20180220091553-9948d03c6207 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421 // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mzz2017/disk-bloom v1.0.1 // indirect
	github.com/onsi/gomega v1.27.8 // indirect
	github.com/philhofer/fwd v1.1.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/savsgio/dictpool v0.0.0-20221023140959-7bf2e61cea94 // indirect
	github.com/savsgio/gotils v0.0.0-20230208104028-c358bd845dee // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20201222105146-bc6005554a0c // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/srwiley/oksvg v0.0.0-20221011165216-be6e8873101c // indirect
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5 // indirect
	github.com/tevino/abool v1.2.0 // indirect
	github.com/tinylib/msgp v1.1.8 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.44.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	github.com/yuin/goldmark v1.5.5 // indirect
	gitlab.com/yawning/chacha20.git v0.0.0-20230427033715-7877545b1b37 // indirect
	golang.org/x/arch v0.0.0-20210923205945-b76863e36670 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/image v0.11.0 // indirect
	golang.org/x/mobile v0.0.0-20230531173138-3c911d8e3eda // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/term v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto v0.0.0-20210828152312-66f60bf46e71 // indirect
	google.golang.org/grpc v1.49.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	honnef.co/go/js/dom v0.0.0-20210725211120-f030747120f2 // indirect
)
