#lang racket/base

(require rackunit
         rackunit/spec
         racket/match
         wirey/protocol
         wirey/protocols/itch
         wirey/protocols/pcap
         wirey/protocols/ethernet
         wirey/protocols/udp
         wirey/protocols/ipv4
         wirey/protocols/tcp)

;; -- helpers --
(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; ===== ITCH 5.0 =====

(describe "ITCH system event"
  (it "has a total size of 12 bytes"
    (check-equal? (protocol-desc-total-size itch-system-event) 12))

  (it "round-trips correctly via accessors"
    (define bs (itch-system-event-encode
                #:message-type "S"
                #:stock-locate 0
                #:tracking     0
                #:timestamp    #x00000E4E1C00
                #:event-code   "O"))
    (define v (itch-system-event-decode bs))
    (check-equal? (itch-system-event-message-type v) "S")
    (check-equal? (itch-system-event-stock-locate v) 0)
    (check-equal? (itch-system-event-tracking v) 0)
    (check-equal? (itch-system-event-timestamp v) #x00000E4E1C00)
    (check-equal? (itch-system-event-event-code v) "O"))

  (it "supports match patterns"
    (define bs (itch-system-event-encode
                #:message-type "S"
                #:stock-locate 0
                #:tracking     0
                #:timestamp    #x00000E4E1C00
                #:event-code   "O"))
    (match (itch-system-event-decode bs)
      [(itch-system-event #:event-code ec #:timestamp ts)
       (check-equal? ec "O")
       (check-equal? ts #x00000E4E1C00)])))

(describe "ITCH add order"
  (it "has a total size of 36 bytes"
    (check-equal? (protocol-desc-total-size itch-add-order) 36))

  (it "round-trips an AAPL buy order"
    (define bs (itch-add-order-encode
                #:message-type "A"
                #:stock-locate 1
                #:tracking     0
                #:timestamp    #x0000094F7A00
                #:order-ref    12345678
                #:buy-sell     "B"
                #:shares       100
                #:stock        "AAPL"
                #:price        1500000))
    (define v (itch-add-order-decode bs))
    (check-equal? (itch-add-order-stock v) "AAPL")
    (check-equal? (itch-add-order-buy-sell v) "B")
    (check-equal? (itch-add-order-shares v) 100)
    (check-equal? (itch-add-order-price v) 1500000)))

(describe "ITCH add order with MPID"
  (it "has a total size of 40 bytes"
    (check-equal? (protocol-desc-total-size itch-add-order-mpid) 40)))

(describe "ITCH order executed"
  (it "has a total size of 31 bytes"
    (check-equal? (protocol-desc-total-size itch-order-executed) 31)))

(describe "ITCH order delete"
  (it "has a total size of 19 bytes"
    (check-equal? (protocol-desc-total-size itch-order-delete) 19)))

(describe "ITCH trade"
  (it "has a total size of 44 bytes"
    (check-equal? (protocol-desc-total-size itch-trade) 44))

  (it "round-trips a trade message"
    (define bs (itch-trade-encode
                #:message-type "P"
                #:stock-locate 42
                #:tracking     7
                #:timestamp    #x0000094F7A00
                #:order-ref    99999
                #:buy-sell     "S"
                #:shares       200
                #:stock        "MSFT"
                #:price        3000000
                #:match-number 5555))
    (define v (itch-trade-decode bs))
    (check-equal? (itch-trade-stock v) "MSFT")
    (check-equal? (itch-trade-buy-sell v) "S")
    (check-equal? (itch-trade-shares v) 200)
    (check-equal? (itch-trade-price v) 3000000)
    (check-equal? (itch-trade-match-number v) 5555))

  (it "supports match on trade fields"
    (define bs (itch-trade-encode
                #:message-type "P"
                #:stock-locate 42
                #:tracking     7
                #:timestamp    #x0000094F7A00
                #:order-ref    99999
                #:buy-sell     "S"
                #:shares       200
                #:stock        "MSFT"
                #:price        3000000
                #:match-number 5555))
    (match (itch-trade-decode bs)
      [(itch-trade #:stock sym #:price p #:shares s)
       (check-equal? sym "MSFT")
       (check-equal? p 3000000)
       (check-equal? s 200)])))

;; ===== PCAP =====

(describe "PCAP global header"
  (it "has a total size of 24 bytes"
    (check-equal? (protocol-desc-total-size pcap-global-header) 24))

  (it "encodes the magic number in little-endian"
    (define bs (pcap-global-header-encode
                #:magic-number  #xA1B2C3D4
                #:version-major 2
                #:version-minor 4
                #:thiszone      0
                #:sigfigs       0
                #:snaplen       65535
                #:network       1))
    (check-equal? (subbytes bs 0 4) (hex->bytes "D4 C3 B2 A1")))

  (it "round-trips correctly"
    (define bs (pcap-global-header-encode
                #:magic-number  #xA1B2C3D4
                #:version-major 2
                #:version-minor 4
                #:thiszone      0
                #:sigfigs       0
                #:snaplen       65535
                #:network       1))
    (define v (pcap-global-header-decode bs))
    (check-equal? (pcap-global-header-magic-number v) #xA1B2C3D4)
    (check-equal? (pcap-global-header-version-major v) 2)
    (check-equal? (pcap-global-header-version-minor v) 4)
    (check-equal? (pcap-global-header-snaplen v) 65535)
    (check-equal? (pcap-global-header-network v) 1)))

(describe "PCAP record header"
  (it "has a total size of 16 bytes"
    (check-equal? (protocol-desc-total-size pcap-record-header) 16))

  (it "round-trips correctly"
    (define bs (pcap-record-header-encode
                #:ts-sec   1616000000
                #:ts-usec  123456
                #:incl-len 64
                #:orig-len 64))
    (define v (pcap-record-header-decode bs))
    (check-equal? (pcap-record-header-ts-sec v) 1616000000)
    (check-equal? (pcap-record-header-ts-usec v) 123456)
    (check-equal? (pcap-record-header-incl-len v) 64)
    (check-equal? (pcap-record-header-orig-len v) 64)))

(describe "PCAP packet (variable-length)"
  (it "encodes header + variable-length data"
    (define bs (pcap-packet-encode
                #:ts-sec   1000
                #:ts-usec  500
                #:incl-len 4
                #:orig-len 100
                #:data     (bytes #xDE #xAD #xBE #xEF)))
    (check-equal? (bytes-length bs) 20))

  (it "decodes variable-length data correctly"
    (define bs (pcap-packet-encode
                #:ts-sec   1000
                #:ts-usec  500
                #:incl-len 3
                #:orig-len 64
                #:data     (bytes 1 2 3)))
    (define v (pcap-packet-decode bs))
    (check-equal? (pcap-packet-ts-sec v) 1000)
    (check-equal? (pcap-packet-incl-len v) 3)
    (check-equal? (pcap-packet-data v) (bytes 1 2 3)))

  (it "round-trips correctly"
    (define bs (pcap-packet-encode
                #:ts-sec   999
                #:ts-usec  0
                #:incl-len 6
                #:orig-len 100
                #:data     (bytes 10 20 30 40 50 60)))
    (define v (pcap-packet-decode bs))
    (check-equal? (pcap-packet-data v) (bytes 10 20 30 40 50 60))
    (check-equal? (pcap-packet-orig-len v) 100))

  (it "supports match patterns"
    (define bs (pcap-packet-encode
                #:ts-sec   1000
                #:ts-usec  0
                #:incl-len 2
                #:orig-len 50
                #:data     (bytes #xAA #xBB)))
    (match (pcap-packet-decode bs)
      [(pcap-packet #:data d #:incl-len len)
       (check-equal? len 2)
       (check-equal? d (bytes #xAA #xBB))])))

;; ===== Ethernet =====

(describe "Ethernet header"
  (it "has a total size of 14 bytes"
    (check-equal? (protocol-desc-total-size ethernet-header) 14))

  (it "encodes known MAC addresses and ethertype"
    (define bs (ethernet-header-encode
                #:dst-mac   (hex->bytes "FF FF FF FF FF FF")
                #:src-mac   (hex->bytes "00 1A 2B 3C 4D 5E")
                #:ethertype #x0800))
    (check-equal? (subbytes bs 0 6) (hex->bytes "FF FF FF FF FF FF"))
    (check-equal? (subbytes bs 12 14) (hex->bytes "08 00")))

  (it "round-trips correctly"
    (define bs (ethernet-header-encode
                #:dst-mac   (bytes 1 2 3 4 5 6)
                #:src-mac   (bytes 7 8 9 10 11 12)
                #:ethertype #x0800))
    (define v (ethernet-header-decode bs))
    (check-equal? (ethernet-header-dst-mac v) (bytes 1 2 3 4 5 6))
    (check-equal? (ethernet-header-src-mac v) (bytes 7 8 9 10 11 12))
    (check-equal? (ethernet-header-ethertype v) #x0800)))

;; ===== UDP =====

(describe "UDP header"
  (it "has a total size of 8 bytes"
    (check-equal? (protocol-desc-total-size udp-header) 8))

  (it "encodes a DNS query header (port 53)"
    (define bs (udp-header-encode
                #:src-port 12345
                #:dst-port 53
                #:length   42
                #:checksum 0))
    (check-equal? (bytes-ref bs 2) #x00)
    (check-equal? (bytes-ref bs 3) #x35))

  (it "round-trips correctly"
    (define bs (udp-header-encode
                #:src-port  49152
                #:dst-port  80
                #:length    100
                #:checksum  #xABCD))
    (define v (udp-header-decode bs))
    (check-equal? (udp-header-src-port v) 49152)
    (check-equal? (udp-header-dst-port v) 80)
    (check-equal? (udp-header-length v) 100)
    (check-equal? (udp-header-checksum v) #xABCD))

  (it "supports match patterns"
    (define bs (udp-header-encode
                #:src-port  49152
                #:dst-port  53
                #:length    42
                #:checksum  0))
    (match (udp-header-decode bs)
      [(udp-header #:dst-port dp)
       (check-equal? dp 53)])))

;; ===== IPv4 =====

(describe "IPv4 header"
  (it "has a total size of 20 bytes"
    (check-equal? (protocol-desc-total-size ipv4-header) 20))

  (it "decodes a known IPv4 header"
    ;; Standard IPv4 header: version=4, ihl=5, dscp=0, ecn=0,
    ;; total-length=1500, id=0xABCD, flags=2(DF), frag=0,
    ;; ttl=64, protocol=6(TCP), checksum=0x0000,
    ;; src=192.168.1.1 (0xC0A80101), dst=10.0.0.1 (0x0A000001)
    (define raw (hex->bytes
                 "45 00 05 DC AB CD 40 00 40 06 00 00 C0 A8 01 01 0A 00 00 01"))
    (define v (ipv4-header-decode raw))
    (check-equal? (ipv4-header-version v) 4)
    (check-equal? (ipv4-header-ihl v) 5)
    (check-equal? (ipv4-header-dscp v) 0)
    (check-equal? (ipv4-header-ecn v) 0)
    (check-equal? (ipv4-header-total-length v) 1500)
    (check-equal? (ipv4-header-identification v) #xABCD)
    (check-equal? (ipv4-header-flags v) 2)
    (check-equal? (ipv4-header-fragment-offset v) 0)
    (check-equal? (ipv4-header-ttl v) 64)
    (check-equal? (ipv4-header-protocol v) 6)
    (check-equal? (ipv4-header-src-ip v) #xC0A80101)
    (check-equal? (ipv4-header-dst-ip v) #x0A000001))

  (it "round-trips correctly"
    (define bs (ipv4-header-encode
                #:version 4 #:ihl 5
                #:dscp 0 #:ecn 0
                #:total-length 1500
                #:identification #xABCD
                #:flags 2 #:fragment-offset 0
                #:ttl 64 #:protocol 6
                #:header-checksum 0
                #:src-ip #xC0A80101
                #:dst-ip #x0A000001))
    (define v (ipv4-header-decode bs))
    (check-equal? (ipv4-header-version v) 4)
    (check-equal? (ipv4-header-ihl v) 5)
    (check-equal? (ipv4-header-total-length v) 1500)
    (check-equal? (ipv4-header-flags v) 2)
    (check-equal? (ipv4-header-ttl v) 64)
    (check-equal? (ipv4-header-src-ip v) #xC0A80101))

  (it "supports match patterns on mixed byte and bitfields"
    (define raw (hex->bytes
                 "45 00 05 DC AB CD 40 00 40 06 00 00 C0 A8 01 01 0A 00 00 01"))
    (match (ipv4-header-decode raw)
      [(ipv4-header #:version ver #:protocol proto #:src-ip src)
       (check-equal? ver 4)
       (check-equal? proto 6)
       (check-equal? src #xC0A80101)])))

;; ===== TCP =====

(describe "TCP header"
  (it "has a total size of 20 bytes"
    (check-equal? (protocol-desc-total-size tcp-header) 20))

  (it "decodes a known TCP SYN header"
    ;; src-port=49152, dst-port=80, seq=1000, ack=0,
    ;; data-offset=5, reserved=0, flags: SYN=1 only,
    ;; window=65535, checksum=0, urgent=0
    ;; Byte 12: data-offset=5 → 0101, reserved=000, NS=0 → 01010000 = 0x50
    ;; Byte 13: CWR=0,ECE=0,URG=0,ACK=0,PSH=0,RST=0,SYN=1,FIN=0 → 00000010 = 0x02
    (define raw (hex->bytes
                 "C0 00 00 50 00 00 03 E8 00 00 00 00 50 02 FF FF 00 00 00 00"))
    (define v (tcp-header-decode raw))
    (check-equal? (tcp-header-src-port v) #xC000)
    (check-equal? (tcp-header-dst-port v) 80)
    (check-equal? (tcp-header-seq-number v) 1000)
    (check-equal? (tcp-header-ack-number v) 0)
    (check-equal? (tcp-header-data-offset v) 5)
    (check-equal? (tcp-header-reserved v) 0)
    (check-equal? (tcp-header-syn v) 1)
    (check-equal? (tcp-header-fin v) 0)
    (check-equal? (tcp-header-ack v) 0)
    (check-equal? (tcp-header-window-size v) #xFFFF))

  (it "round-trips a TCP SYN-ACK"
    (define bs (tcp-header-encode
                #:src-port 80 #:dst-port 49152
                #:seq-number 5000 #:ack-number 1001
                #:data-offset 5 #:reserved 0
                #:ns 0 #:cwr 0 #:ece 0 #:urg 0
                #:ack 1 #:psh 0 #:rst 0 #:syn 1 #:fin 0
                #:window-size 65535
                #:checksum 0 #:urgent-ptr 0))
    (define v (tcp-header-decode bs))
    (check-equal? (tcp-header-src-port v) 80)
    (check-equal? (tcp-header-dst-port v) 49152)
    (check-equal? (tcp-header-seq-number v) 5000)
    (check-equal? (tcp-header-ack-number v) 1001)
    (check-equal? (tcp-header-data-offset v) 5)
    (check-equal? (tcp-header-syn v) 1)
    (check-equal? (tcp-header-ack v) 1)
    (check-equal? (tcp-header-fin v) 0))

  (it "supports match on TCP flags"
    (define bs (tcp-header-encode
                #:src-port 80 #:dst-port 49152
                #:seq-number 5000 #:ack-number 1001
                #:data-offset 5 #:reserved 0
                #:ns 0 #:cwr 0 #:ece 0 #:urg 0
                #:ack 1 #:psh 0 #:rst 0 #:syn 1 #:fin 0
                #:window-size 65535
                #:checksum 0 #:urgent-ptr 0))
    (match (tcp-header-decode bs)
      [(tcp-header #:syn s #:ack a #:dst-port dp)
       (check-equal? s 1)
       (check-equal? a 1)
       (check-equal? dp 49152)])))
