#lang racket/base

(require rackunit
         rackunit/spec
         racket/match
         wirey/protocol
         wirey/protocols/itch
         wirey/protocols/pcap
         wirey/protocols/ethernet
         wirey/protocols/udp)

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
