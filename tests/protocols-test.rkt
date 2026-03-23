#lang racket/base

(require rackunit
         rackunit/spec
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
    (check-equal? (protocol-desc-total-size itch-system-event-protocol) 12))

  (it "round-trips correctly"
    (define v (hasheq 'message-type "S"
                      'stock-locate 0
                      'tracking     0
                      'timestamp    #x00000E4E1C00
                      'event-code   "O"))
    (check-equal? (itch-system-event-decode (itch-system-event-encode v)) v)))

(describe "ITCH add order"
  (it "has a total size of 36 bytes"
    (check-equal? (protocol-desc-total-size itch-add-order-protocol) 36))

  (it "round-trips an AAPL buy order"
    (define v (hasheq 'message-type "A"
                      'stock-locate 1
                      'tracking     0
                      'timestamp    #x0000094F7A00
                      'order-ref    12345678
                      'buy-sell     "B"
                      'shares       100
                      'stock        "AAPL"
                      'price        1500000))  ; $150.0000 implied 4 decimals
    (check-equal? (itch-add-order-decode (itch-add-order-encode v)) v)))

(describe "ITCH add order with MPID"
  (it "has a total size of 40 bytes"
    (check-equal? (protocol-desc-total-size itch-add-order-mpid-protocol) 40)))

(describe "ITCH order executed"
  (it "has a total size of 31 bytes"
    (check-equal? (protocol-desc-total-size itch-order-executed-protocol) 31)))

(describe "ITCH order delete"
  (it "has a total size of 19 bytes"
    (check-equal? (protocol-desc-total-size itch-order-delete-protocol) 19)))

(describe "ITCH trade"
  (it "has a total size of 44 bytes"
    (check-equal? (protocol-desc-total-size itch-trade-protocol) 44))

  (it "round-trips a trade message"
    (define v (hasheq 'message-type "P"
                      'stock-locate 42
                      'tracking     7
                      'timestamp    #x0000094F7A00
                      'order-ref    99999
                      'buy-sell     "S"
                      'shares       200
                      'stock        "MSFT"
                      'price        3000000   ; $300.0000
                      'match-number 5555))
    (check-equal? (itch-trade-decode (itch-trade-encode v)) v)))

;; ===== PCAP =====

(describe "PCAP global header"
  (it "has a total size of 24 bytes"
    (check-equal? (protocol-desc-total-size pcap-global-header-protocol) 24))

  (it "encodes the magic number in little-endian"
    (define v (hasheq 'magic-number  #xA1B2C3D4
                      'version-major 2
                      'version-minor 4
                      'thiszone      0
                      'sigfigs       0
                      'snaplen       65535
                      'network       1))
    (define bs (pcap-global-header-encode v))
    ;; magic in LE: D4 C3 B2 A1
    (check-equal? (subbytes bs 0 4) (hex->bytes "D4 C3 B2 A1")))

  (it "round-trips correctly"
    (define v (hasheq 'magic-number  #xA1B2C3D4
                      'version-major 2
                      'version-minor 4
                      'thiszone      0
                      'sigfigs       0
                      'snaplen       65535
                      'network       1))
    (check-equal? (pcap-global-header-decode (pcap-global-header-encode v)) v)))

(describe "PCAP record header"
  (it "has a total size of 16 bytes"
    (check-equal? (protocol-desc-total-size pcap-record-header-protocol) 16))

  (it "round-trips correctly"
    (define v (hasheq 'ts-sec   1616000000
                      'ts-usec  123456
                      'incl-len 64
                      'orig-len 64))
    (check-equal? (pcap-record-header-decode (pcap-record-header-encode v)) v)))

;; ===== Ethernet =====

(describe "Ethernet header"
  (it "has a total size of 14 bytes"
    (check-equal? (protocol-desc-total-size ethernet-header-protocol) 14))

  (it "encodes known MAC addresses and ethertype"
    (define v (hasheq 'dst-mac   (hex->bytes "FF FF FF FF FF FF")  ; broadcast
                      'src-mac   (hex->bytes "00 1A 2B 3C 4D 5E")
                      'ethertype #x0800))                          ; IPv4
    (define bs (ethernet-header-encode v))
    (check-equal? (subbytes bs 0 6) (hex->bytes "FF FF FF FF FF FF"))
    (check-equal? (subbytes bs 12 14) (hex->bytes "08 00")))

  (it "round-trips correctly"
    (define v (hasheq 'dst-mac   (bytes 1 2 3 4 5 6)
                      'src-mac   (bytes 7 8 9 10 11 12)
                      'ethertype #x0800))
    (check-equal? (ethernet-header-decode (ethernet-header-encode v)) v)))

;; ===== UDP =====

(describe "UDP header"
  (it "has a total size of 8 bytes"
    (check-equal? (protocol-desc-total-size udp-header-protocol) 8))

  (it "encodes a DNS query header (port 53)"
    (define v (hasheq 'src-port  12345
                      'dst-port  53
                      'length    42
                      'checksum  0))
    (define bs (udp-header-encode v))
    ;; dst-port 53 = 0x0035, big-endian → 00 35
    (check-equal? (bytes-ref bs 2) #x00)
    (check-equal? (bytes-ref bs 3) #x35))

  (it "round-trips correctly"
    (define v (hasheq 'src-port  49152
                      'dst-port  80
                      'length    100
                      'checksum  #xABCD))
    (check-equal? (udp-header-decode (udp-header-encode v)) v)))
