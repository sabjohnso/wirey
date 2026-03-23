#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field
         wirey/protocol
         wirey/syntax)

;; Define a protocol using the macro
(define-protocol system-event
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (event-code    alpha  1))

(describe "define-protocol macro"
  (context "protocol descriptor"
    (it "creates a protocol-desc binding"
      (check-pred protocol-desc? system-event-protocol))

    (it "has the correct name"
      (check-eq? (protocol-desc-name system-event-protocol) 'system-event))

    (it "has the correct number of fields"
      (check-equal? (length (protocol-desc-fields system-event-protocol)) 5))

    (it "has the correct total size"
      (check-equal? (protocol-desc-total-size system-event-protocol) 12)))

  (context "generated encode function"
    (it "encodes values to bytes"
      (define bs (system-event-encode
                  (hasheq 'message-type "S"
                          'stock-locate 0
                          'tracking     0
                          'timestamp    #x00000E4E1C00
                          'event-code   "O")))
      (check-equal? (bytes-length bs) 12)
      (check-equal? (bytes-ref bs 0) (char->integer #\S))
      (check-equal? (bytes-ref bs 11) (char->integer #\O))))

  (context "generated decode function"
    (it "decodes bytes to hash"
      (define bs (bytes-append #"S"
                               (bytes 0 0)
                               (bytes 0 42)
                               (bytes 0 0 #x0E #x4E #x1C 0)
                               #"O"))
      (define v (system-event-decode bs))
      (check-equal? (hash-ref v 'message-type) "S")
      (check-equal? (hash-ref v 'stock-locate) 0)
      (check-equal? (hash-ref v 'tracking) 42)
      (check-equal? (hash-ref v 'timestamp) #x00000E4E1C00)
      (check-equal? (hash-ref v 'event-code) "O")))

  (context "round-trip"
    (it "decode(encode(v)) = v"
      (define v (hasheq 'message-type "S"
                        'stock-locate 0
                        'tracking     42
                        'timestamp    #x00000E4E1C00
                        'event-code   "O"))
      (check-equal? (system-event-decode (system-event-encode v)) v))))

;; Test with per-field byte order override
(define-protocol pcap-record
  #:byte-order little
  (ts-sec    uint 4)
  (ts-usec   uint 4)
  (incl-len  uint 4)
  (orig-len  uint 4))

(describe "define-protocol with little-endian default"
  (it "encodes in little-endian"
    (define bs (pcap-record-encode
                (hasheq 'ts-sec   #x01020304
                        'ts-usec  0
                        'incl-len 64
                        'orig-len 64)))
    ;; first 4 bytes should be little-endian 0x01020304
    (check-equal? (bytes-ref bs 0) #x04)
    (check-equal? (bytes-ref bs 1) #x03)
    (check-equal? (bytes-ref bs 2) #x02)
    (check-equal? (bytes-ref bs 3) #x01)))

;; Test per-field byte-order override
(define-protocol mixed-endian
  #:byte-order big
  (big-field    uint 2)
  (little-field uint 2 #:byte-order little))

(describe "define-protocol with per-field byte-order override"
  (it "uses the specified byte-order per field"
    (define bs (mixed-endian-encode
                (hasheq 'big-field    #x0102
                        'little-field #x0304)))
    ;; big-field: big-endian → 01 02
    (check-equal? (bytes-ref bs 0) #x01)
    (check-equal? (bytes-ref bs 1) #x02)
    ;; little-field: little-endian → 04 03
    (check-equal? (bytes-ref bs 2) #x04)
    (check-equal? (bytes-ref bs 3) #x03)))
