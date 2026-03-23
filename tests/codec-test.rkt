#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field
         wirey/protocol
         wirey/codec
         wirey/length-expr)

;; -- helpers --
(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; ===== Encoding =====

(describe "encode"
  (context "uint fields"
    (it "encodes a 2-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'big))))
      (check-equal? (encode p (hasheq 'val #x0102))
                    (bytes 1 2)))

    (it "encodes a 2-byte little-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'little))))
      (check-equal? (encode p (hasheq 'val #x0102))
                    (bytes 2 1)))

    (it "encodes a 4-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 4 'big))))
      (check-equal? (encode p (hasheq 'val #xDEADBEEF))
                    (hex->bytes "DE AD BE EF")))

    (it "encodes a 6-byte big-endian uint (ITCH timestamp)"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'ts 'uint 6 'big))))
      (check-equal? (encode p (hasheq 'ts #x0102030405FF))
                    (hex->bytes "01 02 03 04 05 FF")))

    (it "encodes a 1-byte uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'v 'uint 1 'big))))
      (check-equal? (encode p (hasheq 'v #x42))
                    (bytes #x42)))

    (it "encodes an 8-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'v 'uint 8 'big))))
      (check-equal? (encode p (hasheq 'v #x0102030405060708))
                    (hex->bytes "01 02 03 04 05 06 07 08"))))

  (context "sint fields"
    (it "encodes a positive sint as unsigned"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 4 'big))))
      (check-equal? (encode p (hasheq 'val 1))
                    (hex->bytes "00 00 00 01")))

    (it "encodes a negative sint via two's complement"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 4 'big))))
      (check-equal? (encode p (hasheq 'val -1))
                    (hex->bytes "FF FF FF FF")))

    (it "encodes a negative sint little-endian"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 2 'little))))
      (check-equal? (encode p (hasheq 'val -2))
                    (bytes #xFE #xFF))))

  (context "alpha fields"
    (it "encodes a string right-padded with spaces"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'sym 'alpha 8 'big))))
      (check-equal? (encode p (hasheq 'sym "AAPL"))
                    (bytes-append #"AAPL" #"    ")))

    (it "encodes a single-char alpha"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'c 'alpha 1 'big))))
      (check-equal? (encode p (hasheq 'c "S"))
                    #"S"))

    (it "truncates string to field width"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'c 'alpha 2 'big))))
      (check-equal? (encode p (hasheq 'c "ABCD"))
                    #"AB")))

  (context "octets fields"
    (it "copies raw bytes"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'mac 'octets 6 'big))))
      (check-equal? (encode p (hasheq 'mac (bytes 1 2 3 4 5 6)))
                    (bytes 1 2 3 4 5 6))))

  (context "multi-field protocol"
    (it "encodes ITCH system event message"
      (define p (make-protocol-desc 'system-event
                  (list (make-field-desc 'message-type 'alpha 1 'big)
                        (make-field-desc 'stock-locate 'uint  2 'big)
                        (make-field-desc 'tracking     'uint  2 'big)
                        (make-field-desc 'timestamp    'uint  6 'big)
                        (make-field-desc 'event-code   'alpha 1 'big))))
      (check-equal?
       (encode p (hasheq 'message-type "S"
                         'stock-locate 0
                         'tracking     0
                         'timestamp    #x00000E4E1C00  ; some timestamp
                         'event-code   "O"))
       (bytes-append #"S"
                     (bytes 0 0)
                     (bytes 0 0)
                     (hex->bytes "00 00 0E 4E 1C 00")
                     #"O")))))

;; ===== Decoding =====

(describe "decode"
  (context "uint fields"
    (it "decodes a 2-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'big))))
      (check-equal? (hash-ref (decode p (bytes 1 2)) 'val)
                    #x0102))

    (it "decodes a 2-byte little-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'little))))
      (check-equal? (hash-ref (decode p (bytes 2 1)) 'val)
                    #x0102))

    (it "decodes a 6-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'ts 'uint 6 'big))))
      (check-equal? (hash-ref (decode p (hex->bytes "01 02 03 04 05 FF")) 'ts)
                    #x0102030405FF))

    (it "decodes with an offset"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'big))))
      (check-equal? (hash-ref (decode p (bytes 0 0 1 2) #:offset 2) 'val)
                    #x0102)))

  (context "sint fields"
    (it "decodes a positive sint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 4 'big))))
      (check-equal? (hash-ref (decode p (hex->bytes "00 00 00 01")) 'val)
                    1))

    (it "decodes a negative sint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 4 'big))))
      (check-equal? (hash-ref (decode p (hex->bytes "FF FF FF FF")) 'val)
                    -1)))

  (context "alpha fields"
    (it "decodes and trims trailing spaces"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'sym 'alpha 8 'big))))
      (check-equal? (hash-ref (decode p (bytes-append #"AAPL" #"    ")) 'sym)
                    "AAPL"))

    (it "decodes a full-width alpha without trimming"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'sym 'alpha 4 'big))))
      (check-equal? (hash-ref (decode p #"MSFT") 'sym)
                    "MSFT")))

  (context "octets fields"
    (it "decodes raw bytes"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'mac 'octets 6 'big))))
      (check-equal? (hash-ref (decode p (bytes 1 2 3 4 5 6)) 'mac)
                    (bytes 1 2 3 4 5 6))))

  (context "round-trip"
    (it "decode(encode(v)) = v for uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 4 'big))))
      (define v (hasheq 'val #xCAFEBABE))
      (check-equal? (decode p (encode p v)) v))

    (it "decode(encode(v)) = v for multi-field ITCH message"
      (define p (make-protocol-desc 'system-event
                  (list (make-field-desc 'message-type 'alpha 1 'big)
                        (make-field-desc 'stock-locate 'uint  2 'big)
                        (make-field-desc 'tracking     'uint  2 'big)
                        (make-field-desc 'timestamp    'uint  6 'big)
                        (make-field-desc 'event-code   'alpha 1 'big))))
      (define v (hasheq 'message-type "S"
                        'stock-locate 0
                        'tracking     42
                        'timestamp    #x00000E4E1C00
                        'event-code   "O"))
      (check-equal? (decode p (encode p v)) v))))

;; ===== Bitfield Encoding =====

(describe "encode (bitfields)"
  (context "two 4-bit nibbles in one byte"
    (it "encodes version=4, ihl=5 as 0x45"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4 'big #:unit 'bits))))
      (check-equal? (encode p (hasheq 'version 4 'ihl 5))
                    (bytes #x45))))

  (context "3+13 bit split across two bytes"
    (it "encodes flags=2, fragment-offset=0 as 0x4000"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'flags   'uint 3  'big #:unit 'bits)
                        (make-field-desc 'frag-off 'uint 13 'big #:unit 'bits))))
      ;; flags=2 → 010, frag-off=0 → 0000000000000 → 0100_0000_0000_0000 = 0x4000
      (check-equal? (encode p (hasheq 'flags 2 'frag-off 0))
                    (bytes #x40 #x00))))

  (context "6+2 bit split"
    (it "encodes dscp=0, ecn=3 as 0x03"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'dscp 'uint 6 'big #:unit 'bits)
                        (make-field-desc 'ecn  'uint 2 'big #:unit 'bits))))
      ;; dscp=0 → 000000, ecn=3 → 11 → 00000011 = 0x03
      (check-equal? (encode p (hasheq 'dscp 0 'ecn 3))
                    (bytes #x03))))

  (context "mixed byte and bitfields"
    (it "encodes bitfield group followed by byte field"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                        (make-field-desc 'total   'uint 2  'big))))
      (check-equal? (encode p (hasheq 'version 4 'ihl 5 'total 1500))
                    (bytes #x45 #x05 #xDC))))

  (context "byte field between two bitfield groups"
    (it "encodes correctly"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'a 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'b 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'c 'uint 2 'big)
                        (make-field-desc 'd 'uint 3 'big #:unit 'bits)
                        (make-field-desc 'e 'uint 13 'big #:unit 'bits))))
      ;; a=0xF, b=0x0 → 0xF0
      ;; c=0x0102
      ;; d=7, e=0 → 111_0000000000000 = 0xE000
      (check-equal? (encode p (hasheq 'a #xF 'b 0 'c #x0102 'd 7 'e 0))
                    (bytes #xF0 #x01 #x02 #xE0 #x00)))))

;; ===== Bitfield Decoding =====

(describe "decode (bitfields)"
  (context "two 4-bit nibbles"
    (it "decodes 0x45 as version=4, ihl=5"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4 'big #:unit 'bits))))
      (define v (decode p (bytes #x45)))
      (check-equal? (hash-ref v 'version) 4)
      (check-equal? (hash-ref v 'ihl) 5)))

  (context "3+13 bit split"
    (it "decodes 0x4000 as flags=2, frag-off=0"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'flags   'uint 3  'big #:unit 'bits)
                        (make-field-desc 'frag-off 'uint 13 'big #:unit 'bits))))
      (define v (decode p (bytes #x40 #x00)))
      (check-equal? (hash-ref v 'flags) 2)
      (check-equal? (hash-ref v 'frag-off) 0)))

  (context "6+2 bit split"
    (it "decodes 0x03 as dscp=0, ecn=3"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'dscp 'uint 6 'big #:unit 'bits)
                        (make-field-desc 'ecn  'uint 2 'big #:unit 'bits))))
      (define v (decode p (bytes #x03)))
      (check-equal? (hash-ref v 'dscp) 0)
      (check-equal? (hash-ref v 'ecn) 3)))

  (context "mixed byte and bitfields"
    (it "decodes bitfield group followed by byte field"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                        (make-field-desc 'total   'uint 2  'big))))
      (define v (decode p (bytes #x45 #x05 #xDC)))
      (check-equal? (hash-ref v 'version) 4)
      (check-equal? (hash-ref v 'ihl) 5)
      (check-equal? (hash-ref v 'total) 1500)))

  (context "round-trip"
    (it "decode(encode(v)) = v for bitfields"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                        (make-field-desc 'total   'uint 2  'big))))
      (define v (hasheq 'version 4 'ihl 5 'total 1500))
      (check-equal? (decode p (encode p v)) v))

    (it "decode(encode(v)) = v for IPv4-like byte 0-1 and 6-7"
      (define p (make-protocol-desc 'ipv4-partial
                  (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                        (make-field-desc 'dscp    'uint 6  'big #:unit 'bits)
                        (make-field-desc 'ecn     'uint 2  'big #:unit 'bits)
                        (make-field-desc 'total   'uint 2  'big)
                        (make-field-desc 'ident   'uint 2  'big)
                        (make-field-desc 'flags   'uint 3  'big #:unit 'bits)
                        (make-field-desc 'frag    'uint 13 'big #:unit 'bits))))
      (define v (hasheq 'version 4 'ihl 5
                        'dscp 0 'ecn 0
                        'total 1500
                        'ident #xABCD
                        'flags 2 'frag 0))
      (check-equal? (decode p (encode p v)) v))))

;; ===== Variable-Length Encoding =====

(describe "encode (variable-length)"
  (context "field-ref width"
    (it "encodes a variable-length field using referenced field's value"
      (define p (make-protocol-desc 'pkt
                  (list (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
      (define bs (encode p (hasheq 'len 3 'data (bytes 1 2 3))))
      ;; 2 bytes for len (big-endian 3) + 3 bytes of data
      (check-equal? bs (bytes 0 3 1 2 3)))

    (it "validates data length matches the length field"
      (define p (make-protocol-desc 'pkt
                  (list (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
      (check-exn exn:fail?
        (λ () (encode p (hasheq 'len 3 'data (bytes 1 2)))))))

  (context "compute width"
    (it "encodes with a computed width expression"
      (define p (make-protocol-desc 'msg
                  (list (make-field-desc 'hdr-len 'uint 1 'big)
                        (make-field-desc 'payload 'octets
                                         (make-compute '(- (field-ref hdr-len) 1)
                                                       (λ (lk) (- (lk 'hdr-len) 1)))
                                         'big))))
      ;; hdr-len=5 means payload is 4 bytes
      (define bs (encode p (hasheq 'hdr-len 5 'payload (bytes 10 20 30 40))))
      (check-equal? bs (bytes 5 10 20 30 40))))

  (context "mixed fixed and variable fields"
    (it "encodes fixed fields before and after variable field"
      (define p (make-protocol-desc 'framed
                  (list (make-field-desc 'tag  'uint   1 'big)
                        (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big)
                        (make-field-desc 'crc  'uint   2 'big))))
      (define bs (encode p (hasheq 'tag #xAA 'len 2 'data (bytes #xBB #xCC) 'crc #xDDEE)))
      (check-equal? bs (bytes #xAA #x00 #x02 #xBB #xCC #xDD #xEE)))))

;; ===== Variable-Length Decoding =====

(describe "decode (variable-length)"
  (context "field-ref width"
    (it "decodes a variable-length field"
      (define p (make-protocol-desc 'pkt
                  (list (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
      (define v (decode p (bytes 0 3 1 2 3)))
      (check-equal? (hash-ref v 'len) 3)
      (check-equal? (hash-ref v 'data) (bytes 1 2 3))))

  (context "mixed fixed and variable fields"
    (it "decodes fields after the variable field correctly"
      (define p (make-protocol-desc 'framed
                  (list (make-field-desc 'tag  'uint   1 'big)
                        (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big)
                        (make-field-desc 'crc  'uint   2 'big))))
      (define v (decode p (bytes #xAA #x00 #x02 #xBB #xCC #xDD #xEE)))
      (check-equal? (hash-ref v 'tag) #xAA)
      (check-equal? (hash-ref v 'len) 2)
      (check-equal? (hash-ref v 'data) (bytes #xBB #xCC))
      (check-equal? (hash-ref v 'crc) #xDDEE)))

  (context "round-trip"
    (it "decode(encode(v)) = v for variable-length protocol"
      (define p (make-protocol-desc 'pkt
                  (list (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
      (define v (hasheq 'len 4 'data (bytes 10 20 30 40)))
      (check-equal? (decode p (encode p v)) v))

    (it "decode(encode(v)) = v for framed message"
      (define p (make-protocol-desc 'framed
                  (list (make-field-desc 'tag  'uint   1 'big)
                        (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big)
                        (make-field-desc 'crc  'uint   2 'big))))
      (define v (hasheq 'tag #xAA 'len 5 'data (bytes 1 2 3 4 5) 'crc #x1234))
      (check-equal? (decode p (encode p v)) v))))

;; ===== Computed Fields Encoding =====

(describe "encode (computed fields)"
  (it "computes a field value via two-pass encoding"
    ;; Simple checksum: sum of all other bytes mod 256
    (define (simple-checksum buf)
      (define total 0)
      (for ([i (in-range (bytes-length buf))])
        (set! total (+ total (bytes-ref buf i))))
      (modulo total 256))
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'tag  'uint 1 'big)
                      (make-field-desc 'data 'uint 2 'big)
                      (make-field-desc 'chk  'uint 1 'big #:compute simple-checksum))))
    ;; Encode without providing 'chk — it should be computed
    (define bs (encode p (hasheq 'tag #xAA 'data #x0102)))
    ;; chk = (#xAA + #x01 + #x02 + 0) mod 256 = #xAD
    (check-equal? (bytes-ref bs 3) #xAD)
    ;; The other fields should be correct
    (check-equal? (bytes-ref bs 0) #xAA)
    (check-equal? (subbytes bs 1 3) (bytes #x01 #x02)))

  (it "ignores a provided value for computed fields"
    (define (always-42 buf) 42)
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'val 'uint 1 'big)
                      (make-field-desc 'chk 'uint 1 'big #:compute always-42))))
    (define bs (encode p (hasheq 'val 99 'chk 0)))
    (check-equal? (bytes-ref bs 1) 42)))

;; ===== Contract Validation on Encode =====

(describe "encode (contract validation)"
  (it "passes when contract is satisfied"
    (define (port? v) (and (integer? v) (<= 0 v 65535)))
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'port 'uint 2 'big #:contract port?))))
    (check-not-exn (λ () (encode p (hasheq 'port 80)))))

  (it "raises when contract is violated"
    (define (port? v) (and (integer? v) (<= 0 v 65535)))
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'port 'uint 2 'big #:contract port?))))
    (check-exn exn:fail?
      (λ () (encode p (hasheq 'port 70000)))))

  (it "includes field name in error message"
    (define (positive? v) (> v 0))
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'count 'uint 1 'big #:contract positive?))))
    (check-exn #rx"count"
      (λ () (encode p (hasheq 'count 0)))))

  (it "skips contract check for computed fields"
    (define (always-valid? v) #f) ;; would fail if checked
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'val 'uint 1 'big)
                      (make-field-desc 'chk 'uint 1 'big
                                       #:compute (λ (buf) 42)
                                       #:contract always-valid?))))
    ;; Should not raise — computed fields aren't checked at encode time
    (check-not-exn (λ () (encode p (hasheq 'val 1))))))
